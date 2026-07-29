// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";

/**
 * @title SignatureProofLib
 *
 * @notice Chain-agnostic dual-branch signature verification shared by the recovery contracts.
 *
 * @dev A signer is identified by its canonical MultiOwnable byte encoding and dispatched on length:
 *        - 32 bytes (`abi.encode(address)`) — an EOA, proven by a 64/65-byte ECDSA signature over the
 *          digest, verified with STRICT `ecrecover` only. Deliberately no ERC-1271/6492 fallback: a
 *          smart-account signer's own `isValidSignature` door re-binds `block.chainid`, which would
 *          silently produce per-chain proofs and break the sign-once promise.
 *        - 64 bytes (`abi.encode(x, y)`) — a raw P-256 passkey public key, proven by an ABI-encoded
 *          WebAuthn assertion whose challenge is the digest. No account contract is ever consulted, so no
 *          chain binding applies and undeployed passkeys work natively.
 * @dev Used by {SignatureRecoveryProvider} (signer = a registered guardian commitment) and by
 *      {JustaRecoveryManager}'s admin door (signer = a current account owner).
 * @dev Signature malleability is accepted by design across both callers: replay protection is
 *      salt-consumption in the manager, and no state anywhere keys off raw proof bytes.
 * @dev Passkey verification requires the RIP-7212 precompile or the canonical Solady P256 verifier on the
 *      chain (the same dependency JustanAccount itself has); without both, passkey proofs verify as invalid.
 *
 * @author JustaLab
 */
library SignatureProofLib {

    /**
     * @notice Whether `proof` is a valid signature from the EOA `signer` over `digest`.
     * @dev Strict `ecrecover` only (no ERC-1271/6492). `tryRecoverCalldata` accepts 65-byte and 64-byte
     *      (EIP-2098) signatures and returns `address(0)` on garbage.
     * @dev The caller MUST ensure `signer` is non-zero (this function also rejects it defensively) so the
     *      zero return can never match.
     * @param digest The signed digest.
     * @param signer The expected EOA signer.
     * @param proof The 64/65-byte ECDSA signature.
     * @return Whether the proof is valid.
     */
    function isValidEoaProof(bytes32 digest, address signer, bytes calldata proof) internal view returns (bool) {
        return signer != address(0) && ECDSA.tryRecoverCalldata(digest, proof) == signer;
    }

    /**
     * @notice Whether `proof` is a valid WebAuthn assertion over `digest` from the P-256 key `(x, y)`.
     * @dev Mirrors JustanAccount's own owner verification: challenge = `abi.encode(digest)`,
     *      `requireUserVerification = false`.
     * @dev `tryDecodeAuth` yields a zeroed auth struct on malformed proof bytes, which then fails
     *      verification cleanly.
     * @param digest The signed digest (the WebAuthn challenge).
     * @param x The public key x coordinate.
     * @param y The public key y coordinate.
     * @param proof The ABI-encoded WebAuthn assertion.
     * @return Whether the proof is valid.
     */
    function isValidPasskeyProof(
        bytes32 digest,
        bytes32 x,
        bytes32 y,
        bytes calldata proof
    )
        internal
        view
        returns (bool)
    {
        return WebAuthn.verify(abi.encode(digest), false, WebAuthn.tryDecodeAuth(proof), x, y);
    }

    /**
     * @notice Whether `proof` is a valid signature over `digest` from the signer identified by
     *         `signerBytes` — the full length dispatch over both branches.
     * @dev Returns `false` (never reverts with a library error) for a `signerBytes` that is neither a
     *      32-byte non-zero address nor a 64-byte public key, so callers keep their own error semantics.
     * @dev A 32-byte `signerBytes` with dirty upper bits reverts on `abi.decode`, mirroring the
     *      pre-existing provider behavior for non-canonical encodings.
     * @param digest The signed digest.
     * @param signerBytes The signer in canonical MultiOwnable form: 32-byte `abi.encode(address)` (EOA)
     *        or 64-byte `abi.encode(x, y)` (raw passkey public key).
     * @param proof The signature: 64/65-byte ECDSA, or an ABI-encoded WebAuthn assertion.
     * @return Whether the proof is valid.
     */
    function isValidProof(
        bytes32 digest,
        bytes calldata signerBytes,
        bytes calldata proof
    )
        internal
        view
        returns (bool)
    {
        if (signerBytes.length == 32) {
            return isValidEoaProof(digest, abi.decode(signerBytes, (address)), proof);
        }
        if (signerBytes.length == 64) {
            (bytes32 x, bytes32 y) = abi.decode(signerBytes, (bytes32, bytes32));
            return isValidPasskeyProof(digest, x, y, proof);
        }
        return false;
    }

}
