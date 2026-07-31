// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EIP712 } from "solady/utils/EIP712.sol";

import { IRecoveryProvider } from "../interfaces/IRecoveryProvider.sol";
import { SignatureProofLib } from "../libraries/SignatureProofLib.sol";

/**
 * @title SignatureRecoveryProvider
 *
 * @notice Canonical multichain recovery verifier for JAW accounts: one guardian signature is valid on
 *         every chain the account enrolled on.
 *
 * @dev Two guardian classes, dispatched by commitment length (see {SignatureProofLib} for the shared
 *      verification core):
 *        - 32-byte `abi.encode(address)` — an EOA guardian, proven by a 64/65-byte ECDSA signature over
 *          the canonical digest. A contract address enrolled this way is a dead factor that never
 *          verifies (no ERC-1271/6492 fallback, by design) — enrollment UIs must reject it.
 *        - 64-byte `abi.encode(x, y)` — a raw P-256 passkey public key, proven by an ABI-encoded WebAuthn
 *          assertion. The guardian's own account contract is never consulted, so undeployed passkey
 *          guardians work natively with no ERC-6492 dependency.
 * @dev The EIP-712 domain deliberately omits `chainId` (`_hashTypedDataSansChainId`): with the
 *      deterministic same-address deployment on every chain, the digest is byte-identical everywhere.
 * @dev Replay safety is the manager's job — it consumes the ceremony `salt` per chain and enforces
 *      `expiry`; this provider only binds them into the digest.
 * @dev Holds no per-account state: the manager owns the commitment registry and passes the registered
 *      commitment in on each `verify` call, so one deployment backs any number of guardians and accounts.
 *
 * @author JustaLab
 */
contract SignatureRecoveryProvider is IRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the commitment is not a canonical guardian encoding: exactly 32 bytes holding a
     *         non-zero address with clean upper bits (EOA guardian), or exactly 64 bytes (raw passkey
     *         public key).
     * @dev Exact lengths keep one guardian mapped to exactly one commitment. `abi.decode` ignores trailing
     *      bytes, so without this check two encodings of the same guardian could register as two distinct
     *      recoveries and one signature could satisfy both, silently weakening an M-of-N threshold.
     */
    error SignatureRecoveryProvider_InvalidCommitment();

    /**
     * @notice Thrown when the proof is not a valid signature from the committed guardian over the
     *         canonical digest.
     */
    error SignatureRecoveryProvider_InvalidSignature();

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice EIP-712 typehash for the Recover struct.
     * @dev All guardians of one ceremony sign this same message; `salt` and `expiry` are enforced by the
     *      manager and only bound here.
     */
    bytes32 public constant RECOVER_TYPEHASH =
        keccak256("Recover(address account,bytes subject,bytes32 salt,uint256 expiry)");

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Verify a recovery proof against a committed guardian. Reverts on failure.
     * @dev Deliberately non-view to keep provider mutability semantics uniform across implementations
     *      (see IRecoveryProvider); this implementation performs no state changes.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload bound by the signature.
     * @param salt The ceremony's single-use salt, bound by the signature; consumed per chain by the manager.
     * @param expiry The ceremony's expiry timestamp, bound by the signature; enforced by the manager.
     * @param commitment The registered guardian: 32-byte `abi.encode(address)` (EOA) or 64-byte
     *        `abi.encode(x, y)` (raw passkey public key).
     * @param proof A 64/65-byte ECDSA signature (EOA guardian), or an ABI-encoded WebAuthn assertion
     *        whose challenge is the canonical digest (passkey guardian).
     */
    function verify(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        bytes calldata commitment,
        bytes calldata proof
    )
        external
    {
        bytes32 digest = _recoverDigest(account, subject, salt, expiry);

        if (commitment.length == 32) {
            // EOA guardian: strict ecrecover only, so a chain-bound smart-account envelope can never
            // re-enter this provider. The range check keeps the typed error for a non-canonical
            // registration (zero or dirty upper bits) instead of a raw `abi.decode` panic.
            uint256 word = uint256(abi.decode(commitment, (bytes32)));
            if (word == 0 || word > type(uint160).max) {
                revert SignatureRecoveryProvider_InvalidCommitment();
            }
            // Safe: `word` is range-checked to fit `uint160` above.
            // forge-lint: disable-next-line(unsafe-typecast)
            if (!SignatureProofLib.isValidEoaProof(digest, address(uint160(word)), proof)) {
                revert SignatureRecoveryProvider_InvalidSignature();
            }
        } else if (commitment.length == 64) {
            // Raw passkey guardian: WebAuthn assertion verified directly against the committed public key,
            // so the guardian's own account contract is never consulted.
            (bytes32 x, bytes32 y) = abi.decode(commitment, (bytes32, bytes32));
            if (!SignatureProofLib.isValidPasskeyProof(digest, x, y, proof)) {
                revert SignatureRecoveryProvider_InvalidSignature();
            }
        } else {
            revert SignatureRecoveryProvider_InvalidCommitment();
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Compute the chain-agnostic EIP-712 digest the guardians of a ceremony must sign.
     * @dev EOA guardians sign this digest directly; passkey guardians produce a WebAuthn assertion with
     *      `challenge = abi.encode(digest)`.
     * @dev Identical on every chain (the domain omits chainId and this provider deploys at the same
     *      deterministic address everywhere).
     * @param account The smart account being recovered.
     * @param subject The new-owner payload.
     * @param salt The ceremony's single-use salt.
     * @param expiry The ceremony's expiry timestamp.
     * @return The EIP-712 digest to sign.
     */
    function recoverDigest(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry
    )
        external
        view
        returns (bytes32)
    {
        return _recoverDigest(account, subject, salt, expiry);
    }

    /**
     * @notice EIP-5267 domain descriptor, overridden to report the domain actually signed over.
     * @dev Solady's default advertises a chainId-bound domain, but every digest this contract verifies is
     *      built sans chainId — tooling that autodiscovers the domain via EIP-5267 would otherwise build
     *      digests that can never verify. `fields = 0x0b` (`0b01011`) = name, version, verifyingContract.
     */
    function eip712Domain()
        public
        view
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0b";
        (name, version) = _domainNameAndVersion();
        chainId = 0; // Deliberately absent from the domain (multichain digests).
        verifyingContract = address(this);
        salt = salt; // `bytes32(0)`.
        extensions = extensions; // `new uint256[](0)`.
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Build the chain-agnostic EIP-712 digest for `(account, subject, salt, expiry)`.
     */
    function _recoverDigest(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(RECOVER_TYPEHASH, account, keccak256(subject), salt, expiry));
        return _hashTypedDataSansChainId(structHash);
    }

    /**
     * @dev EIP-712 domain name and version, consumed by Solady's EIP712 base. The domain binds
     *      `{name, version, verifyingContract}` — chainId is deliberately absent.
     */
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "SignatureRecoveryProvider";
        version = "1";
    }

}
