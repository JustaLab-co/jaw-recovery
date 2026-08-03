// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Script } from "forge-std/Script.sol";

import { Base64 } from "solady/utils/Base64.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";

import { IRecoveryManager } from "../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../src/providers/SignatureRecoveryProvider.sol";
import { CodeConstants } from "./HelperConfig.s.sol";

/**
 * @title PrepareRecovery
 * @notice Helper contract for building recovery structs and signing recovery proofs in tests.
 */
contract PrepareRecovery is Script, CodeConstants {

    /**
     * @notice Creates a Recovery struct.
     * @param provider The recovery provider (a stateless verifier).
     * @param commitment Provider-specific commitment bytes.
     * @param delay The per-recovery time-lock in seconds.
     * @return recovery The constructed Recovery struct.
     */
    function createRecovery(
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        public
        pure
        returns (IRecoveryManager.Recovery memory recovery)
    {
        return IRecoveryManager.Recovery({ provider: provider, commitment: commitment, delay: delay });
    }

    /**
     * @notice Creates an Approval struct.
     * @param recoveryId The id of the registered recovery being approved.
     * @param proof The provider-specific proof.
     * @return approval The constructed Approval struct.
     */
    function createApproval(
        bytes32 recoveryId,
        bytes memory proof
    )
        public
        pure
        returns (IRecoveryManager.Approval memory approval)
    {
        return IRecoveryManager.Approval({ recoveryId: recoveryId, proof: proof });
    }

    /**
     * @notice Encodes an EOA as a canonical 32-byte guardian commitment (`abi.encode(eoa)`).
     */
    function encodeEoaCommitment(address eoa) public pure returns (bytes memory) {
        return abi.encode(eoa);
    }

    /**
     * @notice Encodes a passkey public key as a canonical 64-byte guardian commitment (`abi.encode(x, y)`).
     */
    function encodePasskeyCommitment(bytes32 x, bytes32 y) public pure returns (bytes memory) {
        return abi.encode(x, y);
    }

    /**
     * @notice Encodes an EOA owner as a 32-byte recovery subject (`abi.encode(owner)`).
     */
    function encodeEoaSubject(address owner) public pure returns (bytes memory) {
        return abi.encode(owner);
    }

    /**
     * @notice Encodes a passkey public key as a 64-byte recovery subject (`abi.encode(x, y)`).
     */
    function encodePasskeySubject(bytes32 x, bytes32 y) public pure returns (bytes memory) {
        return abi.encode(x, y);
    }

    /**
     * @notice Produces a 65-byte ECDSA recovery proof signed by `privateKey` over the provider's
     *         chain-agnostic EIP-712 digest for `(account, subject, salt, expiry)`.
     * @param provider The signature recovery provider whose domain the proof is bound to.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload.
     * @param salt The ceremony's single-use salt.
     * @param expiry The ceremony's expiry timestamp.
     * @param privateKey The signing key (the committed guardian EOA's key for a valid proof).
     * @return proof The 65-byte `(r, s, v)` signature.
     */
    function signRecoverProof(
        SignatureRecoveryProvider provider,
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 privateKey
    )
        public
        view
        returns (bytes memory proof)
    {
        bytes32 digest = provider.recoverDigest(account, subject, salt, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Produces a 64-byte EIP-2098 compact ECDSA recovery proof signed by `privateKey` over the
     *         provider's chain-agnostic EIP-712 digest for `(account, subject, salt, expiry)`.
     * @dev Mirrors `signRecoverProof` but returns the EIP-2098 short form `(r, vs)` that Solady's ECDSA
     *      also accepts for EOA signers. `vm.sign` yields canonical low-s, so the top bit of `s` is free
     *      to carry the y-parity (`v - 27`).
     * @return proof The 64-byte `(r, vs)` compact signature.
     */
    function signRecoverProofCompact(
        SignatureRecoveryProvider provider,
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 privateKey
    )
        public
        view
        returns (bytes memory proof)
    {
        bytes32 digest = provider.recoverDigest(account, subject, salt, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        return abi.encodePacked(r, vs);
    }

    /**
     * @notice Produces an ABI-encoded WebAuthn assertion over `digest`, signed by `passkeyPk`.
     * @dev The challenge is `abi.encode(digest)` — the convention both recovery contracts and
     *      JustanAccount's own owner verification use. `s` is normalized to low-s, which the P-256
     *      verifier requires.
     * @param digest The digest to assert over (the WebAuthn challenge).
     * @param passkeyPk The P-256 private key producing the assertion.
     * @return proof The ABI-encoded `WebAuthnAuth`.
     */
    function signWebAuthnProof(bytes32 digest, uint256 passkeyPk) public pure returns (bytes memory proof) {
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(abi.encode(digest), true, true),
                '","origin":"https://keys.jaw.id","crossOrigin":false}'
            )
        );
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPk, messageHash);
        if (uint256(s) > P256_CURVE_ORDER / 2) {
            s = bytes32(P256_CURVE_ORDER - uint256(s));
        }

        return abi.encode(
            WebAuthn.WebAuthnAuth({
                authenticatorData: authenticatorData,
                clientDataJSON: clientDataJSON,
                typeIndex: 1,
                challengeIndex: 23,
                r: r,
                s: s
            })
        );
    }

    /**
     * @notice Builds an ADD_RECOVERY admin op (`abi.encode(provider, commitment, delay)`).
     */
    function encodeAddRecoveryOp(
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        public
        pure
        returns (IRecoveryManager.AdminOp memory)
    {
        return IRecoveryManager.AdminOp({
            opType: uint8(IRecoveryManager.AdminOpType.ADD_RECOVERY), data: abi.encode(provider, commitment, delay)
        });
    }

    /**
     * @notice Builds a REMOVE_RECOVERY admin op (`abi.encode(recoveryId)`).
     */
    function encodeRemoveRecoveryOp(bytes32 recoveryId) public pure returns (IRecoveryManager.AdminOp memory) {
        return IRecoveryManager.AdminOp({
            opType: uint8(IRecoveryManager.AdminOpType.REMOVE_RECOVERY), data: abi.encode(recoveryId)
        });
    }

    /**
     * @notice Builds a SET_THRESHOLD admin op (`abi.encode(threshold)`).
     */
    function encodeSetThresholdOp(uint256 threshold) public pure returns (IRecoveryManager.AdminOp memory) {
        return IRecoveryManager.AdminOp({
            opType: uint8(IRecoveryManager.AdminOpType.SET_THRESHOLD), data: abi.encode(threshold)
        });
    }

    /**
     * @notice Builds a CANCEL_REQUEST admin op (`abi.encode(requestId)`).
     */
    function encodeCancelRequestOp(bytes32 requestId) public pure returns (IRecoveryManager.AdminOp memory) {
        return IRecoveryManager.AdminOp({
            opType: uint8(IRecoveryManager.AdminOpType.CANCEL_REQUEST), data: abi.encode(requestId)
        });
    }

    /**
     * @notice Produces a 65-byte ECDSA admin proof signed by `privateKey` over the manager's
     *         chain-agnostic EIP-712 digest for `(account, ops, salt, expiry)`.
     * @param manager The recovery manager whose domain the proof is bound to.
     * @param account The smart account whose recovery configuration is administered.
     * @param ops The ordered admin operations.
     * @param salt The batch's single-use salt.
     * @param expiry The signature's expiry timestamp.
     * @param privateKey The signing key (an EOA owner's key of the account for a valid proof).
     * @return proof The 65-byte `(r, s, v)` signature.
     */
    function signAdminProof(
        IRecoveryManager manager,
        address account,
        IRecoveryManager.AdminOp[] memory ops,
        bytes32 salt,
        uint256 expiry,
        uint256 privateKey
    )
        public
        view
        returns (bytes memory proof)
    {
        bytes32 digest = manager.recoveryAdminDigest(account, ops, salt, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

}
