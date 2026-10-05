// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryProvider
 *
 * @notice Stateless verifier interface for JAW recovery providers.
 *
 * @dev A provider holds NO per-account state: the JustaRecoveryManager owns the commitment registry, the
 *      used-salt registry, and the expiry check, and passes everything in on every call. A provider's sole
 *      job is to answer — for a given commitment — whether a proof authorizes recovering `account` to the
 *      new owner encoded in `subject`.
 * @dev All implementations MUST:
 *        - revert on an invalid proof, and return (no value) on success;
 *        - bind the proof to all of `(account, subject, salt, expiry)`, so it cannot be reused across
 *          accounts, target owners, or ceremonies, and a relayer cannot substitute a salt or expiry other
 *          than the one the guardians authorized;
 *        - verify against `commitment` such that a proof is valid for exactly one commitment. Otherwise one
 *          factor could satisfy several recoveries of the same provider in one request, silently weakening
 *          an M-of-N threshold.
 * @dev Canonical providers (shipped by JustaLab) MUST additionally be multichain — one guardian signature
 *      valid on every enrolled chain:
 *        - derive the proven message exclusively from `(account, subject, salt, expiry)`; never read
 *          `block.chainid` into it;
 *        - never route verification through a chain-binding intermediary (e.g. the ERC-1271 door of a
 *          contract the provider does not control);
 *        - deploy deterministically at the same address on every chain (the signing domain binds the
 *          verifying contract's address);
 *        - keep any provider-internal freshness checks chain-independent.
 *      Third-party providers MAY be chain-bound; their factors are then valid on a single chain only.
 * @dev Implementations MAY enforce stricter freshness than the manager's `expiry` (e.g. a DKIM timestamp
 *      bound); the manager's check is the outer bound.
 *
 * @author JustaLab
 */
interface IRecoveryProvider {

    /**
     * @notice Verify that `proof` authorizes recovering `account` to the owner encoded in `subject`,
     *         against the recovery `commitment`. MUST revert if it does not.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload (opaque to the provider; bound by the proof).
     * @param salt The ceremony's single-use salt; consumed per chain by the manager, bound by the proof.
     * @param expiry The ceremony's expiry timestamp; enforced by the manager, bound by the proof.
     * @param commitment The recovery commitment this proof is checked against (e.g. an EOA, a passkey
     *        public key, an email hash).
     * @param proof Provider-specific proof.
     */
    function verify(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        bytes calldata commitment,
        bytes calldata proof
    )
        external;

}
