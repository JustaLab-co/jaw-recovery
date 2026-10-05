// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryReplayFlow
 *
 * @notice Integration test for replay protection against a real stack and the real SignatureRecoveryProvider.
 * A successful `requestRecovery` consumes the ceremony `salt` for the account on this chain, so the same
 * proofs cannot be replayed here: a second request under a consumed salt reverts before the provider is even
 * consulted. Cancelling a queued request does not release its salt (only `_recoveryRequests` is cleared), so a
 * cancelled ceremony stays dead — recovering again requires a fresh ceremony (a new salt) signed anew.
 */
contract TestRecoveryReplayFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    address payable internal account;

    /// @dev Ceremony expiry shared by every request here; these tests are about salt reuse, not expiry.
    uint256 internal expiry;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));
        account = TEST_ACCOUNT_ADDRESS;

        expiry = block.timestamp + 7 days;

        vm.deal(account, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(address(manager));
    }

    /// @dev Runs one full instant (delay 0) recovery to `newOwner` via `recoveryId`, signing a fresh proof
    ///      over the ceremony `salt` with `recoveryEoaPk`.
    function _recoverTo(bytes32 recoveryId, uint256 recoveryEoaPk, address newOwner, bytes32 salt) private {
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        manager.executeRecoveryRequest(requestId); // delay 0 -> executable immediately
    }

    /**
     * @notice Proofs consumed by a successful request cannot be replayed once their salt is consumed.
     * @dev The first request only queues (never executes), so the subject is still not an owner — proving the
     *      rejection is the salt/replay defense firing (`SaltAlreadyUsed`, checked before the provider is
     *      called), not the already-owner fail-fast.
     */
    function test_ShouldRejectReplayedProofsAfterSaltConsumed(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]).
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-replay");
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        // A successful request consumes the salt for this account on this chain, making the proofs single-use.
        manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertTrue(manager.isSaltUsed(account, salt));

        // Replaying the very same proofs now fails against the consumed salt, before the provider is consulted.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    /**
     * @notice The same registered recovery can recover the account more than once: each request consumes its
     *         ceremony salt, and a fresh proof over a new salt authorizes the next recovery.
     * @dev The salt makes each ceremony single-use, not the recovery one-shot — a user may recover repeatedly
     *      over the account's life (e.g. losing keys more than once), each time with a fresh salt.
     */
    function test_ShouldAllowSequentialRecoveriesWithFreshProofs(
        address owner1,
        address owner2,
        uint256 recoveryEoaPk
    )
        public
    {
        vm.assume(owner1 != address(0) && owner1 != account && owner1 != address(manager));
        vm.assume(owner2 != address(0) && owner2 != account && owner2 != address(manager));
        vm.assume(owner1 != owner2);
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        // One registered recovery (delay 0) backs both recoveries.
        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), 0);

        // First recovery: a fresh ceremony salt.
        bytes32 salt1 = keccak256("salt-seq-1");
        _recoverTo(recoveryId, recoveryEoaPk, owner1, salt1);
        assertTrue(JustanAccount(account).isOwnerAddress(owner1));
        assertTrue(manager.isSaltUsed(account, salt1));

        // Second recovery: same recovery, a distinct fresh salt.
        bytes32 salt2 = keccak256("salt-seq-2");
        _recoverTo(recoveryId, recoveryEoaPk, owner2, salt2);
        assertTrue(JustanAccount(account).isOwnerAddress(owner2));
        assertTrue(manager.isSaltUsed(account, salt2));

        // Both recovered owners coexist alongside the manager.
        assertEq(JustanAccount(account).ownerCount(), 3);
    }

    /**
     * @notice Cancelling a queued request does not release its salt: the cancelled ceremony's proofs stay
     *         dead, but a fresh ceremony (new salt) for the same subject queues successfully.
     * @dev `cancelRecoveryRequest` clears only the pending request, never `_usedSalts`. So (a) the same salt +
     *      same proofs revert `SaltAlreadyUsed`, while (b) a brand-new salt signed for the same subject queues
     *      under a new, distinct request id.
     */
    function test_ShouldKeepSaltConsumedAfterCancelButAllowFreshCeremony(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != account && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodeEoaSubject(newOwner);

        // Queue a request under the first ceremony salt, then cancel it as the account.
        bytes32 salt = keccak256("salt-cancel");
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));

        // (a) Cancellation does not release the salt: the same ceremony's proofs stay dead.
        assertTrue(manager.isSaltUsed(account, salt));
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // (b) A fresh ceremony (new salt) for the SAME subject, signed anew, queues under a new request id.
        bytes32 freshSalt = keccak256("salt-cancel-fresh");
        bytes memory freshProof = signRecoverProof(provider, account, subject, freshSalt, expiry, recoveryEoaPk);
        IRecoveryManager.Approval[] memory freshApprovals = new IRecoveryManager.Approval[](1);
        freshApprovals[0] = createApproval(recoveryId, freshProof);

        bytes32 freshRequestId = manager.requestRecovery(account, subject, freshSalt, expiry, freshApprovals);
        assertTrue(freshRequestId != requestId);
        assertEq(manager.recoveryRequest(freshRequestId).account, account);
        assertTrue(manager.isSaltUsed(account, freshSalt));
    }

}
