// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";
import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryTimelockFlow
 *
 * @notice Integration test for the recovery time-lock against a real stack: a queued request is not
 * executable before its delay elapses, the account can abort a pending request so it never executes, and a
 * request stays executable even after its ceremony `expiry` passes (expiry gates request time only). All
 * prove the real end-to-end consequence — whether the new owner actually lands on the account.
 */
contract TestRecoveryTimelockFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    address payable internal account;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));
        account = TEST_ACCOUNT_ADDRESS;

        vm.deal(account, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(address(manager));
    }

    /// @dev Registers a single EOA-guardian recovery committing to `vm.addr(recoveryEoaPk)` and queues a
    ///      request for `newOwner` over the given ceremony `(salt, expiry)`, returning the request id.
    /// @dev Pins `executeAt == requestedAt + delay` here rather than in each test: every test below warps to
    ///      the `executeAt` it reads back from the contract, so a wrong formula (the delay ignored, say)
    ///      would be invisible everywhere. One assert in the shared helper pins them all.
    function _queueEoaRequest(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        private
        returns (bytes32 requestId, bytes memory subject)
    {
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        subject = encodeEoaSubject(newOwner);
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        uint256 requestedAt = block.timestamp;
        requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertEq(manager.recoveryRequest(requestId).executeAt, uint64(requestedAt + delay));
    }

    /**
     * @notice A queued request cannot execute before its delay, and finalizes once the delay elapses.
     */
    function test_ShouldRejectExecutionBeforeDelayThenSucceedAfter(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));
        vm.assume(delay > 0);
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);

        (bytes32 requestId,) =
            _queueEoaRequest(newOwner, recoveryEoaPk, delay, keccak256("salt-timelock-delay"), block.timestamp + 7 days);
        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;

        // Before the delay elapses, execution is rejected and no owner is added.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotReady.selector, requestId, executeAt)
        );
        manager.executeRecoveryRequest(requestId);
        assertFalse(JustanAccount(account).isOwnerAddress(newOwner));

        // At `executeAt` the request finalizes and the owner lands.
        vm.warp(executeAt);
        manager.executeRecoveryRequest(requestId);
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
    }

    /**
     * @notice A queued request stays executable after its ceremony `expiry` passes.
     * @dev Expiry bounds only how long unused proofs may be submitted at request time; it is never re-checked
     *      once a request is queued. Warping past both the delay and the (short) expiry still finalizes.
     */
    function test_ShouldRemainExecutableAfterExpiryPasses(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);

        // A short ceremony expiry; the request is queued while it is still valid.
        uint256 shortExpiry = block.timestamp + 1 days;
        (bytes32 requestId,) =
            _queueEoaRequest(newOwner, recoveryEoaPk, delay, keccak256("salt-timelock-expiry"), shortExpiry);

        uint256 executeAt = manager.recoveryRequest(requestId).executeAt;

        // Warp past BOTH the delay and the ceremony expiry: a queued request is unaffected by expiry passing.
        uint256 warpTo = executeAt > shortExpiry ? executeAt + 1 : shortExpiry + 1;
        vm.warp(warpTo);
        assertGt(block.timestamp, shortExpiry);

        manager.executeRecoveryRequest(requestId);
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
    }

    /**
     * @notice The account can cancel a pending request, after which it can never execute.
     * @dev The escape hatch is `cancelRecoveryRequest` (callable only by the account); after cancelling,
     *      execution reverts and no owner is ever added.
     */
    function test_ShouldCancelPendingRequestAndBlockExecution(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);

        (bytes32 requestId,) = _queueEoaRequest(
            newOwner, recoveryEoaPk, delay, keccak256("salt-timelock-cancel"), block.timestamp + 7 days
        );

        // The account aborts the pending request.
        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));

        // Execution now reverts (even warping past any delay) and the owner never landed.
        vm.warp(uint256(block.timestamp) + uint256(delay) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);

        assertFalse(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 1);
    }

    /**
     * @notice The account can still cancel after the delay elapses, so its veto persists into the window
     *         where the request is already executable.
     * @dev Cancellation has no time gate: even once `executeAt` has passed and anyone could finalize, the
     *      account can abort first, after which execution reverts and no owner ever lands.
     */
    function test_ShouldAllowCancellationAfterDelayElapses(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);

        (bytes32 requestId,) = _queueEoaRequest(
            newOwner, recoveryEoaPk, delay, keccak256("salt-timelock-cancel-late"), block.timestamp + 7 days
        );

        // Warp past executeAt: the request is now executable by anyone.
        vm.warp(uint256(manager.recoveryRequest(requestId).executeAt) + 1);

        // The account can still cancel it (no time gate on cancellation).
        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));

        // Execution now reverts even though the delay had elapsed, and the owner never landed.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);
        assertFalse(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 1);
    }

    /**
     * @notice If the subject becomes an owner during the delay window, execution reverts but the request is
     *         preserved (CEI), so it stays cancellable rather than being burned.
     * @dev The request-time owner check is best-effort: the owner set can change before execution. When the
     *      subject is added by another path, the real MultiOwnable reverts `MultiOwnable_AlreadyOwner`; the
     *      manager deletes the request before the external add, so a reverting add rolls the delete back and
     *      the request survives.
     */
    function test_ShouldPreserveRequestWhenSubjectBecomesOwnerDuringDelay(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);

        (bytes32 requestId, bytes memory subject) = _queueEoaRequest(
            newOwner, recoveryEoaPk, delay, keccak256("salt-timelock-preserve"), block.timestamp + 7 days
        );

        // During the delay window the subject becomes an owner by another path, so execution will hit
        // MultiOwnable's already-owner guard.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(newOwner);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        // The owner-add reverts; the manager does not catch it, so the whole tx reverts and the CEI delete is
        // rolled back — the request survives rather than being consumed.
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.MultiOwnable_AlreadyOwner.selector, subject));
        manager.executeRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, account);

        // The preserved request is still cancellable by the account.
        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

}
