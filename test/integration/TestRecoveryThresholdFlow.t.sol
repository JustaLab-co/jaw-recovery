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
 * @title TestRecoveryThresholdFlow
 *
 * @notice Integration test for M-of-N recovery against a real stack: several independent recovery EOAs each
 * back one registered recovery, and a threshold of them sign real proofs over the same ceremony
 * `(subject, salt, expiry)`. Proves that a subset meeting the threshold recovers the account, that the queued
 * `executeAt` uses the largest delay among the approving recoveries (the most-cautious factor governs), and
 * that a single invalid approval aborts the whole request.
 */
contract TestRecoveryThresholdFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    address payable internal account;

    /// @dev Ceremony expiry shared by every request here; these tests are not about expiry.
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

    /// @dev Registers an EOA-guardian recovery committing to `eoa` with `delay`, pranked as the account.
    function _addEoaRecovery(address eoa, uint32 delay) private returns (bytes32 recoveryId) {
        vm.prank(account);
        return manager.addRecovery(account, address(provider), encodeEoaCommitment(eoa), delay);
    }

    /// @dev Bounds a fuzzed value to a valid secp256k1 signing key.
    function _boundKey(uint256 pk) private pure returns (uint256) {
        return bound(pk, 1, SECP256K1_CURVE_ORDER - 1);
    }

    /**
     * @notice Recovers an account when a subset of recoveries meeting the threshold approve.
     * @dev Registers three recoveries (three independent signers), sets threshold 2, and recovers with two
     *      distinct valid proofs over the same ceremony. The third recovery never participates.
     */
    function test_ShouldRecoverWhenThresholdApprovalsMet(
        address newOwner,
        uint256 pkA,
        uint256 pkB,
        uint256 pkC
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));

        pkA = _boundKey(pkA);
        pkB = _boundKey(pkB);
        pkC = _boundKey(pkC);
        address eoaA = vm.addr(pkA);
        address eoaB = vm.addr(pkB);
        address eoaC = vm.addr(pkC);
        // Distinct commitments are required: same EOA -> same recoveryId -> RecoveryAlreadyAdded.
        vm.assume(eoaA != eoaB && eoaA != eoaC && eoaB != eoaC);

        bytes32 idA = _addEoaRecovery(eoaA, 0);
        bytes32 idB = _addEoaRecovery(eoaB, 0);
        _addEoaRecovery(eoaC, 0); // registered but does not approve

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-threshold-met");

        // Two distinct recoveries each sign the same ceremony (subject, salt, expiry).
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(idA, signRecoverProof(provider, account, subject, salt, expiry, pkA));
        approvals[1] = createApproval(idB, signRecoverProof(provider, account, subject, salt, expiry, pkB));

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        manager.executeRecoveryRequest(requestId); // delay 0 -> executable immediately

        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice The queued `executeAt` uses the largest delay among the approving recoveries, in either
     *         approval order.
     * @dev Two approving recoveries with strictly different delays: warping only past the smaller delay
     *      still rejects execution; the request is executable only at the larger delay.
     * @dev `swapOrder` fuzzes the position of the larger-delay approval in the array. Approval order is
     *      caller-controlled, so max-delay must hold under BOTH orderings — a "last approval wins"
     *      implementation would let an attacker order a 0-delay factor last and erase the time-lock entirely.
     */
    function test_ShouldQueueWithMaxDelayAcrossApprovals(
        address newOwner,
        uint256 pkA,
        uint256 pkB,
        uint32 delayA,
        uint32 delayB,
        bool swapOrder
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));

        pkA = _boundKey(pkA);
        pkB = _boundKey(pkB);
        address eoaA = vm.addr(pkA);
        address eoaB = vm.addr(pkB);
        vm.assume(eoaA != eoaB);

        // Order the delays so B is strictly larger; B must govern `executeAt`.
        delayB = uint32(bound(delayB, 1, type(uint32).max));
        delayA = uint32(bound(delayA, 0, delayB - 1));

        bytes32 idA = _addEoaRecovery(eoaA, delayA);
        bytes32 idB = _addEoaRecovery(eoaB, delayB);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-threshold-maxdelay");

        IRecoveryManager.Approval memory approvalA =
            createApproval(idA, signRecoverProof(provider, account, subject, salt, expiry, pkA));
        IRecoveryManager.Approval memory approvalB =
            createApproval(idB, signRecoverProof(provider, account, subject, salt, expiry, pkB));

        // The larger-delay approval sits first or last depending on the fuzzed `swapOrder`: the caller picks
        // the order, so the max must govern either way (see the @dev note above).
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = swapOrder ? approvalB : approvalA;
        approvals[1] = swapOrder ? approvalA : approvalB;

        uint256 requestedAt = block.timestamp;
        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);

        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;
        assertEq(executeAt, uint64(requestedAt + delayB));

        // Past only the smaller delay, the request is still locked (the larger delay governs).
        vm.warp(requestedAt + delayA);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotReady.selector, requestId, executeAt)
        );
        manager.executeRecoveryRequest(requestId);
        assertFalse(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 1);

        // At the larger delay it finalizes.
        vm.warp(executeAt);
        manager.executeRecoveryRequest(requestId);
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
    }

    /**
     * @notice A single invalid approval aborts the entire M-of-N request — threshold recovery is all-or-nothing.
     * @dev Two recoveries, threshold 2: one valid proof and one forged (signed by the wrong key for its
     *      commitment). The real provider's strict ecrecover recovers the wrong signer and reverts, so the
     *      whole request reverts, nothing is queued, and the salt is never consumed — an attacker holding one
     *      valid factor gets no partial progress.
     */
    function test_ShouldRejectWholeRequestWhenOneApprovalInvalid(
        address newOwner,
        uint256 pkA,
        uint256 pkB,
        uint256 pkWrong
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));

        pkA = _boundKey(pkA);
        pkB = _boundKey(pkB);
        pkWrong = _boundKey(pkWrong);
        address eoaA = vm.addr(pkA);
        address eoaB = vm.addr(pkB);
        vm.assume(eoaA != eoaB);
        // The forged proof must genuinely fail B's commitment: a wrong signer, not eoaB.
        vm.assume(vm.addr(pkWrong) != eoaB);

        bytes32 idA = _addEoaRecovery(eoaA, 0);
        bytes32 idB = _addEoaRecovery(eoaB, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-threshold-invalid");

        // First approval is valid (A); the second is signed by the wrong key, so B's proof is forged.
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(idA, signRecoverProof(provider, account, subject, salt, expiry, pkA));
        approvals[1] = createApproval(idB, signRecoverProof(provider, account, subject, salt, expiry, pkWrong));

        // The real provider rejects the forged proof and the entire request reverts.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // Nothing was queued and the salt was never consumed (the valid approval alone bought no progress).
        assertFalse(manager.isSaltUsed(account, salt));
        assertEq(manager.recoveryRequest(keccak256(abi.encode(account, subject, salt))).account, address(0));
    }

}
