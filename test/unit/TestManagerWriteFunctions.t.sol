// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { P256 } from "solady/utils/P256.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { IRecoveryProvider } from "../../src/interfaces/IRecoveryProvider.sol";

contract TestManagerWriteFunctions is Test, PrepareRecovery {

    JustaRecoveryManager public manager;

    function setUp() public {
        manager = new JustaRecoveryManager();
    }

    /// @dev Etches `target` with non-empty code so external calls into it pass the contract/extcodesize
    ///      check. Excludes the zero address and precompiles (`vm.etch` rejects precompiles; Prague's reach
    ///      up to 0x11) and the addresses whose code the test relies on (the manager, the test contract, the
    ///      VM), so a fuzzer landing on one is discarded rather than erroring or clobbering it.
    function _etchCode(address target) private {
        vm.assume(uint160(target) > 0xff);
        vm.assume(target != address(manager));
        vm.assume(target != address(this));
        vm.assume(target != address(vm));
        vm.etch(target, hex"00");
    }

    /// @dev Registers a recovery for `account` against a freshly-etched `provider`, pranked as the account.
    ///      Stubs the account as having the manager registered as an owner (the opt-in `addRecovery` now
    ///      requires), since callers of this helper are testing something other than that check.
    function _addRecovery(
        address account,
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        private
        returns (bytes32 recoveryId)
    {
        _etchCode(provider);
        _stubManagerOwner(account, true);
        vm.prank(account);
        return manager.addRecovery(account, provider, commitment, delay);
    }

    /// @dev Stubs `verify` on `provider` to accept (return). Reachable only after the provider is etched.
    function _acceptVerify(address provider) private {
        vm.mockCall(provider, abi.encodeWithSelector(IRecoveryProvider.verify.selector), "");
    }

    /// @dev Etches `account` (so the `isOwnerAddress` call's extcodesize check passes) and stubs that call to
    ///      return `isManagerOwner`, i.e. whether the recovery manager is registered as an owner of `account`.
    function _stubManagerOwner(address account, bool isManagerOwner) private {
        _etchCode(account);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.isOwnerAddress.selector), abi.encode(isManagerOwner));
    }

    /// @dev Etches `account` (so the `isOwnerBytes`/`isOwnerAddress` calls' extcodesize checks pass), stubs
    ///      `isOwnerBytes` to return `isOwner`, and stubs the manager as registered as an owner (true) so the
    ///      `requestRecovery` opt-in check passes by default.
    function _stubAccount(address account, bool isOwner) private {
        _stubManagerOwner(account, true);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.isOwnerBytes.selector), abi.encode(isOwner));
    }

    /// @dev Registers one recovery and queues an accepted recovery request for `account` to take ownership
    ///      of `subject` under `salt` and `expiry`, returning the request id. The account is stubbed as a
    ///      non-owner and the provider's verify is stubbed to accept. Callers must supply an `expiry` that
    ///      is not already in the past at queue time.
    function _queueRequest(
        address account,
        address provider,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint32 delay
    )
        private
        returns (bytes32 requestId)
    {
        bytes32 recoveryId = _addRecovery(account, provider, hex"01", delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        return manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    /*//////////////////////////////////////////////////////////////
                            addRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AddRecovery_RevertIfNotAccount(
        address account,
        address caller,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_RevertIfZeroProvider(address account, bytes calldata commitment, uint32 delay) public {
        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_ZeroProvider.selector);

        vm.prank(account);
        manager.addRecovery(account, address(0), commitment, delay);
    }

    function test_AddRecovery_RevertIfProviderNotContract(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(provider != address(0));
        vm.assume(provider.code.length == 0);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ProviderNotContract.selector, provider)
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_RevertIfEmptyCommitment(address account, address provider, uint32 delay) public {
        _etchCode(provider);

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_EmptyCommitment.selector);

        vm.prank(account);
        manager.addRecovery(account, provider, "", delay);
    }

    function test_AddRecovery_RevertIfAlreadyAdded(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, true);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, provider, commitment, delay);

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryAlreadyAdded.selector, account, recoveryId
            )
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_ShouldRegisterAndEmit(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, true);

        bytes32 expectedId = keccak256(abi.encode(account, provider, commitment));

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdded(account, delay, expectedId);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, provider, commitment, delay);

        assertEq(recoveryId, expectedId);
        assertTrue(manager.hasRecovery(account, recoveryId));
        assertEq(manager.recoveryCount(account), 1);

        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);
        assertEq(recovery.provider, provider);
        assertEq(recovery.commitment, commitment);
        assertEq(recovery.delay, delay);
    }

    function test_AddRecovery_ShouldAllowSameProviderDifferentCommitments(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));
        _etchCode(provider);
        _stubManagerOwner(account, true);

        vm.prank(account);
        bytes32 recoveryId1 = manager.addRecovery(account, provider, commitment1, delay1);

        vm.prank(account);
        bytes32 recoveryId2 = manager.addRecovery(account, provider, commitment2, delay2);

        assertTrue(recoveryId1 != recoveryId2);
        assertEq(manager.recoveryCount(account), 2);
        assertTrue(manager.hasRecovery(account, recoveryId1));
        assertTrue(manager.hasRecovery(account, recoveryId2));
    }

    function test_AddRecovery_RevertIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, false);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ManagerNotAccountOwner.selector, account)
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    /*//////////////////////////////////////////////////////////////
                          removeRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RemoveRecovery_RevertIfNotAccount(address account, address caller, bytes32 recoveryId) public {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.removeRecovery(account, recoveryId);
    }

    function test_RemoveRecovery_RevertIfNotRegistered(address account, bytes32 recoveryId) public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryNotRegistered.selector, account, recoveryId
            )
        );

        vm.prank(account);
        manager.removeRecovery(account, recoveryId);
    }

    function test_RemoveRecovery_RevertIfBelowThreshold(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        // Removing one would drop the count to 1, below the threshold of 2.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RemovalBelowThreshold.selector, 1, 2)
        );

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);
    }

    function test_RemoveRecovery_ShouldRemoveAndEmit(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        // Two recoveries under the default threshold of 1: removing one leaves the other (count 1 >= 1).
        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, delay1);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, delay2);

        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRemoved(account, recoveryId1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);

        // The removed recovery is gone; the other survives.
        assertFalse(manager.hasRecovery(account, recoveryId1));
        assertEq(manager.getRecovery(account, recoveryId1).provider, address(0));
        assertTrue(manager.hasRecovery(account, recoveryId2));
        assertEq(manager.recoveryCount(account), 1);
    }

    function test_RemoveRecovery_ShouldAllowFullOptOut(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        // Start from the state where removals are blocked (count == threshold == 2) and walk the documented
        // opt-out journey: lower the threshold first, then remove down to zero.
        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);
        assertEq(manager.recoveryCount(account), 1);

        // Removing the last recovery (count -> 0) is the full-opt-out exception to the threshold guard.
        vm.prank(account);
        manager.removeRecovery(account, recoveryId2);
        assertEq(manager.recoveryCount(account), 0);
    }

    function test_RemoveRecovery_ShouldAllowReAddWithNewDelay(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment.length != 0);

        // The documented delay-change workflow: remove the recovery and add it again with the new delay.
        // The id is deterministic, so the re-added recovery reclaims the same id with the fresh delay.
        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId);

        vm.prank(account);
        bytes32 reAddedId = manager.addRecovery(account, provider, commitment, delay2);

        assertEq(reAddedId, recoveryId);
        assertTrue(manager.hasRecovery(account, recoveryId));
        assertEq(manager.getRecovery(account, recoveryId).delay, delay2);
    }

    function test_RemoveRecovery_ShouldSucceedIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, 0);

        // The manager was removed as an owner after setup (e.g. the account opted out): teardown must still
        // work, or the account would be stuck with recoveries it can never remove.
        _stubManagerOwner(account, false);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);
        assertEq(manager.recoveryCount(account), 1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId2);
        assertEq(manager.recoveryCount(account), 0);
    }

    /*//////////////////////////////////////////////////////////////
                       setRecoveryThreshold() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetRecoveryThreshold_RevertIfNotAccount(address account, address caller, uint256 threshold) public {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.setRecoveryThreshold(account, threshold);
    }

    function test_SetRecoveryThreshold_RevertIfZero(
        address account,
        address provider,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        _addRecovery(account, provider, commitment, 0);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, 0, 1));

        vm.prank(account);
        manager.setRecoveryThreshold(account, 0);
    }

    function test_SetRecoveryThreshold_RevertIfAboveCount(
        address account,
        address provider,
        bytes calldata commitment,
        uint256 threshold
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(threshold > 1);

        _addRecovery(account, provider, commitment, 0);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, threshold, 1)
        );

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);
    }

    function test_SetRecoveryThreshold_RevertIfNoRecoveries(address account, uint256 threshold) public {
        vm.assume(threshold >= 1);

        // With no recoveries registered, no threshold is valid: configuration requires enrollment first
        // (the same rule that forces ADD_RECOVERY before SET_THRESHOLD inside an admin batch).
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, threshold, 0)
        );

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);
    }

    function test_SetRecoveryThreshold_ShouldSetAndEmit(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint256 threshold
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        // Valid threshold range is [1, recoveryCount] = [1, 2]; default (old) threshold is 1.
        threshold = bound(threshold, 1, 2);

        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryThresholdChanged(account, 1, threshold);

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);

        assertEq(manager.recoveryThreshold(account), threshold);
    }

    function test_SetRecoveryThreshold_ShouldSucceedIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        // The manager was removed as an owner after setup (e.g. the account opted out): lowering the
        // threshold must stay possible, or `removeRecovery`'s below-threshold guard would make stale
        // recoveries permanently impossible to clean up.
        _stubManagerOwner(account, false);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 1);

        assertEq(manager.recoveryThreshold(account), 1);
    }

    /// @dev Wraps a single admin op in the array the door takes.
    function _oneOp(IRecoveryManager.AdminOp memory op) private pure returns (IRecoveryManager.AdminOp[] memory ops) {
        ops = new IRecoveryManager.AdminOp[](1);
        ops[0] = op;
    }

    /// @dev Signs `ops` as the EOA owner `ownerPk`, returning the owner bytes and proof the admin door
    ///      expects. Kept separate from the submitting call: the signing helper fetches the digest from the
    ///      manager, so inlining it would let that staticcall consume a pending `vm.expectRevert`.
    function _signAdmin(
        address account,
        IRecoveryManager.AdminOp[] memory ops,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk
    )
        private
        view
        returns (bytes memory ownerBytes, bytes memory proof)
    {
        ownerBytes = abi.encode(vm.addr(ownerPk));
        proof = signAdminProof(manager, account, ops, salt, expiry, ownerPk);
    }

    /*//////////////////////////////////////////////////////////////
                      executeRecoveryAdmin() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteRecoveryAdmin_RevertIfEmptyAdminOps(
        address account,
        bytes32 salt,
        uint256 expiry,
        bytes calldata ownerBytes,
        bytes calldata proof
    )
        public
    {
        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](0);

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_EmptyAdminOps.selector);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);
    }

    function test_ExecuteRecoveryAdmin_RevertIfProofsExpired(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint256 threshold,
        bytes calldata ownerBytes,
        bytes calldata proof
    )
        public
    {
        vm.assume(expiry < type(uint256).max);
        vm.warp(expiry + 1);

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](1);
        ops[0] = encodeSetThresholdOp(threshold);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ProofsExpired.selector, expiry));
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        // A signature that arrives too late changes nothing: the salt stays free, so the owner can re-sign
        // the same batch under it rather than having to pick a new one.
        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_ExecuteRecoveryAdmin_RevertIfSaltAlreadyUsed(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, true);
        bytes memory ownerBytes = abi.encode(vm.addr(ownerPk));

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](1);
        ops[0] = encodeAddRecoveryOp(provider, hex"01", delay);
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, ownerPk);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);
        assertTrue(manager.isSaltUsed(account, salt));

        // The salt is spent for the account, not just for that batch: a different, freshly signed batch
        // under the same salt is rejected before any of its ops run.
        IRecoveryManager.AdminOp[] memory otherOps = new IRecoveryManager.AdminOp[](1);
        otherOps[0] = encodeAddRecoveryOp(provider, hex"02", delay);
        bytes memory otherProof = signAdminProof(manager, account, otherOps, salt, expiry, ownerPk);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.executeRecoveryAdmin(account, otherOps, salt, expiry, ownerBytes, otherProof);
    }

    function test_ExecuteRecoveryAdmin_RevertIfSaltConsumedByCeremony(
        address account,
        address provider,
        address newOwner,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(newOwner != address(0));
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _queueRequest(account, provider, encodeEoaSubject(newOwner), salt, expiry, delay);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeSetThresholdOp(1));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        // One registry serves both doors: a salt spent by a guardian ceremony is spent for admin batches
        // too.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);
    }

    function test_ExecuteRecoveryAdmin_RevertIfSignerNotAccountOwner(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, false);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(provider, hex"01", delay));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        // A genuine signature is not authority on its own: the signer must be a current owner on this
        // chain, which is what makes a removed owner's outstanding batches die by themselves.
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_SignerNotAccountOwner.selector, account, ownerBytes
            )
        );
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_ExecuteRecoveryAdmin_RevertIfInvalidOwnerProof(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint256 attackerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);
        attackerPk = bound(attackerPk, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(ownerPk != attackerPk);

        _etchCode(provider);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(provider, hex"01", delay));
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, attackerPk);

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_InvalidOwnerProof.selector);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, abi.encode(vm.addr(ownerPk)), proof);

        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_ExecuteRecoveryAdmin_RevertIfOwnerBytesMalformed(
        address account,
        bytes32 salt,
        uint256 expiry,
        bytes calldata ownerBytes,
        bytes calldata proof
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(ownerBytes.length != 32 && ownerBytes.length != 64);

        _stubAccount(account, true);

        // Owner bytes that are neither an address nor a public key match no verification branch, so the
        // proof check fails closed instead of falling through. Unreachable in production — MultiOwnable
        // only ever stores the two canonical forms — so the account is mocked into accepting them here.
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeSetThresholdOp(1));

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_InvalidOwnerProof.selector);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);
    }

    function test_ExecuteRecoveryAdmin_RevertIfSignerIsManager(
        address account,
        bytes32 salt,
        uint256 expiry,
        bytes calldata proof
    )
        public
    {
        vm.assume(expiry > block.timestamp);

        _stubAccount(account, true);

        // After opt-in the manager itself is an owner, so `abi.encode(manager)` clears the owner check —
        // but a contract can never produce an ECDSA signature, so no proof exists that opens this door.
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeSetThresholdOp(1));

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_InvalidOwnerProof.selector);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, abi.encode(address(manager)), proof);
    }

    function test_ExecuteRecoveryAdmin_RevertIfInvalidAdminOp(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint8 opType,
        bytes memory data
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(opType > uint8(type(IRecoveryManager.AdminOpType).max));
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(IRecoveryManager.AdminOp({ opType: opType, data: data }));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidAdminOp.selector, opType));
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_ExecuteRecoveryAdmin_ShouldApplyAddRecoveryOp(
        address account,
        address provider,
        bytes calldata commitment,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(commitment.length != 0);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, true);

        bytes32 expectedId = manager.computeRecoveryId(account, provider, commitment);
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(provider, commitment, delay));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdded(account, delay, expectedId);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, expectedId);
        assertEq(recovery.provider, provider);
        assertEq(recovery.commitment, commitment);
        assertEq(recovery.delay, delay);
    }

    function test_ExecuteRecoveryAdmin_ShouldApplyRemoveRecoveryOp(
        address account,
        address provider,
        bytes calldata commitment,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(commitment.length != 0);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeRemoveRecoveryOp(recoveryId));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRemoved(account, recoveryId);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.hasRecovery(account, recoveryId));
        assertEq(manager.recoveryCount(account), 0);
    }

    function test_ExecuteRecoveryAdmin_ShouldApplySetThresholdOp(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _addRecovery(account, provider, hex"01", 0);
        _addRecovery(account, provider, hex"02", 0);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeSetThresholdOp(2));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryThresholdChanged(account, 1, 2);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertEq(manager.recoveryThreshold(account), 2);
    }

    function test_ExecuteRecoveryAdmin_ShouldApplyCancelRequestOp(
        address account,
        address provider,
        address newOwner,
        bytes32 salt,
        bytes32 ceremonySalt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(newOwner != address(0));
        vm.assume(salt != ceremonySalt);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        bytes32 requestId = _queueRequest(account, provider, encodeEoaSubject(newOwner), ceremonySalt, expiry, delay);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeCancelRequestOp(requestId));
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        // The account bound into the digest stands in for `msg.sender` here, so a relayer's submission
        // cancels on the owner's behalf.
        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRequestCancelled(account, requestId);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    function test_ExecuteRecoveryAdmin_ShouldAcceptPasskeyOwnerProof(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(account != P256.VERIFIER && account != P256.RIP_PRECOMPILE);
        vm.assume(provider != P256.VERIFIER && provider != P256.RIP_PRECOMPILE);

        _etchCode(provider);
        _stubAccount(account, true);
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        // A raw passkey owner authorizes the batch directly: the account's own signature door is never
        // consulted, which is what keeps the batch valid on every chain.
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        bytes memory ownerBytes = abi.encode(bytes32(x), bytes32(y));

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(provider, hex"01", delay));
        bytes memory proof = signWebAuthnProof(manager.recoveryAdminDigest(account, ops, salt, expiry), PASSKEY_PK);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertTrue(manager.hasRecovery(account, manager.computeRecoveryId(account, provider, hex"01")));
    }

    function test_ExecuteRecoveryAdmin_ShouldConsumeSaltAndEmitEnvelope(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, true);

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](2);
        ops[0] = encodeAddRecoveryOp(provider, hex"01", delay);
        ops[1] = encodeAddRecoveryOp(provider, hex"02", delay);
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        assertFalse(manager.isSaltUsed(account, salt));

        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdminExecuted(account, salt, ops.length);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertTrue(manager.isSaltUsed(account, salt));
    }

    function test_ExecuteRecoveryAdmin_ShouldApplyOpsInSignedOrder(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, true);

        // Enrollment in one signature: both guardians are registered before the threshold that counts
        // them is raised.
        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](3);
        ops[0] = encodeAddRecoveryOp(provider, hex"01", delay);
        ops[1] = encodeAddRecoveryOp(provider, hex"02", delay);
        ops[2] = encodeSetThresholdOp(2);
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertEq(manager.recoveryCount(account), 2);
        assertEq(manager.recoveryThreshold(account), 2);
    }

    function test_ExecuteRecoveryAdmin_RevertAndKeepSaltIfAnyOpFails(
        address account,
        address provider,
        bytes32 salt,
        uint256 expiry,
        uint256 ownerPk,
        uint32 delay
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        ownerPk = bound(ownerPk, 1, SECP256K1_CURVE_ORDER - 1);

        _etchCode(provider);
        _stubAccount(account, true);

        // The same three ops in the wrong order: the threshold is raised before the guardians it counts
        // exist. The batch is all-or-nothing, so the two valid adds leave no trace and the salt survives
        // for a corrected re-signature.
        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](3);
        ops[0] = encodeSetThresholdOp(2);
        ops[1] = encodeAddRecoveryOp(provider, hex"01", delay);
        ops[2] = encodeAddRecoveryOp(provider, hex"02", delay);
        (bytes memory ownerBytes, bytes memory proof) = _signAdmin(account, ops, salt, expiry, ownerPk);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, 2, 0));
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertEq(manager.recoveryCount(account), 0);
        assertFalse(manager.isSaltUsed(account, salt));
    }

    /*//////////////////////////////////////////////////////////////
                          requestRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RequestRecovery_RevertIfInvalidApprovalCount(
        address account,
        bytes calldata subject,
        uint8 count,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        // The effective threshold defaults to 1; any other approval count is rejected before anything else.
        vm.assume(count != 1);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](count);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidApprovalCount.selector, count, 1)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfProofsExpired(
        address account,
        address newOwner,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        // The approval count matches the default threshold of 1, so the expiry check (the second guard) is
        // the first thing that can fail. Fuzz `expiry` across its full domain and move "now" just past it —
        // the tightest expired instant. `type(uint256).max` is excluded: it can never expire.
        vm.assume(expiry < type(uint256).max);
        vm.warp(expiry + 1);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ProofsExpired.selector, expiry));
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // The reverting request consumed no salt.
        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_RequestRecovery_RevertIfInvalidSubjectLength(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(subject.length != 32 && subject.length != 64);
        vm.assume(expiry > block.timestamp);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubjectLength.selector, subject.length)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfInvalidSubject(
        address account,
        uint256 dirtySubject,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        // A 32-byte subject whose upper bits do not fit in an address.
        vm.assume(dirtySubject > type(uint160).max);
        bytes memory subject = abi.encode(dirtySubject);
        vm.assume(expiry > block.timestamp);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubject.selector, subject));
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfSubjectZeroAddress(address account, bytes32 salt, uint256 expiry) public {
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodeEoaSubject(address(0));

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        // An owner nobody can ever sign for: the account rejects signatures that recover to `address(0)`.
        // Rejected here, where a retry is free, rather than executing into a recovery that reports success
        // and leaves the user just as locked out with the ceremony spent.
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubject.selector, subject));
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfSubjectZeroPublicKey(address account, bytes32 salt, uint256 expiry) public {
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodePasskeySubject(bytes32(0), bytes32(0));

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        // Same dead-owner case on the passkey side: P-256 rejects the zero key, so no assertion can ever
        // satisfy it. This is also the only content check the 64-byte branch has.
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubject.selector, subject));
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfSaltAlreadyUsed(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(expiry > block.timestamp);

        // A first, fully-valid request consumes the salt for the account.
        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertTrue(manager.isSaltUsed(account, salt));

        // A second request reusing the same salt is rejected, even though the approvals are otherwise valid.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfSubjectAlreadyOwner(
        address account,
        address newOwner,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(newOwner != address(0));
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodeEoaSubject(newOwner);
        _stubAccount(account, true);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SubjectAlreadyOwner.selector, subject)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfManagerNotAccountOwner(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        // Otherwise-fully-valid setup: a registered recovery, the correct approval count, and an accepting
        // provider — the manager opt-in check is the only reason this reverts.
        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);
        _stubManagerOwner(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-1");
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ManagerNotAccountOwner.selector, account)
        );
        manager.requestRecovery(account, subject, salt, block.timestamp + 7 days, approvals);

        // The proof was not consumed: the salt was never marked used.
        assertFalse(manager.isSaltUsed(account, salt));
    }

    function test_RequestRecovery_RevertIfRecoveryNotRegistered(
        address account,
        address newOwner,
        bytes32 recoveryId,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(newOwner != address(0));
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodeEoaSubject(newOwner);
        _stubAccount(account, false);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryNotRegistered.selector, account, recoveryId
            )
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfDuplicateRecovery(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment1,
        bytes calldata commitment2,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        _stubAccount(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(recoveryId1, "");
        approvals[1] = createApproval(recoveryId1, "");

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_DuplicateRecovery.selector, recoveryId1)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_RevertIfProofRejected(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);

        // The provider rejects the proof; its revert must bubble up unchanged.
        bytes memory rejection = abi.encodeWithSignature("ProofRejected()");
        vm.mockCallRevert(provider, abi.encodeWithSelector(IRecoveryProvider.verify.selector), rejection);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(rejection);
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    function test_RequestRecovery_ShouldUseMaxDelay(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, delay1);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, delay2);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        _stubAccount(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(recoveryId1, "");
        approvals[1] = createApproval(recoveryId2, "");

        uint256 maxDelay = delay1 > delay2 ? delay1 : delay2;

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);

        assertEq(manager.recoveryRequest(requestId).executeAt, uint64(block.timestamp + maxDelay));
    }

    function test_RequestRecovery_ShouldMarkSaltUsed(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        assertFalse(manager.isSaltUsed(account, salt));
        manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    function test_RequestRecovery_ShouldQueueEoaSubjectAndEmit(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes32[] memory expectedIds = new bytes32[](1);
        expectedIds[0] = recoveryId;
        bytes32 expectedRequestId = keccak256(abi.encode(account, subject, salt));
        uint64 expectedExecuteAt = uint64(block.timestamp + delay);

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequested(account, expectedRequestId, expectedIds, subject, expectedExecuteAt);

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);

        assertEq(requestId, expectedRequestId);
        assertTrue(manager.isSaltUsed(account, salt));

        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);
        assertEq(request.account, account);
        assertEq(request.executeAt, expectedExecuteAt);
        assertEq(request.subject, subject);
    }

    function test_RequestRecovery_ShouldQueuePasskeySubject(
        address account,
        address provider,
        bytes32 x,
        bytes32 y,
        bytes calldata commitment,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(x != 0 || y != 0);
        vm.assume(expiry > block.timestamp);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodePasskeySubject(x, y);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);

        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);
        assertEq(request.subject, subject);
        assertEq(request.subject.length, 64);
    }

    function test_RequestRecovery_ShouldSupportMultipleSimultaneousRequests(
        address account,
        address provider,
        address ownerA,
        address ownerB,
        uint32 delay,
        bytes32 saltA,
        bytes32 saltB,
        uint256 expiry
    )
        public
    {
        vm.assume(ownerA != ownerB);
        vm.assume(ownerA != address(0) && ownerB != address(0));
        // Distinct salts are the premise: one salt can only ever queue one request per chain.
        vm.assume(saltA != saltB);
        vm.assume(expiry > block.timestamp);

        // A single registered recovery backs both requests; the account is a non-owner and verify accepts.
        bytes32 recoveryId = _addRecovery(account, provider, hex"01", delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes memory subjectA = encodeEoaSubject(ownerA);
        bytes memory subjectB = encodeEoaSubject(ownerB);

        // Queue request A under saltA, then request B under saltB: both coexist under distinct ids
        // (requestId binds the salt, which differs between them).
        bytes32 requestIdA = manager.requestRecovery(account, subjectA, saltA, expiry, approvals);
        bytes32 requestIdB = manager.requestRecovery(account, subjectB, saltB, expiry, approvals);

        assertTrue(requestIdA != requestIdB);
        assertEq(manager.recoveryRequest(requestIdA).subject, subjectA);
        assertEq(manager.recoveryRequest(requestIdB).subject, subjectB);
        assertTrue(manager.isSaltUsed(account, saltA));
        assertTrue(manager.isSaltUsed(account, saltB));

        // Execute A: only request A is consumed; request B stays pending and independently executable.
        vm.warp(manager.recoveryRequest(requestIdA).executeAt);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector), "");
        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (ownerA)));
        manager.executeRecoveryRequest(requestIdA);
        assertEq(manager.recoveryRequest(requestIdA).account, address(0));
        assertEq(manager.recoveryRequest(requestIdB).account, account);

        // Cancel B: consumed independently, with request A already gone.
        vm.prank(account);
        manager.cancelRecoveryRequest(requestIdB);
        assertEq(manager.recoveryRequest(requestIdB).account, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      executeRecoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteRecoveryRequest_RevertIfNotPending(bytes32 requestId) public {
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);
    }

    function test_ExecuteRecoveryRequest_RevertIfNotReady(
        address account,
        address provider,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(delay > 0);
        vm.assume(expiry > block.timestamp);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;

        // Still before `executeAt` (no warp).
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotReady.selector, requestId, executeAt)
        );
        manager.executeRecoveryRequest(requestId);
    }

    function test_ExecuteRecoveryRequest_RevertIfAccountHasNoCode(
        address account,
        address provider,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(newOwner != address(0));
        vm.assume(expiry > block.timestamp);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        // The account loses its code during the time-lock — an EIP-7702 delegation revoked by its key
        // holder. The owner-add returns nothing, so without this guard the call would succeed vacuously:
        // request deleted, success event emitted, no owner registered. Reverting keeps the request alive
        // until the delegation is restored.
        vm.etch(account, "");

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_AccountHasNoCode.selector, account)
        );
        manager.executeRecoveryRequest(requestId);

        assertEq(manager.recoveryRequest(requestId).account, account);
    }

    function test_ExecuteRecoveryRequest_ShouldAddEoaOwnerAndEmit(
        address account,
        address provider,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(newOwner != address(0));
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector), "");

        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (newOwner)));
        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequestExecuted(account, requestId, subject);

        manager.executeRecoveryRequest(requestId);

        // The pending entry is consumed.
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    function test_ExecuteRecoveryRequest_ShouldAddPasskeyOwnerAndEmit(
        address account,
        address provider,
        bytes32 x,
        bytes32 y,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(x != 0 || y != 0);
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodePasskeySubject(x, y);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerPublicKey.selector), "");

        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerPublicKey, (x, y)));
        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequestExecuted(account, requestId, subject);

        manager.executeRecoveryRequest(requestId);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    function test_ExecuteRecoveryRequest_ShouldKeepRequestIfOwnerAddReverts(
        address account,
        address provider,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(newOwner != address(0));
        vm.assume(expiry > block.timestamp);
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        bytes memory addOwnerSel = abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector);

        // The account rejects the owner-add; the manager does not catch it, so the whole tx reverts and the
        // CEI delete is rolled back, leaving the request executable.
        bytes memory accountRevert = abi.encodeWithSelector(MultiOwnable.MultiOwnable_AlreadyOwner.selector, subject);
        vm.mockCallRevert(account, addOwnerSel, accountRevert);

        vm.expectRevert(accountRevert);
        manager.executeRecoveryRequest(requestId);

        // The request survived the failed execution.
        assertEq(manager.recoveryRequest(requestId).account, account);

        // A later successful execution consumes it.
        vm.mockCall(account, addOwnerSel, "");
        manager.executeRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       cancelRecoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CancelRecoveryRequest_RevertIfNotPending(address caller, bytes32 requestId) public {
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        vm.prank(caller);
        manager.cancelRecoveryRequest(requestId);
    }

    function test_CancelRecoveryRequest_RevertIfNotAccount(
        address account,
        address provider,
        address caller,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(caller != account);
        vm.assume(expiry > block.timestamp);

        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );
        vm.prank(caller);
        manager.cancelRecoveryRequest(requestId);
    }

    function test_CancelRecoveryRequest_ShouldCancelAndEmit(
        address account,
        address provider,
        address newOwner,
        uint32 delay,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        vm.assume(expiry > block.timestamp);
        vm.assume(newOwner != address(0));
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, salt, expiry, delay);

        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRequestCancelled(account, requestId);

        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

}
