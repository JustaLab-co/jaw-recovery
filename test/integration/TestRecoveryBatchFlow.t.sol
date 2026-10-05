// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { BaseAccount } from "@account-abstraction/core/BaseAccount.sol";
import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryBatchFlow
 *
 * @notice Integration test for the one-click instant-recovery product flow: the account composes
 * `requestRecovery` and `executeRecoveryRequest` into a single `executeBatch`. With a `delay 0` recovery the
 * queued request is executable in the same transaction, so both steps land atomically. The `requestId` is
 * deterministic (`keccak256(account, subject, salt)`), so the execute call is built ahead of the request;
 * both manager functions are unrestricted and `nonReentrant`, but the two sub-calls are sequential (not
 * nested), so the guard composes.
 */
contract TestRecoveryBatchFlow is Test, PrepareRecovery {

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

    /**
     * @notice Instant recovery in a single transaction: request + execute batched via `account.executeBatch`.
     * @dev Uses a `delay 0` recovery so the request is immediately executable in the same block.
     */
    function test_ShouldRecoverInstantlyViaBatchedRequestAndExecute(address newOwner, uint256 recoveryEoaPk) public {
        vm.assume(newOwner != address(0) && newOwner != account && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        // Register an instant (delay 0) recovery.
        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), 0);

        // Sign a real proof over the ceremony (subject, salt, expiry), and precompute the deterministic id.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-batch");
        uint256 expiry = block.timestamp + 7 days;
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = keccak256(abi.encode(account, subject, salt));

        // One-click recovery: queue and finalize in a single account-driven batch.
        BaseAccount.Call[] memory calls = new BaseAccount.Call[](2);
        calls[0] = BaseAccount.Call({
            target: address(manager),
            value: 0,
            data: abi.encodeCall(manager.requestRecovery, (account, subject, salt, expiry, approvals))
        });
        calls[1] = BaseAccount.Call({
            target: address(manager), value: 0, data: abi.encodeCall(manager.executeRecoveryRequest, (requestId))
        });

        vm.prank(account);
        JustanAccount(account).executeBatch(calls);

        // The new owner landed in one transaction, the proof was consumed, and nothing is left pending.
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertTrue(manager.isSaltUsed(account, salt));
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

}
