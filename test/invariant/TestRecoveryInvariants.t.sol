// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";
import { JustanAccountFactory } from "justanaccount/JustanAccountFactory.sol";

import { CodeConstants } from "../../script/HelperConfig.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

import { RecoveryHandler } from "./handlers/RecoveryHandler.sol";

/**
 * @title TestRecoveryInvariants
 *
 * @notice Stateful fuzzing of the recovery system: properties that must hold after ANY sequence of calls,
 *         not just the sequences the unit and integration suites happen to write down.
 *
 * @dev How a campaign runs: Forge deploys this contract once, then for each `invariant_*` function plays
 *      `runs` random sequences of `depth` calls against the handler, checking the property after every
 *      call. A failure is shrunk to the shortest sequence that still breaks it and printed as a replayable
 *      call list.
 * @dev The campaign targets only {RecoveryHandler} — never the manager directly. Random bytes thrown at
 *      the manager would revert at the first signature check and explore nothing; the handler turns each
 *      fuzzed call into a correctly signed action or a deliberate attack (see its natspec).
 * @dev Real contracts throughout, as in the integration suites: two factory-deployed JustanAccounts with
 *      an EOA owner and a passkey owner each, the real manager, the real provider. Nothing is mocked.
 * @dev Runs with `fail_on_revert = true` (foundry.toml): the handler catches every expected revert itself,
 *      so a revert that escapes it is a broken test and must not pass silently.
 */
contract TestRecoveryInvariants is Test, CodeConstants {

    JustaRecoveryManager internal manager;
    SignatureRecoveryProvider internal provider;
    RecoveryHandler internal handler;

    address[] internal accounts;

    /// @dev Owners every account starts with: the manager, an EOA and a passkey.
    uint256 internal constant INITIAL_OWNERS = 3;

    function setUp() public {
        // A realistic clock: expiries and time-locks are computed from `block.timestamp`.
        vm.warp(1_800_000_000);

        // Passkey proofs need the P-256 verifier at the addresses Solady calls.
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        EntryPoint entryPoint = new EntryPoint();
        JustanAccountFactory factory = new JustanAccountFactory(address(entryPoint));
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();

        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        uint256[] memory ownerPks = new uint256[](2);
        ownerPks[0] = 0xA11CE;
        ownerPks[1] = 0xB0B;

        for (uint256 i = 0; i < ownerPks.length; ++i) {
            address owner = vm.addr(ownerPks[i]);
            bytes[] memory owners = new bytes[](2);
            owners[0] = abi.encode(owner);
            owners[1] = abi.encode(x, y);
            JustanAccount account = factory.createAccount(owners, i);

            // Opt in: the manager becomes an owner so it can register the recovered owner.
            vm.prank(owner);
            account.addOwnerAddress(address(manager));

            accounts.push(address(account));
        }

        handler = new RecoveryHandler(manager, provider, accounts, ownerPks);

        // Only the handler is fuzzed.
        targetContract(address(handler));
    }

    ////////////////////////////////////////////////////////////////////////
    // INVARIANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The manager never does anything its rules forbid, and never refuses anything they allow.
     * @dev The handler predicts the outcome of every legitimate call from its model and records a violation
     *      on a mismatch. It also records one whenever an attack succeeds: a forged, expired, replayed or
     *      wrongly-counted ceremony; an admin batch not signed by a current owner; a stranger using the
     *      account door; a request executing early, twice, or after cancellation.
     */
    function invariant_NoViolation() public view {
        assertEq(handler.violation(), "", "the handler recorded a violation");
    }

    /**
     * @notice A recovery is always achievable: an account with guardians never needs more approvals than it
     *         has guardians, and the threshold is never below 1.
     */
    function invariant_ThresholdIsAlwaysReachable() public view {
        for (uint256 i = 0; i < accounts.length; ++i) {
            uint256 count = manager.recoveryCount(accounts[i]);
            uint256 threshold = manager.recoveryThreshold(accounts[i]);

            assertGe(threshold, 1, "threshold below 1");
            assertTrue(count == 0 || count >= threshold, "fewer guardians than the threshold");
        }
    }

    /**
     * @notice The guardian set, each guardian's delay, and the threshold are exactly what the account's own
     *         successful admin calls made them — on both accounts independently.
     * @dev This is also the isolation property: the two accounts share guardian keys, so anything that
     *      leaked from one account's administration or recovery into the other would diverge here.
     */
    function invariant_RegistryMatchesModel() public view {
        for (uint256 i = 0; i < accounts.length; ++i) {
            address account = accounts[i];
            RecoveryHandler.Model memory model = handler.model(account);

            assertEq(manager.recoveryCount(account), model.count, "guardian count");
            assertEq(manager.getRecoveries(account).length, model.count, "enumerated guardians");
            assertEq(manager.recoveryThreshold(account), model.threshold, "threshold");

            for (uint256 g = 0; g < handler.GUARDIANS(); ++g) {
                bytes32 id = handler.recoveryIdOf(account, g);
                assertEq(manager.hasRecovery(account, id), model.registered[g], "guardian registration");

                IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, id);
                if (model.registered[g]) {
                    assertEq(recovery.provider, address(provider), "guardian provider");
                    assertEq(recovery.commitment, handler.commitmentOf(g), "guardian commitment");
                    assertEq(recovery.delay, model.delay[g], "guardian delay");
                } else {
                    assertEq(recovery.provider, address(0), "removed guardian left data behind");
                    assertEq(recovery.commitment.length, 0, "removed guardian left a commitment behind");
                }
            }
        }
    }

    /**
     * @notice An account gains an owner only through an executed recovery request, and gains exactly one
     *         per execution. Nothing else in the system adds or removes owners.
     */
    function invariant_OwnersChangeOnlyThroughExecutedRecoveries() public view {
        for (uint256 i = 0; i < accounts.length; ++i) {
            assertEq(
                JustanAccount(payable(accounts[i])).ownerCount(),
                INITIAL_OWNERS + handler.ghost_executed(accounts[i]),
                "owner count"
            );
        }
    }

    /**
     * @notice Every request is in exactly the state its history implies, and a pending request never
     *         changes: same account, same new owner, same execution time as when it was queued.
     * @dev Executed: gone from storage and its owner is on the account. Cancelled: gone from storage and
     *      its owner is NOT on the account.
     */
    function invariant_RequestsMatchTheirHistory() public view {
        for (uint256 i = 0; i < handler.requestCount(); ++i) {
            RecoveryHandler.Request memory expected = handler.requestAt(i);
            IRecoveryManager.RecoveryRequest memory stored = manager.recoveryRequest(expected.id);
            bool isOwner = JustanAccount(payable(expected.account)).isOwnerBytes(expected.subject);

            if (expected.state == RecoveryHandler.RequestState.PENDING) {
                assertEq(stored.account, expected.account, "pending request account");
                assertEq(stored.subject, expected.subject, "pending request owner");
                assertEq(stored.executeAt, expected.executeAt, "pending request execution time");
                assertFalse(isOwner, "owner registered before execution");
            } else {
                assertEq(stored.account, address(0), "finished request still stored");
                assertEq(stored.subject.length, 0, "finished request left its owner behind");
                assertEq(isOwner, expected.state == RecoveryHandler.RequestState.EXECUTED, "owner vs outcome");
            }
        }
    }

    /**
     * @notice A consumed salt stays consumed forever, and only in the registry of its own kind: a ceremony
     *         never spends an admin-batch salt and an admin batch never spends a ceremony salt.
     */
    function invariant_SaltsAreSpentOnceInTheirOwnRegistry() public view {
        for (uint256 i = 0; i < handler.ceremonySaltCount(); ++i) {
            RecoveryHandler.SaltUse memory used = handler.ceremonySaltAt(i);
            assertTrue(manager.isSaltUsed(used.account, used.salt), "ceremony salt no longer spent");
            assertFalse(manager.isAdminSaltUsed(used.account, used.salt), "ceremony salt in the admin registry");
        }
        for (uint256 i = 0; i < handler.adminSaltCount(); ++i) {
            RecoveryHandler.SaltUse memory used = handler.adminSaltAt(i);
            assertTrue(manager.isAdminSaltUsed(used.account, used.salt), "admin salt no longer spent");
            assertFalse(manager.isSaltUsed(used.account, used.salt), "admin salt in the ceremony registry");
        }
    }

    /// @dev Runs once at the end of each run. Prints what the run exercised (visible with `-vv`).
    function afterInvariant() public view {
        handler.callSummary();
    }

}
