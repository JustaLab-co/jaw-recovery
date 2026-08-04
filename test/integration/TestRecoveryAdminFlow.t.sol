// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";
import { JustanAccountFactory } from "justanaccount/JustanAccountFactory.sol";

import { ERC7739Utils } from "../../lib/justanaccount/test/utils/ERC7739Utils.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryAdminFlow
 *
 * @notice Integration proof of the signed admin door (`executeRecoveryAdmin`) against a real stack. The unit
 * suite stubs `isOwnerBytes` on fuzzed addresses and never touches a real account, so nothing there proves
 * the door works against genuine MultiOwnable state: that a real owner's key produces a proof the manager
 * accepts, that removing that owner on-chain kills its signatures, that a passkey owner (the JAW norm) can
 * authorize a batch at all, and that the batch's effects are real enough for a subsequent guardian ceremony
 * to recover the account. Every batch here is signed by an account OWNER and submitted by an unrelated
 * `relayer` — the door's whole point is that authorization travels in the signature, not in `msg.sender`.
 */
contract TestRecoveryAdminFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    JustanAccountFactory public factory;
    EntryPoint public entryPoint;

    /// @dev The registered EOA owner that authorizes the admin batches.
    uint256 internal constant ADMIN_OWNER_PK = 0xAD317;

    /// @dev A second registered EOA owner, used to prove a removed owner's signatures die.
    uint256 internal constant SECOND_OWNER_PK = 0x5EC0AD;

    /// @dev Per-recovery time-lock used throughout.
    uint32 internal constant DELAY = 3 days;

    /// @dev Admin-batch expiry window. An admin batch has ONE signer and is relayed immediately, so it needs
    /// no multi-party signing window — the SDK default is 15 minutes.
    uint256 internal constant ADMIN_EXPIRY_WINDOW = 15 minutes;

    /// @dev Guardian-ceremony expiry window (several guardians must sign, so it is far wider).
    uint256 internal constant CEREMONY_EXPIRY_WINDOW = 7 days;

    /// @dev The registered owner whose key signs the admin batches, and its canonical owner bytes.
    address internal adminOwner;
    bytes internal adminOwnerBytes;

    /// @dev The unrelated submitter of every admin batch below.
    address internal relayer;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));
        factory = new JustanAccountFactory(address(entryPoint));

        vm.deal(TEST_ACCOUNT_ADDRESS, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as owner index 0 so it may add the recovered owner at execution.
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(address(manager));

        // Register the admin signer as owner index 1. The 7702 EOA's authority over its own account is
        // `msg.sender == address(this)`, NOT an entry in MultiOwnable's owner registry — so its key is not
        // an owner key. The admin door authenticates purely through `isOwnerBytes`, so it needs a key that
        // belongs to a REGISTERED owner.
        adminOwner = vm.addr(ADMIN_OWNER_PK);
        adminOwnerBytes = abi.encode(adminOwner);
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(adminOwner);

        // WebAuthn verification needs the P256 verifier etched at the addresses Solady staticcalls (the same
        // dependency JustanAccount itself has for passkey owners).
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        relayer = makeAddr("relayer");
    }

    ////////////////////////////////////////////////////////////////////////
    // ADMIN DOOR FLOW TESTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice ONE signed batch enrolls both guardians and raises the threshold, and the configuration it
     *         writes is real enough for a 2-of-2 guardian ceremony to recover the account through it.
     * @dev The whole enrollment is a single owner signature landed by a relayer: two `ADD_RECOVERY`s plus a
     *      `SET_THRESHOLD(2)` in signed order (the threshold is raised only after the guardians it counts
     *      exist). The event expectations pin the emission order — per-op events fire from the shared
     *      internals during the loop, `RecoveryAdminExecuted` closes the batch last. The capstone then runs
     *      the real ceremony (EOA guardian signature + passkey guardian WebAuthn assertion) end to end, so
     *      the admin door is proven by the recovery it enables, not merely by its own storage writes.
     */
    function test_ShouldConfigureRecoveryViaSignedAdminBatchEndToEnd(address newOwner, uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered owner must not already be on the account (manager + adminOwner are).
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != adminOwner);

        // Fuzz the EOA guardian via its signing key (vm.addr/vm.sign need a key in [1, n-1]).
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        bytes memory eoaCommitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));
        bytes memory passkeyCommitment = encodePasskeyCommitment(bytes32(x), bytes32(y));

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](3);
        ops[0] = encodeAddRecoveryOp(address(provider), eoaCommitment, DELAY);
        ops[1] = encodeAddRecoveryOp(address(provider), passkeyCommitment, DELAY);
        ops[2] = encodeSetThresholdOp(2);

        bytes32 salt = keccak256("admin-enrollment-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, ADMIN_OWNER_PK);

        bytes32 eoaRecoveryId = manager.computeRecoveryId(account, address(provider), eoaCommitment);
        bytes32 passkeyRecoveryId = manager.computeRecoveryId(account, address(provider), passkeyCommitment);

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdded(account, DELAY, eoaRecoveryId);
        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdded(account, DELAY, passkeyRecoveryId);
        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryThresholdChanged(account, 1, 2);
        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdminExecuted(account, salt, ops.length);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, adminOwnerBytes, proof);

        assertTrue(manager.hasRecovery(account, eoaRecoveryId));
        assertTrue(manager.hasRecovery(account, passkeyRecoveryId));
        assertEq(manager.recoveryCount(account), 2);
        assertEq(manager.recoveryThreshold(account), 2);
        assertTrue(manager.isSaltUsed(account, salt));

        // Capstone: the admin-enrolled guardians run a real 2-of-2 ceremony against that configuration.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("admin-enrolled-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(
            eoaRecoveryId, signRecoverProof(provider, account, subject, ceremonySalt, ceremonyExpiry, eoaGuardianPk)
        );
        approvals[1] = createApproval(
            passkeyRecoveryId,
            signWebAuthnProof(provider.recoverDigest(account, subject, ceremonySalt, ceremonyExpiry), PASSKEY_PK)
        );

        bytes32 requestId = manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new owner genuinely landed on the account, through a configuration nobody but a relayer ever
        // submitted.
        assertTrue(JustanAccount(account).isOwnerBytes(subject));
    }

    /**
     * @notice A passkey owner — the JAW-norm owner — can authorize an admin batch, verified against its raw
     *         `(x, y)` bytes with no account signature door in the loop.
     * @dev The account is created by the factory with the manager already among its initial owners, so it is
     *      born opted in and this batch is the FIRST transaction its recovery configuration ever needs. The
     *      owner proof is a WebAuthn assertion whose challenge is the admin digest, verified against the raw
     *      `(x, y)` with no account contract consulted — which is what makes the branch chain-agnostic, but
     *      this file never moves `block.chainid`, so that property is PROVEN in
     *      `TestRecoveryAdminMultichainFlow` (`test_ShouldApplyOneAdminBatchOnTwoChains`), not here.
     */
    function test_ShouldAcceptPasskeyOwnerSignedAdminBatch(uint256 eoaGuardianPk, uint32 delay) public {
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // Born opted in: the passkey owner and the manager are both initial owners (no opt-in tx ever).
        bytes[] memory initialOwners = new bytes[](2);
        initialOwners[0] = abi.encode(bytes32(x), bytes32(y));
        initialOwners[1] = abi.encode(address(manager));
        address account = address(factory.createAccount(initialOwners, 0));

        bytes memory ownerBytes = abi.encode(bytes32(x), bytes32(y));
        bytes memory commitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(address(provider), commitment, delay));
        bytes32 salt = keccak256("passkey-owner-admin-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProofPasskey(manager, account, ops, salt, expiry, PASSKEY_PK);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        bytes32 recoveryId = manager.computeRecoveryId(account, address(provider), commitment);
        assertTrue(manager.hasRecovery(account, recoveryId));
        assertEq(manager.getRecovery(account, recoveryId).delay, delay);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice An admin batch signed while its signer was an owner is rejected once the account removes that
     *         owner — the ownership check reads live MultiOwnable state at submission time.
     * @dev The signature never becomes cryptographically invalid; it simply stops being an OWNER's signature.
     *      Because the check precedes salt consumption, the rejected batch leaves no trace at all: the salt
     *      stays fresh and the op it carried never applied.
     * @dev The freshness assertion straight after a revert is tautological on its own — EVM rollback
     *      guarantees it — so the salt's survival is proven by CONSUMING it afterwards: the owner is
     *      re-added and the IDENTICAL batch bytes then land, which is only possible if the failed attempt
     *      wrote nothing.
     */
    function test_ShouldRejectAdminBatchSignedByRemovedOwner(uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        // A third owner joins at index 2 (index 0 = manager, index 1 = adminOwner, both from `setUp`).
        address secondOwner = vm.addr(SECOND_OWNER_PK);
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(secondOwner);
        assertTrue(JustanAccount(account).isOwnerAddress(secondOwner));

        bytes memory ownerBytes = abi.encode(secondOwner);
        bytes memory commitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(address(provider), commitment, DELAY));
        bytes32 salt = keccak256("removed-owner-admin-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;

        // Signed while still an owner, then revoked before the relayer gets around to submitting.
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, SECOND_OWNER_PK);

        vm.prank(account);
        JustanAccount(account).removeOwnerAtIndex(2, ownerBytes);
        assertFalse(JustanAccount(account).isOwnerAddress(secondOwner));

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_SignerNotAccountOwner.selector, account, ownerBytes
            )
        );
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.isSaltUsed(account, salt));
        assertFalse(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));

        // The account changes its mind and re-registers the owner. The same signed bytes — never re-signed —
        // now land, which is the real proof that the rejected submission consumed nothing.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(secondOwner);
        assertTrue(JustanAccount(account).isOwnerAddress(secondOwner));

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertTrue(manager.isSaltUsed(account, salt));
        assertTrue(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));
    }

    /**
     * @notice One signed cancel batch, landed by a relayer, kills a pending recovery request for good.
     * @dev The veto path an owner actually uses when a ceremony they did not authorize is queued: the
     *      guardian was enrolled through the ACCOUNT door, so the only thing the admin door does here is
     *      cancel. `_cancelRecoveryRequest` authorizes on the account bound into the SIGNED digest rather
     *      than on `msg.sender`, which is exactly what lets a relayer land the veto.
     */
    function test_ShouldCancelPendingRequestViaAdminBatchAndBlockExecution(
        address newOwner,
        uint256 eoaGuardianPk
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != adminOwner);

        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodeEoaCommitment(vm.addr(eoaGuardianPk)), DELAY);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("vetoed-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(
            recoveryId, signRecoverProof(provider, account, subject, ceremonySalt, ceremonyExpiry, eoaGuardianPk)
        );

        bytes32 requestId = manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals);
        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;

        // One tap: the owner signs a cancel batch, an unrelated relayer lands it.
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeCancelRequestOp(requestId));
        bytes32 cancelSalt = keccak256("admin-cancel-batch");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, cancelSalt, adminExpiry, ADMIN_OWNER_PK);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, cancelSalt, adminExpiry, adminOwnerBytes, proof);

        // The request is gone; both authorizations are spent on this chain in the one shared salt registry.
        assertEq(manager.recoveryRequest(requestId).account, address(0));
        assertTrue(manager.isSaltUsed(account, cancelSalt));
        assertTrue(manager.isSaltUsed(account, ceremonySalt));

        // Even once the original time-lock has elapsed there is nothing left to execute.
        vm.warp(executeAt);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);

        assertFalse(JustanAccount(account).isOwnerBytes(subject));
    }

    /**
     * @notice A cancel batch submitted before its target request exists reverts WITHOUT consuming its salt,
     *         so the identical signed bytes still veto the request once it lands.
     * @dev This pins the deliberate strict-revert semantics of `_cancelRecoveryRequest`: it reverts on a
     *      non-pending request instead of no-opping. The distinction is the whole security property here.
     *      A no-op would succeed, consume the salt, and leave the owner disarmed — precisely in the race an
     *      attacker controls, since they choose when to submit the ceremony and can watch the mempool for
     *      the veto. Reverting means losing the race costs nothing: the batch is atomic, so the salt write
     *      rolls back with it and the pre-signed veto stays live until it actually cancels something. That
     *      pre-signing is possible at all because `requestId = keccak256(abi.encode(account, subject, salt))`
     *      is deterministic — an owner who has seen a leaked ceremony's parameters can arm the veto before
     *      the attack is on-chain, and hand the same bytes to a relayer to fan out. The cross-chain half of
     *      that story is NOT exercised here (this file never moves `block.chainid`); it is proven in
     *      `TestRecoveryAdminMultichainFlow.test_ShouldCancelOnBothChainsWithOneSignature`.
     */
    function test_ShouldKeepCancelBatchAliveUntilRequestLands(address newOwner, uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != adminOwner);

        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodeEoaCommitment(vm.addr(eoaGuardianPk)), DELAY);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("pre-empted-attack-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;

        // Deterministic and knowable before the request exists — that is what makes the veto pre-signable.
        bytes32 requestId = keccak256(abi.encode(account, subject, ceremonySalt));

        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeCancelRequestOp(requestId));
        bytes32 cancelSalt = keccak256("pre-signed-veto");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, cancelSalt, adminExpiry, ADMIN_OWNER_PK);

        // Landing the veto too early: there is nothing to cancel, so the whole batch reverts...
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, cancelSalt, adminExpiry, adminOwnerBytes, proof);

        // ...and the salt write reverts with it, so the owner is not disarmed by losing the race.
        assertFalse(manager.isSaltUsed(account, cancelSalt));

        // The attack now lands, under exactly the requestId the veto was signed for.
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(
            recoveryId, signRecoverProof(provider, account, subject, ceremonySalt, ceremonyExpiry, eoaGuardianPk)
        );
        assertEq(manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals), requestId);

        // The IDENTICAL batch bytes — same ops, same salt, same signature — now succeed.
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, cancelSalt, adminExpiry, adminOwnerBytes, proof);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
        assertTrue(manager.isSaltUsed(account, cancelSalt));
    }

    /**
     * @notice One failing op reverts the whole batch on real account state: the valid op that already applied
     *         rolls back and the salt survives for a corrected re-signature.
     * @dev The batch enrolls one guardian and then demands a threshold of 2. Ops apply in signed order, so
     *      when `_setRecoveryThreshold` runs the ADD has ALREADY applied and the account's registered count
     *      is 1 (not the 0 it was when the batch was signed) — hence the `InvalidThreshold(2, 1)` args below.
     *      That the reported count already includes the same batch's ADD is itself the evidence that the ops
     *      share one transaction's state; the assertions then prove that shared state is discarded whole.
     * @dev The post-revert freshness assertions are tautological on their own (EVM rollback guarantees
     *      them), so the salt's survival is proven by CONSUMING it: a corrected batch, re-signed under the
     *      SAME salt, then lands — exactly the "fix the threshold and re-sign" recovery path the SDK takes.
     */
    function test_ShouldRevertWholeBatchAndConsumeNothingIfOneOpFails(uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        bytes memory commitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](2);
        ops[0] = encodeAddRecoveryOp(address(provider), commitment, DELAY);
        ops[1] = encodeSetThresholdOp(2);

        bytes32 salt = keccak256("half-valid-admin-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, ADMIN_OWNER_PK);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, 2, 1));
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, adminOwnerBytes, proof);

        // Nothing landed: not the recovery the first op added, not the threshold, not the salt.
        assertFalse(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));
        assertEq(manager.recoveryCount(account), 0);
        assertEq(manager.recoveryThreshold(account), 1);
        assertFalse(manager.isSaltUsed(account, salt));

        // The salt really is still spendable: the same batch with the threshold corrected to a value the
        // post-ADD count supports, re-signed under the SAME salt, now applies in full.
        IRecoveryManager.AdminOp[] memory correctedOps = new IRecoveryManager.AdminOp[](2);
        correctedOps[0] = encodeAddRecoveryOp(address(provider), commitment, DELAY);
        correctedOps[1] = encodeSetThresholdOp(1);
        bytes memory correctedProof = signAdminProof(manager, account, correctedOps, salt, expiry, ADMIN_OWNER_PK);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, correctedOps, salt, expiry, adminOwnerBytes, correctedProof);

        assertTrue(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));
        assertEq(manager.recoveryCount(account), 1);
        assertEq(manager.recoveryThreshold(account), 1);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice A smart-account OWNER cannot authorize an admin batch, even with a proof its own ERC-1271
     *         `isValidSignature` provably accepts.
     * @dev The mirror of the guardian-side strictness test in `TestRecoveryLifecycleFlow`, one layer up: a
     *      32-byte `ownerBytes` is verified with STRICT ecrecover only, with NO ERC-1271/6492 fallback.
     *      WHY that is the desired behavior: a 1271 door would let a smart-account owner re-bind
     *      `block.chainid` inside its own `isValidSignature`, silently turning one signed batch into a
     *      per-chain one and breaking the sign-once multichain promise the whole door exists for
     *      (SPEC-MULTICHAIN-ADMIN D-A2). Smart-account owners are therefore excluded by design and fall
     *      back to the per-chain account door.
     * @dev What makes this load-bearing rather than a tautology is that the proof is REAL: a WebAuthn
     *      assertion from the smart owner's passkey, ERC-7739 PersonalSign-wrapped over the admin digest
     *      using the owner's own EIP-712 domain — asserted below to pass that owner's `isValidSignature`.
     *      The `ownerBytes` is likewise a genuine registry entry (asserted). A green revert against a proof
     *      that PROVABLY satisfies the owner's own 1271 check is what proves no 1271 door exists here.
     */
    function test_ShouldRejectSmartAccountOwnerProofEvenWithAccepting1271(uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        // A passkey-backed JustanAccount, registered as a genuine owner of the account under recovery.
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        bytes[] memory smartOwnerOwners = new bytes[](1);
        smartOwnerOwners[0] = abi.encode(bytes32(x), bytes32(y));
        JustanAccount smartOwner = factory.createAccount(smartOwnerOwners, 1);

        vm.prank(account);
        JustanAccount(account).addOwnerAddress(address(smartOwner));

        bytes memory ownerBytes = abi.encode(address(smartOwner));
        assertTrue(JustanAccount(account).isOwnerBytes(ownerBytes));

        bytes memory commitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(address(provider), commitment, DELAY));
        bytes32 salt = keccak256("smart-account-owner-admin-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;

        bytes32 digest = manager.recoveryAdminDigest(account, ops, salt, expiry);
        bytes memory proof = _smartOwnerProof(address(smartOwner), digest);

        // Sanity: the very same proof genuinely verifies through the smart owner's own ERC-1271 door...
        assertTrue(smartOwner.isValidSignature(digest, proof) == ERC1271_MAGIC);

        // ...yet the admin door refuses it: the 32-byte branch is strict ecrecover, which can never recover
        // a contract address, so no 1271 envelope can satisfy it.
        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_InvalidOwnerProof.selector);
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.isSaltUsed(account, salt));
        assertFalse(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));
    }

    /**
     * @notice The manager cannot authorize a batch on its own behalf, even though opting in makes it a real
     *         owner of the account.
     * @dev Pins SPEC-MULTICHAIN-ADMIN §9d/§9e-2 against REAL state rather than a stub: after opt-in the
     *      manager genuinely IS a registered owner (asserted), so `ownerBytes = abi.encode(manager)` sails
     *      through the ownership check. It dies one line later because the 32-byte branch demands an ECDSA
     *      signature FROM the manager's address, which a contract can never produce — the proof below is
     *      well-formed and simply recovers to someone else. A dead path by construction, pinned so a future
     *      refactor that added a 1271 fallback would fail here loudly.
     */
    function test_ShouldRejectManagerAsOwnerBytesDeadPath(uint256 eoaGuardianPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        // The manager is an owner: `setUp` opted the account in, which is what registers it.
        bytes memory ownerBytes = abi.encode(address(manager));
        assertTrue(JustanAccount(account).isOwnerBytes(ownerBytes));

        bytes memory commitment = encodeEoaCommitment(vm.addr(eoaGuardianPk));
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeAddRecoveryOp(address(provider), commitment, DELAY));
        bytes32 salt = keccak256("manager-as-owner-admin-batch");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;

        // A perfectly well-formed 65-byte ECDSA proof — signed by a key that is not (and cannot be) the
        // manager's, since the manager has no key at all. The signer mismatch IS the point.
        bytes memory proof = signAdminProof(manager, account, ops, salt, expiry, ADMIN_OWNER_PK);

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_InvalidOwnerProof.selector);
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertFalse(manager.isSaltUsed(account, salt));
        assertFalse(manager.hasRecovery(account, manager.computeRecoveryId(account, address(provider), commitment)));
    }

    /**
     * @notice Removing a guardian and lowering the threshold must be signed threshold-FIRST: the reverse
     *         order reverts, and the correct order applies both in one batch.
     * @dev The live-attack scenario for D-A1's signed-order atomicity — "one of my guardians is
     *      compromised, remove it now, everywhere". Op order is part of what the owner signs and the
     *      contract replays it verbatim per chain, so the SDK cannot reorder in transit and the same bytes
     *      behave identically on every chain. Wrong order fails for a real reason: `_removeRecovery` applies
     *      first, leaving 1 recovery against a still-live threshold of 2, which
     *      `RemovalBelowThreshold(1, 2)` refuses — the guard that keeps recovery achievable.
     * @dev The wrong-order batch's salt is then SPENT by an unrelated batch, proving the failed attempt
     *      consumed nothing and the owner was never disarmed by signing the ops the wrong way round.
     */
    function test_ShouldOrderGuardianRemovalBatchThresholdFirst(uint256 firstPk, uint256 secondPk) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        firstPk = bound(firstPk, 1, SECP256K1_CURVE_ORDER - 1);
        secondPk = bound(secondPk, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(vm.addr(firstPk) != vm.addr(secondPk));

        // 2-of-2 through the ACCOUNT door: this test is about the ORDER of the removal batch, not enrollment.
        bytes memory firstCommitment = encodeEoaCommitment(vm.addr(firstPk));
        bytes memory secondCommitment = encodeEoaCommitment(vm.addr(secondPk));

        vm.startPrank(account);
        manager.addRecovery(account, address(provider), firstCommitment, DELAY);
        bytes32 secondId = manager.addRecovery(account, address(provider), secondCommitment, DELAY);
        manager.setRecoveryThreshold(account, 2);
        vm.stopPrank();

        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;

        // WRONG order: the removal lands while the threshold still counts the guardian being removed.
        IRecoveryManager.AdminOp[] memory wrongOps = new IRecoveryManager.AdminOp[](2);
        wrongOps[0] = encodeRemoveRecoveryOp(secondId);
        wrongOps[1] = encodeSetThresholdOp(1);

        bytes32 wrongSalt = keccak256("guardian-removal-wrong-order");
        bytes memory wrongProof = signAdminProof(manager, account, wrongOps, wrongSalt, expiry, ADMIN_OWNER_PK);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RemovalBelowThreshold.selector, 1, 2)
        );
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, wrongOps, wrongSalt, expiry, adminOwnerBytes, wrongProof);

        assertTrue(manager.hasRecovery(account, secondId));
        assertEq(manager.recoveryThreshold(account), 2);

        // CORRECT order, fresh salt: lower the threshold first, then remove the compromised guardian.
        IRecoveryManager.AdminOp[] memory rightOps = new IRecoveryManager.AdminOp[](2);
        rightOps[0] = encodeSetThresholdOp(1);
        rightOps[1] = encodeRemoveRecoveryOp(secondId);

        bytes32 rightSalt = keccak256("guardian-removal-right-order");
        bytes memory rightProof = signAdminProof(manager, account, rightOps, rightSalt, expiry, ADMIN_OWNER_PK);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, rightOps, rightSalt, expiry, adminOwnerBytes, rightProof);

        assertFalse(manager.hasRecovery(account, secondId));
        assertEq(manager.recoveryCount(account), 1);
        assertEq(manager.recoveryThreshold(account), 1);

        // The wrong-order batch's salt survived its revert: a later batch — here the owner re-enrolling the
        // guardian it just removed — spends it, which is the real proof the failed attempt wrote nothing.
        IRecoveryManager.AdminOp[] memory laterOps =
            _oneOp(encodeAddRecoveryOp(address(provider), secondCommitment, DELAY));
        bytes memory laterProof = signAdminProof(manager, account, laterOps, wrongSalt, expiry, ADMIN_OWNER_PK);

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, laterOps, wrongSalt, expiry, adminOwnerBytes, laterProof);

        assertTrue(manager.isSaltUsed(account, wrongSalt));
        assertTrue(manager.hasRecovery(account, secondId));
        assertEq(manager.recoveryCount(account), 2);
    }

    /**
     * @notice Both request-writing doors revert against an account with no code, rather than writing a
     *         request no one could ever execute.
     * @dev SPEC-MULTICHAIN-ADMIN §9a: on a chain where the 4337 account is undeployed (or a 7702 delegation
     *      was revoked) every path that would write recovery state first staticcalls the account —
     *      `isOwnerBytes` on the admin door, `isOwnerBytes(subject)` on the ceremony door — and Solidity's
     *      compiler-emitted extcodesize guard on a value-returning call turns the codeless address into a
     *      bare revert. Fails loudly and closed; the relayer's answer is to deploy first (permissionless)
     *      and resubmit.
     * @dev Pinned precisely BECAUSE the property is emergent rather than an explicit contract check: no
     *      line in `JustaRecoveryManager` tests `account.code.length` on these paths (unlike
     *      `executeRecoveryRequest`, which needs an explicit guard because `addOwner*` returns nothing), so
     *      a refactor to a low-level call would silently reopen the vacuous-success hole.
     */
    function test_ShouldRevertOnCodelessAccount(uint256 eoaGuardianPk) public {
        eoaGuardianPk = bound(eoaGuardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        address codeless = makeAddr("codeless");
        assertEq(codeless.code.length, 0);

        // (a) The admin door: a syntactically valid batch, correctly signed, aimed at a codeless account.
        IRecoveryManager.AdminOp[] memory ops =
            _oneOp(encodeAddRecoveryOp(address(provider), encodeEoaCommitment(vm.addr(eoaGuardianPk)), DELAY));
        bytes32 adminSalt = keccak256("codeless-admin-batch");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory adminProof = signAdminProof(manager, codeless, ops, adminSalt, adminExpiry, ADMIN_OWNER_PK);

        // The batch clears every explicit check (non-empty, unexpired, fresh salt) and then dies in the
        // compiler's extcodesize guard ahead of the `isOwnerBytes` staticcall. Pinning the EMPTY revert
        // data (not a bare `expectRevert`) means a future explicit typed check would fail this test loudly
        // instead of matching by accident.
        vm.expectRevert(bytes(""));
        vm.prank(relayer);
        manager.executeRecoveryAdmin(codeless, ops, adminSalt, adminExpiry, adminOwnerBytes, adminProof);

        // (b) The ceremony door. The account has no registry at all, so the default threshold of 1 applies
        // and one approval is the right shape; expiry, subject and salt all pass too. The staticcall that
        // dies is `isOwnerBytes(subject)`, reached before any approval is ever looked at — which is why the
        // approval below need not name a registered recovery.
        bytes memory subject = encodeEoaSubject(makeAddr("recovered-owner"));
        bytes32 ceremonySalt = keccak256("codeless-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(
            keccak256("any-recovery-id"),
            signRecoverProof(provider, codeless, subject, ceremonySalt, ceremonyExpiry, eoaGuardianPk)
        );

        // Same empty-revert pin as above: the extcodesize guard carries no return data.
        vm.expectRevert(bytes(""));
        vm.prank(relayer);
        manager.requestRecovery(codeless, subject, ceremonySalt, ceremonyExpiry, approvals);

        // Nothing was written for the codeless account by either attempt.
        assertFalse(manager.isSaltUsed(codeless, adminSalt));
        assertFalse(manager.isSaltUsed(codeless, ceremonySalt));
        assertEq(manager.recoveryCount(codeless), 0);
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /// @dev Wraps a single admin op in the one-element array `executeRecoveryAdmin` takes.
    function _oneOp(IRecoveryManager.AdminOp memory op) internal pure returns (IRecoveryManager.AdminOp[] memory ops) {
        ops = new IRecoveryManager.AdminOp[](1);
        ops[0] = op;
    }

    /**
     * @dev Builds the proof a smart-account owner's own ERC-1271 door accepts over `digest`: a WebAuthn
     *      assertion from its passkey, ERC-7739 (PersonalSign) wrapped in the owner account's EIP-712
     *      domain and ABI-encoded as a JustanAccount `SignatureWrapper` at owner index 0.
     */
    function _smartOwnerProof(address smartOwner, bytes32 digest) internal view returns (bytes memory) {
        ERC7739Utils.DomainData memory domainData;
        domainData.name = "JustanAccount";
        domainData.version = "1";
        domainData.chainId = block.chainid;
        domainData.verifyingContract = smartOwner;
        domainData.domainSeparator = ERC7739Utils.computeDomainSeparator(domainData);

        bytes32 erc7739Hash = ERC7739Utils.erc7739HashFromPersonalSignHash(digest, domainData);

        return abi.encode(
            JustanAccount.SignatureWrapper({ ownerIndex: 0, signatureData: signWebAuthnProof(erc7739Hash, PASSKEY_PK) })
        );
    }

}
