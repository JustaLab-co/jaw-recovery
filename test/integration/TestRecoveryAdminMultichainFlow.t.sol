// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";
import { JustanAccountFactory } from "justanaccount/JustanAccountFactory.sol";
import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryAdminMultichainFlow
 *
 * @notice Integration proof of the multichain admin door — the coverage SPEC-MULTICHAIN-ADMIN owes before
 * audit. Two "chains" are simulated exactly as in `TestRecoveryMultichainFlow`, with
 * `vm.snapshotState`/`vm.revertToState` plus `vm.chainId`: same deterministic addresses for the account,
 * manager, provider and EntryPoint, but independently diverging state — the honest in-process equivalent of
 * two forks. Four properties are pinned here. One owner signature configures recovery on every chain, and
 * one owner signature vetoes an attack on every chain (the batch's salt being consumed per chain, so the
 * same bytes stay live where they have not landed). One chainId-0 userop (nonce key 9999, empty paymaster)
 * opts an existing account in on every chain through the audited account door — the manager cannot add
 * itself as an owner, so opting in is account-side by construction. And when a chain misses a batch, that
 * chain fails CLOSED: it validates every ceremony against its OWN registry and threshold, so drift produces
 * a loud revert rather than a partially-applied recovery. The suite closes on the full user journey: an
 * account born opted-in, enrolled with one admin signature, recovered on both chains from one guardian
 * ceremony, under the same `requestId` everywhere.
 */
contract TestRecoveryAdminMultichainFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    JustanAccountFactory public factory;
    EntryPoint public entryPoint;

    /// @dev The registered EOA owner whose single signature authorizes every admin batch below.
    uint256 internal constant ADMIN_OWNER_PK = 0xAD317;

    /// @dev The EOA guardian's signing key.
    uint256 internal constant EOA_GUARDIAN_PK = 0xB0B;

    /// @dev A second EOA guardian, enrolled by an admin batch on one chain only (the drift test).
    uint256 internal constant SECOND_GUARDIAN_PK = 0xB0B2;

    /// @dev Owner key of the factory account used for the chainId-0 opt-in replay.
    uint256 internal constant OPT_IN_OWNER_PK = 0x0071;

    /// @dev Owner key of the factory account used for the full-journey test.
    uint256 internal constant JOURNEY_OWNER_PK = 0x10E4;

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

    /// @dev The unrelated submitter of every admin batch and userop below.
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
    // MULTICHAIN ADMIN FLOW TESTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice THE headline admin property: ONE owner signature enrolls both guardians and raises the
     *         threshold on two chains from the same batch bytes, each chain consuming the salt
     *         independently.
     * @dev The digest omits chainId and the manager deploys at the same deterministic address everywhere,
     *      so the batch the owner signed once is submittable by a relayer on every chain. Chain B is
     *      asserted fresh before it replays — an unconsumed salt and an empty registry — which is what
     *      makes "the same bytes" a genuine second application rather than a residue of chain A.
     * @dev The signer here is deliberately a registered PASSKEY owner — the JAW norm — so the WebAuthn
     *      branch of the admin door is the one carried across the chainId switch: the assertion's challenge
     *      is the sans-chainId digest and it is verified against the raw `(x, y)` with no account contract
     *      consulted, so nothing in the proof can bind a chain. The other two-chain tests in this file sign
     *      with the EOA owner, so both branches are covered multichain.
     */
    function test_ShouldApplyOneAdminBatchOnTwoChains() public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // Register the passkey owner before the fork point, so it is an owner on both chains.
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        bytes memory ownerBytes = abi.encode(bytes32(x), bytes32(y));

        vm.prank(account);
        JustanAccount(account).addOwnerPublicKey(bytes32(x), bytes32(y));
        assertTrue(JustanAccount(account).isOwnerBytes(ownerBytes));

        IRecoveryManager.AdminOp[] memory ops = _enrollmentOps();
        bytes32 salt = keccak256("admin-mc-enrollment");
        uint256 expiry = block.timestamp + ADMIN_EXPIRY_WINDOW;

        // Signed exactly once, here, for every chain.
        bytes memory proof = signAdminProofPasskey(manager, account, ops, salt, expiry, PASSKEY_PK);
        (bytes32 eoaId, bytes32 passkeyId) = _guardianIds(account);

        uint256 snapshot = vm.snapshotState();

        // ----- Chain A -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertTrue(manager.hasRecovery(account, eoaId));
        assertTrue(manager.hasRecovery(account, passkeyId));
        assertEq(manager.recoveryCount(account), 2);
        assertEq(manager.recoveryThreshold(account), 2);
        assertTrue(manager.isSaltUsed(account, salt));

        // ----- Chain B: same addresses, independently diverged state -----
        vm.revertToState(snapshot);
        vm.chainId(OPTIMISM_CHAIN_ID);

        // Chain B never saw the batch: its salt is fresh and nothing is configured there.
        assertFalse(manager.isSaltUsed(account, salt));
        assertFalse(manager.hasRecovery(account, eoaId));
        assertFalse(manager.hasRecovery(account, passkeyId));
        assertEq(manager.recoveryCount(account), 0);
        assertEq(manager.recoveryThreshold(account), 1);

        // The IDENTICAL batch bytes — same ops, same salt, same signature — apply here too.
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof);

        assertTrue(manager.hasRecovery(account, eoaId));
        assertTrue(manager.hasRecovery(account, passkeyId));
        assertEq(manager.recoveryCount(account), 2);
        assertEq(manager.recoveryThreshold(account), 2);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice One-tap veto everywhere: a single signed cancel batch kills the same attack ceremony on both
     *         chains, and on neither can the request then execute.
     * @dev The guardians are enrolled through the ACCOUNT door BEFORE the snapshot, so both chains share
     *      one configuration — the realistic state of an account whose config is synced everywhere. That is
     *      what lets one leaked ceremony queue on every chain: the attacker's proofs are as chain-agnostic
     *      as the honest ones. The veto is pre-signable for exactly the same reason plus determinism —
     *      `requestId = keccak256(abi.encode(account, subject, salt))` is knowable before the attack lands,
     *      so the owner arms one cancel batch and the relayer fans it out. Both the attack and the veto are
     *      built once, before the snapshot, and replayed byte-for-byte on chain B.
     */
    function test_ShouldCancelOnBothChainsWithOneSignature(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != adminOwner);

        // Shared configuration on both chains (enrolled before the fork point).
        _enrollGuardiansViaAccountDoor(account);

        // The attacker's ceremony: valid guardian proofs, a nonzero time-lock, one set of bytes for every
        // chain.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("admin-mc-attack-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;
        IRecoveryManager.Approval[] memory approvals =
            _ceremonyApprovals(account, subject, ceremonySalt, ceremonyExpiry);
        bytes32 requestId = keccak256(abi.encode(account, subject, ceremonySalt));

        // The owner's answer: ONE signed cancel batch for that deterministic id.
        IRecoveryManager.AdminOp[] memory ops = _oneOp(encodeCancelRequestOp(requestId));
        bytes32 cancelSalt = keccak256("admin-mc-veto");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, cancelSalt, adminExpiry, ADMIN_OWNER_PK);

        uint256 t0 = block.timestamp;
        uint256 snapshot = vm.snapshotState();

        // ----- Chain A -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        assertEq(manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals), requestId);
        assertEq(manager.recoveryRequest(requestId).account, account);
        uint64 executeAtA = manager.recoveryRequest(requestId).executeAt;

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, cancelSalt, adminExpiry, adminOwnerBytes, proof);
        assertEq(manager.recoveryRequest(requestId).account, address(0));
        assertTrue(manager.isSaltUsed(account, cancelSalt));

        // Even once the time-lock has elapsed there is nothing left to execute.
        vm.warp(executeAtA);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);
        assertFalse(JustanAccount(account).isOwnerBytes(subject));

        // ----- Chain B: the attack lands here too, and the same veto bytes kill it -----
        vm.revertToState(snapshot);
        vm.warp(t0);
        vm.chainId(OPTIMISM_CHAIN_ID);

        assertFalse(manager.isSaltUsed(account, ceremonySalt));
        assertFalse(manager.isSaltUsed(account, cancelSalt));
        assertEq(manager.recoveryRequest(requestId).account, address(0));

        assertEq(manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals), requestId);
        uint64 executeAtB = manager.recoveryRequest(requestId).executeAt;

        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, cancelSalt, adminExpiry, adminOwnerBytes, proof);
        assertEq(manager.recoveryRequest(requestId).account, address(0));

        vm.warp(executeAtB);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);

        // One owner signature, two chains disarmed — and the attacker's ceremony is spent on both.
        assertFalse(JustanAccount(account).isOwnerBytes(subject));
        assertTrue(manager.isSaltUsed(account, ceremonySalt));
    }

    /**
     * @notice Configuration drift fails CLOSED: the chain that received the admin batch recovers, and the
     *         chain that missed it rejects the very same ceremony instead of applying a weaker one.
     * @dev Each chain validates a ceremony against ITS OWN registry and threshold — there is no shared
     *      state and no cross-chain messaging. The batch that added the second guardian and raised the
     *      threshold to 2 lands on chain A only; on chain B the account is still 1-of-1, so the 2-approval
     *      bundle is not "more than enough", it is simply the wrong shape and reverts with
     *      `InvalidApprovalCount(2, 1)`. Failing closed is the deliberate stance: a partially applied
     *      recovery is worse than a loud refusal, and the salt survives the revert so a correctly shaped
     *      ceremony can still be submitted on the drifted chain once its configuration catches up.
     */
    function test_ShouldFailClosedOnConfigDrift(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != adminOwner);

        // Shared starting point on both chains: one guardian, threshold 1 (the default).
        bytes memory firstCommitment = encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK));
        bytes memory secondCommitment = encodeEoaCommitment(vm.addr(SECOND_GUARDIAN_PK));

        vm.prank(account);
        bytes32 firstId = manager.addRecovery(account, address(provider), firstCommitment, DELAY);
        bytes32 secondId = manager.computeRecoveryId(account, address(provider), secondCommitment);

        // The batch that will reach only one chain.
        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](2);
        ops[0] = encodeAddRecoveryOp(address(provider), secondCommitment, DELAY);
        ops[1] = encodeSetThresholdOp(2);

        bytes32 adminSalt = keccak256("admin-mc-drift-batch");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory proof = signAdminProof(manager, account, ops, adminSalt, adminExpiry, ADMIN_OWNER_PK);

        // One 2-of-2 ceremony, signed once, aimed at every chain.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("admin-mc-drift-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(
            firstId, signRecoverProof(provider, account, subject, ceremonySalt, ceremonyExpiry, EOA_GUARDIAN_PK)
        );
        approvals[1] = createApproval(
            secondId, signRecoverProof(provider, account, subject, ceremonySalt, ceremonyExpiry, SECOND_GUARDIAN_PK)
        );

        uint256 t0 = block.timestamp;
        uint256 snapshot = vm.snapshotState();

        // ----- Chain A: the batch lands, so the 2-of-2 ceremony fits and recovers -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        vm.prank(relayer);
        manager.executeRecoveryAdmin(account, ops, adminSalt, adminExpiry, adminOwnerBytes, proof);
        assertEq(manager.recoveryCount(account), 2);
        assertEq(manager.recoveryThreshold(account), 2);

        bytes32 requestId = manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);
        assertTrue(JustanAccount(account).isOwnerBytes(subject));

        // ----- Chain B: the batch never arrived, so the account is still 1-of-1 there -----
        vm.revertToState(snapshot);
        vm.warp(t0);
        vm.chainId(OPTIMISM_CHAIN_ID);

        assertFalse(manager.isSaltUsed(account, adminSalt));
        assertFalse(manager.hasRecovery(account, secondId));
        assertEq(manager.recoveryCount(account), 1);
        assertEq(manager.recoveryThreshold(account), 1);

        // The identical ceremony bytes are refused here — loudly, against this chain's own threshold.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidApprovalCount.selector, 2, 1)
        );
        manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, approvals);

        // Nothing was half-applied: no owner added, and the ceremony's salt is untouched on this chain.
        assertFalse(JustanAccount(account).isOwnerBytes(subject));
        assertFalse(manager.isSaltUsed(account, ceremonySalt));

        // Failing closed is not the same as being bricked. The salt survived, so the SAME ceremony —
        // re-shaped to this chain's 1-of-1 configuration by dropping the approval it cannot use, with
        // guardian 1's proof reused byte-for-byte since it binds only (account, subject, salt, expiry) —
        // queues here under the very same deterministic requestId chain A used.
        IRecoveryManager.Approval[] memory catchUpApprovals = new IRecoveryManager.Approval[](1);
        catchUpApprovals[0] = approvals[0];

        bytes32 catchUpRequestId =
            manager.requestRecovery(account, subject, ceremonySalt, ceremonyExpiry, catchUpApprovals);

        assertEq(catchUpRequestId, requestId);
        assertEq(manager.recoveryRequest(catchUpRequestId).account, account);
        assertTrue(manager.isSaltUsed(account, ceremonySalt));
    }

    /**
     * @notice ONE chainId-0 userop, signed once, opts an existing account in to recovery on two chains
     *         through a real EntryPoint.
     * @dev The manager cannot register itself as an owner — that is account-side authority — so opt-in
     *      rides the account's audited `executeWithoutChainIdValidation` door (D-A5), whose allowlist
     *      already contains `addOwnerAddress`. `validateUserOp` recomputes the hash via
     *      `getUserOpHashWithoutChainId` whenever the callData targets that function and enforces nonce key
     *      9999, so the signature below is made over the sans-chainId hash and the EntryPoint's own
     *      chain-bound hash never enters the picture.
     * @dev The preconditions from SPEC-MULTICHAIN-ADMIN §9b are what make ONE signature enough, and they
     *      are visible in the setup: the hash binds the whole userop, so the key-9999 nonce SEQUENCE must
     *      match on both chains (asserted before each submission) and `paymasterAndData` must be empty —
     *      a per-chain paymaster voucher would change the bytes and break the replay. Sponsorship is
     *      therefore the mechanism §9b actually prescribes: the RELAYER prefunds the account's EntryPoint
     *      deposit with a permissionless `depositTo` on each chain, so the op costs the user nothing and
     *      the account's own balance is asserted to stay at zero throughout. Deposits are per-chain state,
     *      hence the second `depositTo` after the state revert.
     * @dev The closing leg pins the other half of the sequence-parity precondition: replaying the
     *      IDENTICAL op on a chain that already consumed it fails LOUDLY, in the EntryPoint, with
     *      `FailedOp(0, "AA25 invalid account nonce")`. Sequence divergence can therefore never be silent —
     *      the relayer sees a typed revert per §9c and the SDK re-aligns or falls back to a per-chain
     *      signature.
     */
    function test_ShouldOptInWithOneChainIdZeroUserOpOnTwoChains() public {
        address ownerEoa = vm.addr(OPT_IN_OWNER_PK);

        // An ordinary existing account: one EOA owner, NOT opted in to recovery, and holding NO ether —
        // every wei of gas below comes from the relayer's deposit.
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(ownerEoa);
        JustanAccount account = factory.createAccount(initialOwners, 0);
        assertEq(address(account).balance, 0);
        assertFalse(account.isOwnerAddress(address(manager)));

        vm.deal(relayer, 10 ether);

        // The replayable nonce key the account itself demands for chainId-0 operations.
        uint256 replayableNonce = (account.REPLAYABLE_NONCE_KEY() << 64) | 0;

        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector, address(manager));
        bytes memory callData = abi.encodeWithSelector(account.executeWithoutChainIdValidation.selector, calls);

        PackedUserOperation memory userOp = _createUserOp(address(account), replayableNonce, callData);

        // Signed ONCE, over the hash that omits chainId.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPT_IN_OWNER_PK, account.getUserOpHashWithoutChainId(userOp));
        userOp.signature =
            abi.encode(JustanAccount.SignatureWrapper({ ownerIndex: 0, signatureData: abi.encodePacked(r, s, v) }));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        uint256 snapshot = vm.snapshotState();

        // ----- Chain A -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        assertEq(entryPoint.getNonce(address(account), uint192(account.REPLAYABLE_NONCE_KEY())), replayableNonce);

        // Relayer sponsorship, §9b style: a permissionless deposit for the account, no paymaster bytes.
        vm.prank(relayer);
        entryPoint.depositTo{ value: 1 ether }(address(account));

        vm.prank(relayer);
        entryPoint.handleOps(ops, payable(relayer));
        assertTrue(account.isOwnerAddress(address(manager)));
        assertEq(address(account).balance, 0);

        // The opt-in is real, not cosmetic: the account door now accepts a recovery registration, which
        // `_addRecovery` refuses unless the manager is an owner.
        vm.prank(address(account));
        bytes32 recoveryId = manager.addRecovery(
            address(account), address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)), DELAY
        );
        assertTrue(manager.hasRecovery(address(account), recoveryId));

        // ----- Chain B: same account address, untouched state -----
        vm.revertToState(snapshot);
        vm.chainId(OPTIMISM_CHAIN_ID);

        assertFalse(account.isOwnerAddress(address(manager)));
        assertEq(entryPoint.getNonce(address(account), uint192(account.REPLAYABLE_NONCE_KEY())), replayableNonce);

        // Deposits are per-chain state, so the relayer prefunds again here.
        vm.prank(relayer);
        entryPoint.depositTo{ value: 1 ether }(address(account));

        // The IDENTICAL userop — same nonce, same callData, same signature — lands here too.
        vm.prank(relayer);
        entryPoint.handleOps(ops, payable(relayer));
        assertTrue(account.isOwnerAddress(address(manager)));
        assertEq(address(account).balance, 0);

        vm.prank(address(account));
        bytes32 recoveryIdB = manager.addRecovery(
            address(account), address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)), DELAY
        );
        assertTrue(manager.hasRecovery(address(account), recoveryIdB));

        // Replay is per-chain single-use: the key-9999 sequence has advanced here, so resubmitting the very
        // same signed bytes on this chain is refused by the EntryPoint before the account is touched.
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA25 invalid account nonce"));
        vm.prank(relayer);
        entryPoint.handleOps(ops, payable(relayer));
    }

    /**
     * @notice The product headline, end to end on two chains: an account born opted-in, enrolled with ONE
     *         admin signature, recovered from ONE guardian ceremony, under the same `requestId` everywhere.
     * @dev The human cost of covering N chains is tallied by what this test signs: ZERO opt-in signatures
     *      (the manager is among `initialOwners`, so the CREATE2 address commits to being opted in and the
     *      account deploys that way on every chain — D-A5), ONE admin signature for the whole enrollment
     *      (two guardians plus the threshold, in one batch), and M guardian signatures for the recovery
     *      itself (here 2: one EOA, one passkey). Total: 1 + M signatures for N chains, none of them
     *      per-chain, versus the N x (2 + M) of the single-chain door. Everything else in the flow is
     *      relayer work: the same three payloads are submitted on chain B byte-for-byte, and the owner is
     *      not involved again.
     * @dev The `requestId` equality across chains is not a nicety — it is what lets one veto, one status
     *      view and one indexer entry cover the whole fan-out.
     * @dev The journey deliberately stops at a successful recovery: its one-tap CANCEL leg — the owner
     *      vetoing that same `requestId` on every chain from a single signed batch — is covered by
     *      `test_ShouldCancelOnBothChainsWithOneSignature`, kept separate so each test tells one story.
     */
    function test_ShouldRunFullJourneyWithOneAdminSignature(address newOwner) public {
        address journeyOwner = vm.addr(JOURNEY_OWNER_PK);
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != address(manager));
        vm.assume(newOwner != journeyOwner);

        // Born opted in on every chain: same initial owners => same address => the manager is an owner
        // wherever this account exists, with no opt-in transaction ever.
        bytes[] memory initialOwners = new bytes[](2);
        initialOwners[0] = abi.encode(journeyOwner);
        initialOwners[1] = abi.encode(address(manager));
        JustanAccount account = factory.createAccount(initialOwners, 0);
        vm.deal(address(account), 10 ether);
        vm.assume(newOwner != address(account));
        assertTrue(account.isOwnerAddress(address(manager)));

        // ONE admin signature: both guardians and the threshold, for every chain.
        IRecoveryManager.AdminOp[] memory ops = _enrollmentOps();
        bytes32 adminSalt = keccak256("admin-mc-journey-enrollment");
        uint256 adminExpiry = block.timestamp + ADMIN_EXPIRY_WINDOW;
        bytes memory adminProof =
            signAdminProof(manager, address(account), ops, adminSalt, adminExpiry, JOURNEY_OWNER_PK);
        bytes memory journeyOwnerBytes = abi.encode(journeyOwner);

        // ONE guardian ceremony: each guardian signs the same (subject, salt, expiry) exactly once.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 ceremonySalt = keccak256("admin-mc-journey-ceremony");
        uint256 ceremonyExpiry = block.timestamp + CEREMONY_EXPIRY_WINDOW;
        IRecoveryManager.Approval[] memory approvals =
            _ceremonyApprovals(address(account), subject, ceremonySalt, ceremonyExpiry);
        bytes32 expectedRequestId = keccak256(abi.encode(address(account), subject, ceremonySalt));

        uint256 t0 = block.timestamp;
        uint256 snapshot = vm.snapshotState();

        // ----- Chain A: enroll, request, wait out the time-lock, recover -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        vm.prank(relayer);
        manager.executeRecoveryAdmin(address(account), ops, adminSalt, adminExpiry, journeyOwnerBytes, adminProof);
        assertEq(manager.recoveryThreshold(address(account)), 2);

        vm.prank(relayer);
        bytes32 requestIdA = manager.requestRecovery(address(account), subject, ceremonySalt, ceremonyExpiry, approvals);
        assertEq(requestIdA, expectedRequestId);

        vm.warp(manager.recoveryRequest(requestIdA).executeAt);
        manager.executeRecoveryRequest(requestIdA);
        assertTrue(account.isOwnerBytes(subject));

        // ----- Chain B: the same three payloads, submitted again by the relayer alone -----
        vm.revertToState(snapshot);
        vm.warp(t0);
        vm.chainId(OPTIMISM_CHAIN_ID);

        // Opted in here too by construction, and nothing else has happened yet.
        assertTrue(account.isOwnerAddress(address(manager)));
        assertFalse(account.isOwnerBytes(subject));
        assertFalse(manager.isSaltUsed(address(account), adminSalt));
        assertFalse(manager.isSaltUsed(address(account), ceremonySalt));

        vm.prank(relayer);
        manager.executeRecoveryAdmin(address(account), ops, adminSalt, adminExpiry, journeyOwnerBytes, adminProof);
        assertEq(manager.recoveryThreshold(address(account)), 2);

        vm.prank(relayer);
        bytes32 requestIdB = manager.requestRecovery(address(account), subject, ceremonySalt, ceremonyExpiry, approvals);
        assertEq(requestIdB, expectedRequestId);
        assertEq(requestIdB, requestIdA);

        vm.warp(manager.recoveryRequest(requestIdB).executeAt);
        manager.executeRecoveryRequest(requestIdB);
        assertTrue(account.isOwnerBytes(subject));
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
     * @dev The enrollment batch replayed across chains: both guardians, then the threshold that counts them
     *      (raised only after the guardians it counts exist, since ops apply in signed order).
     */
    function _enrollmentOps() internal view returns (IRecoveryManager.AdminOp[] memory ops) {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        ops = new IRecoveryManager.AdminOp[](3);
        ops[0] = encodeAddRecoveryOp(address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)), DELAY);
        ops[1] = encodeAddRecoveryOp(address(provider), encodePasskeyCommitment(bytes32(x), bytes32(y)), DELAY);
        ops[2] = encodeSetThresholdOp(2);
    }

    /// @dev The two guardians' recovery ids for an account (deterministic, so knowable before enrollment).
    function _guardianIds(address account) internal view returns (bytes32 eoaId, bytes32 passkeyId) {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        eoaId = manager.computeRecoveryId(account, address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)));
        passkeyId =
            manager.computeRecoveryId(account, address(provider), encodePasskeyCommitment(bytes32(x), bytes32(y)));
    }

    /**
     * @dev Enrolls the same two guardians through the ACCOUNT door, for tests whose subject is what happens
     *      AFTER enrollment (so the configuration is shared by both simulated chains).
     */
    function _enrollGuardiansViaAccountDoor(address payable account) internal {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        vm.startPrank(account);
        manager.addRecovery(account, address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)), DELAY);
        manager.addRecovery(account, address(provider), encodePasskeyCommitment(bytes32(x), bytes32(y)), DELAY);
        manager.setRecoveryThreshold(account, 2);
        vm.stopPrank();
    }

    /**
     * @dev One ceremony's approvals: the EOA guardian and the passkey guardian each sign the same
     *      `(subject, salt, expiry)` once.
     */
    function _ceremonyApprovals(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (IRecoveryManager.Approval[] memory approvals)
    {
        (bytes32 eoaId, bytes32 passkeyId) = _guardianIds(account);

        approvals = new IRecoveryManager.Approval[](2);
        approvals[0] =
            createApproval(eoaId, signRecoverProof(provider, account, subject, salt, expiry, EOA_GUARDIAN_PK));
        approvals[1] = createApproval(
            passkeyId, signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK)
        );
    }

    /**
     * @dev A chainId-0 userop envelope: the gas fields are one canonical set for every chain (§9b) and
     *      `paymasterAndData` is empty, since any per-chain byte would change the hash the owner signed.
     */
    function _createUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData
    )
        internal
        pure
        returns (PackedUserOperation memory)
    {
        uint128 verificationGasLimit = 16_777_216;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;

        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: verificationGasLimit,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

}
