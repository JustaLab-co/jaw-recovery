// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title TestRecoveryMultichainFlow
 *
 * @notice Integration proof of the sign-once multichain property. Two "chains" are simulated with
 * `vm.snapshotState`/`vm.revertToState` plus `vm.chainId`: same deterministic addresses for the account,
 * manager, and provider, but independently diverging state — the honest in-process equivalent of two
 * forks. One guardian ceremony (an EOA guardian and a raw-pubkey passkey guardian, each signing exactly
 * once) is submitted byte-for-byte on both chains, executes on both, consumes its salt on each chain
 * independently, and yields the same `requestId` everywhere. The mirror property is also pinned: the
 * shared `requestId` does NOT make the account's veto global — cancelling on one chain leaves the other
 * chain's identically-identified request untouched. The ERC-6492 reverting verifier is never etched in
 * this suite — passkey guardians (deployed or not) need no 6492 infrastructure on the multichain path.
 *
 * @dev Scope caveat on the 7702 delegation: it is attached once at the ambient chain in `setUp` and is
 *      inherited by both simulated chains as ordinary account state, so the delegation cost is NOT modeled
 *      here — a real deployment needs a per-chain authorization tuple (or a `chainId = 0` one, which still
 *      binds the EOA nonce). `TestRecoveryAdminMultichainFlow` carries the deployment-parity story honestly
 *      instead, via factory-deployed accounts and the chainId-0 opt-in userop.
 */
contract TestRecoveryMultichainFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    /// @dev The EOA guardian's signing key.
    uint256 internal constant EOA_GUARDIAN_PK = 0xB0B;

    /// @dev Solady's canonical ERC-6492 reverting verifier address. Deliberately NEVER etched in this
    /// suite: its absence proves the multichain path has no 6492 dependency.
    address internal constant ERC6492_VERIFIER = 0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

    /// @dev Per-recovery time-lock used throughout.
    uint32 internal constant DELAY = 3 days;

    /// @dev Ceremony expiry window used throughout.
    uint256 internal constant EXPIRY_WINDOW = 7 days;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));

        vm.deal(TEST_ACCOUNT_ADDRESS, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it may add the recovered owner at execution.
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(address(manager));

        // WebAuthn verification needs the P256 verifier etched at the addresses Solady staticcalls
        // (the same dependency JustanAccount itself has for passkey owners — nothing 6492-related).
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);
    }

    ////////////////////////////////////////////////////////////////////////
    // MULTICHAIN FLOW TESTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice THE headline property: one 2-of-2 ceremony (EOA + raw passkey guardian, one signature
     *         each) executes end to end on two chains from the same proof bytes, with the same
     *         `requestId` on both, and each chain consuming the salt independently.
     */
    function test_ShouldExecuteOneCeremonyOnTwoChains(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        _enrollGuardians(account);

        // ONE signing ceremony: both guardians sign the same (subject, salt, expiry) exactly once.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("multichain-ceremony-1");
        uint256 expiry = block.timestamp + EXPIRY_WINDOW;
        IRecoveryManager.Approval[] memory approvals = _ceremonyApprovals(account, subject, salt, expiry);

        uint256 t0 = block.timestamp;
        uint256 snapshot = vm.snapshotState();

        // ----- Chain A -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        bytes32 requestIdA = manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertEq(requestIdA, keccak256(abi.encode(account, subject, salt)));
        assertTrue(manager.isSaltUsed(account, salt));

        vm.warp(t0 + DELAY);
        manager.executeRecoveryRequest(requestIdA);
        assertTrue(JustanAccount(account).isOwnerBytes(subject));

        // ----- Chain B: same addresses, independently diverged state -----
        vm.revertToState(snapshot);
        vm.warp(t0);
        vm.chainId(OPTIMISM_CHAIN_ID);

        // Chain B never saw the ceremony: salt unconsumed, owner not yet added.
        assertFalse(manager.isSaltUsed(account, salt));
        assertFalse(JustanAccount(account).isOwnerBytes(subject));

        // The IDENTICAL proof bytes queue and execute here too, under the same requestId.
        bytes32 requestIdB = manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertEq(requestIdB, requestIdA);

        vm.warp(t0 + DELAY);
        manager.executeRecoveryRequest(requestIdB);
        assertTrue(JustanAccount(account).isOwnerBytes(subject));

        // Salts are consumed independently in BOTH directions: unused on B before its submission (above),
        // and now spent on B too — chain A's consumption neither blocked nor substituted for B's.
        assertTrue(manager.isSaltUsed(account, salt));

        // The whole flow — including the passkey guardian — ran with no ERC-6492 verifier on "chain".
        assertEq(ERC6492_VERIFIER.code.length, 0);
    }

    /**
     * @notice A raw-pubkey passkey guardian works alone (threshold 1) with zero 6492 infrastructure —
     *         the guardian is a key, not a contract, so "undeployed" is the natural state.
     */
    function test_ShouldRecoverWithRawPasskeyGuardianWithout6492Infra(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodePasskeyCommitment(bytes32(x), bytes32(y)), DELAY);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("passkey-only-ceremony");
        uint256 expiry = block.timestamp + EXPIRY_WINDOW;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(
            recoveryId, signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK)
        );

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        vm.warp(block.timestamp + DELAY);
        manager.executeRecoveryRequest(requestId);

        assertTrue(JustanAccount(account).isOwnerBytes(subject));
        assertEq(ERC6492_VERIFIER.code.length, 0);
    }

    /**
     * @notice Expiry kills a leaked ceremony everywhere at once: a chain that never consumed the salt
     *         still rejects the proofs once `expiry` has passed.
     * @dev The chain-B leg reverts at the expiry check, which sits BEFORE any signature verification, so on
     *      its own it would stay green even under a chainId-bound-digest regression. Asserting the digest is
     *      unchanged on both chains makes both legs discriminating: chain A proves the proofs verify there,
     *      chain B proves they were still the same proofs when expiry killed them.
     */
    function test_RequestRecovery_RevertIfCeremonyExpiredOnUntouchedChain(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        _enrollGuardians(account);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("expiring-ceremony");
        uint256 expiry = block.timestamp + EXPIRY_WINDOW;
        IRecoveryManager.Approval[] memory approvals = _ceremonyApprovals(account, subject, salt, expiry);

        // The ambient-chain digest, captured before either chain is simulated.
        bytes32 d0 = provider.recoverDigest(account, subject, salt, expiry);

        uint256 snapshot = vm.snapshotState();

        // Chain A consumes the ceremony while it is fresh.
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        assertEq(provider.recoverDigest(account, subject, salt, expiry), d0);
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // Chain B never consumed it — but past expiry the proofs are dead there too.
        vm.revertToState(snapshot);
        vm.chainId(OPTIMISM_CHAIN_ID);
        assertEq(provider.recoverDigest(account, subject, salt, expiry), d0);
        assertFalse(manager.isSaltUsed(account, salt));

        vm.warp(expiry + 1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ProofsExpired.selector, expiry));
        manager.requestRecovery(account, subject, salt, expiry, approvals);
    }

    /**
     * @notice Cancelling on one chain leaves the OTHER chain's identically-identified request untouched,
     *         while on the cancelling chain the dead salt is worked around with a fresh salt and re-signed
     *         proofs for the same subject.
     * @dev Cancellation is PER-CHAIN state. The `requestId` is `keccak256(account, subject, salt)` and is
     *      therefore shared by every chain the ceremony lands on, which makes it tempting to read a veto as
     *      global — it is not. This is the assertion that it is not: chain B queues and EXECUTES the very
     *      requestId chain A cancelled. A veto is only real once it has been fanned out to every chain, so
     *      the SDK's cancel-everywhere duty (SPEC-MULTICHAIN §2) is a hard requirement, not an optimization.
     * @dev The chain-A half preserves the veto/retry economics the single-chain suite pins: the cancelled
     *      salt is spent forever, but guardians re-approving the SAME subject under a fresh salt completes —
     *      the recovering user never needs a new passkey ceremony.
     */
    function test_ShouldKeepOtherChainUnaffectedByCancelAndAllowFreshSaltRetry(address newOwner) public {
        address payable account = TEST_ACCOUNT_ADDRESS;
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        _enrollGuardians(account);

        // ONE ceremony, built before the snapshot so both chains submit byte-identical proofs.
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("cancelled-ceremony");
        uint256 expiry = block.timestamp + EXPIRY_WINDOW;
        IRecoveryManager.Approval[] memory approvals = _ceremonyApprovals(account, subject, salt, expiry);
        bytes32 expectedRequestId = keccak256(abi.encode(account, subject, salt));

        uint256 t0 = block.timestamp;
        uint256 snapshot = vm.snapshotState();

        // ----- Chain A: the account vetoes, then guardians retry under a fresh salt -----
        vm.chainId(MAINNET_ETH_CHAIN_ID);
        bytes32 requestIdA = manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertEq(requestIdA, expectedRequestId);

        vm.prank(account);
        manager.cancelRecoveryRequest(requestIdA);
        assertEq(manager.recoveryRequest(requestIdA).account, address(0));

        // The cancelled ceremony's salt is spent on this chain forever.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SaltAlreadyUsed.selector, account, salt)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // A fresh salt with freshly signed proofs targets the SAME subject and completes.
        bytes32 freshSalt = keccak256("cancelled-ceremony-retry");
        IRecoveryManager.Approval[] memory freshApprovals = _ceremonyApprovals(account, subject, freshSalt, expiry);
        bytes32 retryRequestId = manager.requestRecovery(account, subject, freshSalt, expiry, freshApprovals);

        vm.warp(t0 + DELAY);
        manager.executeRecoveryRequest(retryRequestId);
        assertTrue(JustanAccount(account).isOwnerBytes(subject));

        // ----- Chain B: same addresses, and it never saw the veto -----
        vm.revertToState(snapshot);
        vm.warp(t0);
        vm.chainId(OPTIMISM_CHAIN_ID);

        // Chain B never consumed the salt — chain A's request/cancel touched only chain A's registry.
        assertFalse(manager.isSaltUsed(account, salt));

        // The ORIGINAL ceremony bytes queue here under the very requestId chain A cancelled.
        bytes32 requestIdB = manager.requestRecovery(account, subject, salt, expiry, approvals);
        assertEq(requestIdB, requestIdA);
        assertEq(manager.recoveryRequest(requestIdB).account, account);

        // And it executes: chain A's cancel bought this chain nothing.
        vm.warp(t0 + DELAY);
        manager.executeRecoveryRequest(requestIdB);
        assertTrue(JustanAccount(account).isOwnerBytes(subject));
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Enrolls the EOA guardian and the raw-pubkey passkey guardian and sets threshold 2. The passkey
     *      guardian is committed as its bare `(x, y)` — the key IS the guardian, so no contract, deployed
     *      or counterfactual, is involved anywhere on this path.
     */
    function _enrollGuardians(address payable account) internal returns (bytes32 eoaId, bytes32 passkeyId) {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        vm.startPrank(account);
        eoaId = manager.addRecovery(account, address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)), DELAY);
        passkeyId =
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
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        bytes32 eoaId =
            manager.computeRecoveryId(account, address(provider), encodeEoaCommitment(vm.addr(EOA_GUARDIAN_PK)));
        bytes32 passkeyId =
            manager.computeRecoveryId(account, address(provider), encodePasskeyCommitment(bytes32(x), bytes32(y)));

        approvals = new IRecoveryManager.Approval[](2);
        approvals[0] =
            createApproval(eoaId, signRecoverProof(provider, account, subject, salt, expiry, EOA_GUARDIAN_PK));
        approvals[1] = createApproval(
            passkeyId, signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK)
        );
    }

}
