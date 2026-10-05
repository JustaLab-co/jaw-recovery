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
 * @title TestRecoveryLifecycleFlow
 *
 * @notice Integration test for the full recovery lifecycle against a real stack: a 7702-delegated
 * JustanAccount that has opted in by registering the manager as an owner, the real SignatureRecoveryProvider,
 * and real guardian proofs. Where the unit tests mock `verify` and the account and only assert the
 * `addOwner*` selector was called, these prove the new owner is genuinely registered on the account after
 * `addRecovery -> requestRecovery -> warp -> executeRecoveryRequest`. It also pins the provider's deliberate
 * strictness: a smart-account guardian enrolled by its address can never approve a recovery, even with a
 * signature its own ERC-1271 `isValidSignature` accepts.
 */
contract TestRecoveryLifecycleFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    JustanAccountFactory public factory;
    JustanAccount public guardian;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));

        vm.deal(TEST_ACCOUNT_ADDRESS, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner during
        // execution (MultiOwnable's owner-add is gated to owners/the account itself).
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(address(manager));

        // Deploy a passkey-backed JustanAccount to act as a recovery guardian. WebAuthn verification needs
        // the P256 verifier etched at the addresses Solady's WebAuthn library staticcalls.
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        factory = new JustanAccountFactory(address(entryPoint));
        bytes[] memory guardianOwners = new bytes[](1);
        guardianOwners[0] = abi.encode(bytes32(x), bytes32(y));
        guardian = factory.createAccount(guardianOwners, 0);
    }

    /**
     * @notice Recovers an account to a new EOA owner end to end and proves the owner is really registered.
     * @dev addRecovery (ECDSA commitment) -> requestRecovery with a real signed proof (real provider.verify
     *      + real isOwnerBytes) -> warp past the delay -> executeRecoveryRequest -> the new EOA is an owner.
     */
    function test_ShouldRecoverWithEoaOwnerEndToEnd(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay,
        address recipient
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered owner must not already be on the account.
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        // The capstone recipient must be a plain EOA: exclude precompiles/zero (<= 0xff, incl. Prague's BLS
        // precompiles) and any contract (the account holds the funds; other contracts may reject the ETH).
        vm.assume(uint160(recipient) > 0xff);
        vm.assume(recipient.code.length == 0);

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]). Under
        // the new provider's strict ecrecover the guardian's code length is irrelevant (its account contract
        // is never consulted), so the old `recoveryEoa.code.length == 0` ERC-1271-path guard is gone.
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        // Register a single ECDSA recovery committing to `recoveryEoa`.
        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        // The committed EOA signs a real proof over the ceremony's (subject, salt, expiry).
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-eoa-owner");
        uint256 expiry = block.timestamp + 7 days;
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        // Queue the request, then fast-forward to its execution time and finalize.
        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new EOA is now a real owner (manager + newOwner = 2) and the ceremony salt has been consumed.
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertTrue(manager.isSaltUsed(account, salt));

        // Confirm recovered owner can control the account with an ETH transfer.
        uint256 recipientBefore = recipient.balance;
        uint256 accountBefore = account.balance;
        vm.prank(newOwner);
        JustanAccount(account).execute(recipient, 1 ether, "");
        assertEq(recipient.balance, recipientBefore + 1 ether);
        assertEq(account.balance, accountBefore - 1 ether);
    }

    /**
     * @notice Recovers an account to a new passkey owner end to end and proves the owner is really registered.
     * @dev Same flow with a 64-byte passkey subject, exercising the `addOwnerPublicKey` branch.
     */
    function test_ShouldRecoverWithPasskeyOwnerEndToEnd(
        bytes32 x,
        bytes32 y,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered passkey must not already be on the account.
        vm.assume(!JustanAccount(account).isOwnerPublicKey(x, y));
        // The all-zero public key is a dead owner (P256 rejects it), so `_validateSubject` reverts
        // `InvalidSubject` on it — exclude the draw rather than let it flake this happy-path fuzz run.
        vm.assume(!(x == 0 && y == 0));

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]). Code
        // length is irrelevant under strict ecrecover, so no guard on `recoveryEoa` (see the EOA-owner test).
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodePasskeySubject(x, y);
        bytes32 salt = keccak256("salt-passkey-owner");
        uint256 expiry = block.timestamp + 7 days;
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new passkey is now a real owner (manager + passkey = 2) and the ceremony salt has been consumed.
        assertTrue(JustanAccount(account).isOwnerPublicKey(x, y));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertTrue(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice A smart-account guardian enrolled by its ADDRESS (32-byte commitment) can NEVER approve a
     *         recovery, even with a signature its own ERC-1271 `isValidSignature` accepts.
     * @dev This test pins the deliberate strictness of the new provider, and is valuable precisely because
     *      the inner signature is REAL: a WebAuthn assertion from the guardian's passkey, wrapped in ERC-7739
     *      PersonalSign over the provider digest — exactly the envelope the guardian re-derives and accepts in
     *      `isValidSignature` (asserted below). Yet a 32-byte commitment is verified with STRICT ecrecover
     *      only, with no ERC-1271/6492 fallback. WHY this is the desired behavior: a 1271 door would let a
     *      smart-account signer re-bind `block.chainid` inside its own verification, silently producing
     *      per-chain proofs and breaking the sign-once multichain promise. Smart-account guardians are
     *      therefore excluded by design; the supported multichain factor is the raw P-256 passkey public key
     *      (a 64-byte commitment), verified directly in the provider with no account contract in the loop.
     *      Because the proof genuinely passes the guardian's 1271 check, a green revert here proves no 1271
     *      door exists.
     */
    function test_RequestRecovery_RevertWhenGuardianIsSmartAccount(address newOwner, uint32 delay) public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered owner must not already be on the account.
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        // Enroll the passkey-backed guardian by its contract ADDRESS as a 32-byte (EOA-shaped) commitment.
        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodeEoaCommitment(address(guardian)), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-smart-account-guardian");
        uint256 expiry = block.timestamp + 7 days;

        // A proof the guardian would accept via ERC-1271: its passkey's WebAuthn assertion, ERC-7739-wrapped
        // over the provider's canonical digest using the guardian's own EIP-712 domain.
        bytes memory proof = _signPasskeyGuardianProof(account, subject, salt, expiry);

        // Sanity: the very same proof genuinely verifies through the guardian's own ERC-1271 door...
        bytes32 digest = provider.recoverDigest(account, subject, salt, expiry);
        assertTrue(guardian.isValidSignature(digest, proof) == ERC1271_MAGIC);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        // ...yet the provider rejects it: a 32-byte commitment is strict-ecrecover only, so a WebAuthn/1271
        // envelope can never satisfy it.
        vm.expectRevert(
            abi.encodeWithSelector(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector)
        );
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        // The rejected request consumed nothing: the ceremony salt stays fully replayable.
        assertFalse(manager.isSaltUsed(account, salt));
    }

    /**
     * @notice A fresh account that never opted in cannot register a recovery; after it registers the
     *         manager as an owner, the identical call succeeds.
     * @dev Unlike every other test here, this deploys a separate JustanAccount via the factory rather than
     *      using `TEST_ACCOUNT_ADDRESS` (already opted in during `setUp`), since it needs an account that has
     *      never registered the manager as an owner.
     */
    function test_AddRecovery_RevertIfManagerNotAccountOwner(address freshOwner) public {
        vm.assume(freshOwner != address(0));
        // `address(manager)` is in the fuzzer's address dictionary: drawing it would make the fresh account
        // born with the manager already an owner, so the expected revert would never fire.
        vm.assume(freshOwner != address(manager));

        bytes[] memory freshOwners = new bytes[](1);
        freshOwners[0] = abi.encode(freshOwner);
        JustanAccount freshAccount = factory.createAccount(freshOwners, 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_ManagerNotAccountOwner.selector, address(freshAccount)
            )
        );
        vm.prank(address(freshAccount));
        manager.addRecovery(address(freshAccount), address(provider), encodeEoaCommitment(freshOwner), 0);

        // Opt in, then the identical call succeeds.
        vm.prank(address(freshAccount));
        freshAccount.addOwnerAddress(address(manager));

        vm.prank(address(freshAccount));
        bytes32 recoveryId =
            manager.addRecovery(address(freshAccount), address(provider), encodeEoaCommitment(freshOwner), 0);

        assertTrue(manager.hasRecovery(address(freshAccount), recoveryId));
    }

    /**
     * @notice If the 7702 delegation is revoked mid-timelock, execution reverts loudly and the queued request
     *         survives, so recovery resumes the moment the delegation returns.
     * @dev The story SPEC-MULTICHAIN-ADMIN §9a flags: `addOwnerAddress`/`addOwnerPublicKey` return nothing, so
     *      Solidity emits no code-existence check and a call to a re-codeless address would SUCCEED vacuously
     *      — request deleted, event emitted, no owner added. The manager's `account.code.length` guard turns
     *      that silent false success into `JustaRecoveryManager_AccountHasNoCode`, and because the guard fires
     *      before the CEI delete the pending request is never burned.
     * @dev Where the unit coverage pins this against a mocked address, this proves it on the real delegated
     *      account: the delegation designator is saved, wiped with `vm.etch(account, "")` (the key holder
     *      un-delegating), then etched back verbatim. Re-etching the saved code is the honest equivalent of a
     *      fresh authorization tuple — `vm.signAndAttachDelegation` cannot be re-run cleanly mid-test — and it
     *      restores the exact `0xef0100 || implementation` designator the account had.
     */
    function test_ShouldPreserveRequestWhenDelegationRevokedMidTimelock(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));
        // A nonzero delay is what makes "mid-timelock" a real window.
        vm.assume(delay > 0);

        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-delegation-revoked");
        uint256 expiry = block.timestamp + 7 days;

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] =
            createApproval(recoveryId, signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk));

        bytes32 requestId = manager.requestRecovery(account, subject, salt, expiry, approvals);
        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;

        // Save the live delegation designator, then un-delegate: the address is a bare EOA again.
        bytes memory delegatedCode = account.code;
        assertGt(delegatedCode.length, 0);
        vm.etch(account, "");
        assertEq(account.code.length, 0);

        // At `executeAt` the guard fires instead of a vacuous success.
        vm.warp(executeAt);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_AccountHasNoCode.selector, account)
        );
        manager.executeRecoveryRequest(requestId);

        // The request was NOT burned by the failed attempt (the guard precedes the CEI delete).
        assertEq(manager.recoveryRequest(requestId).account, account);

        // Re-delegating restores the account, and the surviving request finalizes with no re-signing.
        vm.etch(account, delegatedCode);
        manager.executeRecoveryRequest(requestId);

        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
    }

    /**
     * @dev Builds the guardian's ERC-1271 proof: a WebAuthn signature from the guardian's passkey over the
     *      provider's `(account, subject, salt, expiry)` digest, wrapped in ERC-7739 (PersonalSign) using the
     *      guardian account's own EIP-712 domain — the form the guardian re-derives in `isValidSignature`.
     */
    function _signPasskeyGuardianProof(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes memory)
    {
        return _webAuthnProof(_guardian7739Hash(address(guardian), account, subject, salt, expiry));
    }

    /**
     * @dev The ERC-7739 (PersonalSign) hash a JustanAccount `signer` validates in `isValidSignature`, built
     *      from the signer's EIP-712 domain (name/version/chainId/address) and the provider's canonical
     *      recovery digest.
     */
    function _guardian7739Hash(
        address signer,
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 digest = provider.recoverDigest(account, subject, salt, expiry);

        ERC7739Utils.DomainData memory domainData;
        domainData.name = "JustanAccount";
        domainData.version = "1";
        domainData.chainId = block.chainid;
        domainData.verifyingContract = signer;
        domainData.domainSeparator = ERC7739Utils.computeDomainSeparator(domainData);

        return ERC7739Utils.erc7739HashFromPersonalSignHash(digest, domainData);
    }

    /// @dev Wraps `erc7739Hash` in a WebAuthn assertion signed by the guardian's passkey, ABI-encoded as a
    ///      JustanAccount `SignatureWrapper` at owner index 0.
    function _webAuthnProof(bytes32 erc7739Hash) internal pure returns (bytes memory) {
        return abi.encode(
            JustanAccount.SignatureWrapper({ ownerIndex: 0, signatureData: signWebAuthnProof(erc7739Hash, PASSKEY_PK) })
        );
    }

}
