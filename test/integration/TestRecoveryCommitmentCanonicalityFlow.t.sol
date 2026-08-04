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
 * @title TestRecoveryCommitmentCanonicalityFlow
 *
 * @notice Integration test for the SignatureRecoveryProvider's commitment-canonicality defense against a real
 * stack. The manager keys recoveries by `keccak256(account, provider, commitment)` over the raw commitment
 * bytes and only rejects an empty commitment, so two non-canonical encodings of the same EOA both register as
 * *distinct* recoveries. Without the provider's exact-length dispatch, an attacker holding one signature could
 * satisfy two approvals of the "same" guardian and silently dilute an M-of-N threshold. The provider blocks
 * this by dispatching strictly on length:
 *
 *   - A trailing-byte variant (`abi.encode(eoa) || 0x00`, 33 bytes) is neither 32 nor 64 bytes, so it reverts
 *     `SignatureRecoveryProvider_InvalidCommitment` at verify — a dead slot.
 *   - A zero-padded variant (`abi.encode(eoa) || 32 zero bytes`, 64 bytes) is now read as a raw P-256 passkey
 *     public key (x = the padded EOA, y = 0), so a reused ECDSA signature is verified as a WebAuthn assertion
 *     and fails `SignatureRecoveryProvider_InvalidSignature` — also a dead slot.
 *
 * Either way the whole request reverts, nothing is queued, and the salt is never consumed: the dilution
 * bypass fails end to end.
 */
contract TestRecoveryCommitmentCanonicalityFlow is Test, PrepareRecovery {

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

        // The 64-byte zero-padded variant routes to the passkey (WebAuthn) path; etch the P256 verifier so
        // that path resolves deterministically to "invalid" for a reused ECDSA proof instead of relying on
        // missing-precompile semantics.
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        vm.deal(account, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(address(manager));
    }

    /**
     * @notice Both non-canonical encodings of one EOA register as distinct recoveries alongside the canonical
     *         32-byte one: the manager keys by raw commitment bytes and only rejects an empty one.
     * @dev Documents the accepted residual — the manager admits the dead slots at registration; the provider
     *      is what rejects them at verify (covered below). The trailing-byte variant `abi.decode`s to the same
     *      signer; the zero-padded variant is a different guardian *class* entirely (a passkey pubkey).
     */
    function test_ShouldRegisterNonCanonicalCommitmentsAsDistinctRecoveries(address eoa, uint32 delay) public {
        vm.assume(eoa != address(0));

        bytes memory canonical = encodeEoaCommitment(eoa); // 32 bytes
        bytes memory trailing = bytes.concat(canonical, hex"00"); // 33 bytes, still decodes to `eoa`
        bytes memory padded = bytes.concat(canonical, new bytes(32)); // 64 bytes, reads as passkey (x, y=0)

        vm.prank(account);
        bytes32 canonicalId = manager.addRecovery(account, address(provider), canonical, delay);
        vm.prank(account);
        bytes32 trailingId = manager.addRecovery(account, address(provider), trailing, delay);
        vm.prank(account);
        bytes32 paddedId = manager.addRecovery(account, address(provider), padded, delay);

        // Three distinct recoveries are registered side by side.
        assertTrue(canonicalId != trailingId && canonicalId != paddedId && trailingId != paddedId);
        assertEq(manager.recoveryCount(account), 3);
        assertTrue(manager.hasRecovery(account, canonicalId));
        assertTrue(manager.hasRecovery(account, trailingId));
        assertTrue(manager.hasRecovery(account, paddedId));

        // The registered delay is stored verbatim (the fuzzed value is otherwise never observed here).
        assertEq(manager.getRecovery(account, canonicalId).delay, delay);
    }

    /**
     * @notice One signature cannot satisfy a 2-of-2 across a canonical (32B) and a trailing-byte (33B)
     *         commitment of the same signer: the trailing-byte slot reverts `InvalidCommitment`, so the whole
     *         request reverts.
     * @dev The account registers the same EOA twice (canonical + trailing byte) — two distinct recoveryIds, so
     *      the manager's distinctness check is satisfied — sets threshold 2, and submits one valid signature
     *      for both slots. The provider rejects the non-32/64-byte commitment before the signature is even
     *      checked, so nothing is queued and the salt is untouched.
     */
    function test_ShouldRejectThresholdBypassViaTrailingByteCommitment(address newOwner, uint256 recoveryEoaPk) public {
        vm.assume(newOwner != address(0) && newOwner != account && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        bytes memory canonical = encodeEoaCommitment(recoveryEoa);
        bytes memory trailing = bytes.concat(canonical, hex"00");

        vm.prank(account);
        bytes32 canonicalId = manager.addRecovery(account, address(provider), canonical, 0);
        vm.prank(account);
        bytes32 trailingId = manager.addRecovery(account, address(provider), trailing, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-canonicality-trailing");
        uint256 expiry = block.timestamp + 7 days;

        // The attacker holds one valid signature from `recoveryEoa` and reuses it for both slots.
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(canonicalId, proof); // 32B slot verifies the ECDSA proof
        approvals[1] = createApproval(trailingId, proof); // 33B slot reverts at verify

        // The trailing-byte slot reverts (length is neither 32 nor 64) after the canonical slot passes, so the
        // entire request reverts and nothing is queued.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidCommitment.selector);
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        assertFalse(manager.isSaltUsed(account, salt));
        assertEq(manager.recoveryRequest(keccak256(abi.encode(account, subject, salt))).account, address(0));
    }

    /**
     * @notice One signature cannot satisfy a 2-of-2 across a canonical (32B) and a zero-padded (64B)
     *         commitment of the same signer: the 64-byte slot is read as a passkey pubkey, so the reused ECDSA
     *         signature fails WebAuthn verification (`InvalidSignature`) and the whole request reverts.
     * @dev The 64-byte encoding is no longer a dead length — it decodes as `(x = padded EOA, y = 0)` and routes
     *      to the WebAuthn path. An ECDSA `(r, s, v)` blob is not a valid WebAuthn assertion, so verification
     *      fails on the signature rather than the commitment, but the dilution attack is still blocked end to
     *      end: nothing is queued and the salt is untouched.
     */
    function test_ShouldRejectThresholdBypassViaZeroPaddedCommitment(address newOwner, uint256 recoveryEoaPk) public {
        vm.assume(newOwner != address(0) && newOwner != account && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        bytes memory canonical = encodeEoaCommitment(recoveryEoa);
        bytes memory padded = bytes.concat(canonical, new bytes(32)); // 64 bytes: reads as passkey (x, y=0)

        vm.prank(account);
        bytes32 canonicalId = manager.addRecovery(account, address(provider), canonical, 0);
        vm.prank(account);
        bytes32 paddedId = manager.addRecovery(account, address(provider), padded, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 salt = keccak256("salt-canonicality-padded");
        uint256 expiry = block.timestamp + 7 days;

        // The attacker holds one valid ECDSA signature from `recoveryEoa` and reuses it for both slots.
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(canonicalId, proof); // 32B slot verifies the ECDSA proof
        approvals[1] = createApproval(paddedId, proof); // 64B slot verifies the SAME bytes as WebAuthn -> fails

        // Attribution: unlike the trailing-byte sibling (whose `InvalidCommitment` names its own slot), BOTH
        // branches of `verify` revert with the SAME `InvalidSignature` selector — so the expected revert below
        // would look identical if the canonical slot were the one failing, and the test would pass while
        // proving nothing about the padded slot. This plain call reverts unless the reused proof genuinely
        // satisfies the canonical 32-byte slot, which is the premise of the whole attack.
        provider.verify(account, subject, salt, expiry, canonical, proof);

        // The zero-padded slot routes to WebAuthn and the reused ECDSA bytes are not a valid assertion, so it
        // reverts InvalidSignature after the canonical slot passes; the whole request reverts.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        manager.requestRecovery(account, subject, salt, expiry, approvals);

        assertFalse(manager.isSaltUsed(account, salt));
        assertEq(manager.recoveryRequest(keccak256(abi.encode(account, subject, salt))).account, address(0));
    }

}
