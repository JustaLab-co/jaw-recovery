// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

contract TestSignatureRecoveryProvider is Test, PrepareRecovery {

    SignatureRecoveryProvider public provider;

    function setUp() public {
        provider = new SignatureRecoveryProvider();

        // WebAuthn verification needs the P256 verifier etched at the addresses Solady staticcalls.
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);
    }

    /// @dev Hand-rolled sans-chainId EIP-712 digest, independent of the contract's own implementation.
    function _handRolledDigest(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH_SANS_CHAIN_ID,
                keccak256(bytes("SignatureRecoveryProvider")),
                keccak256(bytes("1")),
                address(provider)
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(provider.RECOVER_TYPEHASH(), account, keccak256(subject), salt, expiry));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /*//////////////////////////////////////////////////////////////
                        RECOVER_TYPEHASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoverTypehash_ShouldMatchCanonicalString() public view {
        assertEq(
            provider.RECOVER_TYPEHASH(), keccak256("Recover(address account,bytes subject,bytes32 salt,uint256 expiry)")
        );
    }

    /*//////////////////////////////////////////////////////////////
                        recoverDigest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoverDigest_ShouldMatchHandRolledSansChainIdEip712(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        public
        view
    {
        // Keystone: the digest equals a hand-rolled sans-chainId EIP-712 computation, pinning the domain
        // shape (name, version, verifyingContract — NO chainId) and the struct encoding. This is the one
        // property the verify tests cannot catch, since they sign the contract's own digest.
        assertEq(
            provider.recoverDigest(account, subject, salt, expiry), _handRolledDigest(account, subject, salt, expiry)
        );
    }

    function test_RecoverDigest_ShouldBeChainIdIndependent(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint64 chainId
    )
        public
    {
        vm.assume(chainId != 0);

        // The digest is byte-identical under any chainId — the property every multichain proof stands on.
        bytes32 digestBefore = provider.recoverDigest(account, subject, salt, expiry);

        vm.chainId(chainId);
        assertEq(provider.recoverDigest(account, subject, salt, expiry), digestBefore);
    }

    /*//////////////////////////////////////////////////////////////
                    verify() TESTS — EOA BRANCH
    //////////////////////////////////////////////////////////////*/

    function test_Verify_RevertIfCommitmentSignerZero(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        bytes memory proof
    )
        public
    {
        // `ecrecover` yields `address(0)` for any signature it cannot recover, so a zero commitment would
        // otherwise be satisfied by garbage bytes. It is rejected as a non-canonical registration before
        // the proof is looked at: no proof, well-formed or not, can ever satisfy it.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidCommitment.selector);
        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(address(0)), proof);
    }

    function test_Verify_RevertIfCommitmentNotAnAddress(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 dirtyCommitment,
        bytes memory proof
    )
        public
    {
        // A 32-byte commitment whose upper bits do not fit in an address. The range check keeps this a
        // typed `InvalidCommitment` — decoding it straight into an `address` would raise a bare ABI panic
        // instead, leaving whoever debugs a failed recovery with no idea which factor was misregistered.
        vm.assume(dirtyCommitment > type(uint160).max);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidCommitment.selector);
        provider.verify(account, subject, salt, expiry, abi.encode(dirtyCommitment), proof);
    }

    function test_Verify_RevertIfWrongSigner(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk,
        uint256 attackerPk
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);
        attackerPk = bound(attackerPk, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(guardianPk != attackerPk);

        // A perfectly well-formed signature over the correct ceremony digest, produced by a key that is
        // not the committed guardian: recovery succeeds but yields the wrong address, so the proof is
        // rejected. Isolates the signer mismatch — the proof bytes themselves are valid.
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, attackerPk);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(vm.addr(guardianPk)), proof);
    }

    function test_Verify_RevertIfMalformedProof(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        address guardian,
        bytes memory proof
    )
        public
    {
        // A non-zero guardian, so the commitment passes and the signature check is what fails.
        vm.assume(guardian != address(0));

        // Only 65-byte and 64-byte (EIP-2098 compact) signatures are recoverable. Anything else recovers
        // to `address(0)`, which can never equal the committed guardian — malformed bytes fail closed as
        // an invalid signature instead of reverting inside the recovery library.
        vm.assume(proof.length != 64 && proof.length != 65);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(guardian), proof);
    }

    function test_Verify_RevertIfContractSignerEvenWithAccepting1271(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 signerPk,
        address contractSigner
    )
        public
    {
        signerPk = bound(signerPk, 1, SECP256K1_CURVE_ORDER - 1);

        // A fuzzed address safe to etch: past the precompile range, not already carrying code, and not one
        // of the addresses this test depends on.
        vm.assume(uint160(contractSigner) > 0xff);
        vm.assume(contractSigner.code.length == 0);
        vm.assume(contractSigner != vm.addr(signerPk));
        vm.assume(
            contractSigner != address(vm) && contractSigner != address(this) && contractSigner != address(provider)
        );

        // Give the committed address a contract that blesses ANY signature through its ERC-1271 door.
        vm.etch(contractSigner, hex"00");
        vm.mockCall(contractSigner, abi.encodeWithSelector(ERC1271_MAGIC), abi.encode(ERC1271_MAGIC));

        // Strictness proof: the EOA branch is ecrecover-only, so the mocked door is never consulted and a
        // structurally valid signature from an unrelated key still fails. This is what keeps the sign-once
        // promise honest — a smart account's own signature door re-binds chainId, so letting one in here
        // would silently turn portable proofs into per-chain ones.
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, signerPk);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(contractSigner), proof);
    }

    function test_Verify_RevertIfAnyBoundFieldDiffers(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);
        // Leaves room to flip `expiry` upward without overflowing.
        vm.assume(expiry < type(uint256).max);

        bytes memory commitment = encodeEoaCommitment(vm.addr(guardianPk));
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, guardianPk);

        // The proof authorizes exactly one ceremony: every field the guardian saw is bound into the
        // digest, so changing any single one of them at submission invalidates it. This is what stops a
        // relayer from re-aiming a collected proof at another account, another new owner, another salt, or
        // a longer life than the guardian agreed to.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(address(uint160(account) ^ 1), subject, salt, expiry, commitment, proof);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, abi.encodePacked(subject, hex"00"), salt, expiry, commitment, proof);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt ^ bytes32(uint256(1)), expiry, commitment, proof);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry + 1, commitment, proof);
    }

    function test_Verify_ShouldAcceptEoaSignature(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        // The canonical EOA path: a 65-byte signature over the ceremony digest from the committed
        // guardian. `verify` returns nothing and only ever reverts, so completing the call is the
        // assertion. `expiry` is fuzzed without constraint on purpose — the provider binds it into the
        // digest but never enforces the clock, which is the manager's job.
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, guardianPk);

        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(vm.addr(guardianPk)), proof);
    }

    function test_Verify_ShouldAcceptCompactSignature(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        // The 64-byte EIP-2098 compact form packs the recovery id into the top bit of `s`. Wallets emit
        // either form, and the recovery library accepts both, so the SDK can pass a guardian's signature
        // through untouched instead of normalizing it.
        bytes memory proof = signRecoverProofCompact(provider, account, subject, salt, expiry, guardianPk);

        provider.verify(account, subject, salt, expiry, encodeEoaCommitment(vm.addr(guardianPk)), proof);
    }

    function test_Verify_ShouldAcceptMalleableSignature(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianPk, provider.recoverDigest(account, subject, salt, expiry));

        // Characterization, not endorsement: low-s is not enforced, so the `(r, N - s)` twin of a valid
        // signature recovers the same signer and is accepted. Harmless by design — the twin proves the
        // same digest, consumes the same salt in the manager and yields the same requestId, and no state
        // anywhere keys off raw proof bytes. Pinned here so adding a low-s check is a deliberate, loud
        // change rather than a silent one.
        bytes32 twinS = bytes32(SECP256K1_CURVE_ORDER - uint256(s));
        uint8 twinV = v == 27 ? 28 : 27;

        provider.verify(
            account, subject, salt, expiry, encodeEoaCommitment(vm.addr(guardianPk)), abi.encodePacked(r, twinS, twinV)
        );
    }

    function test_Verify_ShouldAcceptSameProofUnderDifferentChainIds(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint256 guardianPk,
        uint64 chainId
    )
        public
    {
        guardianPk = bound(guardianPk, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(chainId != 0);

        // Sign once, verify anywhere: the same proof bytes are accepted before and after the chain changes
        // underneath the provider. The sign-once promise, observed at the provider level.
        bytes memory commitment = encodeEoaCommitment(vm.addr(guardianPk));
        bytes memory proof = signRecoverProof(provider, account, subject, salt, expiry, guardianPk);

        provider.verify(account, subject, salt, expiry, commitment, proof);

        vm.chainId(chainId);
        provider.verify(account, subject, salt, expiry, commitment, proof);
    }

    /*//////////////////////////////////////////////////////////////
                  verify() TESTS — PASSKEY BRANCH
    //////////////////////////////////////////////////////////////*/

    function test_Verify_RevertIfPasskeyProofForDifferentCeremony(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        // Leaves room to sign over a neighbouring ceremony without overflowing.
        vm.assume(expiry < type(uint256).max);
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // A genuine assertion from the committed key, but its challenge is the digest of a different
        // ceremony — the same field-binding guarantee the EOA branch has, carried by the WebAuthn
        // challenge instead of by ecrecover.
        bytes memory proof = signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry + 1), PASSKEY_PK);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodePasskeyCommitment(bytes32(x), bytes32(y)), proof);
    }

    function test_Verify_RevertIfPasskeyWrongKey(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // A genuine assertion for this ceremony, checked against a commitment holding a different key:
        // P-256 verification fails, so one guardian's passkey can never satisfy another's factor.
        bytes memory proof = signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodePasskeyCommitment(bytes32(x), bytes32(y + 1)), proof);
    }

    function test_Verify_RevertIfPasskeyProofMalformed(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        bytes memory proof
    )
        public
    {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // Bytes that do not decode as a WebAuthn assertion yield a zeroed struct rather than a decode
        // revert, so verification fails closed on the empty challenge instead of bubbling a raw panic.
        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, salt, expiry, encodePasskeyCommitment(bytes32(x), bytes32(y)), proof);
    }

    function test_Verify_ShouldAcceptPasskeyProof(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        public
    {
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // The raw-pubkey path: a genuine WebAuthn assertion whose challenge is the ceremony digest,
        // verified straight against the committed key. The guardian's own account contract is never
        // consulted, which is what makes undeployed passkey guardians work with no ERC-6492 machinery and
        // keeps the proof free of any chain binding.
        bytes memory proof = signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK);

        provider.verify(account, subject, salt, expiry, encodePasskeyCommitment(bytes32(x), bytes32(y)), proof);
    }

    function test_Verify_ShouldAcceptPasskeyProofUnderDifferentChainIds(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        uint64 chainId
    )
        public
    {
        vm.assume(chainId != 0);
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);

        // Sign once, verify anywhere — the passkey half of the multichain promise.
        bytes memory commitment = encodePasskeyCommitment(bytes32(x), bytes32(y));
        bytes memory proof = signWebAuthnProof(provider.recoverDigest(account, subject, salt, expiry), PASSKEY_PK);

        provider.verify(account, subject, salt, expiry, commitment, proof);

        vm.chainId(chainId);
        provider.verify(account, subject, salt, expiry, commitment, proof);
    }

    /*//////////////////////////////////////////////////////////////
              verify() TESTS — NON-CANONICAL COMMITMENT
    //////////////////////////////////////////////////////////////*/

    function test_Verify_RevertIfCommitmentLengthInvalid(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        bytes memory commitment,
        bytes memory proof
    )
        public
    {
        // Neither branch: exactly 32 bytes (EOA) and exactly 64 bytes (passkey) are the only canonical
        // guardian encodings. The exactness is what keeps one guardian mapped to one commitment — since
        // `abi.decode` ignores trailing bytes, accepting longer encodings would let the same guardian
        // register as two distinct recoveries and satisfy both with a single signature, quietly halving
        // an M-of-N threshold.
        vm.assume(commitment.length != 32 && commitment.length != 64);

        vm.expectRevert(SignatureRecoveryProvider.SignatureRecoveryProvider_InvalidCommitment.selector);
        provider.verify(account, subject, salt, expiry, commitment, proof);
    }

    /*//////////////////////////////////////////////////////////////
                          eip712Domain() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Eip712Domain_ShouldReportTheSansChainIdDomain(uint64 chainId) public {
        vm.assume(chainId != 0);
        vm.chainId(chainId);

        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 reportedChainId,
            address verifyingContract,
            bytes32 domainSalt,
            uint256[] memory extensions
        ) = provider.eip712Domain();

        // EIP-5267 discovery must describe the domain guardians actually sign under: `0b01011` = name,
        // version, verifyingContract, with chainId deliberately absent whatever chain the call lands on.
        assertEq(uint8(fields), uint8(0x0b));
        assertEq(name, "SignatureRecoveryProvider");
        assertEq(version, "1");
        assertEq(reportedChainId, 0);
        assertEq(verifyingContract, address(provider));
        assertEq(domainSalt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    function test_Eip712Domain_ShouldMatchTheDigestDomainSeparator(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        public
        view
    {
        (, string memory name, string memory version,, address verifyingContract,,) = provider.eip712Domain();

        // Rebuild the separator from nothing but what the descriptor reports: an approval page that
        // discovers the domain this way must land on the digest the provider verifies.
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH_SANS_CHAIN_ID, keccak256(bytes(name)), keccak256(bytes(version)), verifyingContract
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(provider.RECOVER_TYPEHASH(), account, keccak256(subject), salt, expiry));

        assertEq(
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)),
            provider.recoverDigest(account, subject, salt, expiry)
        );
    }

}
