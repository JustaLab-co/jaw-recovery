// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../src/providers/SignatureRecoveryProvider.sol";

contract TestManagerReadFunctions is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    SignatureRecoveryProvider public provider;

    function setUp() public {
        manager = new JustaRecoveryManager();
        provider = new SignatureRecoveryProvider();
    }

    /// @dev Etches `account` (so the `isOwnerAddress` call's extcodesize check passes) and stubs it to
    ///      report the manager as a registered owner, satisfying `addRecovery`'s opt-in check.
    function _stubManagerOwner(address account) private {
        vm.assume(uint160(account) > 0xff);
        vm.assume(account != address(manager));
        vm.assume(account != address(this));
        vm.assume(account != address(vm));
        vm.etch(account, hex"00");
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.isOwnerAddress.selector), abi.encode(true));
    }

    /// @dev Registers a recovery for `account` (pranked as the registrant) against the deployed provider.
    function _addRecovery(address account, bytes memory commitment, uint32 delay) private returns (bytes32 recoveryId) {
        _stubManagerOwner(account);
        vm.prank(account);
        return manager.addRecovery(account, address(provider), commitment, delay);
    }

    /// @dev Hand-rolled sans-chainId EIP-712 digest for an admin batch, independent of the manager's own
    ///      implementation. Hashes the ops array per EIP-712: each op to its own struct hash, then the
    ///      concatenation of those hashes.
    function _handRolledAdminDigest(
        address account,
        IRecoveryManager.AdminOp[] memory ops,
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
                keccak256(bytes("JustaRecoveryManager")),
                keccak256(bytes("1")),
                address(manager)
            )
        );

        bytes memory packedOpHashes;
        for (uint256 i = 0; i < ops.length; ++i) {
            packedOpHashes = abi.encodePacked(
                packedOpHashes,
                keccak256(abi.encode(manager.ADMIN_OP_TYPEHASH(), ops[i].opType, keccak256(ops[i].data)))
            );
        }

        bytes32 structHash = keccak256(
            abi.encode(manager.RECOVERY_ADMIN_TYPEHASH(), account, keccak256(packedOpHashes), salt, expiry)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev Builds an ops array from fuzzed parallel arrays, truncated to their common length (capped, to
    ///      keep hashing cost bounded).
    function _buildOps(
        uint8[] memory opTypes,
        bytes[] memory opDatas
    )
        private
        pure
        returns (IRecoveryManager.AdminOp[] memory ops)
    {
        uint256 count = opTypes.length < opDatas.length ? opTypes.length : opDatas.length;
        if (count > 8) {
            count = 8;
        }

        ops = new IRecoveryManager.AdminOp[](count);
        for (uint256 i = 0; i < count; ++i) {
            ops[i] = IRecoveryManager.AdminOp({ opType: opTypes[i], data: opDatas[i] });
        }
    }

    /*//////////////////////////////////////////////////////////////
                            TYPEHASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AdminOpTypehash_ShouldMatchCanonicalString() public view {
        assertEq(manager.ADMIN_OP_TYPEHASH(), keccak256("AdminOp(uint8 opType,bytes data)"));
    }

    function test_RecoveryAdminTypehash_ShouldMatchCanonicalString() public view {
        // The referenced `AdminOp` type is appended to the primary type, per EIP-712. Wallets rebuild this
        // string from the typed-data JSON they are handed, so any drift here — a renamed field, a changed
        // order, a lost suffix — silently invalidates every signature an owner produces.
        assertEq(
            manager.RECOVERY_ADMIN_TYPEHASH(),
            keccak256(
                "RecoveryAdmin(address account,AdminOp[] ops,bytes32 salt,uint256 expiry)AdminOp(uint8 opType,bytes data)"
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        computeRecoveryId() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ComputeRecoveryId_ShouldMatchExpectedHash(
        address account,
        address provider_,
        bytes calldata commitment
    )
        public
        view
    {
        assertEq(
            manager.computeRecoveryId(account, provider_, commitment),
            keccak256(abi.encode(account, provider_, commitment))
        );
    }

    /*//////////////////////////////////////////////////////////////
                            hasRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HasRecovery_ShouldReturnFalseForUnregistered(address account, bytes32 recoveryId) public view {
        assertFalse(manager.hasRecovery(account, recoveryId));
    }

    function test_HasRecovery_ShouldReturnTrueForRegistered(
        address account,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, commitment, delay);

        assertTrue(manager.hasRecovery(account, recoveryId));
    }

    /*//////////////////////////////////////////////////////////////
                            getRecoveries() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRecoveries_ShouldReturnEmptyWhenNoneRegistered(address account) public view {
        assertEq(manager.getRecoveries(account).length, 0);
    }

    function test_GetRecoveries_ShouldReturnRegisteredRecoveries(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, delay1);
        _addRecovery(account, commitment2, delay2);

        IRecoveryManager.Recovery[] memory recoveries = manager.getRecoveries(account);

        // EnumerableSet preserves insertion order with no removals.
        assertEq(recoveries.length, 2);
        assertEq(recoveries[0].provider, address(provider));
        assertEq(recoveries[0].commitment, commitment1);
        assertEq(recoveries[0].delay, delay1);
        assertEq(recoveries[1].provider, address(provider));
        assertEq(recoveries[1].commitment, commitment2);
        assertEq(recoveries[1].delay, delay2);
    }

    /*//////////////////////////////////////////////////////////////
                            getRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRecovery_ShouldReturnZeroedForUnregistered(address account, bytes32 recoveryId) public view {
        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);

        assertEq(recovery.provider, address(0));
        assertEq(recovery.commitment.length, 0);
        assertEq(recovery.delay, 0);
    }

    function test_GetRecovery_ShouldReturnRegisteredRecovery(
        address account,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, commitment, delay);

        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);

        assertEq(recovery.provider, address(provider));
        assertEq(recovery.commitment, commitment);
        assertEq(recovery.delay, delay);
    }

    /*//////////////////////////////////////////////////////////////
                            recoveryCount() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryCount_ShouldBeZeroInitially(address account) public view {
        assertEq(manager.recoveryCount(account), 0);
    }

    function test_RecoveryCount_ShouldReflectRegistrations(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, 0);
        assertEq(manager.recoveryCount(account), 1);

        _addRecovery(account, commitment2, 0);
        assertEq(manager.recoveryCount(account), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        recoveryThreshold() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryThreshold_ShouldDefaultToOne(address account) public view {
        assertEq(manager.recoveryThreshold(account), 1);
    }

    function test_RecoveryThreshold_ShouldReflectSetValue(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint256 threshold
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, 0);
        _addRecovery(account, commitment2, 0);

        // Valid threshold range is [1, recoveryCount] = [1, 2].
        threshold = bound(threshold, 1, 2);

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);

        assertEq(manager.recoveryThreshold(account), threshold);
    }

    /*//////////////////////////////////////////////////////////////
                            isSaltUsed() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsSaltUsed_ShouldBeFalseInitially(address account, bytes32 salt) public view {
        assertFalse(manager.isSaltUsed(account, salt));
    }

    /*//////////////////////////////////////////////////////////////
                      recoveryAdminDigest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryAdminDigest_ShouldMatchHandRolledSansChainIdEip712(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint8[] memory opTypes,
        bytes[] memory opDatas
    )
        public
        view
    {
        // Keystone: the digest equals a hand-rolled sans-chainId EIP-712 computation, pinning the domain
        // shape (name, version, verifyingContract — NO chainId), the struct encoding, and the array-of-
        // structs hashing the ops go through. Nothing else can catch a mistake here: the signing helpers
        // ask the contract for its own digest, so a wrong encoding would still verify against itself.
        IRecoveryManager.AdminOp[] memory ops = _buildOps(opTypes, opDatas);

        assertEq(
            manager.recoveryAdminDigest(account, ops, salt, expiry), _handRolledAdminDigest(account, ops, salt, expiry)
        );
    }

    function test_RecoveryAdminDigest_ShouldBeChainIdIndependent(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint8[] memory opTypes,
        bytes[] memory opDatas,
        uint64 chainId
    )
        public
    {
        vm.assume(chainId != 0);
        IRecoveryManager.AdminOp[] memory ops = _buildOps(opTypes, opDatas);

        // One owner signature must authorize the same batch on every chain, so the digest cannot move
        // when the chain does.
        bytes32 digestBefore = manager.recoveryAdminDigest(account, ops, salt, expiry);

        vm.chainId(chainId);
        assertEq(manager.recoveryAdminDigest(account, ops, salt, expiry), digestBefore);
    }

    function test_RecoveryAdminDigest_ShouldDependOnOpOrder(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint8 opTypeA,
        bytes memory dataA,
        uint8 opTypeB,
        bytes memory dataB
    )
        public
        view
    {
        // Two distinct ops, or swapping them would be a no-op.
        vm.assume(keccak256(abi.encode(opTypeA, dataA)) != keccak256(abi.encode(opTypeB, dataB)));

        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](2);
        ops[0] = IRecoveryManager.AdminOp({ opType: opTypeA, data: dataA });
        ops[1] = IRecoveryManager.AdminOp({ opType: opTypeB, data: dataB });

        IRecoveryManager.AdminOp[] memory swapped = new IRecoveryManager.AdminOp[](2);
        swapped[0] = ops[1];
        swapped[1] = ops[0];

        // Order is part of what the owner signs. Config ops are order-sensitive (a threshold cannot be
        // raised before the guardians it counts exist), so a reordered batch has to be a different
        // message — that is what lets every chain apply one signed sequence identically.
        assertTrue(
            manager.recoveryAdminDigest(account, ops, salt, expiry)
                != manager.recoveryAdminDigest(account, swapped, salt, expiry)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        recoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryRequest_ShouldReturnZeroedForUnknownId(bytes32 requestId) public view {
        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);

        assertEq(request.account, address(0));
        assertEq(request.executeAt, 0);
        assertEq(request.subject.length, 0);
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
        ) = manager.eip712Domain();

        // EIP-5267 discovery must describe the domain that is actually signed over, not the inherited
        // default: `0b01011` = name, version, verifyingContract, with chainId deliberately absent. Tooling
        // that builds typed data from this descriptor would otherwise bind a chainId and produce digests
        // that can never verify — on any chain, under any key.
        assertEq(uint8(fields), uint8(0x0b));
        assertEq(name, "JustaRecoveryManager");
        assertEq(version, "1");
        assertEq(reportedChainId, 0);
        assertEq(verifyingContract, address(manager));
        assertEq(domainSalt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    function test_Eip712Domain_ShouldMatchTheDigestDomainSeparator(
        address account,
        bytes32 salt,
        uint256 expiry,
        uint8[] memory opTypes,
        bytes[] memory opDatas
    )
        public
        view
    {
        (, string memory name, string memory version,, address verifyingContract,,) = manager.eip712Domain();

        // The descriptor is only useful if it reproduces the real thing: rebuild the separator purely from
        // what `eip712Domain` reports, and the resulting digest must equal the one the manager verifies.
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH_SANS_CHAIN_ID, keccak256(bytes(name)), keccak256(bytes(version)), verifyingContract
            )
        );

        IRecoveryManager.AdminOp[] memory ops = _buildOps(opTypes, opDatas);
        bytes memory packedOpHashes;
        for (uint256 i = 0; i < ops.length; ++i) {
            packedOpHashes = abi.encodePacked(
                packedOpHashes,
                keccak256(abi.encode(manager.ADMIN_OP_TYPEHASH(), ops[i].opType, keccak256(ops[i].data)))
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(manager.RECOVERY_ADMIN_TYPEHASH(), account, keccak256(packedOpHashes), salt, expiry)
        );

        assertEq(
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)),
            manager.recoveryAdminDigest(account, ops, salt, expiry)
        );
    }

}
