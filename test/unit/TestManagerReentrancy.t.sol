// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";

import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { IRecoveryProvider } from "../../src/interfaces/IRecoveryProvider.sol";

/**
 * @dev An account that is also its own recovery provider: the only shape in which a provider's `verify`
 *      can satisfy `msg.sender == account` and reach the account door while `requestRecovery` is running.
 *      Its `verify` replays whatever call the test armed it with back into the manager.
 */
contract ReentrantAccountProvider {

    JustaRecoveryManager internal immutable MANAGER;
    bytes internal reentrantCall;

    constructor(JustaRecoveryManager manager) {
        MANAGER = manager;
    }

    function arm(bytes calldata call_) external {
        reentrantCall = call_;
    }

    function isOwnerAddress(address) external pure returns (bool) {
        return true;
    }

    function isOwnerBytes(bytes memory) external pure returns (bool) {
        return false;
    }

    function addRecovery(bytes calldata commitment) external returns (bytes32) {
        return MANAGER.addRecovery(address(this), address(this), commitment, 0);
    }

    function verify(
        address,
        bytes calldata,
        bytes32,
        uint256,
        bytes calldata,
        bytes calldata
    )
        external
        returns (bytes4)
    {
        (bool ok, bytes memory ret) = address(MANAGER).call(reentrantCall);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return IRecoveryProvider.verify.selector;
    }

}

/**
 * @title TestManagerReentrancy
 *
 * @notice The account door is closed while `requestRecovery` is verifying proofs: a provider cannot change
 *         the registry, the threshold, or the pending requests in the middle of a verification loop.
 */
contract TestManagerReentrancy is Test {

    JustaRecoveryManager internal manager;
    ReentrantAccountProvider internal account;
    bytes32 internal recoveryId;

    function setUp() public {
        manager = new JustaRecoveryManager();
        account = new ReentrantAccountProvider(manager);
        recoveryId = account.addRecovery(hex"01");
    }

    function _requestExpectingReentrancy(bytes memory reentrantCall) internal {
        account.arm(reentrantCall);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = IRecoveryManager.Approval({ recoveryId: recoveryId, proof: "" });
        bytes memory subject = abi.encode(address(0xBEEF));
        bytes32 salt = keccak256("reentrancy");

        vm.expectRevert(ReentrancyGuard.Reentrancy.selector);
        manager.requestRecovery(address(account), subject, salt, block.timestamp + 1, approvals);

        assertFalse(manager.isSaltUsed(address(account), salt));
    }

    function test_AddRecovery_RevertIfReenteredDuringRequest() public {
        _requestExpectingReentrancy(
            abi.encodeCall(manager.addRecovery, (address(account), address(account), hex"02", 0))
        );
    }

    function test_RemoveRecovery_RevertIfReenteredDuringRequest() public {
        _requestExpectingReentrancy(abi.encodeCall(manager.removeRecovery, (address(account), recoveryId)));
    }

    function test_SetRecoveryThreshold_RevertIfReenteredDuringRequest() public {
        _requestExpectingReentrancy(abi.encodeCall(manager.setRecoveryThreshold, (address(account), 1)));
    }

    function test_CancelRecoveryRequest_RevertIfReenteredDuringRequest() public {
        _requestExpectingReentrancy(abi.encodeCall(manager.cancelRecoveryRequest, (bytes32(uint256(1)))));
    }

}
