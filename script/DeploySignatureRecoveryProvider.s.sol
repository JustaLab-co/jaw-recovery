// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Script, console2 } from "forge-std/Script.sol";
import { SafeSingletonDeployer } from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";
import { P256 } from "solady/utils/P256.sol";

import { SignatureRecoveryProvider } from "../src/providers/SignatureRecoveryProvider.sol";

/**
 * @notice Deploy the SignatureRecoveryProvider contract.
 * @dev The deterministic same-address deploy is load-bearing: the provider's chain-agnostic EIP-712
 *      domain binds the verifying contract's address, so guardian signatures are only portable across
 *      chains where the provider lives at the same address.
 */
contract DeploySignatureRecoveryProvider is Script {

    /// @dev Set to address(0) until the first deterministic deploy; the assert below is guarded so
    /// the first run succeeds. Update with the real address afterwards to enforce the same address
    /// across every chain.
    address constant EXPECTED_PROVIDER = address(0);

    bytes32 constant PROVIDER_SALT = 0x0000000000000000000000000000000000000000000000000000000000000001;

    function run() public {
        console2.log("Deploying SignatureRecoveryProvider on chain ID", block.chainid);

        if (block.chainid == 31_337) {
            vm.startBroadcast();
            deploy();
            vm.stopBroadcast();
        } else {
            // Passkey guardian proofs verify via Solady's P256, which needs the RIP-7212 precompile or
            // the canonical P256 verifier on this chain — without both, P256 returns false SILENTLY and
            // every passkey guardian would quietly never verify. Refuse to deploy onto such a chain.
            // (Same dependency JustanAccount itself has for passkey owners.)
            require(P256.hasPrecompileOrVerifier(), "chain lacks RIP-7212 precompile and P256 verifier");

            deployWithSafeSingleton();
        }
    }

    function deploy() internal {
        SignatureRecoveryProvider provider = new SignatureRecoveryProvider{ salt: 0 }();

        logAddress("SignatureRecoveryProvider", address(provider));
    }

    function deployWithSafeSingleton() internal {
        address provider = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(SignatureRecoveryProvider).creationCode, args: "", salt: PROVIDER_SALT
        });

        console2.log("Deployed SignatureRecoveryProvider:", provider);
        if (EXPECTED_PROVIDER != address(0)) {
            assert(provider == EXPECTED_PROVIDER);
        }

        logAddress("SignatureRecoveryProvider", provider);
    }

    function logAddress(string memory name, address addr) internal pure {
        console2.logString(string.concat(name, ": ", Strings.toHexString(addr)));
    }

}
