// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Script, console2 } from "forge-std/Script.sol";

abstract contract CodeConstants {

    ////////////////////////////////////////////////////////////////////////
    // CHAIN IDS
    ////////////////////////////////////////////////////////////////////////

    uint256 public constant LOCAL_CHAIN_ID = 31_337;

    uint256 public constant MAINNET_ETH_CHAIN_ID = 1;
    uint256 public constant ETH_SEPOLIA_CHAIN_ID = 11_155_111;

    uint256 public constant BASE_CHAIN_ID = 8453;
    uint256 public constant BASE_SEPOLIA_CHAIN_ID = 84_532;

    uint256 public constant OPTIMISM_CHAIN_ID = 10;
    uint256 public constant OPTIMISM_SEPOLIA_CHAIN_ID = 11_155_420;

    uint256 public constant ARBITRUM_ONE_CHAIN_ID = 42_161;
    uint256 public constant ARBITRUM_SEPOLIA_CHAIN_ID = 421_614;

    uint256 public constant AVALANCHE_CHAIN_ID = 43_114;
    uint256 public constant AVALANCHE_FUJI_CHAIN_ID = 43_113;

    uint256 public constant BSC_CHAIN_ID = 56;
    uint256 public constant BSC_TESTNET_CHAIN_ID = 97;

    uint256 public constant LINEA_CHAIN_ID = 59_144;
    uint256 public constant LINEA_SEPOLIA_CHAIN_ID = 59_141;

    uint256 public constant CELO_CHAIN_ID = 42_220;
    uint256 public constant CELO_SEPOLIA_CHAIN_ID = 11_142_220;

    uint256 public constant FLARE_CHAIN_ID = 14;
    uint256 public constant FLARE_COSTON2_CHAIN_ID = 114;

    uint256 public constant INK_CHAIN_ID = 57_073;
    uint256 public constant INK_SEPOLIA_CHAIN_ID = 763_373;

    uint256 public constant DOS_CHAIN_ID = 7979;

    uint256 public constant GNOSIS_CHAIN_ID = 100;

    uint256 public constant ARC_TESTNET_CHAIN_ID = 5_042_002;

    uint256 public constant POLYGON_CHAIN_ID = 137;
    uint256 public constant POLYGON_AMOY_CHAIN_ID = 80_002;

    ////////////////////////////////////////////////////////////////////////
    // ENTRY POINT
    ////////////////////////////////////////////////////////////////////////

    /// @notice Address of the v0.8 EntryPoint contract.
    address public constant ENTRYPOINT_ADDRESS = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    ////////////////////////////////////////////////////////////////////////
    // TEST ACCOUNTS (Anvil defaults)
    ////////////////////////////////////////////////////////////////////////

    // Anvil default account #1
    address payable public constant TEST_ACCOUNT_ADDRESS = payable(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    uint256 public constant TEST_ACCOUNT_PRIVATE_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    /// @notice A fixed P-256 passkey private key for WebAuthn tests (P-256 keys are not fuzzable like
    ///         secp256k1 ones; passkey-branch logic is key-independent).
    uint256 public constant PASSKEY_PK = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2;

    // Secp256k1 curve order for signature validation
    uint256 public constant SECP256K1_CURVE_ORDER =
        115_792_089_237_316_195_423_570_985_008_687_907_852_837_564_279_074_904_382_605_163_141_518_161_494_337;

    /// @notice secp256r1 (P-256) curve order, for low-s normalization of `vm.signP256` outputs.
    uint256 public constant P256_CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    ////////////////////////////////////////////////////////////////////////
    // SIGNATURE TEST CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /// @notice `keccak256("EIP712Domain(string name,string version,address verifyingContract)")` — the
    ///         sans-chainId domain typehash Solady uses in `_hashTypedDataSansChainId`.
    bytes32 public constant DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        keccak256("EIP712Domain(string name,string version,address verifyingContract)");

    /// @notice The ERC-1271 magic value / selector (`isValidSignature(bytes32,bytes)`).
    bytes4 public constant ERC1271_MAGIC = 0x1626ba7e;

    ////////////////////////////////////////////////////////////////////////
    // P256 VERIFIER (WebAuthn test infra)
    ////////////////////////////////////////////////////////////////////////

    /// @notice RIP-7212 / FreshCryptoLib P256 verifier runtime bytecode, etched at `P256.VERIFIER` and
    ///         `P256.RIP_PRECOMPILE` in tests that exercise passkey (WebAuthn) signature validation.
    bytes internal constant P256_VERIFIER_BYTECODE =
        hex"3d604052610216565b60008060006ffffffffeffffffffffffffffffffffff60601b19808687098188890982838389096004098384858485093d510985868b8c096003090891508384828308850385848509089650838485858609600809850385868a880385088509089550505050808188880960020991505093509350939050565b81513d83015160408401516ffffffffeffffffffffffffffffffffff60601b19808384098183840982838388096004098384858485093d510985868a8b096003090896508384828308850385898a09089150610102848587890960020985868787880960080987038788878a0387088c0908848b523d8b015260408a0152565b505050505050505050565b81513d830151604084015185513d87015160408801518361013d578287523d870182905260408701819052610102565b80610157578587523d870185905260408701849052610102565b6ffffffffeffffffffffffffffffffffff60601b19808586098183840982818a099850828385830989099750508188830383838809089450818783038384898509870908935050826101be57836101be576101b28a89610082565b50505050505050505050565b808485098181860982828a09985082838a8b0884038483860386898a09080891506102088384868a0988098485848c09860386878789038f088a0908848d523d8d015260408c0152565b505050505050505050505050565b6020357fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325513d6040357f7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a88111156102695782035b60206108005260206108205260206108405280610860526002830361088052826108a0526ffffffffeffffffffffffffffffffffff60601b198060031860205260603560803560203d60c061080060055afa60203d1416837f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8585873d5189898a09080908848384091484831085851016888710871510898b108b151016609f3611161616166103195760206080f35b60809182523d820152600160c08190527f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966102009081527f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f53d909101526102405261038992509050610100610082565b610397610200610400610082565b6103a7610100608061018061010d565b6103b7610200608061028061010d565b6103c861020061010061030061010d565b6103d961020061018061038061010d565b6103e9610400608061048061010d565b6103fa61040061010061050061010d565b61040b61040061018061058061010d565b61041c61040061020061060061010d565b61042c610600608061068061010d565b61043d61060061010061070061010d565b61044e61060061018061078061010d565b81815182350982825185098283846ffffffffeffffffffffffffffffffffff60601b193d515b82156105245781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f71c16610600888a1b60f51c16176040810151801585151715610564578061055357506105fe565b81513d8301519750955093506105fe565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a015109089350836105b957806105b9576105a9898c8c610008565b9a509b50995050505050506105fe565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b5082156106af5781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f51c16610600888a1b60f31c161760408101518015851517156106ef57806106de5750610789565b81513d830151975095509350610789565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a01510908935083610744578061074457610734898c8c610008565b9a509b5099505050505050610789565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b50600488019760fb19016104745750816107a2573d6040f35b81610860526002810361088052806108a0523d3d60c061080060055afa898983843d513d510987090614163d525050505050505050503d3df3fea264697066735822122063ce32ec0e56e7893a1f6101795ce2e38aca14dd12adb703c71fe3bee27da71e64736f6c634300081a0033";

}

contract HelperConfig is CodeConstants, Script {

    error HelperConfig__InvalidChainId();

    struct NetworkConfig {
        address entryPointAddress;
    }

    function isSupportedChain(uint256 chainId) public pure returns (bool) {
        return chainId == ETH_SEPOLIA_CHAIN_ID || chainId == MAINNET_ETH_CHAIN_ID || chainId == BASE_CHAIN_ID
            || chainId == BASE_SEPOLIA_CHAIN_ID || chainId == OPTIMISM_CHAIN_ID || chainId == OPTIMISM_SEPOLIA_CHAIN_ID
            || chainId == ARBITRUM_ONE_CHAIN_ID || chainId == ARBITRUM_SEPOLIA_CHAIN_ID || chainId == AVALANCHE_CHAIN_ID
            || chainId == AVALANCHE_FUJI_CHAIN_ID || chainId == BSC_CHAIN_ID || chainId == BSC_TESTNET_CHAIN_ID
            || chainId == LINEA_CHAIN_ID || chainId == LINEA_SEPOLIA_CHAIN_ID || chainId == CELO_CHAIN_ID
            || chainId == CELO_SEPOLIA_CHAIN_ID || chainId == FLARE_CHAIN_ID || chainId == FLARE_COSTON2_CHAIN_ID
            || chainId == INK_CHAIN_ID || chainId == INK_SEPOLIA_CHAIN_ID || chainId == DOS_CHAIN_ID
            || chainId == GNOSIS_CHAIN_ID || chainId == ARC_TESTNET_CHAIN_ID || chainId == POLYGON_CHAIN_ID
            || chainId == POLYGON_AMOY_CHAIN_ID;
    }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        if (chainId == LOCAL_CHAIN_ID) {
            return getOrCreateAnvilEthConfig();
        } else if (isSupportedChain(chainId)) {
            return NetworkConfig({ entryPointAddress: ENTRYPOINT_ADDRESS });
        } else {
            revert HelperConfig__InvalidChainId();
        }
    }

    function getConfig() public returns (NetworkConfig memory) {
        return getConfigByChainId(block.chainid);
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        console2.log("Deploying mocks...");
        vm.startBroadcast();
        EntryPoint entryPoint = new EntryPoint();
        vm.stopBroadcast();
        console2.log("Mocks deployed!");

        return NetworkConfig({ entryPointAddress: address(entryPoint) });
    }

}
