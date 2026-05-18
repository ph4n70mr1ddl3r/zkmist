// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {RiscZeroGroth16Verifier} from "risc0-ethereum/contracts/src/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0-ethereum/contracts/src/groth16/ControlID.sol";

/// @notice Deploy all ZKMist contracts to Base in a single transaction.
/// @dev Usage:
///      forge script script/DeployAll.s.sol --rpc-url $BASE_RPC_URL --broadcast
///
/// Required environment variables:
///   PRIVATE_KEY (or ETH_WALLET_PRIVATE_KEY) — Deployer private key with ETH on Base
///
/// Optional environment variables:
///   IMAGE_ID     — Guest program image ID (bytes32 hex). If not set, uses default.
///   MERKLE_ROOT  — Merkle root of eligibility tree (bytes32 hex). If not set, uses default.
///
/// Deployment order (3 contracts, CREATE nonce prediction):
///   1. RiscZeroGroth16Verifier (from risc0-ethereum)
///   2. ZKMToken (minter = predicted airdrop address)
///   3. ZKMAirdrop (references token, verifier, imageId, merkleRoot)
contract DeployAll is Script {
    // Default values (computed from the project)
    // Guest image ID from: cargo run -p zkmist-tools --bin compute-image-id
    bytes32 constant DEFAULT_IMAGE_ID = 0x05ef31c9fea9a30ee1902fc49a7aae3e48fce139ffc9b728858dee5b36423277;

    // Merkle root from the CLI's KNOWN_MERKLE_ROOT constant
    bytes32 constant DEFAULT_MERKLE_ROOT = 0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    function run() external {
        // Resolve deployer key
        uint256 deployerKey;
        if (vm.envExists("PRIVATE_KEY")) {
            deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        } else {
            deployerKey = uint256(vm.envBytes32("ETH_WALLET_PRIVATE_KEY"));
        }

        // Resolve image ID and merkle root (allow overrides via env)
        bytes32 imageId = vm.envOr("IMAGE_ID", DEFAULT_IMAGE_ID);
        bytes32 merkleRoot = vm.envOr("MERKLE_ROOT", DEFAULT_MERKLE_ROOT);

        // ── Predict airdrop address BEFORE startBroadcast ───────────────
        //
        // Foundry simulation deploys `new` contracts from the SCRIPT contract
        // address, but the real broadcast replays them from the DEPLOYER address.
        // This means simulation addresses ≠ broadcast addresses, so we cannot
        // verify the prediction inside startBroadcast. We read the deployer's
        // on-chain nonce and compute the prediction before entering broadcast mode.
        //
        // Deployment order from deployer:
        //   nonce   → RiscZeroGroth16Verifier
        //   nonce+1 → ZKMToken (minter = predicted airdrop)
        //   nonce+2 → ZKMAirdrop
        address deployer = vm.addr(deployerKey);
        uint256 deployerNonce = vm.getNonce(deployer);
        address predictedAirdrop = vm.computeCreateAddress(deployer, deployerNonce + 2);

        console.log("Deployer:", deployer);
        console.log("Deployer nonce:", deployerNonce);
        console.log("Predicted airdrop:", predictedAirdrop);

        vm.startBroadcast(deployerKey);

        // ── Step 1: Deploy RISC Zero Groth16 Verifier ────────────────────
        RiscZeroGroth16Verifier verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console.log("RiscZeroGroth16Verifier deployed at:", address(verifier));

        // ── Step 2: Deploy ZKMToken with predicted minter ────────────────
        ZKMToken token = new ZKMToken(predictedAirdrop);
        console.log("ZKMToken deployed at:", address(token));

        // ── Step 3: Deploy ZKMAirdrop ────────────────────────────────────
        ZKMAirdrop airdrop = new ZKMAirdrop(address(token), address(verifier), imageId, merkleRoot);
        console.log("ZKMAirdrop deployed at:", address(airdrop));

        // ── Verify ───────────────────────────────────────────────────────
        // NOTE: address(airdrop) in simulation != predictedAirdrop because
        // simulation deploys from the script contract. On real broadcast,
        // the addresses WILL match. We verify the minter is set correctly
        // for the predicted address.
        require(token.minter() == predictedAirdrop, "Minter not set to predicted airdrop");

        console.log("");
        console.log("==================================================");
        console.log("  ZKMist Deployment Complete!");
        console.log("==================================================");
        console.log("  Verifier:       ", address(verifier));
        console.log("  Token:          ", address(token));
        console.log("  Predicted airdrop:", predictedAirdrop);
        console.log("  Simulated airdrop:", address(airdrop));
        console.log("  Token minter:   ", token.minter());
        console.log("  Image ID:       ", vm.toString(imageId));
        console.log("  Merkle root:    ", vm.toString(merkleRoot));
        console.log("  Claim amount:   10,000 ZKM");
        console.log("  Max claims:     1,000,000");
        console.log("  Claim deadline: 2027-01-01 00:00:00 UTC");
        console.log("==================================================");
        console.log("");
        console.log("  NOTE: Simulated addresses differ from broadcast addresses.");
        console.log("  After broadcast, verify: token.minter() == airdrop address");
        console.log("");
        console.log("  Update AIRDROP_CONTRACT in cli/src/constants.rs:");
        console.log("  On broadcast, airdrop will be at:", predictedAirdrop);

        vm.stopBroadcast();
    }
}
