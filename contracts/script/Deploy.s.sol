// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";

/// @notice Deploy ZKMist contracts to Base (assumes verifier is already deployed).
/// @dev Usage: forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast
///
/// ⚠️  Use DeployAll.s.sol instead if you need to deploy the verifier as well.
///      This script is for deploying to a chain where the RiscZeroGroth16Verifier
///      has already been deployed separately.
///
/// Required environment variables:
///   VERIFIER_ADDRESS   — RISC Zero Groth16 verifier address on Base
///   IMAGE_ID           — Guest program image ID (bytes32 hex)
///   MERKLE_ROOT        — Merkle root of eligibility tree (bytes32 hex)
///
/// Optional environment variables:
///   PRIVATE_KEY (or ETH_WALLET_PRIVATE_KEY) — Deployer private key
contract Deploy is Script {
    function run() external {
        // Resolve deployer key (match DeployAll.s.sol interface)
        uint256 deployerKey;
        if (vm.envExists("PRIVATE_KEY")) {
            deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        } else {
            deployerKey = uint256(vm.envBytes32("ETH_WALLET_PRIVATE_KEY"));
        }

        address verifier = vm.envAddress("VERIFIER_ADDRESS");
        bytes32 imageId = vm.envBytes32("IMAGE_ID");
        bytes32 merkleRoot = vm.envBytes32("MERKLE_ROOT");

        // ── Predict airdrop address BEFORE startBroadcast ─────────────
        //
        // Foundry simulation deploys `new` contracts from the SCRIPT contract
        // address, but the real broadcast replays them from the DEPLOYER address.
        // Reading the nonce inside startBroadcast returns the SCRIPT's nonce
        // during simulation, not the deployer's on-chain nonce — causing
        // incorrect address prediction. We resolve the deployer address and
        // read its nonce before entering broadcast mode.
        //
        // Deployment order from deployer:
        //   nonce   → ZKMToken (minter = predicted airdrop)
        //   nonce+1 → ZKMAirdrop
        address deployer = vm.addr(deployerKey);
        uint256 deployerNonce = vm.getNonce(deployer);
        address predictedAirdrop = vm.computeCreateAddress(deployer, deployerNonce + 1);

        console.log("Deployer:", deployer);
        console.log("Deployer nonce:", deployerNonce);
        console.log("Predicted airdrop:", predictedAirdrop);

        vm.startBroadcast(deployerKey);

        // ── Step 1: Deploy ZKMToken with predicted minter ────────────────
        ZKMToken token = new ZKMToken(predictedAirdrop);
        console.log("ZKMToken deployed at:", address(token));
        console.log("Predicted airdrop address:", predictedAirdrop);

        // ── Step 2: Deploy airdrop ───────────────────────────────────────
        ZKMAirdrop airdrop = new ZKMAirdrop(address(token), verifier, imageId, merkleRoot);
        console.log("ZKMAirdrop deployed at:", address(airdrop));

        // NOTE: address(airdrop) in simulation != predictedAirdrop because
        // simulation deploys from the script contract. On real broadcast,
        // the addresses WILL match.
        require(token.minter() == predictedAirdrop, "Minter not set to predicted airdrop");

        console.log("Deployment complete!");
        console.log("  Token minter:", token.minter());
        console.log("  Merkle root:", vm.toString(merkleRoot));
        console.log("  Image ID:", vm.toString(imageId));
        console.log("  Claim amount: 10,000 ZKM");
        console.log("  Max claims: 1,000,000");
        console.log("  Claim deadline: 2027-01-01 00:00:00 UTC");
        console.log("");
        console.log("  NOTE: Simulated addresses differ from broadcast addresses.");
        console.log("  After broadcast, verify: token.minter() == airdrop address");

        vm.stopBroadcast();
    }
}
