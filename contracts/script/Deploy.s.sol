// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";

/// @notice Deploy ZKMist contracts to Base.
/// @dev Usage: forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast
///
/// Required environment variables:
///   VERIFIER_ADDRESS   — RISC Zero Groth16 verifier address on Base
///   IMAGE_ID           — Guest program image ID (bytes32 hex)
///   MERKLE_ROOT        — Merkle root of eligibility tree (bytes32 hex)
contract Deploy is Script {
    function run() external {
        address verifier = vm.envAddress("VERIFIER_ADDRESS");
        bytes32 imageId = vm.envBytes32("IMAGE_ID");
        bytes32 merkleRoot = vm.envBytes32("MERKLE_ROOT");

        vm.startBroadcast();

        // Deploy token with address(0) as temporary minter, then deploy airdrop,
        // then redeploy token with correct airdrop minter.
        // Alternative: deploy token, then airdrop, then the token constructor needs
        // the airdrop address. Use CREATE to predict airdrop address.
        //
        // Simplest: two-step deploy (token first, then airdrop), but minter must
        // be set correctly. Since minter is immutable, we need the airdrop address
        // at token deploy time.
        //
        // Solution: predict CREATE address based on deployer nonce.

        // Step 1: Deploy token with predicted airdrop address as minter
        uint256 deployerNonce = vm.getNonce(msg.sender);
        address predictedAirdrop = vm.computeCreateAddress(msg.sender, deployerNonce + 1);

        ZKMToken token = new ZKMToken(predictedAirdrop);
        console.log("ZKMToken deployed at:", address(token));
        console.log("Predicted airdrop address:", predictedAirdrop);

        // Step 2: Deploy airdrop
        ZKMAirdrop airdrop = new ZKMAirdrop(address(token), verifier, imageId, merkleRoot);
        console.log("ZKMAirdrop deployed at:", address(airdrop));

        require(address(airdrop) == predictedAirdrop, "Address prediction failed");
        require(token.minter() == address(airdrop), "Minter mismatch");

        console.log("Deployment complete!");
        console.log("  Token minter:", token.minter());
        console.log("  Merkle root:", vm.toString(merkleRoot));
        console.log("  Image ID:", vm.toString(imageId));
        console.log("  Claim amount: 10,000 ZKM");
        console.log("  Max claims: 1,000,000");
        console.log("  Claim deadline: 2027-01-01 00:00:00 UTC");

        vm.stopBroadcast();
    }
}
