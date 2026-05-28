// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMTokenV2} from "../src/ZKMTokenV2.sol";
import {ZKMAirdropV2} from "../src/ZKMAirdropV2.sol";

/// @title DeployV2 — Deploy ZKMist V2 contracts (Halo2-KZG)
/// @notice Deploys ZKMTokenV2, Halo2Verifier, and ZKMAirdropV2 to Base.
///
/// Usage:
///   forge script script/DeployV2.s.sol --rpc-url $BASE_RPC_URL --broadcast
///
/// Prerequisites:
///   1. Halo2Verifier.sol must be generated first via gen-verifier tool
///   2. Deployer must have ETH on Base for gas
contract DeployV2 is Script {
    // ── Configuration ────────────────────────────────────────────────────

    /// Merkle root of the eligibility tree.
    bytes32 constant MERKLE_ROOT =
        0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    /// Halo2Verifier contract address (deploy separately, then set here).
    /// Generate with: cargo run --bin gen-verifier
    address constant VERIFIER_ADDRESS = address(0); // TODO: set after deploying Halo2Verifier

    // ── Deployment ───────────────────────────────────────────────────────

    function run() external {
        require(VERIFIER_ADDRESS != address(0), "Set VERIFIER_ADDRESS before deploying");

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        // Step 1: Deploy ZKMTokenV2
        // The minter will be set to the predicted airdrop address.
        // With CREATE, if deployer nonce is N, token is at nonce N,
        // and airdrop is at nonce N+1 (or use CREATE2 for exact prediction).
        address deployer = vm.addr(deployerKey);
        address predictedAirdrop = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);

        ZKMTokenV2 token = new ZKMTokenV2(predictedAirdrop);
        console.log("ZKMTokenV2 deployed at:", address(token));
        console.log("  Minter (predicted airdrop):", predictedAirdrop);

        // Step 2: Deploy ZKMAirdropV2
        ZKMAirdropV2 airdrop = new ZKMAirdropV2(
            address(token),
            VERIFIER_ADDRESS,
            MERKLE_ROOT
        );
        console.log("ZKMAirdropV2 deployed at:", address(airdrop));
        console.log("  Token:", address(airdrop.token()));
        console.log("  Verifier:", address(airdrop.verifier()));
        console.log("  MerkleRoot:", vm.toString(airdrop.merkleRoot()));
        console.log("  ClaimAmount:", airdrop.CLAIM_AMOUNT());
        console.log("  MaxClaims:", airdrop.MAX_CLAIMS());
        console.log("  ClaimDeadline:", airdrop.CLAIM_DEADLINE());

        // Verify minter matches
        require(token.minter() == address(airdrop), "Minter mismatch");
        console.log("  [OK] Minter matches airdrop address");

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("ZKMTokenV2:    ", address(token));
        console.log("ZKMAirdropV2:  ", address(airdrop));
        console.log("Halo2Verifier: ", VERIFIER_ADDRESS);
        console.log("Chain:         Base (8453)");
    }
}

/// @title DeployVerifier — Deploy only the Halo2Verifier contract
/// @notice Deploy this first, then set VERIFIER_ADDRESS in DeployV2.
contract DeployVerifier is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        // TODO: Import and deploy Halo2Verifier.sol
        // This will be auto-generated from the circuit verification key.
        // Halo2Verifier verifier = new Halo2Verifier();
        // console.log("Halo2Verifier deployed at:", address(verifier));

        console.log("TODO: Deploy Halo2Verifier after generating from VK");
        console.log("Run: cargo run --bin gen-verifier -- --vk <vk_file> --output contracts/src/Halo2Verifier.sol");

        vm.stopBroadcast();
    }
}
