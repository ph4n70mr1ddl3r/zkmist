// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMTokenV2} from "../src/ZKMTokenV2.sol";
import {ZKMAirdropV2} from "../src/ZKMAirdropV2.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.sol";

/// @title DeployV2 — Deploy ZKMist V2 contracts (Halo2-KZG)
/// @notice Deploys Halo2Verifier, ZKMTokenV2, and ZKMAirdropV2 to Base.
///
/// Usage:
///   forge script script/DeployV2.s.sol --rpc-url $BASE_RPC_URL --broadcast
///
/// Prerequisites:
///   1. Halo2Verifier.sol must be generated first via gen-verifier tool
///   2. Deployer must have ETH on Base for gas

// ── Step 1: Deploy the verifier separately ──────────────────────────────

contract DeployVerifier is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        Halo2Verifier verifier = new Halo2Verifier();
        console.log("Halo2Verifier deployed at:", address(verifier));
        console.log("  IS_PRODUCTION_VERIFIER:", verifier.IS_PRODUCTION_VERIFIER());
        console.log("  VK_HASH:", vm.toString(verifier.VK_HASH()));

        vm.stopBroadcast();

        console.log("");
        console.log("Set VERIFIER_ADDRESS in DeployV2 to: %s", address(verifier));
    }
}

// ── Step 2: Deploy token + airdrop (after verifier is deployed) ─────────

contract DeployV2 is Script {
    // ── Configuration ────────────────────────────────────────────────────

    /// Merkle root of the eligibility tree.
    bytes32 constant MERKLE_ROOT =
        0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    /// Halo2Verifier contract address — set after deploying with DeployVerifier.
    address constant VERIFIER_ADDRESS = address(0); // TODO: set after deploying Halo2Verifier

    // ── Deployment ───────────────────────────────────────────────────────

    function run() external {
        require(VERIFIER_ADDRESS != address(0), "Set VERIFIER_ADDRESS before deploying");

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        address deployer = vm.addr(deployerKey);
        uint256 nonce = vm.getNonce(deployer);

        // Predict airdrop address: token is deployed at nonce, airdrop at nonce+1
        address predictedAirdrop = vm.computeCreateAddress(deployer, nonce + 1);

        // Step 1: Deploy ZKMTokenV2 (minter = predicted airdrop address)
        ZKMTokenV2 token = new ZKMTokenV2(predictedAirdrop);
        console.log("ZKMTokenV2 deployed at:", address(token));
        console.log("  Minter (predicted airdrop):", predictedAirdrop);
        console.log("  Max supply:", token.MAX_SUPPLY());

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
        console.log("");
        console.log("Next steps:");
        console.log("  1. Verify contracts on BaseScan");
        console.log("  2. Test claim on Base Sepolia first");
        console.log("  3. Update cli/src/constants.rs with contract addresses");
    }
}
