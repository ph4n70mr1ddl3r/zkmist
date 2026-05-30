// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.sol";

/// @title Deploy — Deploy ZKMist contracts (Halo2-KZG)
/// @notice Deploys Halo2Verifier, ZKMToken, and ZKMAirdrop to Base.
///
/// Usage:
///   # Testnet (Base Sepolia):
///   forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC --broadcast
///
///   # Mainnet (Base):
///   forge script script/Deploy.s.sol --rpc-url $BASE_RPC --broadcast
///
/// Prerequisites:
///   1. Halo2Verifier.sol must be regenerated with snark-verifier:
///      cargo run --bin gen-verifier -- --output contracts/src/Halo2Verifier.sol
///   2. Verify IS_PRODUCTION_VERIFIER is true in the generated verifier
///   3. Deployer must have ETH on Base for gas (~$0.50 for all 3 contracts)
///
/// Safety checks:
///   - Verifier must be production-ready (IS_PRODUCTION_VERIFIER == true)
///   - Merkle root matches known eligibility tree root
///   - Chain ID must be 8453 (Base) or 84532 (Base Sepolia)
///   - Claim deadline must be in the future

contract Deploy is Script {
    // ── Configuration ────────────────────────────────────────────────────

    /// Merkle root of the eligibility tree.
    /// 64,116,228 qualified addresses, 26-level Poseidon, BN254.
    bytes32 constant MERKLE_ROOT = 0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    /// Expected claim deadline: 2027-01-01 00:00:00 UTC
    uint256 constant EXPECTED_CLAIM_DEADLINE = 1_798_761_600;

    /// Expected claim amount: 10,000 ZKM
    uint256 constant EXPECTED_CLAIM_AMOUNT = 10_000e18;

    /// Expected max claims: 1,000,000
    uint256 constant EXPECTED_MAX_CLAIMS = 1_000_000;

    // ── Deployment ───────────────────────────────────────────────────────

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // ── Pre-deployment validation ─────────────────────────────────
        console.log("=== ZKMist Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");

        // Validate chain
        require(block.chainid == 8453 || block.chainid == 84532, "Must deploy on Base (8453) or Base Sepolia (84532)");

        // Validate deadline is in the future
        require(block.timestamp < EXPECTED_CLAIM_DEADLINE, "Claim deadline has already passed");

        // ── Step 1: Deploy Halo2Verifier ──────────────────────────────
        console.log("Step 1: Deploying Halo2Verifier...");
        Halo2Verifier verifier = new Halo2Verifier();
        console.log("  Halo2Verifier:", address(verifier));
        console.log("  IS_PRODUCTION_VERIFIER:", verifier.IS_PRODUCTION_VERIFIER());
        console.log("  VK_HASH:", vm.toString(verifier.VK_HASH()));
        console.log("  K:", verifier.K());

        // SAFETY: Reject deployment with a non-production verifier
        require(
            verifier.IS_PRODUCTION_VERIFIER(),
            "ABORT: Halo2Verifier is not production-ready. Regenerate with snark-verifier."
        );

        // ── Step 2: Predict airdrop address ───────────────────────────
        uint256 nonce = vm.getNonce(deployer);
        // verifier at nonce, token at nonce+1, airdrop at nonce+2
        address predictedAirdrop = vm.computeCreateAddress(deployer, nonce + 2);
        console.log("");
        console.log("Step 2: Predicting addresses...");
        console.log("  Current nonce:", nonce);
        console.log("  Predicted airdrop:", predictedAirdrop);

        // ── Step 3: Deploy ZKMToken ──────────────────────────────────
        console.log("");
        console.log("Step 3: Deploying ZKMToken...");
        ZKMToken token = new ZKMToken(predictedAirdrop);
        console.log("  ZKMToken:", address(token));
        console.log("  Minter (predicted airdrop):", predictedAirdrop);
        console.log("  Max supply:", token.MAX_SUPPLY());
        require(token.minter() == predictedAirdrop, "Minter prediction failed");

        // ── Step 4: Deploy ZKMAirdrop ─────────────────────────────────
        console.log("");
        console.log("Step 4: Deploying ZKMAirdrop...");
        ZKMAirdrop airdrop = new ZKMAirdrop(address(token), address(verifier), MERKLE_ROOT);
        console.log("  ZKMAirdrop:", address(airdrop));

        // ── Post-deployment validation ────────────────────────────────
        console.log("");
        console.log("=== Post-deployment validation ===");

        // Verify minter matches actual airdrop address
        require(token.minter() == address(airdrop), "Minter mismatch");
        console.log("  [OK] Minter matches airdrop address");

        // Verify airdrop parameters
        require(airdrop.merkleRoot() == MERKLE_ROOT, "Root mismatch");
        console.log("  [OK] Merkle root matches");

        require(airdrop.CLAIM_AMOUNT() == EXPECTED_CLAIM_AMOUNT, "Claim amount mismatch");
        console.log("  [OK] Claim amount: 10,000 ZKM");

        require(airdrop.MAX_CLAIMS() == EXPECTED_MAX_CLAIMS, "Max claims mismatch");
        console.log("  [OK] Max claims: 1,000,000");

        require(airdrop.CLAIM_DEADLINE() == EXPECTED_CLAIM_DEADLINE, "Deadline mismatch");
        console.log("  [OK] Claim deadline: 2027-01-01 00:00:00 UTC");

        require(address(airdrop.token()) == address(token), "Token mismatch");
        console.log("  [OK] Token reference correct");

        require(address(airdrop.verifier()) == address(verifier), "Verifier mismatch");
        console.log("  [OK] Verifier reference correct");

        vm.stopBroadcast();

        // ── Summary ───────────────────────────────────────────────────
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Halo2Verifier: ", address(verifier));
        console.log("ZKMToken:      ", address(token));
        console.log("ZKMAirdrop:    ", address(airdrop));
        console.log("Chain:         %s", block.chainid == 8453 ? "Base (mainnet)" : "Base Sepolia (testnet)");
        console.log("");
        console.log("Next steps:");
        console.log("  1. Verify contracts on BaseScan:");
        console.log("     forge verify-contract <address> Halo2Verifier --chain base");
        console.log("     forge verify-contract <address> ZKMToken --chain base");
        console.log("     forge verify-contract <address> ZKMAirdrop --chain base");
        console.log("  2. Update cli/src/constants.rs:");
        console.log("     AIRDROP_CONTRACT = \"%s\"", address(airdrop));
        console.log("  3. Test claim on testnet first (if testnet)");
        console.log("  4. Generate a proof and submit to validate E2E");
    }
}
