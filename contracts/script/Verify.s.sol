// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";

/// @title Verify — Post-deployment verification script
/// @notice Reads on-chain state after deployment and asserts all critical invariants.
///         Run this after broadcasting DeployAll.s.sol to confirm the deployment is correct.
///
/// @dev Usage:
///      forge script script/Verify.s.sol --rpc-url $BASE_RPC_URL \
///          --etherscan-api-key $BASESCAN_API_KEY
///
///      Or with explicit addresses:
///      TOKEN=0x... AIRDROP=0x... forge script script/Verify.s.sol --rpc-url $BASE_RPC_URL
///
/// Required environment variables:
///   AIRDROP        — Deployed ZKMAirdrop contract address
///
/// Optional environment variables:
///   TOKEN          — Deployed ZKMToken contract address (read from airdrop if not set)
///   IMAGE_ID       — Expected guest program image ID (bytes32 hex). If set, verified on-chain.
///   MERKLE_ROOT    — Expected Merkle root (bytes32 hex). If set, verified on-chain.
contract Verify is Script {
    function run() external view {
        // ── Resolve addresses ─────────────────────────────────────────────
        address airdropAddr = vm.envAddress("AIRDROP");
        ZKMAirdrop airdrop = ZKMAirdrop(airdropAddr);

        // Read token address from airdrop (avoids needing a separate env var)
        ZKMToken token = ZKMToken(address(airdrop.token()));

        console.log("=== ZKMist Deployment Verification ===");
        console.log("");
        console.log("Airdrop:", address(airdrop));
        console.log("Token:  ", address(token));
        console.log("");

        // ── Verify ZKMToken ───────────────────────────────────────────────
        console.log("--- ZKMToken ---");

        assertEq(token.name(), "ZKMist", "Token name mismatch");
        assertEq(token.symbol(), "ZKM", "Token symbol mismatch");
        console.log("  [OK] name: ZKMist, symbol: ZKM");

        assertEq(token.MAX_SUPPLY(), 10_000_000_000e18, "MAX_SUPPLY mismatch");
        console.log("  [OK] MAX_SUPPLY: 10,000,000,000 ZKM");

        assertEq(token.totalSupply(), 0, "Initial supply must be 0");
        console.log("  [OK] Initial supply: 0");

        assertEq(token.minter(), address(airdrop), "Minter must be the airdrop contract");
        console.log("  [OK] Minter is airdrop contract");

        // ── Verify ZKMAirdrop ─────────────────────────────────────────────
        console.log("");
        console.log("--- ZKMAirdrop ---");

        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18, "CLAIM_AMOUNT mismatch");
        console.log("  [OK] CLAIM_AMOUNT: 10,000 ZKM");

        assertEq(airdrop.MAX_CLAIMS(), 1_000_000, "MAX_CLAIMS mismatch");
        console.log("  [OK] MAX_CLAIMS: 1,000,000");

        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600, "CLAIM_DEADLINE mismatch");
        console.log("  [OK] CLAIM_DEADLINE: 1798761600 (2027-01-01 00:00:00 UTC)");

        assertEq(airdrop.totalClaims(), 0, "totalClaims must start at 0");
        console.log("  [OK] totalClaims: 0");

        assertTrue(airdrop.isClaimWindowOpen(), "Claim window must be open at deployment");
        console.log("  [OK] Claim window: OPEN");

        assertEq(airdrop.claimsRemaining(), 1_000_000, "claimsRemaining must be MAX_CLAIMS");
        console.log("  [OK] claimsRemaining: 1,000,000");

        // ── Verify immutables ─────────────────────────────────────────────
        console.log("");
        console.log("--- Immutables ---");

        address verifier = address(airdrop.verifier());
        bytes32 onChainImageId = airdrop.imageId();
        bytes32 onChainMerkleRoot = airdrop.merkleRoot();

        assertTrue(verifier != address(0), "Verifier must not be zero address");
        console.log("  Verifier:   ", verifier);
        console.log("  Image ID:   ", vm.toString(onChainImageId));
        console.log("  Merkle root:", vm.toString(onChainMerkleRoot));

        // Cross-check against expected values if provided
        if (vm.envExists("IMAGE_ID")) {
            bytes32 expectedImageId = vm.envBytes32("IMAGE_ID");
            assertEq(onChainImageId, expectedImageId, "Image ID mismatch!");
            console.log("  [OK] Image ID matches expected value");
        } else {
            console.log("  [SKIP] IMAGE_ID not set — skipping image ID check");
        }

        if (vm.envExists("MERKLE_ROOT")) {
            bytes32 expectedRoot = vm.envBytes32("MERKLE_ROOT");
            assertEq(onChainMerkleRoot, expectedRoot, "Merkle root mismatch!");
            console.log("  [OK] Merkle root matches expected value");
        } else {
            console.log("  [SKIP] MERKLE_ROOT not set — skipping root check");
        }

        // ── Summary ───────────────────────────────────────────────────────
        console.log("");
        console.log("=== ALL CHECKS PASSED ===");
        console.log("");
        console.log("Update CLI constants in cli/src/constants.rs:");
        console.log("  AIRDROP_CONTRACT = \"%s\"", address(airdrop));
        console.log("  KNOWN_IMAGE_ID   = \"%s\"", vm.toString(onChainImageId));
        console.log("  KNOWN_MERKLE_ROOT = \"%s\"", vm.toString(onChainMerkleRoot));
    }
}
