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
    bytes32 constant DEFAULT_IMAGE_ID =
        0x05ef31c9fea9a30ee1902fc49a7aae3e48fce139ffc9b728858dee5b36423277;

    // Merkle root from the CLI's KNOWN_MERKLE_ROOT constant
    bytes32 constant DEFAULT_MERKLE_ROOT =
        0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

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

        vm.startBroadcast(deployerKey);

        // ── Step 1: Deploy RISC Zero Groth16 Verifier ────────────────────
        //
        // Uses the control root and BN254 control ID from risc0-ethereum's
        // auto-generated ControlID.sol (matched to the risc0-zkvm v3.0.5 crate).
        // This verifier accepts Groth16-compressed STARK proofs.
        //
        // Gas: ~6M gas (~$0.18 on Base)
        RiscZeroGroth16Verifier verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console.log("RiscZeroGroth16Verifier deployed at:", address(verifier));

        // ── Step 2: Deploy ZKMToken with predicted minter ────────────────
        //
        // Predict the airdrop address using CREATE address computation.
        // Nonces from deployer: 0=RiscZeroGroth16Verifier, 1=ZKMToken, 2=ZKMAirdrop
        uint256 deployerNonce = vm.getNonce(msg.sender);
        // After deploying verifier (nonce++), token will be at deployerNonce+1,
        // airdrop at deployerNonce+2. But we already deployed verifier above,
        // so current nonce is deployerNonce+1. Token is next (nonce+1), airdrop
        // is nonce+2.
        address predictedAirdrop = vm.computeCreateAddress(msg.sender, deployerNonce + 2);

        ZKMToken token = new ZKMToken(predictedAirdrop);
        console.log("ZKMToken deployed at:", address(token));
        console.log("Predicted airdrop address:", predictedAirdrop);

        // ── Step 3: Deploy ZKMAirdrop ────────────────────────────────────
        //
        // The airdrop contract is fully immutable. All parameters are set in
        // the constructor and cannot be changed after deployment.
        ZKMAirdrop airdrop =
            new ZKMAirdrop(address(token), address(verifier), imageId, merkleRoot);
        console.log("ZKMAirdrop deployed at:", address(airdrop));

        // ── Verify deployment correctness ────────────────────────────────
        require(address(airdrop) == predictedAirdrop, "Address prediction failed");
        require(token.minter() == address(airdrop), "Minter mismatch");

        console.log("");
        console.log("==================================================");
        console.log("  ZKMist Deployment Complete!");
        console.log("==================================================");
        console.log("  Verifier:      ", address(verifier));
        console.log("  Token:         ", address(token));
        console.log("  Airdrop:       ", address(airdrop));
        console.log("  Token minter:  ", token.minter());
        console.log("  Image ID:      ", vm.toString(imageId));
        console.log("  Merkle root:   ", vm.toString(merkleRoot));
        console.log("  Claim amount:  10,000 ZKM");
        console.log("  Max claims:    1,000,000");
        console.log("  Claim deadline: 2027-01-01 00:00:00 UTC");
        console.log("==================================================");
        console.log("");
        console.log("  WARNING:  Update AIRDROP_CONTRACT in cli/src/main.rs:");
        console.log("  const AIRDROP_CONTRACT: &str = \"", address(airdrop), "\";");

        vm.stopBroadcast();
    }
}
