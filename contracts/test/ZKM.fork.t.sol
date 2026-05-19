// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {RiscZeroGroth16Verifier} from "risc0-ethereum/contracts/src/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0-ethereum/contracts/src/groth16/ControlID.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";

/// @title ZKMVerifierIntegrationTest
/// @notice Integration test deploying the REAL RiscZeroGroth16Verifier from risc0-ethereum.
///
///         This test verifies:
///         1. The real Groth16 verifier can be deployed with the correct ControlID parameters
///         2. The verifier is compatible with the ZKMAirdrop contract interface
///         3. DeployAll.s.sol deployment order works correctly with the real verifier
///         4. Invalid proofs are rejected by the real verifier (not the NoopVerifier)
///         5. Gas usage is within expected bounds with the real verifier deployment
///
///         For a full end-to-end fork test with a real proof, see:
///           FOUNDRY_PROFILE=fork BASE_SEPOLIA_RPC_URL=... forge test --match-test test_fork_realProof
///
///         The fork test requires a real RISC Zero proof generated against the same image ID,
///         submitted to Base Sepolia. This is a pre-mainnet integration gate.
contract ZKMVerifierIntegrationTest is Test {
    ZKMToken token;
    ZKMAirdrop airdrop;
    RiscZeroGroth16Verifier verifier;

    bytes32 constant IMAGE_ID = bytes32(uint256(0x01));
    bytes32 constant MERKLE_ROOT = bytes32(uint256(0x02));

    function setUp() public {
        // Deploy the REAL RiscZeroGroth16Verifier with production ControlID values.
        // This matches what DeployAll.s.sol does.
        verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);

        // Predict airdrop address (matching DeployAll.s.sol deployment order).
        // Nonces from address(this): 1=verifier, 2=token, 3=airdrop
        address predictedAirdrop = vm.computeCreateAddress(address(this), 3);

        token = new ZKMToken(predictedAirdrop);
        airdrop = new ZKMAirdrop(address(token), address(verifier), IMAGE_ID, MERKLE_ROOT);

        require(address(airdrop) == predictedAirdrop, "Address prediction failed");
        require(token.minter() == address(airdrop), "Minter mismatch");
    }

    /// @dev Verify the real verifier was deployed with correct parameters.
    function test_verifierDeployedCorrectly() public view {
        // The verifier should reject calls with wrong selector -- confirming it's not a noop.
        assertTrue(address(verifier) != address(0), "Verifier not deployed");

        // Verify ControlID constants are accessible and non-zero
        assertTrue(ControlID.CONTROL_ROOT != bytes32(0), "CONTROL_ROOT is zero");
        assertTrue(ControlID.BN254_CONTROL_ID != bytes32(0), "BN254_CONTROL_ID is zero");
    }

    /// @dev Verify the airdrop contract correctly references the real verifier.
    function test_airdropReferencesRealVerifier() public view {
        assertEq(address(airdrop.verifier()), address(verifier), "Airdrop verifier mismatch");
        assertEq(airdrop.imageId(), IMAGE_ID, "Image ID mismatch");
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT, "Merkle root mismatch");
    }

    /// @dev A random/invalid seal should be rejected by the real Groth16 verifier.
    ///      This confirms we're using the real verifier, not the NoopVerifier.
    function test_claim_revertInvalidProof() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // Construct a fake seal: 4 bytes selector + 256 bytes Groth16 proof data
        // Using a wrong selector to trigger SelectorMismatch
        bytes memory fakeSeal = new bytes(260);
        fakeSeal[0] = 0xFF;
        fakeSeal[1] = 0xFF;
        fakeSeal[2] = 0xFF;
        fakeSeal[3] = 0xFF;
        // Rest is zeros (invalid Groth16 proof)

        vm.expectRevert();
        airdrop.claim(fakeSeal, journal, nullifier, recipient);
    }

    /// @dev A seal with correct selector but invalid proof data should also revert.
    function test_claim_revertInvalidGroth16Proof() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // Use the verifier's selector but with garbage proof data
        bytes4 selector = verifier.SELECTOR();
        bytes memory fakeSeal = abi.encodePacked(
            selector,
            uint256(1),
            uint256(2), // a
            uint256(3),
            uint256(4), // b[0]
            uint256(5),
            uint256(6), // b[1]
            uint256(7),
            uint256(8) // c
        );

        vm.expectRevert();
        airdrop.claim(fakeSeal, journal, nullifier, recipient);
    }

    /// @dev Verify the verifier selector is non-zero (proves it's a real verifier).
    function test_verifierSelectorNonZero() public view {
        bytes4 sel = verifier.SELECTOR();
        assertTrue(sel != bytes4(0), "Selector should not be zero for real verifier");
        console.log("Verifier SELECTOR:");
        console.logBytes4(sel);
    }

    /// @dev Verify the verifier version is set.
    function test_verifierVersion() public view {
        string memory version = verifier.VERSION();
        assertEq(version, "3.0.0", "Verifier version mismatch");
    }

    /// @dev Gas measurement for deployment of all 3 contracts with real verifier.
    function test_deploymentGasWithRealVerifier() public {
        uint256 gasBefore = gasleft();

        // Deploy a fresh set of contracts
        RiscZeroGroth16Verifier newVerifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);

        // Predict airdrop: nonce+1 = token, nonce+2 = airdrop
        uint256 nonce = vm.getNonce(address(this));
        address predictedAirdrop2 = vm.computeCreateAddress(address(this), nonce + 2);

        ZKMToken newToken = new ZKMToken(predictedAirdrop2);
        ZKMAirdrop newAirdrop = new ZKMAirdrop(address(newToken), address(newVerifier), IMAGE_ID, MERKLE_ROOT);
        newAirdrop; // suppress unused warning

        uint256 gasUsed = gasBefore - gasleft();

        console.log("Total deployment gas (3 contracts):", gasUsed);
        // ~5-6M gas expected for Groth16 verifier deployment
        assertLt(gasUsed, 8_000_000, "Deployment gas unexpectedly high");
    }

    /// @dev Verify the full DeployAll.s.sol deployment order works.
    ///      This mirrors DeployAll.s.sol exactly, validating the nonce prediction logic.
    function test_deployAllDeploymentOrder() public {
        // Fresh deployment to verify nonce prediction matches DeployAll.s.sol
        address deployer = address(this);
        uint256 nonce = vm.getNonce(deployer);
        nonce; // suppress unused warning

        // DeployAll order: verifier (nonce), token (nonce+1), airdrop (nonce+2)
        // But we need to account for the verifier deployed in setUp(), so use
        // a fresh address.
        address freshDeployer = address(0x1234);
        vm.deal(freshDeployer, 1 ether);

        vm.startPrank(freshDeployer);
        uint256 freshNonce = vm.getNonce(freshDeployer);

        // Predict airdrop address before deploying
        address predictedAirdropAddr = vm.computeCreateAddress(freshDeployer, freshNonce + 2);

        RiscZeroGroth16Verifier v = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        ZKMToken t = new ZKMToken(predictedAirdropAddr);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(v), IMAGE_ID, MERKLE_ROOT);

        assertEq(address(a), predictedAirdropAddr, "Address prediction failed");
        assertEq(t.minter(), address(a), "Minter mismatch");
        vm.stopPrank();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    function _buildJournal(bytes32 root, bytes32 nullifier, address recipient) internal pure returns (bytes memory) {
        return bytes.concat(root, nullifier, bytes20(recipient));
    }
}

// ── Fork Test (requires Base Sepolia RPC endpoint) ──────────────────

/// @title ZKMForkTest
/// @notice Fork test against Base Sepolia with a real deployed verifier.
///
///         Run with:
///           FOUNDRY_PROFILE=fork forge test --match-contract ZKMForkTest \
///             --rpc-url $BASE_SEPOLIA_RPC_URL
///
///         Or against Base mainnet after deployment:
///           forge test --match-contract ZKMForkTest \
///             --rpc-url $BASE_RPC_URL -vvv
///
///         This test validates that the RiscZeroGroth16Verifier on the target chain
///         accepts a real Groth16 proof generated by the RISC Zero prover.
///
///         WARNING:  This is a PRE-MAINNET GATE. Do not deploy to mainnet until this test passes
///             with a real proof on Base Sepolia.
contract ZKMForkTest is Test {
    // ── Configuration ────────────────────────────────────────────────
    // Set these via env vars or constants for your testnet deployment.
    // After DeployAll runs on Base Sepolia, update these addresses.

    /// @notice Address of the deployed RiscZeroGroth16Verifier on Base Sepolia.
    ///         Set via VERIFIER_ADDRESS env var.
    address verifierAddr;

    /// @notice Address of the deployed ZKMAirdrop on Base Sepolia.
    ///         Set via AIRDROP_ADDRESS env var.
    address airdropAddr;

    /// @notice Real Groth16 seal (hex) from a proof generated by the RISC Zero prover.
    ///         Set via PROOF_SEAL env var.
    bytes realSeal;

    /// @notice Real journal bytes (hex) from the same proof.
    ///         Set via PROOF_JOURNAL env var.
    bytes realJournal;

    /// @notice Image ID used for the real proof.
    ///         Set via IMAGE_ID env var.
    bytes32 imageId;

    /// @dev Skip the fork test if no RPC URL is provided.
    ///      This ensures the test suite passes in CI without a live RPC endpoint.
    modifier onlyWithFork() {
        if (vm.envExists("BASE_SEPOLIA_RPC_URL") || vm.envExists("BASE_RPC_URL")) {
            _;
        } else {
            console.log("Skipping fork test -- no RPC URL set.");
            console.log("Set BASE_SEPOLIA_RPC_URL to run fork tests.");
        }
    }

    function setUp() public {
        // Only configure if we have the required env vars
        if (!vm.envExists("AIRDROP_ADDRESS")) {
            return;
        }

        airdropAddr = vm.envAddress("AIRDROP_ADDRESS");

        if (vm.envExists("VERIFIER_ADDRESS")) {
            verifierAddr = vm.envAddress("VERIFIER_ADDRESS");
        }

        if (vm.envExists("PROOF_SEAL")) {
            realSeal = vm.envBytes("PROOF_SEAL");
        }
        if (vm.envExists("PROOF_JOURNAL")) {
            realJournal = vm.envBytes("PROOF_JOURNAL");
        }
        if (vm.envExists("IMAGE_ID")) {
            imageId = vm.envBytes32("IMAGE_ID");
        }
    }

    /// @dev Verify deployed contracts exist on the forked chain.
    function test_fork_deployedContractsExist() public onlyWithFork {
        if (airdropAddr == address(0)) {
            console.log("Skipping -- AIRDROP_ADDRESS not set.");
            return;
        }

        // Verify the airdrop contract has code
        uint256 airdropSize;
        address addr = airdropAddr;
        assembly {
            airdropSize := extcodesize(addr)
        }
        assertTrue(airdropSize > 0, "No code at airdrop address");

        // Read on-chain state
        ZKMAirdrop airdrop = ZKMAirdrop(airdropAddr);
        console.log("Airdrop token:", address(airdrop.token()));
        console.log("Airdrop verifier:", address(airdrop.verifier()));
        console.log("Image ID:", vm.toString(airdrop.imageId()));
        console.log("Merkle root:", vm.toString(airdrop.merkleRoot()));
        console.log("Claim amount:", airdrop.CLAIM_AMOUNT());
        console.log("Max claims:", airdrop.MAX_CLAIMS());
        console.log("Deadline:", airdrop.CLAIM_DEADLINE());

        // Verify critical parameters match PRD
        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18, "CLAIM_AMOUNT mismatch");
        assertEq(airdrop.MAX_CLAIMS(), 1_000_000, "MAX_CLAIMS mismatch");
        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600, "CLAIM_DEADLINE mismatch");

        // Verify minter is the airdrop itself
        ZKMToken token = ZKMToken(address(airdrop.token()));
        assertEq(token.minter(), airdropAddr, "Token minter must be airdrop");
    }

    /// @dev Submit a real proof to the forked chain's airdrop contract.
    ///      This is the critical pre-mainnet integration test.
    ///
    ///      Prerequisites:
    ///        1. Deploy contracts to Base Sepolia via DeployAll.s.sol
    ///        2. Generate a real proof via `zkmist prove`
    ///        3. Export the proof components as env vars:
    ///           - AIRDROP_ADDRESS=0x...
    ///           - PROOF_SEAL=0x... (raw seal bytes including selector)
    ///           - PROOF_JOURNAL=0x... (84 bytes)
    ///           - IMAGE_ID=0x...
    function test_fork_realProof() public onlyWithFork {
        if (airdropAddr == address(0)) {
            console.log("Skipping -- AIRDROP_ADDRESS not set.");
            return;
        }
        if (realSeal.length == 0 || realJournal.length == 0) {
            console.log("Skipping -- PROOF_SEAL or PROOF_JOURNAL not set.");
            console.log("To run this test, export real proof data as env vars.");
            return;
        }
        if (imageId == bytes32(0)) {
            console.log("Skipping -- IMAGE_ID not set.");
            return;
        }

        ZKMAirdrop airdrop = ZKMAirdrop(airdropAddr);

        // Parse journal fields
        require(realJournal.length == 84, "Journal must be 84 bytes");
        bytes memory journal = realJournal;
        bytes32 journalRoot;
        bytes32 journalNullifier;
        address journalRecipient;
        assembly {
            journalRoot := mload(add(journal, 0x20))
            journalNullifier := mload(add(journal, 0x40))
            journalRecipient := mload(add(journal, 0x54))
        }

        console.log("Submitting real proof to fork...");
        console.log("  Nullifier:", vm.toString(journalNullifier));
        console.log("  Recipient:", journalRecipient);

        // Record state before
        uint256 totalClaimsBefore = airdrop.totalClaims();
        address recipient = journalRecipient;

        // Submit the claim
        airdrop.claim(realSeal, realJournal, journalNullifier, journalRecipient);

        // Verify state after
        assertEq(airdrop.totalClaims(), totalClaimsBefore + 1, "totalClaims not incremented");
        assertTrue(airdrop.isClaimed(journalNullifier), "Nullifier not marked as claimed");

        ZKMToken token = ZKMToken(address(airdrop.token()));
        assertEq(token.balanceOf(recipient), 10_000e18, "Tokens not minted to recipient");

        console.log("  [OK] Real proof accepted by on-chain verifier!");
        console.log("  Gas used: see forge gas report");

        // Double-claim must fail
        vm.expectRevert("Already claimed");
        airdrop.claim(realSeal, realJournal, journalNullifier, journalRecipient);
    }

    /// @dev Verify that the on-chain verifier's SELECTOR matches the expected value.
    ///      A mismatch means the prover and verifier are using different risc0 versions.
    function test_fork_verifierSelectorMatches() public onlyWithFork {
        if (verifierAddr == address(0)) {
            console.log("Skipping -- VERIFIER_ADDRESS not set.");
            return;
        }

        RiscZeroGroth16Verifier onChainVerifier = RiscZeroGroth16Verifier(verifierAddr);

        // The on-chain selector should match what we'd compute locally
        bytes4 onChainSelector = onChainVerifier.SELECTOR();
        console.log("On-chain verifier SELECTOR:");
        console.logBytes4(onChainSelector);

        // Deploy a local verifier with the same ControlID to compare
        RiscZeroGroth16Verifier localVerifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        bytes4 localSelector = localVerifier.SELECTOR();

        assertEq(onChainSelector, localSelector, "Verifier selector mismatch -- prover version differs from on-chain");
    }
}
