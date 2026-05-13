// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {NoopVerifier} from "./TestUtils.sol";

/// @title ZKME2ETest
/// @notice End-to-end integration test simulating the full claim pipeline:
///         eligibility list → Merkle tree → proof generation → claim → mint.
///
///         Uses a NoopVerifier (real proofs require the RISC Zero zkVM).
///         Tests the complete data flow: address → leaf → tree → journal → contract.
contract ZKME2ETest is Test {
    // ── Test parameters ──────────────────────────────────────────────────
    // Small tree for testing: 4 levels, 16 leaves
    // Matches the Rust test_end_to_end_merkle_proof test in merkle-tree/src/lib.rs
    uint256 constant TEST_TREE_DEPTH = 4;

    // PRD test vector private key: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    // Derived address: 0xfcad0b19bb29d4674531d6f115237e16afce377c
    // Leaf hash:       0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9
    // Computed via Poseidon(1 input, t=2) over BN254.

    bytes32 constant IMAGE_ID = bytes32(uint256(0x01));

    // PRD test addresses
    address constant RECIPIENT = address(0xB0B);
    address constant PRD_ADDRESS = 0xFCAd0B19bB29D4674531d6f115237E16AfCE377c;

    // ── Deploy helper ────────────────────────────────────────────────────

    /// @notice Deploys a fresh set of test contracts with address prediction.
    /// @param _root The merkle root to use for the airdrop contract.
    /// @return testToken The deployed ZKMToken.
    /// @return testAirdrop The deployed ZKMAirdrop.
    function _deployTestSystem(bytes32 _root) internal returns (ZKMToken testToken, ZKMAirdrop testAirdrop) {
        uint256 nonceBefore = vm.getNonce(address(this));
        address predictedAirdrop = vm.computeCreateAddress(address(this), nonceBefore + 2);

        NoopVerifier testVerifier = new NoopVerifier();
        testToken = new ZKMToken(predictedAirdrop);
        testAirdrop = new ZKMAirdrop(address(testToken), address(testVerifier), IMAGE_ID, _root);

        require(address(testAirdrop) == predictedAirdrop, "Address prediction failed");
        require(testToken.minter() == address(testAirdrop), "Minter mismatch");
    }

    // ── E2E Test 1: Full claim flow with precomputed tree data ───────────
    //
    // Simulates the complete pipeline:
    // 1. Construct journal bytes (merkleRoot + nullifier + recipient)
    // 2. Submit claim to ZKMAirdrop contract
    // 3. Verify tokens minted correctly
    // 4. Verify nullifier prevents double-claim
    function test_e2e_fullClaimFlow() public {
        bytes32 testRoot = bytes32(uint256(0xDEAD));
        bytes32 testNullifier = bytes32(uint256(0xBEEF));
        address testRecipient = address(0xCAFE);

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Build journal
        bytes memory journal = _buildJournal(testRoot, testNullifier, testRecipient);

        // Verify journal layout
        assertEq(journal.length, 84);
        bytes32 jRoot;
        bytes32 jNullifier;
        address jRecipient;
        assembly {
            jRoot := mload(add(journal, 0x20))
            jNullifier := mload(add(journal, 0x40))
            jRecipient := mload(add(journal, 0x54))
        }
        assertEq(jRoot, testRoot);
        assertEq(jNullifier, testNullifier);
        assertEq(jRecipient, testRecipient);

        // Claim
        testAirdrop.claim("", journal, testNullifier, testRecipient);

        // Verify mint
        assertEq(testToken.balanceOf(testRecipient), 10_000e18);
        assertEq(testToken.totalSupply(), 10_000e18);
        assertTrue(testAirdrop.isClaimed(testNullifier));
        assertEq(testAirdrop.totalClaims(), 1);

        // Double-claim must fail
        vm.expectRevert("Already claimed");
        testAirdrop.claim("", journal, testNullifier, testRecipient);
    }

    // ── E2E Test 2: Multi-claim scenario ─────────────────────────────────
    function test_e2e_multipleClaimsBuildSupply() public {
        bytes32 testRoot = bytes32(uint256(0xABCD));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Claim 100 times
        uint256 numClaims = 100;
        for (uint256 i = 1; i <= numClaims; i++) {
            bytes32 nullifier = bytes32(uint256(i));
            address recipient = address(uint160(i));
            bytes memory journal = _buildJournal(testRoot, nullifier, recipient);
            testAirdrop.claim("", journal, nullifier, recipient);
        }

        assertEq(testAirdrop.totalClaims(), numClaims);
        assertEq(testAirdrop.claimsRemaining(), 1_000_000 - numClaims);
        assertEq(testToken.totalSupply(), numClaims * 10_000e18);
    }

    // ── E2E Test 3: Burn after claim ─────────────────────────────────────
    function test_e2e_claimThenBurn() public {
        bytes32 testRoot = bytes32(uint256(0xFACE));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Claim
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(testRoot, nullifier, recipient);
        testAirdrop.claim("", journal, nullifier, recipient);

        assertEq(testToken.balanceOf(recipient), 10_000e18);
        assertEq(testToken.totalSupply(), 10_000e18);

        // Burn half
        vm.prank(recipient);
        testToken.burn(5_000e18);

        assertEq(testToken.balanceOf(recipient), 5_000e18);
        assertEq(testToken.totalSupply(), 5_000e18); // supply decreased

        // Transfer remaining to another address
        vm.prank(recipient);
        testToken.transfer(address(0xCAFE), 5_000e18);

        assertEq(testToken.balanceOf(recipient), 0);
        assertEq(testToken.balanceOf(address(0xCAFE)), 5_000e18);
        assertEq(testToken.totalSupply(), 5_000e18); // unchanged by transfer
    }

    // ── E2E Test 4: Claim window boundary ────────────────────────────────
    function test_e2e_claimWindowCloses() public {
        bytes32 testRoot = bytes32(uint256(0xBEEF));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Claim before deadline
        assertTrue(testAirdrop.isClaimWindowOpen());
        bytes32 nullifier = bytes32(uint256(1));
        address recipient = address(1);
        bytes memory journal = _buildJournal(testRoot, nullifier, recipient);
        testAirdrop.claim("", journal, nullifier, recipient);

        // Warp past deadline: 2027-01-01 00:00:00 UTC
        vm.warp(1_798_761_600);
        assertFalse(testAirdrop.isClaimWindowOpen());

        // Claim should fail
        bytes32 nullifier2 = bytes32(uint256(2));
        address recipient2 = address(2);
        bytes memory journal2 = _buildJournal(testRoot, nullifier2, recipient2);
        vm.expectRevert("Claim period ended");
        testAirdrop.claim("", journal2, nullifier2, recipient2);
    }

    // ── E2E Test 5: Relayer submits for someone else ─────────────────────
    function test_e2e_relayerSubmitsForClaimant() public {
        bytes32 testRoot = bytes32(uint256(0x1234));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Relayer submits proof on behalf of claimant
        bytes32 nullifier = bytes32(uint256(0x42));
        address claimant = address(0xB0B);
        address relayer = address(0xDEAD);
        bytes memory journal = _buildJournal(testRoot, nullifier, claimant);

        vm.prank(relayer); // relayer submits, not the claimant
        testAirdrop.claim("", journal, nullifier, claimant);

        // Tokens go to the claimant, not the relayer
        assertEq(testToken.balanceOf(claimant), 10_000e18);
        assertEq(testToken.balanceOf(relayer), 0);
    }

    // ── E2E Test 6: Max supply cap ───────────────────────────────────────
    function test_e2e_maxSupplyCap() public {
        bytes32 testRoot = bytes32(uint256(0x5678));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        // Simulate 999,999 claims
        vm.store(address(testAirdrop), bytes32(uint256(0)), bytes32(uint256(999_999)));

        // 1,000,000th claim succeeds
        bytes32 nullifier = bytes32(uint256(1_000_000));
        address recipient = address(uint160(1_000_000));
        bytes memory journal = _buildJournal(testRoot, nullifier, recipient);
        testAirdrop.claim("", journal, nullifier, recipient);
        assertEq(testAirdrop.totalClaims(), 1_000_000);

        // 1,000,001st fails
        bytes32 nullifier2 = bytes32(uint256(1_000_001));
        address recipient2 = address(uint160(1_000_001));
        bytes memory journal2 = _buildJournal(testRoot, nullifier2, recipient2);
        vm.expectRevert("Claim cap reached");
        testAirdrop.claim("", journal2, nullifier2, recipient2);
    }

    // ── E2E Test 7: Journal tampering detection ──────────────────────────
    function test_e2e_journalTamperingDetected() public {
        bytes32 testRoot = bytes32(uint256(0x9ABC));

        (ZKMToken testToken, ZKMAirdrop testAirdrop) = _deployTestSystem(testRoot);

        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);

        // Tampered root in journal
        bytes memory badJournal1 = _buildJournal(bytes32(uint256(0xBAD)), nullifier, recipient);
        vm.expectRevert("Root mismatch");
        testAirdrop.claim("", badJournal1, nullifier, recipient);

        // Tampered nullifier in journal
        bytes memory badJournal2 = _buildJournal(testRoot, bytes32(uint256(0xBAD)), recipient);
        vm.expectRevert("Nullifier mismatch");
        testAirdrop.claim("", badJournal2, nullifier, recipient);

        // Tampered recipient in journal
        bytes memory badJournal3 = _buildJournal(testRoot, nullifier, address(0xBAD));
        vm.expectRevert("Recipient mismatch");
        testAirdrop.claim("", badJournal3, nullifier, recipient);

        // Valid journal works
        bytes memory goodJournal = _buildJournal(testRoot, nullifier, recipient);
        testAirdrop.claim("", goodJournal, nullifier, recipient);
        assertEq(testToken.balanceOf(recipient), 10_000e18);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    function _buildJournal(bytes32 root, bytes32 nullifier, address recipient) internal pure returns (bytes memory) {
        return bytes.concat(root, nullifier, bytes20(recipient));
    }
}
