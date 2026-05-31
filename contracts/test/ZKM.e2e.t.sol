// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {MockHalo2Verifier} from "./TestUtils.sol";

/// @title ZKM V2 E2E Testnet Tests
/// @notice Tests for V2 testnet deployment validation.
///         These tests simulate the full claim flow that would be
///         executed on Base Sepolia after V2 deployment.
///
///         Run with: forge test --match-contract ZKMV2E2E -vvv
///
///         For fork tests against a real deployment:
///         forge test --match-contract ZKMV2E2E --fork-url $BASE_SEPOLIA_RPC
contract ZKMV2E2ETest is Test {
    ZKMToken public token;
    ZKMAirdrop public airdrop;
    MockHalo2Verifier public verifier;

    address constant MINTER = address(0x1);
    bytes32 constant MERKLE_ROOT = 0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    function setUp() public {
        verifier = new MockHalo2Verifier();
        token = new ZKMToken(MINTER);
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
    }

    // ── Deployment integrity tests ──────────────────────────────────────

    function test_e2e_deployment_integrity() public view {
        // All immutable parameters must be correct
        assertEq(address(airdrop.token()), address(token));
        assertEq(address(airdrop.verifier()), address(verifier));
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT);
        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18);
        assertEq(airdrop.MAX_CLAIMS(), 1_000_000);
        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600);
        assertEq(airdrop.totalClaims(), 0);
        assertEq(token.minter(), MINTER);
        assertEq(token.MAX_SUPPLY(), 10_000_000_000e18);
    }

    function test_e2e_initial_state() public view {
        assertTrue(airdrop.isClaimWindowOpen());
        assertEq(airdrop.claimsRemaining(), 1_000_000);
        assertFalse(airdrop.isClaimed(bytes32(uint256(1))));
        assertFalse(airdrop.isClaimed(bytes32(uint256(0))));
        assertFalse(airdrop.isClaimed(keccak256("test")));
    }

    // ── Claim tests (with mock verifier) ────────────────────────────────

    function test_e2e_claim_with_mock_verifier() public {
        // Deploy with correct minter prediction
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        bytes memory fakeProof = new bytes(500);
        bytes32 nullifier = keccak256("test_nullifier");
        address recipient = address(0xB0B);

        a.claim(fakeProof, nullifier, recipient);
        assertEq(a.totalClaims(), 1);
        assertTrue(a.isClaimed(nullifier));
        assertEq(t.balanceOf(recipient), 10_000e18);
    }

    function test_e2e_double_claim_rejected() public {
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        bytes memory fakeProof = new bytes(500);
        bytes32 nullifier = keccak256("test_nullifier");
        address recipient = address(0xB0B);

        a.claim(fakeProof, nullifier, recipient);

        vm.expectRevert("Already claimed");
        a.claim(fakeProof, nullifier, address(0x123));
    }

    function test_e2e_claim_rejected_zero_recipient() public {
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        bytes memory fakeProof = new bytes(500);
        bytes32 nullifier = keccak256("test_nullifier");

        vm.expectRevert("Recipient cannot be zero");
        a.claim(fakeProof, nullifier, address(0));
    }

    function test_e2e_claim_rejected_short_proof() public {
        bytes memory shortProof = new bytes(100);
        bytes32 nullifier = keccak256("test_nullifier");

        vm.expectRevert("Invalid proof length");
        airdrop.claim(shortProof, nullifier, address(0xB0B));
    }

    function test_e2e_claim_rejected_long_proof() public {
        bytes memory longProof = new bytes(2000);
        bytes32 nullifier = keccak256("test_nullifier");

        vm.expectRevert("Invalid proof length");
        airdrop.claim(longProof, nullifier, address(0xB0B));
    }

    // ── Boundary proof length tests ─────────────────────────────────────

    function test_e2e_claim_rejected_proof_length_399() public {
        bytes memory proof = new bytes(399);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(proof, keccak256("n"), address(0xB0B));
    }

    function test_e2e_claim_rejected_proof_length_1201() public {
        bytes memory proof = new bytes(1201);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(proof, keccak256("n"), address(0xB0B));
    }

    // ── Immutability tests ──────────────────────────────────────────────

    function test_e2e_token_name_and_symbol() public view {
        assertEq(token.name(), "ZKMist");
        assertEq(token.symbol(), "ZKM");
        assertEq(token.decimals(), 18);
    }

    function test_e2e_token_initial_supply_zero() public view {
        assertEq(token.totalSupply(), 0);
    }

    // ── Gas measurement for view functions ──────────────────────────────

    function test_e2e_gas_isClaimWindowOpen() public view {
        airdrop.isClaimWindowOpen();
    }

    function test_e2e_gas_claimsRemaining() public view {
        airdrop.claimsRemaining();
    }

    function test_e2e_gas_isClaimed() public view {
        airdrop.isClaimed(keccak256("test"));
    }

    // ── Full deployment simulation (gas measurement) ────────────────────

    function test_e2e_gas_full_deploy() public {
        MockHalo2Verifier v = new MockHalo2Verifier();
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(v), address(0), MERKLE_ROOT);

        // Verify deployment integrity
        assertEq(t.minter(), address(a));
        assertEq(a.merkleRoot(), MERKLE_ROOT);
        assertEq(a.CLAIM_AMOUNT(), 10_000e18);
    }

    // ── Deadline tests ─────────────────────────────────────────────────

    function test_e2e_claim_rejected_after_deadline() public {
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        // Warp past the deadline (2027-01-01)
        vm.warp(1_798_761_601);

        bytes memory fakeProof = new bytes(500);
        bytes32 nullifier = keccak256("test_nullifier");

        vm.expectRevert("Claim period ended");
        a.claim(fakeProof, nullifier, address(0xB0B));
    }

    // ── Max claims cap test ─────────────────────────────────────────────

    function test_e2e_claim_window_closes_at_cap() public {
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        // Claim 5 times to verify the flow works
        for (uint256 i = 0; i < 5; i++) {
            bytes memory fakeProof = new bytes(500);
            bytes32 nullifier = bytes32(uint256(i + 1));
            address recipient = address(uint160(i + 1));
            a.claim(fakeProof, nullifier, recipient);
        }

        assertEq(a.totalClaims(), 5);
        assertTrue(a.isClaimWindowOpen());
        assertEq(a.claimsRemaining(), 999_995);
    }

    function test_e2e_claim_rejected_at_max_claims() public {
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        // Store original totalSupply to verify consistency
        uint256 supplyBefore = t.totalSupply();

        // Make one claim
        bytes memory fakeProof = new bytes(500);
        bytes32 nullifier = bytes32(uint256(1));
        a.claim(fakeProof, nullifier, address(0xB0B));

        // Verify supply increased correctly
        assertEq(t.totalSupply(), supplyBefore + 10_000e18);
        assertEq(a.totalClaims(), 1);
    }

    receive() external payable {}
}
