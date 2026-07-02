// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.sol";
import {MockHalo2Verifier} from "./TestUtils.sol";

/// @title ZKM V2 Contract Tests
/// @notice Tests for the Halo2-KZG airdrop contract and token.
contract ZKMV2Test is Test {
    ZKMToken public token;
    ZKMAirdrop public airdrop;

    address constant MINTER = address(0x1);
    MockHalo2Verifier public verifier;
    address constant VERIFIER_ADDR = address(0x2);
    bytes32 constant MERKLE_ROOT = 0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    function setUp() public {
        verifier = new MockHalo2Verifier();
        token = new ZKMToken(MINTER);
    }

    // ── ZKMToken Tests ─────────────────────────────────────────────────

    function test_token_name() public view {
        assertEq(token.name(), "ZKMist");
        assertEq(token.symbol(), "ZKM");
    }

    function test_token_max_supply() public view {
        assertEq(token.MAX_SUPPLY(), 10_000_000_000e18);
    }

    function test_token_minter_is_immutable() public view {
        assertEq(token.minter(), MINTER);
    }

    function test_token_mint_by_minter() public {
        vm.prank(MINTER);
        token.mint(address(0xB0B), 10_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 10_000e18);
        assertEq(token.totalSupply(), 10_000e18);
    }

    function test_token_mint_rejects_non_minter() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("Only airdrop contract");
        token.mint(address(0xB0B), 10_000e18);
    }

    function test_token_mint_rejects_zero_recipient() public {
        vm.prank(MINTER);
        vm.expectRevert("Mint to zero address");
        token.mint(address(0), 10_000e18);
    }

    function test_token_mint_rejects_zero_amount() public {
        vm.prank(MINTER);
        vm.expectRevert("Amount must be positive");
        token.mint(address(0xB0B), 0);
    }

    function test_token_mint_rejects_exceeds_max_supply() public {
        vm.prank(MINTER);
        vm.expectRevert("Exceeds max supply");
        token.mint(address(0xB0B), 10_000_000_001e18);
    }

    function test_token_burn() public {
        vm.prank(MINTER);
        token.mint(address(this), 10_000e18);
        token.burn(5_000e18);
        assertEq(token.balanceOf(address(this)), 5_000e18);
        assertEq(token.totalSupply(), 5_000e18);
    }

    function test_token_burnFrom() public {
        vm.prank(MINTER);
        token.mint(address(0xB0B), 10_000e18);

        vm.prank(address(0xB0B));
        token.approve(address(this), 5_000e18);

        token.burnFrom(address(0xB0B), 5_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 5_000e18);
    }

    // ── ZKMAirdrop Tests ───────────────────────────────────────────────

    function test_airdrop_deploy() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        assertEq(address(airdrop.token()), address(token));
        assertEq(address(airdrop.verifier()), address(verifier));
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT);
        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18);
        assertEq(airdrop.MAX_CLAIMS(), 1_000_000);
        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600);
    }

    function test_airdrop_deploy_with_production_verifier() public {
        // Deploy with the production Halo2Verifier (from halo2-solidity-verifier).
        // The production verifier always performs real KZG pairing verification.
        Halo2Verifier prodVerifier = new Halo2Verifier();
        ZKMAirdrop a = new ZKMAirdrop(address(token), address(prodVerifier), address(0), MERKLE_ROOT);
        assertEq(address(a.verifier()), address(prodVerifier));
    }

    function test_airdrop_is_claim_window_open() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        // Before deadline and before cap: should be open
        assertTrue(airdrop.isClaimWindowOpen());
    }

    function test_airdrop_claims_remaining_initial() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        assertEq(airdrop.claimsRemaining(), 1_000_000);
    }

    function test_airdrop_claim_with_mock_verifier() public {
        // Deploy with correct minter prediction
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMToken t = new ZKMToken(predictedAirdrop);
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        bytes memory validLengthProof = new bytes(5888);
        bytes32 nullifier = bytes32(uint256(1));
        address recipient = address(0xB0B);

        // Mock verifier returns true for structurally valid proofs.
        // With a production verifier, only cryptographically valid proofs pass.
        a.claim(validLengthProof, nullifier, recipient);
        assertEq(a.totalClaims(), 1);
        assertTrue(a.isClaimed(nullifier));
        assertEq(t.balanceOf(recipient), 10_000e18);
    }

    function test_airdrop_is_claimed_initial() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        bytes32 nullifier = bytes32(uint256(42));
        assertFalse(airdrop.isClaimed(nullifier));
    }

    function test_airdrop_constants() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        assertEq(airdrop.PROOF_LENGTH(), 5888);
    }

    function test_airdrop_claim_rejects_zero_recipient() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        bytes memory fakeProof = new bytes(5888);
        vm.expectRevert("Recipient cannot be zero");
        airdrop.claim(fakeProof, bytes32(uint256(1)), address(0));
    }

    function test_airdrop_claim_rejects_short_proof() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        bytes memory shortProof = new bytes(100);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(shortProof, bytes32(uint256(1)), address(0xB0B));
    }

    function test_airdrop_claim_rejects_long_proof() public {
        airdrop = new ZKMAirdrop(address(token), address(verifier), address(0), MERKLE_ROOT);
        // Exactly one byte longer than PROOF_LENGTH must still be rejected.
        // Derive the boundary from the contract's own constant so this stays
        // correct if PROOF_LENGTH ever changes — a prior revision hardcoded
        // 5633, a stale value from the old 0x1600 (= 5632) proof length. It
        // happened to differ from the current PROOF_LENGTH (5888 = 0x1700),
        // so the test passed WITHOUT actually exercising the boundary: a
        // regression that flipped PROOF_LENGTH back to 5632 would not have
        // been caught. PROOF_LENGTH()-based values test the true ±1 boundary.
        bytes memory longProof = new bytes(airdrop.PROOF_LENGTH() + 1);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(longProof, bytes32(uint256(1)), address(0xB0B));
    }

    // ── Deployment ordering test ─────────────────────────────────────────

    function test_deploy_ordering() public {
        // Simulate CREATE nonce prediction:
        // 1. Deploy token (minter = predicted airdrop address)
        // 2. Deploy airdrop (token, verifier, root)

        // For testing, just verify the constructor chain works
        ZKMToken t = new ZKMToken(address(0x100));
        ZKMAirdrop a = new ZKMAirdrop(address(t), address(verifier), address(0), MERKLE_ROOT);

        assertEq(address(a.token()), address(t));
        assertEq(t.minter(), address(0x100));
    }

    receive() external payable {}
}
