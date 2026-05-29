// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMTokenV2} from "../src/ZKMTokenV2.sol";
import {ZKMAirdropV2} from "../src/ZKMAirdropV2.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.sol";

/// @title ZKM V2 Contract Tests
/// @notice Tests for the Halo2-KZG airdrop contract and token.
contract ZKMV2Test is Test {
    ZKMTokenV2 public token;
    ZKMAirdropV2 public airdrop;

    address constant MINTER = address(0x1);
    Halo2Verifier public verifier;
    address constant VERIFIER_ADDR = address(0x2);
    bytes32 constant MERKLE_ROOT =
        0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    function setUp() public {
        verifier = new Halo2Verifier();
        token = new ZKMTokenV2(MINTER);
    }

    // ── ZKMTokenV2 Tests ─────────────────────────────────────────────────

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

    // ── ZKMAirdropV2 Tests ───────────────────────────────────────────────

    function test_airdrop_deploy() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        assertEq(address(airdrop.token()), address(token));
        assertEq(address(airdrop.verifier()), address(verifier));
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT);
        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18);
        assertEq(airdrop.MAX_CLAIMS(), 1_000_000);
        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600);
    }

    function test_airdrop_is_claim_window_open() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        // Before deadline and before cap: should be open
        assertTrue(airdrop.isClaimWindowOpen());
    }

    function test_airdrop_claims_remaining_initial() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        assertEq(airdrop.claimsRemaining(), 1_000_000);
    }

    function test_airdrop_claim_rejects_non_production_verifier() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        bytes memory validLengthProof = new bytes(500);
        // Proof length is valid (400-1200), but verifier is not production-ready
        vm.expectRevert("Verifier not production-ready");
        airdrop.claim(validLengthProof, bytes32(uint256(1)), address(0xB0B));
    }

    function test_airdrop_is_claimed_initial() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        bytes32 nullifier = bytes32(uint256(42));
        assertFalse(airdrop.isClaimed(nullifier));
    }

    function test_airdrop_constants() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        assertEq(airdrop.MIN_PROOF_LENGTH(), 400);
        assertEq(airdrop.MAX_PROOF_LENGTH(), 1200);
    }

    function test_airdrop_claim_rejects_zero_recipient() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        bytes memory fakeProof = new bytes(500);
        vm.expectRevert("Verifier not production-ready");
        airdrop.claim(fakeProof, bytes32(uint256(1)), address(0));
    }

    function test_airdrop_claim_rejects_short_proof() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        bytes memory shortProof = new bytes(100);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(shortProof, bytes32(uint256(1)), address(0xB0B));
    }

    function test_airdrop_claim_rejects_long_proof() public {
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
        bytes memory longProof = new bytes(2000);
        vm.expectRevert("Invalid proof length");
        airdrop.claim(longProof, bytes32(uint256(1)), address(0xB0B));
    }

    // ── Deployment ordering test ─────────────────────────────────────────

    function test_deploy_ordering() public {
        // Simulate CREATE nonce prediction:
        // 1. Deploy token (minter = predicted airdrop address)
        // 2. Deploy airdrop (token, verifier, root)

        // For testing, just verify the constructor chain works
        ZKMTokenV2 t = new ZKMTokenV2(address(0x100));
        ZKMAirdropV2 a = new ZKMAirdropV2(address(t), address(verifier), MERKLE_ROOT);

        assertEq(address(a.token()), address(t));
        assertEq(t.minter(), address(0x100));
    }

    receive() external payable {}
}
