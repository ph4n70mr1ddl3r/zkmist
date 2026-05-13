// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {NoopVerifier} from "./TestUtils.sol";

contract ZKMTokenTest is Test {
    ZKMToken token;
    address minter;

    function setUp() public {
        minter = address(0xA11CE);
        token = new ZKMToken(minter);
    }

    function test_name() public view {
        assertEq(token.name(), "ZKMist");
    }

    function test_symbol() public view {
        assertEq(token.symbol(), "ZKM");
    }

    function test_maxSupply() public view {
        assertEq(token.MAX_SUPPLY(), 10_000_000_000e18);
    }

    function test_initialSupply() public view {
        assertEq(token.totalSupply(), 0);
    }

    function test_minter() public view {
        assertEq(token.minter(), minter);
    }

    function test_mint() public {
        vm.prank(minter);
        token.mint(address(0xB0B), 10_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 10_000e18);
        assertEq(token.totalSupply(), 10_000e18);
    }

    function test_mint_revertNotMinter() public {
        vm.expectRevert("Only airdrop contract");
        token.mint(address(0xB0B), 10_000e18);
    }

    function test_mint_revertExceedsMaxSupply() public {
        vm.prank(minter);
        vm.expectRevert("Exceeds max supply");
        token.mint(address(0xB0B), 10_000_000_001e18);
    }

    function test_mint_upToMaxSupply() public {
        vm.prank(minter);
        token.mint(address(0xB0B), 10_000_000_000e18);
        assertEq(token.totalSupply(), token.MAX_SUPPLY());
    }

    function test_burn() public {
        vm.prank(minter);
        token.mint(address(this), 10_000e18);
        token.burn(5_000e18);
        assertEq(token.balanceOf(address(this)), 5_000e18);
        assertEq(token.totalSupply(), 5_000e18);
    }

    function test_burn_revertInsufficientBalance() public {
        vm.prank(minter);
        token.mint(address(this), 1_000e18);
        vm.expectRevert();
        token.burn(2_000e18);
    }

    function test_burnFrom() public {
        vm.prank(minter);
        token.mint(address(0xB0B), 10_000e18);

        vm.prank(address(0xB0B));
        token.approve(address(this), 5_000e18);

        token.burnFrom(address(0xB0B), 5_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 5_000e18);
        assertEq(token.totalSupply(), 5_000e18);
    }

    function test_burnFrom_revertInsufficientAllowance() public {
        vm.prank(minter);
        token.mint(address(0xB0B), 10_000e18);

        vm.expectRevert();
        token.burnFrom(address(0xB0B), 5_000e18);
    }

    function test_transfer() public {
        vm.prank(minter);
        token.mint(address(this), 10_000e18);
        token.transfer(address(0xB0B), 1_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 1_000e18);
    }

    function test_approveAndTransferFrom() public {
        vm.prank(minter);
        token.mint(address(this), 10_000e18);
        token.approve(address(0xB0B), 5_000e18);

        vm.prank(address(0xB0B));
        token.transferFrom(address(this), address(0xB0B), 5_000e18);
        assertEq(token.balanceOf(address(0xB0B)), 5_000e18);
    }
}

contract ZKMAirdropTest is Test {
    ZKMToken token;
    ZKMAirdrop airdrop;
    NoopVerifier verifier;

    bytes32 constant IMAGE_ID = bytes32(uint256(0x01));
    bytes32 constant MERKLE_ROOT = bytes32(uint256(0x02));

    function setUp() public {
        verifier = new NoopVerifier();

        // Predict the airdrop contract address.
        // Nonces from address(this): 1=NoopVerifier, 2=ZKMToken, 3=ZKMAirdrop
        address predictedAirdrop = vm.computeCreateAddress(address(this), 3);

        // Deploy token with predicted airdrop address as minter
        token = new ZKMToken(predictedAirdrop);

        // Deploy airdrop
        airdrop = new ZKMAirdrop(address(token), address(verifier), IMAGE_ID, MERKLE_ROOT);

        require(address(airdrop) == predictedAirdrop, "Address prediction failed");
        require(token.minter() == address(airdrop), "Minter mismatch");
    }

    /// @dev Build a valid 84-byte journal for the given claim parameters.
    function _buildJournal(bytes32 root, bytes32 nullifier, address recipient) internal pure returns (bytes memory) {
        return bytes.concat(root, nullifier, bytes20(recipient));
    }

    function test_constants() public view {
        assertEq(airdrop.CLAIM_AMOUNT(), 10_000e18);
        assertEq(airdrop.MAX_CLAIMS(), 1_000_000);
        assertEq(airdrop.CLAIM_DEADLINE(), 1_798_761_600);
        assertEq(airdrop.imageId(), IMAGE_ID);
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT);
    }

    function test_claim_success() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        airdrop.claim("", journal, nullifier, recipient);

        assertEq(token.balanceOf(recipient), 10_000e18);
        assertEq(airdrop.totalClaims(), 1);
        assertTrue(airdrop.isClaimed(nullifier));
    }

    function test_claim_multipleDifferentNullifiers() public {
        for (uint256 i = 1; i <= 5; i++) {
            bytes32 nullifier = bytes32(uint256(i));
            address recipient = address(uint160(i));
            bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
            airdrop.claim("", journal, nullifier, recipient);
        }
        assertEq(airdrop.totalClaims(), 5);
        assertEq(airdrop.claimsRemaining(), 999_995);
        assertEq(token.totalSupply(), 50_000e18);
    }

    function test_claim_revertDeadlineExpired() public {
        vm.warp(1_798_761_600); // exactly at deadline
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.expectRevert("Claim period ended");
        airdrop.claim("", journal, nullifier, recipient);
    }

    function test_claim_revertDeadlineBoundary() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // 1 second before deadline should work
        vm.warp(1_798_761_599);
        airdrop.claim("", journal, nullifier, recipient);
        assertEq(airdrop.totalClaims(), 1);
    }

    function test_claim_revertCapReached() public {
        // Set totalClaims to 1M via direct storage write (slot 0)
        vm.store(address(airdrop), bytes32(uint256(0)), bytes32(uint256(1_000_000)));

        bytes32 nullifier = bytes32(uint256(1_000_001));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.expectRevert("Claim cap reached");
        airdrop.claim("", journal, nullifier, recipient);
    }

    function test_claim_atCapBoundary() public {
        // Set totalClaims to 999,999
        vm.store(address(airdrop), bytes32(uint256(0)), bytes32(uint256(999_999)));

        // 1,000,000th claim should succeed
        bytes32 nullifier = bytes32(uint256(1_000_000));
        address recipient = address(uint160(1_000_000));
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
        airdrop.claim("", journal, nullifier, recipient);
        assertEq(airdrop.totalClaims(), 1_000_000);

        // 1,000,001st should fail
        bytes32 nullifier2 = bytes32(uint256(1_000_001));
        address recipient2 = address(uint160(1_000_001));
        bytes memory journal2 = _buildJournal(MERKLE_ROOT, nullifier2, recipient2);
        vm.expectRevert("Claim cap reached");
        airdrop.claim("", journal2, nullifier2, recipient2);
    }

    function test_claim_revertDoubleClaim() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        airdrop.claim("", journal, nullifier, recipient);

        // Second claim with same nullifier
        address recipient2 = address(0xCAFE);
        bytes memory journal2 = _buildJournal(MERKLE_ROOT, nullifier, recipient2);

        vm.expectRevert("Already claimed");
        airdrop.claim("", journal2, nullifier, recipient2);
    }

    function test_claim_revertZeroRecipient() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.expectRevert("Recipient cannot be zero address");
        airdrop.claim("", journal, nullifier, recipient);
    }

    function test_claim_revertInvalidJournalLength() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);

        // 96 bytes instead of 84
        bytes memory journal = bytes.concat(
            MERKLE_ROOT,
            nullifier,
            bytes32(uint256(0)), // extra 12 bytes
            bytes20(recipient)
        );

        vm.expectRevert("Invalid journal length");
        airdrop.claim("", journal, nullifier, recipient);
    }

    function test_claim_revertRootMismatch() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes32 wrongRoot = bytes32(uint256(0xFF));

        bytes memory journal = _buildJournal(wrongRoot, nullifier, recipient);

        vm.expectRevert("Root mismatch");
        airdrop.claim("", journal, nullifier, recipient);
    }

    function test_claim_revertNullifierMismatch() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        bytes32 wrongNullifier = bytes32(uint256(0x43));
        address recipient = address(0xB0B);

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.expectRevert("Nullifier mismatch");
        airdrop.claim("", journal, wrongNullifier, recipient);
    }

    function test_claim_revertRecipientMismatch() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        address wrongRecipient = address(0xCAFE);

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.expectRevert("Recipient mismatch");
        airdrop.claim("", journal, nullifier, wrongRecipient);
    }

    function test_isClaimWindowOpen() public view {
        assertTrue(airdrop.isClaimWindowOpen());
    }

    function test_isClaimWindowOpen_closedByTime() public {
        vm.warp(1_798_761_600);
        assertFalse(airdrop.isClaimWindowOpen());
    }

    function test_claimsRemaining() public view {
        assertEq(airdrop.claimsRemaining(), 1_000_000);
    }

    function test_anyoneCanSubmit() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // Submit from a different address than the recipient
        vm.prank(address(0xDEAD));
        airdrop.claim("", journal, nullifier, recipient);

        assertEq(token.balanceOf(recipient), 10_000e18);
    }

    function test_claim_event() public {
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);
        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // Claimed(nullifier indexed, amount, recipient indexed, totalClaims)
        // Check topics: topic0 (sig), topic1 (nullifier), topic2 (recipient)
        vm.expectEmit(true, true, true, true);
        emit ZKMAirdrop.Claimed(nullifier, 10_000e18, recipient, 1);
        airdrop.claim("", journal, nullifier, recipient);
    }
}
