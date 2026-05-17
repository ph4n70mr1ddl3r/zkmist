// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {NoopVerifier} from "./TestUtils.sol";

/// @title ZKMFuzzTest
/// @notice Fuzz tests for ZKMToken and ZKMAirdrop contracts.
///         Uses random inputs to verify invariants and boundary conditions.
contract ZKMTokenFuzzTest is Test {
    ZKMToken token;
    address minter;

    function setUp() public {
        minter = address(0xA11CE);
        token = new ZKMToken(minter);
    }

    // ── Mint + Burn supply invariant ──────────────────────────────────

    /// @notice Total supply must always equal sum of all balances.
    ///         Fuzzed mint and burn amounts across multiple accounts.
    function testFuzz_supplyEqualsBalances(uint256 mintAmount, uint256 burnAmount, address to) public {
        // Bound mint amount to max supply
        mintAmount = bound(mintAmount, 1, token.MAX_SUPPLY());
        // Burn amount must not exceed minted amount
        burnAmount = bound(burnAmount, 0, mintAmount);
        // Avoid zero address
        vm.assume(to != address(0));

        vm.prank(minter);
        token.mint(to, mintAmount);
        assertEq(token.totalSupply(), mintAmount);
        assertEq(token.balanceOf(to), mintAmount);

        if (burnAmount > 0) {
            vm.prank(to);
            token.burn(burnAmount);
        }

        assertEq(token.totalSupply(), mintAmount - burnAmount);
        assertEq(token.balanceOf(to), mintAmount - burnAmount);
        // Invariant: totalSupply == sum of all balances (single holder)
        assertEq(token.totalSupply(), token.balanceOf(to));
    }

    /// @notice Multiple mints must never exceed MAX_SUPPLY.
    function testFuzz_cumulativeMintRespectsMaxSupply(uint256 totalMint, address to) public {
        // Bound total mint to [1, MAX_SUPPLY]
        totalMint = bound(totalMint, 1, token.MAX_SUPPLY());
        vm.assume(to != address(0));

        vm.prank(minter);
        token.mint(to, totalMint);

        assertLe(token.totalSupply(), token.MAX_SUPPLY());
        assertEq(token.totalSupply(), totalMint);
    }

    /// @notice Cannot mint more than MAX_SUPPLY even with a small overshoot.
    function testFuzz_mintRevertOnOvershoot(uint256 amount) public {
        // Start with a valid amount, then try to overshoot
        amount = bound(amount, 1, token.MAX_SUPPLY());

        vm.prank(minter);
        token.mint(address(0xB0B), amount);

        // Any positive additional mint that pushes past MAX_SUPPLY must revert
        uint256 remaining = token.MAX_SUPPLY() - token.totalSupply();
        if (remaining == 0) {
            vm.prank(minter);
            vm.expectRevert("Exceeds max supply");
            token.mint(address(0xB0B), 1);
        } else {
            vm.prank(minter);
            vm.expectRevert("Exceeds max supply");
            token.mint(address(0xB0B), remaining + 1);
        }
    }

    /// @notice burn cannot burn more than balance
    function testFuzz_burnRevertOnInsufficientBalance(uint256 mintAmount, uint256 burnAmount) public {
        mintAmount = bound(mintAmount, 1, token.MAX_SUPPLY());
        burnAmount = bound(burnAmount, mintAmount + 1, type(uint256).max);

        vm.prank(minter);
        token.mint(address(this), mintAmount);

        vm.expectRevert();
        token.burn(burnAmount);
    }

    /// @notice transfer respects balance limits
    function testFuzz_transferRevertOnInsufficientBalance(uint256 mintAmount, uint256 transferAmount, address to)
        public
    {
        mintAmount = bound(mintAmount, 1, token.MAX_SUPPLY());
        transferAmount = bound(transferAmount, mintAmount + 1, type(uint256).max);
        vm.assume(to != address(0));

        vm.prank(minter);
        token.mint(address(this), mintAmount);

        vm.expectRevert();
        token.transfer(to, transferAmount);
    }

    /// @notice successful transfer preserves total supply
    function testFuzz_transferPreservesSupply(uint256 mintAmount, uint256 transferAmount, address to) public {
        mintAmount = bound(mintAmount, 1, token.MAX_SUPPLY());
        transferAmount = bound(transferAmount, 1, mintAmount);
        vm.assume(to != address(0));
        vm.assume(to != address(this)); // exclude self-transfer

        vm.prank(minter);
        token.mint(address(this), mintAmount);

        uint256 supplyBefore = token.totalSupply();
        token.transfer(to, transferAmount);

        assertEq(token.totalSupply(), supplyBefore);
        assertEq(token.balanceOf(address(this)), mintAmount - transferAmount);
        assertEq(token.balanceOf(to), transferAmount);
    }

    /// @notice approve + transferFrom preserves total supply
    function testFuzz_transferFromPreservesSupply(
        uint256 mintAmount,
        uint256 approveAmount,
        uint256 transferAmount,
        address owner,
        address spender,
        address recipient
    ) public {
        mintAmount = bound(mintAmount, 1, token.MAX_SUPPLY());
        approveAmount = bound(approveAmount, 1, mintAmount);
        transferAmount = bound(transferAmount, 1, approveAmount);
        vm.assume(owner != address(0) && spender != address(0) && recipient != address(0));
        vm.assume(owner != spender);
        vm.assume(owner != recipient);
        vm.assume(spender != recipient);

        vm.prank(minter);
        token.mint(owner, mintAmount);

        vm.prank(owner);
        token.approve(spender, approveAmount);

        uint256 supplyBefore = token.totalSupply();

        vm.prank(spender);
        token.transferFrom(owner, recipient, transferAmount);

        assertEq(token.totalSupply(), supplyBefore);
        assertEq(token.balanceOf(owner), mintAmount - transferAmount);
        assertEq(token.balanceOf(recipient), transferAmount);
    }
}

contract ZKMAirdropFuzzTest is Test {
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

        token = new ZKMToken(predictedAirdrop);
        airdrop = new ZKMAirdrop(address(token), address(verifier), IMAGE_ID, MERKLE_ROOT);

        require(address(airdrop) == predictedAirdrop, "Address prediction failed");
        require(token.minter() == address(airdrop), "Minter mismatch");
    }

    function _buildJournal(bytes32 root, bytes32 nullifier, address recipient) internal pure returns (bytes memory) {
        return bytes.concat(root, nullifier, bytes20(recipient));
    }

    // ── Supply invariant ─────────────────────────────────────────────

    /// @notice After N claims, totalSupply == N * CLAIM_AMOUNT.
    function testFuzz_supplyAfterClaims(uint8 numClaims) public {
        numClaims = uint8(bound(numClaims, 1, 50)); // reasonable bound for test speed

        for (uint256 i = 1; i <= numClaims; i++) {
            bytes32 nullifier = keccak256(abi.encode(i));
            address recipient = address(uint160(uint160(i) + 100));
            bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
            airdrop.claim("", journal, nullifier, recipient);
        }

        assertEq(airdrop.totalClaims(), numClaims);
        assertEq(token.totalSupply(), uint256(numClaims) * airdrop.CLAIM_AMOUNT());
    }

    /// @notice Invariant: totalSupply == totalClaims * CLAIM_AMOUNT - totalBurned
    ///         Simulates claim → burn → verify across multiple claimants.
    function testFuzz_supplyAfterClaimAndBurn(uint8 numClaims, uint8 burnIdx) public {
        numClaims = uint8(bound(numClaims, 2, 20));
        burnIdx = uint8(bound(burnIdx, 1, numClaims));

        uint256 totalBurned = 0;

        for (uint256 i = 1; i <= numClaims; i++) {
            bytes32 nullifier = keccak256(abi.encode(i));
            address recipient = address(uint160(uint160(i) + 100));
            bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
            airdrop.claim("", journal, nullifier, recipient);

            // Burn half of one claimant's tokens
            if (i == burnIdx) {
                uint256 burnAmount = airdrop.CLAIM_AMOUNT() / 2;
                vm.prank(recipient);
                token.burn(burnAmount);
                totalBurned = burnAmount;
            }
        }

        assertEq(token.totalSupply(), uint256(numClaims) * airdrop.CLAIM_AMOUNT() - totalBurned);
    }

    // ── Nullifier uniqueness ─────────────────────────────────────────

    /// @notice Different nullifiers must produce independent claims.
    function testFuzz_uniqueNullifiersProduceUniqueClaims(uint256 n1, uint256 n2) public {
        vm.assume(n1 != n2);
        // Bound to avoid running into cap
        vm.assume(n1 > 0 && n2 > 0);
        n1 = bound(n1, 1, 999_999);
        n2 = bound(n2, 1, 999_999);
        vm.assume(n1 != n2);

        bytes32 null1 = bytes32(keccak256(abi.encode(n1)));
        bytes32 null2 = bytes32(keccak256(abi.encode(n2)));
        address recip1 = address(uint160(n1));
        address recip2 = address(uint160(n2));
        vm.assume(recip1 != address(0));
        vm.assume(recip2 != address(0));
        vm.assume(recip1 != recip2);

        bytes memory j1 = _buildJournal(MERKLE_ROOT, null1, recip1);
        bytes memory j2 = _buildJournal(MERKLE_ROOT, null2, recip2);

        airdrop.claim("", j1, null1, recip1);
        airdrop.claim("", j2, null2, recip2);

        assertTrue(airdrop.isClaimed(null1));
        assertTrue(airdrop.isClaimed(null2));
        assertEq(airdrop.totalClaims(), 2);
    }

    /// @notice Same nullifier must always be rejected on second use.
    function testFuzz_doubleClaimAlwaysRejected(bytes32 nullifier, address recipient) public {
        vm.assume(recipient != address(0));
        vm.assume(nullifier != bytes32(0));

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        // First claim succeeds
        airdrop.claim("", journal, nullifier, recipient);

        // Second claim with same nullifier always reverts (even different recipient)
        address otherRecipient = address(uint160(uint160(recipient) ^ 0xFF));
        vm.assume(otherRecipient != address(0));
        bytes memory journal2 = _buildJournal(MERKLE_ROOT, nullifier, otherRecipient);
        vm.expectRevert("Already claimed");
        airdrop.claim("", journal2, nullifier, otherRecipient);
    }

    // ── Journal tampering ────────────────────────────────────────────

    /// @notice Tampered root in journal always reverts.
    function testFuzz_tamperedRootRejected(bytes32 wrongRoot, bytes32 nullifier, address recipient) public {
        vm.assume(recipient != address(0));
        vm.assume(wrongRoot != MERKLE_ROOT);
        vm.assume(nullifier != bytes32(0));

        bytes memory badJournal = _buildJournal(wrongRoot, nullifier, recipient);
        vm.expectRevert("Root mismatch");
        airdrop.claim("", badJournal, nullifier, recipient);
    }

    /// @notice Tampered nullifier in journal always reverts.
    function testFuzz_tamperedNullifierRejected(bytes32 nullifier, bytes32 wrongNullifier, address recipient) public {
        vm.assume(recipient != address(0));
        vm.assume(nullifier != bytes32(0));
        vm.assume(wrongNullifier != nullifier);

        bytes memory journal = _buildJournal(MERKLE_ROOT, wrongNullifier, recipient);
        vm.expectRevert("Nullifier mismatch");
        airdrop.claim("", journal, nullifier, recipient);
    }

    /// @notice Tampered recipient in journal always reverts.
    function testFuzz_tamperedRecipientRejected(bytes32 nullifier, address recipient, address wrongRecipient) public {
        vm.assume(recipient != address(0));
        vm.assume(wrongRecipient != address(0));
        vm.assume(recipient != wrongRecipient);
        vm.assume(nullifier != bytes32(0));

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, wrongRecipient);
        vm.expectRevert("Recipient mismatch");
        airdrop.claim("", journal, nullifier, recipient);
    }

    // ── Deadline and cap boundary ────────────────────────────────────

    /// @notice Claims at any time before deadline succeed.
    function testFuzz_claimBeforeDeadlineSucceeds(uint256 secondsBeforeDeadline, bytes32 nullifier) public {
        secondsBeforeDeadline = bound(secondsBeforeDeadline, 1, airdrop.CLAIM_DEADLINE());
        vm.assume(nullifier != bytes32(0));
        address recipient = address(uint160(uint256(nullifier)));
        vm.assume(recipient != address(0));

        vm.warp(airdrop.CLAIM_DEADLINE() - secondsBeforeDeadline);

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
        airdrop.claim("", journal, nullifier, recipient);

        assertEq(token.balanceOf(recipient), airdrop.CLAIM_AMOUNT());
    }

    /// @notice Claims at any time >= deadline revert.
    function testFuzz_claimAtOrAfterDeadlineReverts(uint256 secondsAfterDeadline) public {
        secondsAfterDeadline = bound(secondsAfterDeadline, 0, 365 days);
        bytes32 nullifier = bytes32(uint256(0x42));
        address recipient = address(0xB0B);

        vm.warp(airdrop.CLAIM_DEADLINE() + secondsAfterDeadline);

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
        vm.expectRevert("Claim period ended");
        airdrop.claim("", journal, nullifier, recipient);
    }

    // ── claimsRemaining invariant ────────────────────────────────────

    /// @notice claimsRemaining + totalClaims == MAX_CLAIMS (before cap)
    function testFuzz_claimsRemainingInvariant(uint8 numClaims) public {
        numClaims = uint8(bound(numClaims, 0, 50));

        for (uint256 i = 1; i <= numClaims; i++) {
            bytes32 nullifier = keccak256(abi.encode(i));
            address recipient = address(uint160(uint160(i) + 100));
            bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);
            airdrop.claim("", journal, nullifier, recipient);
        }

        assertEq(airdrop.claimsRemaining() + airdrop.totalClaims(), airdrop.MAX_CLAIMS());
    }

    // ── Permissionless submission ────────────────────────────────────

    /// @notice Anyone can submit a valid claim for any recipient.
    function testFuzz_anyoneCanSubmit(address submitter, bytes32 nullifier, address recipient) public {
        vm.assume(submitter != address(0));
        vm.assume(recipient != address(0));
        vm.assume(nullifier != bytes32(0));
        vm.assume(submitter != recipient); // submitter and recipient must differ for balance check

        bytes memory journal = _buildJournal(MERKLE_ROOT, nullifier, recipient);

        vm.prank(submitter);
        airdrop.claim("", journal, nullifier, recipient);

        // Tokens go to recipient, not submitter
        assertEq(token.balanceOf(recipient), airdrop.CLAIM_AMOUNT());
        assertEq(token.balanceOf(submitter), 0);
    }
}

// ── Invariant Tests (Foundry handler-based) ──────────────────────────

/// @title ZKMAirdropInvariantTest
/// @notice Invariant test verifying totalSupply == totalClaims * CLAIM_AMOUNT
///         across arbitrary call sequences.
contract ZKMAirdropInvariantTest is Test {
    ZKMToken token;
    ZKMAirdrop airdrop;
    NoopVerifier verifier;
    Handler handler;

    bytes32 constant IMAGE_ID = bytes32(uint256(0x01));
    bytes32 constant MERKLE_ROOT = bytes32(uint256(0x02));

    function setUp() public {
        verifier = new NoopVerifier();

        // Nonces from address(this): 1=NoopVerifier, 2=ZKMToken, 3=ZKMAirdrop
        address predictedAirdrop = vm.computeCreateAddress(address(this), 3);

        token = new ZKMToken(predictedAirdrop);
        airdrop = new ZKMAirdrop(address(token), address(verifier), IMAGE_ID, MERKLE_ROOT);

        handler = new Handler(airdrop, token);

        // Target only the handler — prevents Foundry from calling ZKMToken.mint()
        // or ZKMToken.burn() directly (which would bypass the airdrop and break invariants).
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = Handler.claim.selector;
        selectors[1] = Handler.burn.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        // Exclude all other contracts from fuzzing
        excludeContract(address(token));
        excludeContract(address(airdrop));
        excludeContract(address(verifier));
    }

    /// @dev Invariant: token.totalSupply() == totalClaims * CLAIM_AMOUNT - totalBurned
    function invariant_supplyMatchesClaims() public view {
        assertEq(token.totalSupply(), airdrop.totalClaims() * airdrop.CLAIM_AMOUNT() - handler.ghost_burned());
    }

    /// @dev Invariant: claims never exceeds MAX_CLAIMS
    function invariant_claimsDoNotExceedMax() public view {
        assertLe(airdrop.totalClaims(), airdrop.MAX_CLAIMS());
    }

    /// @dev Invariant: claimsRemaining + totalClaims == MAX_CLAIMS (when under cap)
    function invariant_claimsRemainingConsistent() public view {
        assertEq(airdrop.claimsRemaining() + airdrop.totalClaims(), airdrop.MAX_CLAIMS());
    }
}

/// @notice Handler for invariant testing. Exposes claim() and burn() as
///         ghost operations with bounded inputs.
contract Handler is Test {
    ZKMAirdrop public airdrop;
    ZKMToken public token;

    uint256 public ghost_claims;
    uint256 public ghost_burned;

    mapping(uint256 => bool) public usedNullifiers;

    constructor(ZKMAirdrop _airdrop, ZKMToken _token) {
        airdrop = _airdrop;
        token = _token;
    }

    function claim(uint256 nullifierSeed, address recipient) external {
        // Only claim if window is open
        if (!airdrop.isClaimWindowOpen()) return;

        // Bound inputs
        vm.assume(recipient != address(0));
        nullifierSeed = bound(nullifierSeed, 1, type(uint256).max);

        // Skip if nullifier already used
        bytes32 nullifier = keccak256(abi.encode(nullifierSeed));
        if (usedNullifiers[nullifierSeed]) return;
        usedNullifiers[nullifierSeed] = true;

        bytes memory journal = bytes.concat(airdrop.merkleRoot(), nullifier, bytes20(recipient));

        airdrop.claim("", journal, nullifier, recipient);
        ghost_claims++;
    }

    function burn(uint256 claimIndex, uint256 amount) external {
        // Bound to existing claimant
        if (claimIndex == 0 || claimIndex > ghost_claims) return;
        amount = bound(amount, 1, airdrop.CLAIM_AMOUNT());

        address claimant = address(uint160(uint160(claimIndex) + 100));
        if (token.balanceOf(claimant) < amount) return;

        vm.prank(claimant);
        token.burn(amount);
        ghost_burned += amount;
    }
}
