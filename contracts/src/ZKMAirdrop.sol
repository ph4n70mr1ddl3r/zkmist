// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZKMToken} from "./ZKMToken.sol";
import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";

/// @title ZKMAirdrop — Privacy-preserving ZKM token claim contract
/// @notice Fully immutable. No admin, no owner, no pause, no upgrade.
/// @dev Journal layout (84 bytes):
///      [0:32]   merkleRoot   (bytes32)
///      [32:64]  nullifier    (bytes32)
///      [64:84]  recipient    (address — raw 20 bytes)
contract ZKMAirdrop {
    ZKMToken public immutable token;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    bytes32 public immutable merkleRoot;

    uint256 public constant CLAIM_AMOUNT = 10_000e18; // 10,000 ZKM
    uint256 public constant MAX_CLAIMS = 1_000_000;
    uint256 public constant CLAIM_DEADLINE = 1_798_761_600; // 2027-01-01 00:00:00 UTC

    uint256 public totalClaims;
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Emitted when a claim succeeds.
    /// @param nullifier  The claim's nullifier (opaque, not the qualified address).
    /// @param amount     Always CLAIM_AMOUNT (10,000 ZKM).
    /// @param recipient  Address that received the tokens.
    /// @param totalClaims Updated claim count after this claim.
    event Claimed(
        bytes32 indexed nullifier,
        uint256 amount,
        address indexed recipient,
        uint256 totalClaims
    );

    constructor(
        address _token,
        address _verifier,
        bytes32 _imageId,
        bytes32 _merkleRoot
    ) {
        token = ZKMToken(_token);
        verifier = IRiscZeroVerifier(_verifier);
        imageId = _imageId;
        merkleRoot = _merkleRoot;
    }

    /// @notice Claim ZKM tokens by submitting a valid ZK proof.
    /// @param _proof     RISC Zero STARK proof (Groth16-wrapped seal).
    /// @param _journal   Journal bytes (84 bytes: merkleRoot + nullifier + recipient).
    /// @param _nullifier The nullifier for this claim (prevents double-claim).
    /// @param _recipient Address to receive 10,000 ZKM.
    function claim(
        bytes calldata _proof,
        bytes calldata _journal,
        bytes32 _nullifier,
        address _recipient
    ) external {
        // Check claim window
        require(block.timestamp < CLAIM_DEADLINE, "Claim period ended");
        require(totalClaims < MAX_CLAIMS, "Claim cap reached");
        require(!usedNullifiers[_nullifier], "Already claimed");
        require(_recipient != address(0), "Recipient cannot be zero address");

        // Validate journal layout: must be exactly 84 bytes
        // Layout: merkleRoot[0:32] ++ nullifier[32:64] ++ recipient[64:84]
        require(_journal.length == 84, "Invalid journal length");

        // Verify RISC Zero proof
        // Journal digest: SHA-256 of raw journal bytes
        bytes32 journalDigest = bytes32(sha256(_journal));
        verifier.verify(_proof, imageId, journalDigest);

        // Validate journal contents match claim parameters
        require(bytes32(_journal[0:32]) == merkleRoot, "Root mismatch");
        require(bytes32(_journal[32:64]) == _nullifier, "Nullifier mismatch");
        require(
            address(bytes20(_journal[64:84])) == _recipient,
            "Recipient mismatch"
        );

        // Mark claimed and mint
        usedNullifiers[_nullifier] = true;
        totalClaims++;
        token.mint(_recipient, CLAIM_AMOUNT);

        emit Claimed(_nullifier, CLAIM_AMOUNT, _recipient, totalClaims);
    }

    // ── View helpers ──────────────────────────────────────────────────────

    /// @notice Check if a nullifier has already been used to claim.
    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Number of claims remaining before the cap is reached.
    function claimsRemaining() external view returns (uint256) {
        return MAX_CLAIMS - totalClaims;
    }

    /// @notice Whether the claim window is still open.
    function isClaimWindowOpen() external view returns (bool) {
        return block.timestamp < CLAIM_DEADLINE && totalClaims < MAX_CLAIMS;
    }
}
