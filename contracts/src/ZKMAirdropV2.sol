// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZKMTokenV2} from "./ZKMTokenV2.sol";

/// @title ZKMAirdropV2 — Privacy-preserving ZKM token claim contract (Halo2)
/// @notice Fully immutable. No admin, no owner, no pause, no upgrade.
/// @dev Differs from V1: uses Halo2-KZG proof verification instead of RISC Zero.
///      Public inputs are passed directly as calldata — no journal parsing needed.
contract ZKMAirdropV2 {
    ZKMTokenV2 public immutable token;
    /// @notice Halo2 verifier contract. Exposes verify(proof, publicInputs) returns (bool).
    address public immutable verifier;
    bytes32 public immutable merkleRoot;

    uint256 public constant CLAIM_AMOUNT = 10_000e18;         // 10,000 ZKM
    uint256 public constant MAX_CLAIMS = 1_000_000;
    uint256 public constant CLAIM_DEADLINE = 1_798_761_600;    // 2027-01-01 00:00:00 UTC
    uint256 public constant MIN_PROOF_LENGTH = 400;
    uint256 public constant MAX_PROOF_LENGTH = 1200;

    uint256 public totalClaims;
    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(
        bytes32 indexed nullifier,
        uint256 amount,
        address indexed recipient,
        uint256 totalClaims
    );

    constructor(
        address _token,
        address _verifier,
        bytes32 _merkleRoot
    ) {
        token = ZKMTokenV2(_token);
        verifier = _verifier;
        merkleRoot = _merkleRoot;
    }

    /// @notice Claim ZKM tokens with a valid Halo2 proof.
    /// @param proof The Halo2 KZG proof bytes.
    /// @param nullifier The claim's nullifier (poseidon(key, domain)).
    /// @param recipient Address to receive 10,000 ZKM.
    function claim(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient
    ) external {
        // Validate proof length
        require(proof.length >= MIN_PROOF_LENGTH && proof.length <= MAX_PROOF_LENGTH, "Invalid proof length");

        // Check claim window
        require(block.timestamp < CLAIM_DEADLINE, "Claim period ended");
        require(totalClaims < MAX_CLAIMS, "Claim cap reached");
        require(!usedNullifiers[nullifier], "Already claimed");
        require(recipient != address(0), "Recipient cannot be zero");

        // Construct public inputs: [merkleRoot, nullifier, recipient]
        uint256[3] memory publicInputs = [
            uint256(merkleRoot),
            uint256(nullifier),
            uint256(uint160(recipient))
        ];

        // Verify Halo2 proof via the verifier contract
        // The verifier checks the proof against the public inputs, which bind:
        //   - merkleRoot: ensures the address is in the eligibility tree
        //   - nullifier: prevents double-claims, derived from private key
        //   - recipient: front-running protection (bound inside the proof)
        (bool success, ) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,uint256[3])", proof, publicInputs)
        );
        require(success, "Verifier call failed");
        bool valid = abi.decode(retval, (bool));
        require(valid, "Invalid proof");

        // Mark claimed and mint
        usedNullifiers[nullifier] = true;
        totalClaims++;
        token.mint(recipient, CLAIM_AMOUNT);

        emit Claimed(nullifier, CLAIM_AMOUNT, recipient, totalClaims);
    }

    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function claimsRemaining() external view returns (uint256) {
        return totalClaims >= MAX_CLAIMS ? 0 : MAX_CLAIMS - totalClaims;
    }

    function isClaimWindowOpen() external view returns (bool) {
        return block.timestamp < CLAIM_DEADLINE && totalClaims < MAX_CLAIMS;
    }
}
