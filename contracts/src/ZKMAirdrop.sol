// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZKMToken} from "./ZKMToken.sol";
import {Halo2Verifier} from "./Halo2Verifier.axiom.sol";

/// @title ZKMAirdrop — Privacy-preserving ZKM token claim contract (axiom Halo2-KZG)
/// @notice Fully immutable. No admin, no owner, no pause, no upgrade.
/// @dev Verifies axiom-backend Halo2-KZG proofs via the snark-verifier-generated
///      `Halo2Verifier` (a `fallback`-based contract that takes
///      `encode_calldata(instances, proof)` = instances (32-byte BE each) ++ proof,
///      and reverts on an invalid proof). The public inputs are
///      `[merkleRoot, nullifier, recipient]` — the circuit's single public
///      instance column. The VK is embedded in the verifier contract (no
///      separate verifying-key contract, unlike the legacy PSE verifier).
contract ZKMAirdrop {
    ZKMToken public immutable token;
    /// @notice axiom Halo2 verifier (snark-verifier-generated; embeds the VK).
    Halo2Verifier public immutable verifier;
    bytes32 public immutable merkleRoot;

    uint256 public constant CLAIM_AMOUNT = 10_000e18; // 10,000 ZKM
    uint256 public constant MAX_CLAIMS = 1_000_000;
    uint256 public constant CLAIM_DEADLINE = 1_798_761_600; // 2027-01-01 00:00:00 UTC

    uint256 public totalClaims;
    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(bytes32 indexed nullifier, uint256 amount, address indexed recipient, uint256 totalClaims);

    constructor(address _token, address _verifier, bytes32 _merkleRoot) {
        // Defense-in-depth: a zero `verifier` would make the `staticcall` in
        // `claim` return `ok = true` (no code at address(0)) and accept ANY
        // proof — a full drain. Both are immutable, so a bad value can never
        // be corrected after deployment.
        require(_token != address(0) && _verifier != address(0), "Zero address");
        token = ZKMToken(_token);
        verifier = Halo2Verifier(_verifier);
        merkleRoot = _merkleRoot;
    }

    /// @notice Claim ZKM tokens with a valid axiom Halo2 proof.
    /// @param proof  The axiom Halo2 KZG proof bytes (EvmTranscript).
    /// @param nullifier The claim's nullifier — `poseidon(privkey mod p, domain)`
    ///                  under the halo2-base Poseidon convention.
    /// @param recipient Address to receive 10,000 ZKM.
    ///
    /// @dev Checks-Effects-Interactions: nullifier + totalClaims are set BEFORE
    ///      the external `token.mint`, and the minter is immutable, so a
    ///      re-entry into `claim` cannot double-spend (same nullifier already
    ///      marked used). The verifier is read-only (staticcall).
    function claim(bytes calldata proof, bytes32 nullifier, address recipient) external {
        require(block.timestamp < CLAIM_DEADLINE, "Claim period ended");
        require(totalClaims < MAX_CLAIMS, "Claim cap reached");
        require(!usedNullifiers[nullifier], "Already claimed");
        require(recipient != address(0), "Recipient cannot be zero");

        // Calldata = instances (32-byte big-endian each) ++ proof — matches
        // snark-verifier's `encode_calldata`. The instances are the circuit's
        // public column: [merkleRoot, nullifier, recipient].
        bytes memory cd = abi.encodePacked(uint256(merkleRoot), uint256(nullifier), uint256(uint160(recipient)), proof);
        // The verifier reverts on an invalid proof; `staticcall` returns ok=false.
        (bool ok,) = address(verifier).staticcall(cd);
        require(ok, "Invalid proof");

        // Mark claimed and mint.
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
