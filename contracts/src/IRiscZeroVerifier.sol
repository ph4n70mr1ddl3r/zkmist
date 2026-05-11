// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice RISC Zero verifier interface (Groth16 variant).
/// @dev The deployed verifier is RiscZeroGroth16Verifier from risc0-ethereum.
///      It internally compresses STARK proofs for cheap on-chain verification (~400K gas).
interface IRiscZeroVerifier {
    /// @notice Verify a RISC Zero STARK proof (wrapped in Groth16).
    /// @param seal  The encoded proof (Groth16 seal).
    /// @param imageId  The guest program image ID (commitment to the binary).
    /// @param journalDigest  SHA-256 hash of the journal bytes.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}
