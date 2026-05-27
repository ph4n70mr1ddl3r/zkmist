//! Halo2-KZG prover integration for ZKMist V2.
//!
//! **Status: Stub.** This module will be implemented when the V2 circuit
//! is complete (after Phase 2 secp256k1 + Keccak gadgets are done).
//!
//! # Planned API
//!
//! ```ignore
//! use zkmist_circuits::{ZKMistV2ClaimCircuit, PoseidonParams};
//!
//! // Load circuit parameters
//! let leaf_params = PoseidonParams::new_circom(1);
//! let interior_params = PoseidonParams::new_circom(2);
//!
//! // Build the circuit with private inputs
//! let circuit = ZKMistV2ClaimCircuit::new(
//!     private_key,
//!     merkle_siblings,
//!     path_indices,
//!     merkle_root,     // public input
//!     nullifier,       // public input
//!     recipient,       // public input
//! );
//!
//! // Generate the Halo2-KZG proof
//! let proof = generate_proof(&circuit, k)?;
//!
//! // Save proof file
//! save_proof_file(&proof, nullifier, recipient)?;
//! ```
//!
//! # Proof generation flow
//!
//! ```text
//! 1. Load private key and Merkle proof (cached from `zkmist prove`)
//! 2. Build ZKMistV2ClaimCircuit with all inputs
//! 3. Generate proving key and verification key (or load cached)
//! 4. Create Halo2-KZG proof (~10-30 seconds)
//! 5. Save proof.json for submission
//! ```
//!
//! # Dependencies (planned)
//!
//! | Crate | Purpose |
//! |-------|---------|
//! | `halo2_proofs` | Proof generation and verification |
//! | `halo2curves` | BN254 curve primitives |
//! | `snark-verifier` | Solidity proof encoding |
//! | `zkmist-circuits` | Circuit definitions |

use std::path::Path;

/// Generate a Halo2-KZG proof for a V2 claim.
///
/// **Not yet implemented.** Requires the full V2 circuit (secp256k1 + Keccak).
///
/// # Arguments
///
/// * `private_key` - The claimant's secp256k1 private key (32 bytes)
/// * `siblings` - Merkle proof sibling hashes (26 × 32 bytes)
/// * `path_indices` - Merkle proof direction flags (26 bytes, each 0 or 1)
/// * `merkle_root` - The eligibility tree root (32 bytes, public input)
/// * `recipient` - The recipient address (20 bytes, public input)
/// * `output_path` - Where to save the proof file
///
/// # Returns
///
/// The nullifier (32 bytes) on success.
#[allow(dead_code)]
pub fn generate_v2_proof(
    _private_key: &[u8; 32],
    _siblings: &[[u8; 32]; 26],
    _path_indices: &[u8; 26],
    _merkle_root: &[u8; 32],
    _recipient: &[u8; 20],
    _output_path: &Path,
) -> Result<[u8; 32], String> {
    Err(
        "V2 proof generation is not yet implemented. \
         The secp256k1 and Keccak-256 gadgets are still in development (Phase 2). \
         Use V1 (RISC Zero) for claiming in the meantime."
            .to_string(),
    )
}

/// Verify a Halo2-KZG proof locally.
///
/// **Not yet implemented.**
#[allow(dead_code)]
pub fn verify_v2_proof(_proof_path: &Path) -> Result<(), String> {
    Err(
        "V2 proof verification is not yet implemented. \
         Use V1 (RISC Zero) for verification in the meantime."
            .to_string(),
    )
}

/// Generate the Solidity verifier contract from the verification key.
///
/// **Not yet implemented.** Will use `snark-verifier` to generate
/// `Halo2Verifier.sol` from the circuit's verification key.
///
/// # Workflow
///
/// ```text
/// 1. Build the circuit with dummy inputs
/// 2. Compute the verification key (VK)
/// 3. Run snark-verifier to generate Solidity
/// 4. Output: contracts/src/Halo2Verifier.sol
/// ```
#[allow(dead_code)]
pub fn generate_solidity_verifier(_output_path: &Path) -> Result<(), String> {
    Err(
        "Solidity verifier generation is not yet implemented. \
         Requires the completed V2 circuit and snark-verifier toolchain."
            .to_string(),
    )
}
