//! ZKMist V2 Circuits — Halo2-KZG anonymous airdrop claim proofs
//!
//! ## Status: Phase 1 implemented (Poseidon + Merkle + Nullifier)
//!
//! The following gadgets are implemented and cross-validated against
//! `light-poseidon` and `zkmist-merkle-tree`:
//!
//! - **Poseidon hash** — t=2 (leaf) and t=3 (interior/nullifier) gadgets
//! - **Merkle proof** — 26-level Poseidon Merkle path verification
//! - **Nullifier** — `poseidon(Fr(key), Fr(domain))` with V2 domain separator
//! - **Conditional swap** — for Merkle path direction handling
//!
//! Stubs (Phase 2):
//! - **secp256k1** — scalar multiplication for key→address derivation
//! - **Keccak-256** — public key → Ethereum address
//!
//! ## API Validation Spike
//!
//! The `trivial` module contains the original spike that validated the
//! Halo2 PSE v0.3.0 API, field interop, and real KZG proof generation.

pub mod gadgets;
pub mod keccak;
pub mod merkle;
pub mod nullifier;
pub mod poseidon;
pub mod secp256k1;
pub mod trivial;

// Re-export key types for convenience
pub use poseidon::{PoseidonChip, PoseidonConfig, PoseidonParams};
