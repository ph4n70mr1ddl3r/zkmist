//! ZKMist V2 Circuits — Halo2-KZG spike and validation
//!
//! This crate contains the Halo2-KZG circuit definitions for ZKMist V2.
//!
//! ## Current status: API validation spike
//!
//! The `trivial` module validates that the Halo2 PSE v0.3.0 API works correctly:
//! - Real KZG proof generation and verification on BN254
//! - Field element interop between `halo2curves::bn256::Fr` and `ark_bn254::Fr`
//! - Lookup tables, custom gates, copy constraints, selectors
//!
//! ## API findings (halo2_proofs 0.3.0 / halo2curves 0.6.0)
//!
//! Key differences from common Halo2 tutorials:
//!
//! | Feature | Expected | Actual |
//! |---------|----------|--------|
//! | `Circuit::Params` | Associated type | Not in trait |
//! | `circuit-params` feature | Exists | Does not exist |
//! | `meta.lookup()` | `(name, closure)` | `(closure)` only |
//! | `meta.lookup_table()` | `lookup_table(name)` | `lookup_table_column()` |
//! | `query_fixed()` | `(col, rotation)` | `(col)` only (per-region) |
//! | `region.instance_cell()` | Method | Not available; use `assign_advice_from_instance` |
//! | `TranscriptReadBuffer` | Type | Use `Blake2bRead::init()` |
//! | Curve type param | `Bn256` | `G1Affine` |
//!
//! ## V2 circuit plan
//!
//! The full ZKMist V2 circuit will implement:
//! 1. **secp256k1 scalar multiplication** — private key → public key → address
//! 2. **Keccak-256** — hash public key to derive Ethereum address
//! 3. **Poseidon hash** — leaf hash (t=2) and interior hash (t=3) for Merkle tree
//! 4. **Merkle proof** — 26-level verification of address membership
//! 5. **Nullifier** — `poseidon(Fr(key), Fr("ZKMist_V2_NULLIFIER"))`
//!
//! Risk assessment:
//! - Poseidon + Merkle + Nullifier: LOW risk (algebraic, no lookups needed)
//! - Keccak-256: MEDIUM risk (~200K constraints, lookup tables)
//! - secp256k1: HIGH risk (non-native field arithmetic, ~50-100K constraints)

pub mod trivial;
