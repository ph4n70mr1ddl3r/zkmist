//! Keccak-256 hash gadget (Phase 2 stub).
//!
//! **Status: Stub.** Implementation is planned for Phase 2 (Weeks 3-5).
//!
//! # What the gadget must do
//!
//! Hashes the uncompressed secp256k1 public key (64 bytes) to derive
//! the Ethereum address:
//!
//! ```text
//! keccak256(pub_key_x || pub_key_y)
//! address = hash[12..32]    // last 20 bytes
//! ```
//!
//! # Implementation approach
//!
//! Reference implementations:
//! - `privacy-scaling-explorations/halo2wrong` — Keccak256 gadget
//! - `scroll-tech/zkevm-circuits` — Optimized Keccak in production zkEVM
//!
//! Key ideas:
//! - 24 rounds of Keccak-f[1600] permutation
//! - Each round: θ, ρ, π, χ, ι steps
//! - Use lookup tables for the χ step (non-linear)
//! - Linear steps (θ, ρ, π, ι) are free in PLONKish (fixed routing)
//!
//! Estimated constraints: ~200-300K
//!
//! # ⚠️ Important: Keccak-256 ≠ SHA3-256
//!
//! Ethereum uses the **original Keccak-256** (NIST submission before SHA-3
//! standardization). These are different hash functions that produce
//! different outputs. The `sha3` crate's `Sha3_256` is WRONG for Ethereum.
//! The `tiny-keccak` crate's `Keccak::v256()` is correct.

/// Placeholder for the Keccak-256 gadget.
///
/// Will be implemented in Phase 2.
pub struct Keccak256Gadget;

impl Keccak256Gadget {
    /// TODO: Compute Keccak-256 hash inside the circuit.
    ///
    /// Inputs:
    /// - `data`: assigned cells representing the input bytes
    ///
    /// Outputs:
    /// - `hash`: 32-byte Keccak-256 hash
    pub fn hash() {
        todo!("Phase 2: Keccak-256 gadget")
    }
}
