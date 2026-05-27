//! secp256k1 scalar multiplication gadget (Phase 2 stub).
//!
//! **Status: Stub.** This is the highest-risk component of the V2 circuit.
//! Implementation is planned for Phase 2 (Weeks 3-5 of the V2 timeline).
//!
//! # What the gadget must do
//!
//! Proves: "I know a private key `k` such that `secp256k1_scalar_mul(k, G)` produces
//! the public key whose Keccak-256 hash matches address X."
//!
//! ```text
//! P = k * G    (secp256k1 scalar multiplication)
//! address = keccak256(P.x || P.y)[12:32]
//! ```
//!
//! # Implementation approaches
//!
//! ## Approach A: Windowed scalar multiplication (recommended)
//!
//! Reference implementations:
//! - `scroll-tech/halo2-secp256k1` — Used in Scroll's zkEVM
//! - `summa-dev/summa-solvency` — Privacy-preserving solvency proofs
//!
//! Key ideas:
//! - Decompose the 256-bit scalar into 4-bit windows (64 windows)
//! - Use lookup tables for precomputed point additions
//! - Handle non-native field arithmetic (secp256k1 field ≠ BN254 scalar field)
//!
//! Estimated constraints: ~50-100K
//!
//! ## Approach B: ECDSA verify
//!
//! Instead of computing `P = k * G`, verify an ECDSA signature `(r, s)` against
//! the public key. This shifts complexity but still requires non-native arithmetic.
//!
//! ## Approach C: Precomputed table
//!
//! Precompute scalar multiplication tables at circuit setup time, reducing
//! the online proving cost. Requires larger fixed columns.
//!
//! # Non-native field arithmetic
//!
//! secp256k1 operates over the field:
//! ```text
//! p_secp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
//! ```
//!
//! This is NOT the same as BN254's scalar field (`p_bn254 ≈ 2^254`). All secp256k1
//! operations must use non-native field arithmetic techniques:
//! - Represent secp256k1 field elements as multiple BN254 field elements
//! - Use range checks and modular reduction after each operation
//! - Halo2 lookup tables for efficient bit decomposition
//!
//! # Risk assessment
//!
//! | Risk | Level | Mitigation |
//! |------|-------|------------|
//! | Non-native field arithmetic | HIGH | Use proven implementations from Scroll/Summa |
//! | Constraint count blowup | MEDIUM | Profile early with T2.11 benchmark |
//! | Proving time too slow | MEDIUM | Optimize lookup tables, consider k=20 |

/// Placeholder for the secp256k1 scalar multiplication gadget.
///
/// Will be implemented in Phase 2.
pub struct Secp256k1Gadget;

impl Secp256k1Gadget {
    /// TODO: Derive Ethereum address from a private key inside the circuit.
    ///
    /// Inputs:
    /// - `private_key`: 32-byte secp256k1 private key (private input)
    ///
    /// Outputs:
    /// - `address`: 20-byte Ethereum address (constrained against expected)
    ///
    /// This will:
    /// 1. Decompose the private key into 4-bit windows
    /// 2. Compute `P = k * G` using windowed scalar multiplication
    /// 3. Encode `P` as uncompressed public key (64 bytes)
    /// 4. Compute `keccak256(P.x || P.y)`
    /// 5. Extract the last 20 bytes as the address
    pub fn derive_address() {
        todo!("Phase 2: secp256k1 scalar multiplication gadget")
    }
}
