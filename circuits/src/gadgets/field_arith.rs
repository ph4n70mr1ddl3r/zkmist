//! Non-native field arithmetic helpers for Halo2-KZG circuits.
//!
//! When performing secp256k1 operations inside a BN254 Halo2 circuit, every
//! field element from the "outer" field (secp256k1, ~256-bit) must be
//! represented as multiple BN254 field elements ("limbs"). This module
//! defines the interface and helpers for constrained non-native arithmetic.
//!
//! # Limb representation
//!
//! A secp256k1 field element `x` is stored as 4 × 64-bit little-endian limbs:
//!
//! ```text
//! x = limb[0] + limb[1]·2^64 + limb[2]·2^128 + limb[3]·2^192
//! ```
//!
//! Each limb is a BN254 field element constrained to [0, 2^64).
//!
//! # Constraint strategy
//!
//! Every operation (add, mul, sub) must be **constrained** — the circuit
//! must enforce that the output is the unique correct result for the given
//! inputs. The constraint strategy for each operation is:
//!
//! ## Addition with carry propagation
//!
//! For each limb `i` (from 0 to 3):
//! 1. Copy `a[i]` and `b[i]` into the region
//! 2. Assign `carry_in[i]` (0 for limb 0, output of previous limb)
//! 3. Compute `raw = a[i] + b[i] + carry_in[i]`
//! 4. Assign `result[i] = raw mod 2^64`
//! 5. Assign `carry_out[i] = raw >> 64`
//! 6. Constrain: `a[i] + b[i] + carry_in[i] - result[i] - carry_out[i]·2^64 = 0`
//! 7. Range-check `carry_out[i]` to [0, 2] (max from two 64-bit adds + 1-bit carry)
//!
//! ## Modular reduction
//!
//! After raw addition, the result may exceed the secp256k1 field prime `p`.
//! Reduction is done by conditionally subtracting `p`:
//! 1. Compute `witness_should_reduce = (raw_result >= p)` (outside circuit)
//! 2. Assign `should_reduce` as a boolean advice cell
//! 3. Assign `reduced = raw_result - should_reduce · p`
//! 4. Constrain: `reduced + should_reduce · p = raw_result`
//! 5. Constrain: `should_reduce ∈ {0, 1}`
//!
//! ## Multiplication (schoolbook)
//!
//! The 4×4 schoolbook multiplication produces 16 partial products, each up
//! to 128 bits. These are accumulated into an 8-limb wide result, then
//! reduced mod p using the identity `2^256 ≡ c (mod p)` where
//! `c = 2^32 + 977 = 0x1000003D1`.
//!
//! Each partial product `a[i] * b[j]` is constrained via an `s_mul` gate.
//! Accumulation is constrained via `s_add` gates with carry propagation.
//! The wide-to-narrow reduction is constrained limb-by-limb.
//!
//! # Security considerations
//!
//! **Every limb must be range-checked.** Without range checks, a malicious
//! prover could assign limb values exceeding 2^64, bypassing carry logic
//! and producing invalid "field elements" that still satisfy the BN254
//! arithmetic gates. Range checks use Halo2 lookup tables (8-bit byte
//! decomposition, 8 lookups per 64-bit limb).
//!
//! **Carry values must be range-checked.** The carry between limbs is at
//! most 2 (for addition: max 2·(2^64 - 1) + 1 = 2^65 - 1, carry = 1;
//! for multiplication accumulation: larger, needs wider range).
//!
//! # Production recommendation
//!
//! For production use, consider using a proven non-native field arithmetic
//! library:
//!
//! - [`scroll-tech/halo2-secp256k1`](https://github.com/scroll-tech/halo2-secp256k1)
//!   — Optimized secp256k1 gadget for Halo2, used in Scroll's zkEVM.
//! - [`summa-dev/summa-solvency`](https://github.com/summa-dev/summa-solvency)
//!   — Exchange solverity proof with Halo2 non-native field arithmetic.
//! - [`privacy-scaling-explorations/halo2wrong`](https://github.com/privacy-scaling-explorations/halo2wrong)
//!   — General-purpose Halo2 gadgets including non-native field arithmetic.
//!
//! These libraries handle edge cases (overflow, reduction, point at infinity)
//! that are easy to get wrong in a hand-rolled implementation.

/// Maximum value of a 64-bit limb: 2^64 - 1.
pub const LIMB_MASK: u64 = u64::MAX;

/// Number of limbs for representing a 256-bit field element.
pub const NUM_LIMBS: usize = 4;

/// Bits per limb.
pub const LIMB_BITS: usize = 64;

/// secp256k1 field prime as 4 little-endian 64-bit limbs.
pub const SECP_P_LIMBS: [u64; NUM_LIMBS] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 group order as 4 little-endian 64-bit limbs.
pub const SECP_N_LIMBS: [u64; NUM_LIMBS] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// Reduction constant: 2^256 ≡ c (mod p_secp) where c = 2^32 + 977.
/// This is used to reduce a 512-bit schoolbook product to 256 bits.
pub const REDUCTION_CONSTANT: u64 = 0x1000003D1;
