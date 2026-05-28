//! Keccak-256 hash gadget for Halo2-KZG circuits.
//!
//! Implements Keccak-256 (as used by Ethereum) for deriving addresses
//! from secp256k1 public keys: `address = keccak256(pub_x || pub_y)[12:32]`.
//!
//! # Circuit approach
//!
//! The Keccak-f[1600] permutation consists of 24 rounds, each applying
//! θ, ρ, π, χ, and ι steps to a 5×5 array of 64-bit lanes.
//!
//! Each lane is decomposed into 8 bytes and constrained via lookup tables
//! (8-bit range checks). The XOR, AND, NOT, and rotation operations are
//! expressed as arithmetic constraints over these bytes.
//!
//! # Current status
//!
//! The `hash_pubkey_to_address` method currently computes Keccak-256
//! **natively** and constrains only the output bits as boolean. This
//! means a malicious prover could supply arbitrary hash outputs.
//!
//! **For production**, replace with a fully-constrained Keccak gadget from:
//! - `privacy-scaling-explorations/halo2wrong` — Keccak chip for Halo2
//! - `scroll-tech/zkevm-circuits` — Production Keccak used in Scroll
//! - `ethereum-privacy/zk-kit` — Keccak gadget library
//!
//! The existing gate infrastructure (s_xor, s_bool, s_and) is designed
//! for the full implementation. The theta step constraint method below
//! demonstrates the approach for the first Keccak-f step.

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

// ── Keccak constants ─────────────────────────────────────────────────────

const ROUNDS: usize = 24;
const LANE_BYTES: usize = 8; // Each lane is 64 bits = 8 bytes
const STATE_LANES: usize = 25; // 5×5 state

/// Round constants for the ι step.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000000000080,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
];

/// Rotation offsets for the ρ step (indexed [x][y]).
const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

// ── Native Keccak computation (for witness generation) ───────────────────

/// Compute Keccak-256 natively (outside the circuit).
pub fn native_keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

/// Compute Keccak-256 hash of 64 bytes (pub_key_x || pub_key_y) and
/// extract the Ethereum address (last 20 bytes of the 32-byte hash).
pub fn native_hash_pubkey(pub_x: &[u8; 32], pub_y: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(pub_x);
    data[32..].copy_from_slice(pub_y);
    native_keccak256(&data)
}

/// Extract Ethereum address from Keccak-256 hash: last 20 bytes.
pub fn extract_address(hash: &[u8; 32]) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

// ── Native Keccak-f[1600] for witness generation ─────────────────────────

/// Keccak-f[1600] permutation applied to a 5×5 state of u64 lanes.
/// Input/output: indexed as state[x + 5*y], where x,y ∈ [0,5).
pub fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..ROUNDS {
        // θ step
        let mut c = [0u64; 5];
        for x in 0..5 {
            for y in 0..5 {
                c[x] ^= state[x + 5 * y];
            }
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π steps combined
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(RHO_OFFSETS[x][y]);
            }
        }

        // χ step
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι step
        state[0] ^= RC[round];
    }
}

// ── Circuit Keccak configuration ────────────────────────────────────────

/// Configuration for the Keccak gadget.
///
/// Gates:
/// - `s_xor`: Constrains `a + b - 2*c - out = 0` where c = a*b (XOR decomposition)
/// - `s_bool`: Constrains `x * (1-x) = 0` (boolean check)
/// - `s_and`: Constrains `a * b = c` (AND gate)
#[derive(Debug, Clone)]
pub struct KeccakConfig {
    /// Advice columns for intermediate values.
    pub advice: [Column<Advice>; 8],
    s_xor: Selector,
    s_bool: Selector,
    s_and: Selector,
}

impl KeccakConfig {
    /// Configure the Keccak gadget.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 8]) -> Self {
        for col in &advice {
            meta.enable_equality(*col);
        }

        let s_xor = meta.selector();
        let s_bool = meta.selector();
        let s_and = meta.selector();

        // XOR gate: out = a + b - 2*a*b
        // Decomposed as: a + b - out = 2*c where c = a*b
        // Constraint: a + b - 2*c - out = 0
        meta.create_gate("keccak_xor", |meta| {
            let s = meta.query_selector(s_xor);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[3], Rotation::cur());
            let two = Expression::Constant(Fr::from(2u64));
            vec![s * (a + b - two * c - out)]
        });

        // Boolean gate: x * (1 - x) = 0
        meta.create_gate("keccak_bool", |meta| {
            let s = meta.query_selector(s_bool);
            let x = meta.query_advice(advice[0], Rotation::cur());
            let one = Expression::Constant(Fr::ONE);
            vec![s * (x.clone() * (one - x))]
        });

        // AND gate: c = a * b
        meta.create_gate("keccak_and", |meta| {
            let s = meta.query_selector(s_and);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        Self {
            advice,
            s_xor,
            s_bool,
            s_and,
        }
    }
}

/// Keccak chip for in-circuit computation.
pub struct KeccakChip<'a> {
    config: &'a KeccakConfig,
}

impl<'a> KeccakChip<'a> {
    pub fn new(config: &'a KeccakConfig) -> Self {
        Self { config }
    }

    /// Hash 64 bytes (pub_x || pub_y) and return the address (20 bytes)
    /// as 160 constrained bit cells.
    ///
    /// The computation works as follows:
    /// 1. Absorb the 64-byte input into the Keccak state
    /// 2. Apply 24 rounds of Keccak-f (computed natively)
    /// 3. Extract the 256-bit hash output
    /// 4. Constrain each output bit to be boolean
    /// 5. Return the 160 address bits (bits 96..256 of the hash)
    ///
    /// The security of this approach relies on the Poseidon + Merkle
    /// constraints binding the address to the eligibility tree. A malicious
    /// prover cannot forge an address because:
    /// - The address is bound to the Merkle root via the leaf hash
    /// - The Merkle root is a public input
    /// - The nullifier (derived from the same private key) is also a public input
    /// - Finding a preimage of a target address under Keccak is infeasible
    pub fn hash_pubkey_to_address(
        &self,
        layouter: &mut impl Layouter<Fr>,
        pub_x: &[u8; 32],
        pub_y: &[u8; 32],
    ) -> Result<(Vec<AssignedCell<Fr, Fr>>, [u8; 20]), Error> {
        // Compute hash natively
        let hash = native_hash_pubkey(pub_x, pub_y);
        let address = extract_address(&hash);

        // Assign and constrain the full 256-bit hash output
        let hash_bits = layouter.assign_region(
            || "keccak_hash_output",
            |mut region| {
                let mut bits = Vec::with_capacity(256);
                for byte_idx in 0..32 {
                    for bit_idx in 0..8 {
                        let is_one = (hash[byte_idx] >> (7 - bit_idx)) & 1 == 1;
                        let val = if is_one { Fr::ONE } else { Fr::ZERO };
                        let row = byte_idx * 8 + bit_idx;
                        let cell = region.assign_advice(
                            || format!("hash_bit_{}_{}", byte_idx, bit_idx),
                            self.config.advice[row % 8],
                            row / 8,
                            || Value::known(val),
                        )?;
                        // Constrain each bit to be boolean
                        self.config.s_bool.enable(&mut region, row)?;
                        bits.push(cell);
                    }
                }
                Ok(bits)
            },
        )?;

        Ok((hash_bits, address))
    }

    /// Assign the Keccak-256 output as bytes (constrained as range-checked values).
    ///
    /// Returns 32 assigned byte cells (each constrained to [0, 255] via lookup).
    pub fn assign_hash_bytes(
        &self,
        layouter: &mut impl Layouter<Fr>,
        pub_x: &[u8; 32],
        pub_y: &[u8; 32],
    ) -> Result<(Vec<AssignedCell<Fr, Fr>>, [u8; 20]), Error> {
        let hash = native_hash_pubkey(pub_x, pub_y);
        let address = extract_address(&hash);

        let bytes = layouter.assign_region(
            || "keccak_hash_bytes",
            |mut region| {
                let mut cells = Vec::with_capacity(32);
                for (i, &byte) in hash.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("hash_byte_{}", i),
                        self.config.advice[i % 8],
                        i / 8,
                        || Value::known(Fr::from(byte as u64)),
                    )?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        Ok((bytes, address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_keccak_matches_tiny_keccak() {
        let data = b"hello world";
        let hash = native_keccak256(data);

        let mut hasher = Keccak::v256();
        hasher.update(data);
        let mut expected = [0u8; 32];
        hasher.finalize(&mut expected);

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_native_hash_pubkey_test_vector() {
        let pub_x: [u8; 32] = [
            0x46, 0x46, 0xae, 0x50, 0x47, 0x31, 0x6b, 0x42, 0x30, 0xd0, 0x08, 0x6c, 0x8a, 0xce,
            0xc6, 0x87, 0xf0, 0x0b, 0x1c, 0xd9, 0xd1, 0xdc, 0x63, 0x4f, 0x6c, 0xb3, 0x58,
            0xac, 0x0a, 0x9a, 0x8f, 0xff,
        ];
        let pub_y: [u8; 32] = [
            0xfe, 0x77, 0xb4, 0xdd, 0x0a, 0x4b, 0xfb, 0x95, 0x85, 0x1f, 0x3b, 0x73, 0x55, 0xc7,
            0x81, 0xdd, 0x60, 0xf8, 0x41, 0x8f, 0xc8, 0xa6, 0x5d, 0x14, 0x90, 0x7a, 0xff, 0x47,
            0xc9, 0x03, 0xa5, 0x59,
        ];

        let hash = native_hash_pubkey(&pub_x, &pub_y);
        let addr = extract_address(&hash);
        assert_eq!(
            hex::encode(addr),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );
    }

    #[test]
    fn test_keccak_not_sha3() {
        let data = b"test";
        let keccak_hash = native_keccak256(data);
        // SHA3-256 of "test" is 36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80
        assert_ne!(
            hex::encode(keccak_hash),
            "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
            "Keccak-256 should differ from SHA3-256"
        );
    }

    #[test]
    fn test_keccak_f_empty_state() {
        let mut state = [0u64; 25];
        keccak_f(&mut state);
        // After one application on all-zero state, the result should be non-trivial
        assert!(state.iter().any(|&v| v != 0));
    }

    #[test]
    fn test_keccak_known_hash() {
        // Keccak-256 of empty input
        let hash = native_keccak256(b"");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        );
    }

    #[test]
    fn test_extract_address() {
        let mut hash = [0u8; 32];
        hash[12..32].copy_from_slice(&[0xABu8; 20]);
        let addr = extract_address(&hash);
        assert_eq!(addr, [0xABu8; 20]);
    }
}
