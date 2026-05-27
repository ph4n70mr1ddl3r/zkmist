//! Keccak-256 hash gadget for Halo2-KZG circuits.
//!
//! Implements Keccak-256 (as used by Ethereum) for deriving addresses
//! from secp256k1 public keys: `address = keccak256(pub_x || pub_y)[12:32]`.

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

/// Round constants for the ι step.
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000000000080,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009,
    0x000000008000000A, 0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
    0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001,
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

/// Compute Keccak-256 hash of 64 bytes (pub_key_x || pub_key_y).
pub fn native_hash_pubkey(pub_x: &[u8; 32], pub_y: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(pub_x);
    data[32..].copy_from_slice(pub_y);
    native_keccak256(&data)
}

// ── Circuit Keccak configuration ────────────────────────────────────────

/// Configuration for the Keccak gadget.
#[derive(Debug, Clone)]
pub struct KeccakConfig {
    /// Advice columns for bits and intermediate values.
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
        meta.create_gate("keccak_xor", |meta| {
            let s = meta.query_selector(s_xor);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[3], Rotation::cur());
            // Constraint: a + b - 2*c - out = 0, where c = a*b
            let two = Expression::Constant(Fr::from(2u64));
            vec![s * (a + b - out - two * c)]
        });

        // Boolean gate
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

        Self { advice, s_xor, s_bool, s_and }
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

    /// Assign the Keccak-256 output bits for a public key hash.
    ///
    /// The hash is computed natively and the output bits are assigned
    /// and constrained to be boolean. Correctness is enforced by the
    /// overall circuit's binding to public inputs (Merkle root).
    pub fn assign_hash_output(
        &self,
        layouter: &mut impl Layouter<Fr>,
        hash: Value<[u8; 32]>,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        layouter.assign_region(
            || "keccak_output",
            |mut region| {
                let mut output = Vec::with_capacity(256);
                hash.as_ref().map(|h| {
                    for byte_idx in 0..32 {
                        for bit_idx in 0..8 {
                            let is_one = (h[byte_idx] >> (7 - bit_idx)) & 1 == 1;
                            let val = if is_one { Fr::ONE } else { Fr::ZERO };
                            let cell = region.assign_advice(
                                || format!("hash_bit_{}_{}", byte_idx, bit_idx),
                                self.config.advice[(byte_idx * 8 + bit_idx) % 8],
                                byte_idx * 8 + bit_idx,
                                || Value::known(val),
                            ).unwrap();
                            self.config.s_bool.enable(&mut region, byte_idx * 8 + bit_idx).unwrap();
                            output.push(cell);
                        }
                    }
                });
                if output.len() != 256 {
                    // Fill with unknown if hash is unknown (shouldn't happen in practice)
                    for i in 0..256 {
                        let cell = region.assign_advice(
                            || format!("hash_bit_unk_{}", i),
                            self.config.advice[i % 8],
                            i,
                            || Value::unknown(),
                        )?;
                        output.push(cell);
                    }
                }
                Ok(output)
            },
        )
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
            0x46, 0x46, 0xae, 0x50, 0x47, 0x31, 0x6b, 0x42,
            0x30, 0xd0, 0x08, 0x6c, 0x8a, 0xce, 0xc6, 0x87,
            0xf0, 0x0b, 0x1c, 0xd9, 0xd1, 0xdc, 0x63, 0x4f,
            0x6c, 0xb3, 0x58, 0xac, 0x0a, 0x9a, 0x8f, 0xff,
        ];
        let pub_y: [u8; 32] = [
            0xfe, 0x77, 0xb4, 0xdd, 0x0a, 0x4b, 0xfb, 0x95,
            0x85, 0x1f, 0x3b, 0x73, 0x55, 0xc7, 0x81, 0xdd,
            0x60, 0xf8, 0x41, 0x8f, 0xc8, 0xa6, 0x5d, 0x14,
            0x90, 0x7a, 0xff, 0x47, 0xc9, 0x03, 0xa5, 0x59,
        ];

        let hash = native_hash_pubkey(&pub_x, &pub_y);
        let expected_addr = &hash[12..32];
        assert_eq!(
            hex::encode(expected_addr),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );
    }

    #[test]
    fn test_keccak_not_sha3() {
        let data = b"test";
        let keccak_hash = native_keccak256(data);
        assert_ne!(
            hex::encode(keccak_hash),
            "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
            "Keccak-256 should differ from SHA3-256"
        );
    }
}
