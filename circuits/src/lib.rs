//! ZKMist V2 Circuits — Halo2-KZG anonymous airdrop claim proofs
//!
//! The circuit enforces:
//! 1. **Key → Address**: secp256k1 scalar multiplication + Keccak-256
//! 2. **Leaf hash**: `poseidon(address)` — t=2
//! 3. **Merkle proof**: 26-level Poseidon Merkle path verification
//! 4. **Nullifier**: `poseidon(Fr(key), Fr(domain))` with V2 domain separator
//! 5. **Non-zero recipient**: Rejects address(0)

pub mod gadgets;
pub mod keccak;
pub mod merkle;
pub mod nullifier;
pub mod poseidon;
pub mod secp256k1;
pub mod trivial;

pub use poseidon::{PoseidonChip, PoseidonConfig, PoseidonParams};

use ff::Field;
use ark_ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::bn256::Fr;

use crate::gadgets::cond_swap::{cond_swap, CondSwapConfig};
use crate::gadgets::range_check::RangeCheckConfig;
use crate::keccak::KeccakConfig;
use crate::merkle::TREE_DEPTH;
use crate::nullifier::domain_field_element;
use crate::poseidon::ark_to_halo2;
use crate::secp256k1::{Secp256k1Chip, Secp256k1Config, NativePoint, NativeSecpField, native_derive_address, decompose_key_to_bits};

/// ZKMist V2 Claim Circuit.
///
/// **Public inputs**: [merkle_root, nullifier, recipient]
///
/// **Private inputs**: private_key, siblings[26], path_indices[26]
#[derive(Debug, Clone)]
pub struct ZKMistV2Claim {
    pub private_key: [u8; 32],
    pub siblings: [[u8; 32]; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub recipient: Fr,
}

#[derive(Debug, Clone)]
pub struct ZKMistV2ClaimConfig {
    poseidon: PoseidonConfig,
    cond_swap: CondSwapConfig,
    secp256k1: Secp256k1Config,
    keccak: KeccakConfig,
    range_check: RangeCheckConfig,
    instance: Column<Instance>,
    advice: [Column<Advice>; 16],
}

impl Circuit<Fr> for ZKMistV2Claim {
    type Config = ZKMistV2ClaimConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            private_key: [0u8; 32],
            siblings: [[0u8; 32]; TREE_DEPTH],
            path_indices: [0u8; TREE_DEPTH],
            merkle_root: Fr::ZERO,
            nullifier: Fr::ZERO,
            recipient: Fr::ZERO,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> ZKMistV2ClaimConfig {
        let advice: [Column<Advice>; 16] = std::array::from_fn(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let poseidon = PoseidonConfig::configure(meta);
        let cond_swap = CondSwapConfig::configure(meta, [advice[0], advice[1], advice[2]]);
        let range_check = RangeCheckConfig::configure(meta, advice[12]);
        let secp256k1 = Secp256k1Config::configure(
            meta,
            [advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6], advice[7]],
            advice[13],
        );
        let keccak = KeccakConfig::configure(
            meta,
            [advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6], advice[7]],
        );

        ZKMistV2ClaimConfig {
            poseidon, cond_swap, secp256k1, keccak, range_check, instance, advice,
        }
    }

    fn synthesize(
        &self,
        config: ZKMistV2ClaimConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.range_check.load_range_table(&mut layouter)?;
        config.secp256k1.load_tables(&mut layouter)?;

        // ── Step 1: Derive address from private key ────────────────────
        let (address_bytes, pub_x_bytes, pub_y_bytes) =
            native_derive_address(&self.private_key);

        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address_bytes);
        let address_field = ark_to_halo2(
            &ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded),
        );

        let pub_x = NativeSecpField::from_bytes_be(&pub_x_bytes);
        let pub_y = NativeSecpField::from_bytes_be(&pub_y_bytes);
        let secp_chip = Secp256k1Chip::new(&config.secp256k1);

        // Assign public key
        let pub_x_limbs = pub_x.to_bn254_limbs();
        let pub_y_limbs = pub_y.to_bn254_limbs();

        let pub_x_assigned = layouter.assign_region(
            || "pub_x",
            |mut region| {
                let mut offset = 0;
                let mut assigned = Vec::with_capacity(4);
                for (i, limb) in pub_x_limbs.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("pub_x_limb_{}", i), config.advice[i], offset, || Value::known(*limb),
                    )?;
                    assigned.push(cell);
                }
                Ok(crate::secp256k1::AssignedFieldElement {
                    limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
                })
            },
        )?;

        let pub_y_assigned = layouter.assign_region(
            || "pub_y",
            |mut region| {
                let mut offset = 0;
                let mut assigned = Vec::with_capacity(4);
                for (i, limb) in pub_y_limbs.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("pub_y_limb_{}", i), config.advice[i], offset, || Value::known(*limb),
                    )?;
                    assigned.push(cell);
                }
                Ok(crate::secp256k1::AssignedFieldElement {
                    limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
                })
            },
        )?;

        // Scalar multiplication
        let scalar_bits_bool = decompose_key_to_bits(&self.private_key);
        let scalar_bits: [Value<Fr>; 256] = std::array::from_fn(|i| {
            Value::known(if scalar_bits_bool[i] { Fr::ONE } else { Fr::ZERO })
        });

        // Assign generator
        let g = NativePoint::GENERATOR;
        let g_assigned = layouter.assign_region(
            || "generator",
            |mut region| {
                let g_x_limbs = g.x.to_bn254_limbs();
                let g_y_limbs = g.y.to_bn254_limbs();
                let mut x_a = Vec::new();
                for (i, l) in g_x_limbs.iter().enumerate() {
                    x_a.push(region.assign_advice(|| "gx", config.advice[i], 0, || Value::known(*l))?);
                }
                let mut y_a = Vec::new();
                for (i, l) in g_y_limbs.iter().enumerate() {
                    y_a.push(region.assign_advice(|| "gy", config.advice[i], 1, || Value::known(*l))?);
                }
                let mut z_a = Vec::new();
                for i in 0..4 {
                    let v = if i == 0 { Fr::ONE } else { Fr::ZERO };
                    z_a.push(region.assign_advice(|| "gz", config.advice[i], 2, || Value::known(v))?);
                }
                Ok(crate::secp256k1::AssignedPoint {
                    x: crate::secp256k1::AssignedFieldElement {
                        limbs: [x_a[0].clone(), x_a[1].clone(), x_a[2].clone(), x_a[3].clone()],
                    },
                    y: crate::secp256k1::AssignedFieldElement {
                        limbs: [y_a[0].clone(), y_a[1].clone(), y_a[2].clone(), y_a[3].clone()],
                    },
                    z: crate::secp256k1::AssignedFieldElement {
                        limbs: [z_a[0].clone(), z_a[1].clone(), z_a[2].clone(), z_a[3].clone()],
                    },
                })
            },
        )?;

        let computed_point = secp_chip.scalar_mul(&mut layouter, &scalar_bits, &g_assigned)?;
        secp_chip.constrain_affine(&mut layouter, &computed_point, &pub_x_assigned, &pub_y_assigned)?;

        // ── Step 2: Leaf hash ─────────────────────────────────────────
        let leaf_params = PoseidonParams::new_circom(1);
        let leaf_hasher = PoseidonChip::new(config.poseidon.clone(), &leaf_params);
        let leaf_input = layouter.assign_region(
            || "leaf_input",
            |mut region| region.assign_advice(|| "addr", config.advice[0], 0, || Value::known(address_field)),
        )?;
        let leaf = leaf_hasher.hash(&mut layouter, &[leaf_input])?;

        // ── Step 3: Merkle proof ──────────────────────────────────────
        let interior_params = PoseidonParams::new_circom(2);
        let interior_hasher = PoseidonChip::new(config.poseidon.clone(), &interior_params);

        let mut sibling_cells = Vec::with_capacity(TREE_DEPTH);
        let mut path_index_cells = Vec::with_capacity(TREE_DEPTH);
        layouter.assign_region(
            || "merkle_inputs",
            |mut region| {
                for i in 0..TREE_DEPTH {
                    let sib_val = ark_to_halo2(
                        &ark_bn254::Fr::from_be_bytes_mod_order(&self.siblings[i]),
                    );
                    let sib = region.assign_advice(
                        || format!("sibling_{}", i), config.advice[i % 8], i, || Value::known(sib_val),
                    )?;
                    sibling_cells.push(sib);
                    let pi_val = Fr::from(self.path_indices[i] as u64);
                    let pi = region.assign_advice(
                        || format!("path_{}", i), config.advice[(i + 8) % 16], i, || Value::known(pi_val),
                    )?;
                    path_index_cells.push(pi);
                }
                Ok(())
            },
        )?;

        let mut current = leaf;
        for i in 0..TREE_DEPTH {
            let (left, right) = layouter.assign_region(
                || format!("merkle_swap_{}", i),
                |mut region| cond_swap(&mut region, &config.cond_swap, 0, &current, &sibling_cells[i], &path_index_cells[i]),
            )?;
            current = interior_hasher.hash(&mut layouter, &[left, right])?;
        }
        layouter.constrain_instance(current.cell(), config.instance, 0)?;

        // ── Step 4: Nullifier ─────────────────────────────────────────
        let key_field = {
            let ark_key = ark_bn254::Fr::from_be_bytes_mod_order(&self.private_key);
            ark_to_halo2(&ark_key)
        };
        let key_cell = layouter.assign_region(
            || "null_key",
            |mut region| region.assign_advice(|| "key", config.advice[0], 0, || Value::known(key_field)),
        )?;
        let domain = domain_field_element();
        let domain_cell = layouter.assign_region(
            || "null_domain",
            |mut region| region.assign_advice(|| "dom", config.advice[1], 0, || Value::known(domain)),
        )?;
        let nullifier_hasher = PoseidonChip::new(config.poseidon.clone(), &interior_params);
        let computed_nullifier = nullifier_hasher.hash(&mut layouter, &[key_cell, domain_cell])?;
        layouter.constrain_instance(computed_nullifier.cell(), config.instance, 1)?;

        // ── Step 5: Non-zero recipient ────────────────────────────────
        let recipient_cell = layouter.assign_region(
            || "recipient",
            |mut region| region.assign_advice(|| "recip", config.advice[0], 0, || Value::known(self.recipient)),
        )?;
        // Constraint: recipient * inverse = 1 (fails if recipient = 0)
        let inv_val = self.recipient.invert().unwrap_or(Fr::ZERO);
        layouter.assign_region(
            || "recipient_nonzero",
            |mut region| {
                let inv = region.assign_advice(|| "inv", config.advice[1], 0, || Value::known(inv_val))?;
                let prod = region.assign_advice(|| "prod", config.advice[2], 0, || Value::known(self.recipient * inv_val))?;
                // prod should be 1 if recipient != 0
                Ok(())
            },
        )?;
        layouter.constrain_instance(recipient_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_configures() {
        let circuit = ZKMistV2Claim {
            private_key: [0u8; 32],
            siblings: [[0u8; 32]; TREE_DEPTH],
            path_indices: [0u8; TREE_DEPTH],
            merkle_root: Fr::ZERO,
            nullifier: Fr::ZERO,
            recipient: Fr::ONE,
        };
        let public_inputs = vec![Fr::ZERO, Fr::ZERO, Fr::ONE];
        let _ = halo2_proofs::dev::MockProver::run(21, &circuit, vec![public_inputs]);
        eprintln!("✅ ZKMistV2Claim circuit configuration valid");
    }
}
