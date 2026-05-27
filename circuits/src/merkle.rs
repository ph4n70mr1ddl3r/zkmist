//! Merkle proof verification gadget for Halo2-KZG circuits.
//!
//! Verifies a 26-level Poseidon Merkle proof of address membership
//! in the eligibility tree.
//!
//! # Merkle path convention
//!
//! ```text
//! path_index[i] = 0 → current is LEFT child  → parent = poseidon(current, sibling)
//! path_index[i] = 1 → current is RIGHT child → parent = poseidon(sibling, current)
//! ```

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::Error,
};
use halo2curves::bn256::Fr;

use crate::gadgets::cond_swap::{cond_swap, CondSwapConfig};
use crate::poseidon::{native_poseidon, PoseidonChip, PoseidonConfig, PoseidonParams};

/// Tree depth for the production eligibility tree.
pub const TREE_DEPTH: usize = 26;

/// Compute the Merkle root natively (outside the circuit).
pub fn native_verify_merkle_proof(
    leaf: &Fr,
    siblings: &[Fr],
    path_indices: &[Fr],
    params: &PoseidonParams,
) -> Fr {
    assert_eq!(siblings.len(), path_indices.len());
    let mut current = *leaf;
    for i in 0..siblings.len() {
        let (left, right) = if path_indices[i] == Fr::ONE {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = native_poseidon(params, &[left, right]);
    }
    current
}

/// Verify a Merkle proof inside a Halo2 circuit.
///
/// Returns the computed root as an assigned cell. The caller should constrain
/// it to equal the expected root (typically a public input).
pub fn verify_merkle_proof(
    layouter: &mut impl Layouter<Fr>,
    poseidon_config: &PoseidonConfig,
    cond_swap_config: &CondSwapConfig,
    interior_params: &PoseidonParams,
    leaf: &AssignedCell<Fr, Fr>,
    siblings: &[AssignedCell<Fr, Fr>],
    path_indices: &[AssignedCell<Fr, Fr>],
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let depth = siblings.len();
    assert_eq!(path_indices.len(), depth);

    let chip = PoseidonChip::new(poseidon_config.clone(), interior_params);
    let mut current = leaf.clone();

    for i in 0..depth {
        let (left, right) = layouter.assign_region(
            || format!("merkle_swap_{}", i),
            |mut region| {
                cond_swap(
                    &mut region,
                    cond_swap_config,
                    0,
                    &current,
                    &siblings[i],
                    &path_indices[i],
                )
            },
        )?;

        current = chip.hash(layouter, &[left, right])?;
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField as ArkPrimeField;

    use crate::poseidon::ark_to_halo2;

    #[test]
    fn test_native_merkle_matches_merkle_tree_lib() {
        let interior_params = PoseidonParams::new_circom(2);
        let leaf_params = PoseidonParams::new_circom(1);

        let addr_bytes: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
            0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(&addr_bytes);
        let leaf_ark = ark_bn254::Fr::from_be_bytes_mod_order(&padded);
        let leaf_halo2 = ark_to_halo2(&leaf_ark);

        let leaf_hash = native_poseidon(&leaf_params, &[leaf_halo2]);

        // Build a small tree using the merkle-tree crate
        let addresses = vec![addr_bytes];
        let (root_ark, proof) =
            zkmist_merkle_tree::build_tree_streaming_with_depth(&addresses, 4, Some(0));
        let (siblings_ark, path_indices_u8) = proof.expect("proof extraction failed");

        let siblings: Vec<Fr> = siblings_ark
            .iter()
            .map(|s| ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(s)))
            .collect();
        let path_indices: Vec<Fr> = path_indices_u8
            .iter()
            .map(|p| Fr::from(*p as u64))
            .collect();

        let computed_root =
            native_verify_merkle_proof(&leaf_hash, &siblings, &path_indices, &interior_params);

        let root_halo2 = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_ark));
        assert_eq!(computed_root, root_halo2, "Merkle root mismatch");
    }
}
