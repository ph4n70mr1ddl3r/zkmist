//! Nullifier computation gadget for Halo2-KZG circuits.
//!
//! Computes `nullifier = poseidon(Fr(privateKey), Fr(domain))` inside
//! the circuit and constrains it to match the expected public input.
//!
//! V2 uses `"ZKMist_V2_NULLIFIER"` for domain separation.

use ark_ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use halo2curves::bn256::Fr;

use crate::poseidon::{native_poseidon, PoseidonChip, PoseidonConfig, PoseidonParams};

/// V2 nullifier domain separator (19 bytes).
pub const NULLIFIER_DOMAIN_V2: &[u8; 19] = b"ZKMist_V2_NULLIFIER";

/// Compute the nullifier natively (outside the circuit).
pub fn native_compute_nullifier(key: &Fr, params: &PoseidonParams) -> Fr {
    let domain = domain_field_element();
    native_poseidon(params, &[*key, domain])
}

/// Get the V2 domain separator as a Halo2 Fr element.
pub fn domain_field_element() -> Fr {
    let mut domain_padded = [0u8; 32];
    domain_padded[..NULLIFIER_DOMAIN_V2.len()].copy_from_slice(NULLIFIER_DOMAIN_V2);
    let ark = ark_bn254::Fr::from_be_bytes_mod_order(&domain_padded);
    crate::poseidon::ark_to_halo2(&ark)
}

/// Compute the nullifier inside a Halo2 circuit and constrain it.
pub fn compute_nullifier(
    layouter: &mut impl Layouter<Fr>,
    poseidon_config: &PoseidonConfig,
    params: &PoseidonParams,
    private_key: &AssignedCell<Fr, Fr>,
    expected_nullifier: &AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let chip = PoseidonChip::new(poseidon_config.clone(), params);

    let domain = domain_field_element();
    let domain_cell = layouter.assign_region(
        || "nullifier_domain",
        |mut region| {
            region.assign_advice(
                || "domain",
                poseidon_config.advice[0],
                0,
                || Value::known(domain),
            )
        },
    )?;

    let nullifier = chip.hash(layouter, &[private_key.clone(), domain_cell])?;

    // Constrain nullifier == expected via a region copy constraint
    layouter.assign_region(
        || "nullifier_eq",
        |mut region| {
            let nc = region.assign_advice(
                || "n",
                poseidon_config.advice[0],
                0,
                || nullifier.value().copied(),
            )?;
            region.constrain_equal(nullifier.cell(), nc.cell())?;
            let ec = region.assign_advice(
                || "e",
                poseidon_config.advice[1],
                0,
                || expected_nullifier.value().copied(),
            )?;
            region.constrain_equal(expected_nullifier.cell(), ec.cell())?;
            region.constrain_equal(nc.cell(), ec.cell())?;
            Ok(())
        },
    )?;

    Ok(nullifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_nullifier_differs_from_v1() {
        let params = PoseidonParams::new_circom(2);
        let key = crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from(42u64));

        let v2 = native_compute_nullifier(&key, &params);

        let v1_bytes = b"ZKMist_V1_NULLIFIER";
        let mut v1_padded = [0u8; 32];
        v1_padded[..v1_bytes.len()].copy_from_slice(v1_bytes);
        let v1_domain =
            crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&v1_padded));
        let v1 = native_poseidon(&params, &[key, v1_domain]);

        assert_ne!(v2, v1, "V2 nullifier must differ from V1");
    }

    #[test]
    fn test_nullifier_deterministic() {
        let params = PoseidonParams::new_circom(2);
        let key = crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from(123u64));
        let n1 = native_compute_nullifier(&key, &params);
        let n2 = native_compute_nullifier(&key, &params);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_unique_per_key() {
        let params = PoseidonParams::new_circom(2);
        let k1 = crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from(1u64));
        let k2 = crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from(2u64));
        let n1 = native_compute_nullifier(&k1, &params);
        let n2 = native_compute_nullifier(&k2, &params);
        assert_ne!(n1, n2);
    }
}
