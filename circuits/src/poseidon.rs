//! Poseidon hash gadget for Halo2-KZG circuits.
//!
//! Implements the Poseidon permutation as Halo2 constraints, using the
//! **exact same round constants and MDS matrix** as `light-poseidon` v0.4
//! (Circom-compatible parameters on BN254).
//!
//! # Parameters
//!
//! | Variant   | t  | Inputs | R_F | R_P  | Usage                    |
//! |-----------|----|--------|-----|------|--------------------------|
//! | Leaf      | 2  | 1      | 8   | 56   | `poseidon(address)`      |
//! | Interior  | 3  | 2      | 8   | 57   | `poseidon(left, right)`  |
//! | Nullifier | 3  | 2      | 8   | 57   | `poseidon(key, domain)`  |
//!
//! # Gate design
//!
//! Four simple gates over 3 advice columns + 1 fixed column:
//!
//! | Gate       | Constraint                  | Purpose                      |
//! |------------|-----------------------------|------------------------------|
//! | `s_mul`    | `a * b - c = 0`            | Multiplication (S-box x^5)   |
//! | `s_add`    | `a + b - c = 0`            | Addition (MDS accumulation)  |
//! | `s_add_fix`| `a + fixed - b = 0`        | Add round constant (ARC)     |
//! | `s_mul_fix`| `a * fixed - b = 0`        | Multiply by MDS coefficient  |
//!
//! # S-box decomposition
//!
//! `x^5` is computed as 3 multiplications:
//! ```text
//! x²  = x * x
//! x⁴  = x² * x²
//! x⁵  = x⁴ * x       (via copy constraint from original x)
//! ```

use ark_ff::{BigInteger, PrimeField};
use ff::{Field, PrimeField as Halo2PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

// ── Field element conversion: ark-bn254 ↔ halo2curves ──────────────────

/// Convert an `ark_bn254::Fr` (big-endian) to `halo2curves::bn256::Fr` (little-endian).
///
/// Both represent elements of the same BN254 scalar field, but use opposite
/// byte orderings. The numerical value is preserved.
pub fn ark_to_halo2(ark: &ark_bn254::Fr) -> Fr {
    let be_bytes = ark.into_bigint().to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    // Reverse big-endian → little-endian
    padded.reverse();
    <Fr as Halo2PrimeField>::from_repr(padded).expect("valid BN254 field element")
}

/// Convert a `halo2curves::bn256::Fr` (little-endian) to `ark_bn254::Fr` (big-endian).
pub fn halo2_to_ark(h: &Fr) -> ark_bn254::Fr {
    let le_bytes = h.to_repr();
    let mut be_bytes = le_bytes.as_ref().to_vec();
    be_bytes.reverse();
    ark_bn254::Fr::from_be_bytes_mod_order(&be_bytes)
}

// ── Poseidon parameters (from light-poseidon) ──────────────────────────

/// Precomputed Poseidon parameters for a specific arity.
///
/// Round constants and MDS matrix are extracted from `light-poseidon` v0.4
/// (Circom-compatible parameters on BN254), converted to `halo2curves::Fr`.
#[derive(Clone, Debug)]
pub struct PoseidonParams {
    /// Round constants: `t * (R_F + R_P)` elements.
    /// Indexed as `ark[round * t + i]` for round `r`, state element `i`.
    pub ark: Vec<Fr>,
    /// MDS matrix: `t × t`.
    pub mds: Vec<Vec<Fr>>,
    /// State width (t).
    pub t: usize,
    /// Number of full rounds (R_F).
    pub full_rounds: usize,
    /// Number of partial rounds (R_P).
    pub partial_rounds: usize,
    /// S-box exponent (always 5).
    pub alpha: u64,
}

impl PoseidonParams {
    /// Generate Poseidon parameters for the given Circom-compatible arity.
    ///
    /// `nr_inputs` is the number of hash inputs (arity):
    /// - `1` → t=2, R_F=8, R_P=56 (leaf hasher)
    /// - `2` → t=3, R_F=8, R_P=57 (interior hasher, nullifier)
    pub fn new_circom(nr_inputs: usize) -> Self {
        use light_poseidon::parameters::bn254_x5;

        let ark_params = bn254_x5::get_poseidon_parameters::<ark_bn254::Fr>(nr_inputs as u8 + 1)
            .expect("light-poseidon parameter generation failed");

        let ark: Vec<Fr> = ark_params.ark.iter().map(ark_to_halo2).collect();
        let mds: Vec<Vec<Fr>> = ark_params
            .mds
            .iter()
            .map(|row| row.iter().map(ark_to_halo2).collect())
            .collect();

        Self {
            ark,
            mds,
            t: ark_params.width,
            full_rounds: ark_params.full_rounds,
            partial_rounds: ark_params.partial_rounds,
            alpha: ark_params.alpha,
        }
    }

    /// Total number of rounds.
    pub fn total_rounds(&self) -> usize {
        self.full_rounds + self.partial_rounds
    }

    /// Number of first-half full rounds (R_F / 2).
    pub fn half_full_rounds(&self) -> usize {
        self.full_rounds / 2
    }
}

// ── Native Poseidon permutation (for witness computation) ───────────────

/// Compute the Poseidon permutation natively (outside the circuit).
///
/// This produces the exact same output as `light_poseidon::Poseidon::hash()`.
/// Used to generate witness values for the Halo2 circuit.
pub fn native_poseidon(params: &PoseidonParams, inputs: &[Fr]) -> Fr {
    let t = params.t;
    assert_eq!(inputs.len(), t - 1, "inputs must be t-1 elements");

    // Initialize state: [0, input_1, input_2, ...]
    let mut state = vec![Fr::ZERO];
    state.extend_from_slice(inputs);
    assert_eq!(state.len(), t);

    let all_rounds = params.total_rounds();
    let half_full = params.half_full_rounds();

    // First half full rounds
    for round in 0..half_full {
        apply_arc(&mut state, round, params);
        apply_sbox_full(&mut state, params.alpha);
        apply_mds(&mut state, params);
    }

    // Partial rounds
    for round in half_full..half_full + params.partial_rounds {
        apply_arc(&mut state, round, params);
        apply_sbox_partial(&mut state, params.alpha);
        apply_mds(&mut state, params);
    }

    // Second half full rounds
    for round in half_full + params.partial_rounds..all_rounds {
        apply_arc(&mut state, round, params);
        apply_sbox_full(&mut state, params.alpha);
        apply_mds(&mut state, params);
    }

    state[0]
}

fn apply_arc(state: &mut [Fr], round: usize, params: &PoseidonParams) {
    for (i, s) in state.iter_mut().enumerate() {
        *s += params.ark[round * params.t + i];
    }
}

fn apply_sbox_full(state: &mut [Fr], alpha: u64) {
    for s in state.iter_mut() {
        *s = s.pow([alpha]);
    }
}

fn apply_sbox_partial(state: &mut [Fr], alpha: u64) {
    state[0] = state[0].pow([alpha]);
}

fn apply_mds(state: &mut [Fr], params: &PoseidonParams) {
    let t = params.t;
    let mut new_state = vec![Fr::ZERO; t];
    for (i, new_s) in new_state.iter_mut().enumerate().take(t) {
        for (j, s) in state.iter().enumerate() {
            let mut prod = *s;
            prod *= params.mds[i][j];
            *new_s += prod;
        }
    }
    state.copy_from_slice(&new_state);
}

// ── Halo2 circuit configuration ─────────────────────────────────────────

/// Circuit configuration for the Poseidon gadget.
///
/// Uses 3 advice columns and 1 fixed column with 4 simple gates.
#[derive(Debug, Clone)]
pub struct PoseidonConfig {
    /// Advice columns: general-purpose computation.
    pub advice: [Column<Advice>; 3],
    /// Fixed column: round constants and MDS coefficients.
    pub fixed: Column<Fixed>,
    /// Selector: `a * b = c`
    s_mul: Selector,
    /// Selector: `a + b = c`
    s_add: Selector,
    /// Selector: `a + fixed = b`
    s_add_fix: Selector,
    /// Selector: `a * fixed = b`
    s_mul_fix: Selector,
}

impl PoseidonConfig {
    /// Add the Poseidon columns and gates to the constraint system.
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let fixed = meta.fixed_column();

        // Enable copy constraints on all advice columns
        for col in &advice {
            meta.enable_equality(*col);
        }

        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_add_fix = meta.selector();
        let s_mul_fix = meta.selector();

        // Gate 1: a * b = c  (advice[0] * advice[1] = advice[2])
        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        // Gate 2: a + b = c  (advice[0] + advice[1] = advice[2])
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        // Gate 3: a + fixed = b  (advice[0] + fixed = advice[1])
        meta.create_gate("add_fix", |meta| {
            let s = meta.query_selector(s_add_fix);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a + f - b)]
        });

        // Gate 4: a * fixed = b  (advice[0] * fixed = advice[1])
        meta.create_gate("mul_fix", |meta| {
            let s = meta.query_selector(s_mul_fix);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * f - b)]
        });

        Self {
            advice,
            fixed,
            s_mul,
            s_add,
            s_add_fix,
            s_mul_fix,
        }
    }
}

// ── Poseidon chip (synthesis) ───────────────────────────────────────────

/// A Poseidon chip that computes `poseidon(inputs)` inside a Halo2 circuit.
pub struct PoseidonChip<'a> {
    config: PoseidonConfig,
    params: &'a PoseidonParams,
}

impl<'a> PoseidonChip<'a> {
    /// Create a new Poseidon chip with the given configuration and parameters.
    pub fn new(config: PoseidonConfig, params: &'a PoseidonParams) -> Self {
        Self { config, params }
    }

    /// Compute `poseidon(inputs)` inside a Halo2 layouter.
    ///
    /// `inputs` must be `t - 1` already-assigned cells. Returns the hash
    /// output as an assigned cell.
    pub fn hash(
        &self,
        layouter: &mut impl Layouter<Fr>,
        inputs: &[AssignedCell<Fr, Fr>],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let t = self.params.t;
        assert_eq!(inputs.len(), t - 1, "inputs must be t-1 elements");

        layouter.assign_region(
            || "poseidon_permutation",
            |mut region| {
                let mut offset = 0;

                // Initialize state: [0, inputs[0], inputs[1], ...]
                let mut state: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(t);

                // State[0] = 0 (capacity element)
                let zero_cell = region.assign_advice(
                    || "capacity = 0",
                    self.config.advice[0],
                    offset,
                    || Value::known(Fr::ZERO),
                )?;
                state.push(zero_cell);
                offset += 1;

                // Copy input cells into state
                for (i, input) in inputs.iter().enumerate() {
                    let input_val = input.value().copied();
                    let input_copy = region.assign_advice(
                        || format!("input_{}", i),
                        self.config.advice[0],
                        offset,
                        || input_val,
                    )?;
                    region.constrain_equal(input.cell(), input_copy.cell())?;
                    state.push(input_copy);
                    offset += 1;
                }

                let all_rounds = self.params.total_rounds();
                let half_full = self.params.half_full_rounds();

                // First half full rounds
                for round in 0..half_full {
                    offset = self.apply_round(&mut region, offset, &mut state, round, true)?;
                }

                // Partial rounds
                for round in half_full..half_full + self.params.partial_rounds {
                    offset = self.apply_round(&mut region, offset, &mut state, round, false)?;
                }

                // Second half full rounds
                for round in half_full + self.params.partial_rounds..all_rounds {
                    offset = self.apply_round(&mut region, offset, &mut state, round, true)?;
                }

                Ok(state[0].clone())
            },
        )
    }

    fn apply_round(
        &self,
        region: &mut Region<Fr>,
        mut offset: usize,
        state: &mut Vec<AssignedCell<Fr, Fr>>,
        round: usize,
        full_sbox: bool,
    ) -> Result<usize, Error> {
        let t = self.params.t;

        // ARC: state[i] += rc[round*t + i]
        let mut after_arc: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(t);
        for (i, _state_cell) in state.iter().enumerate() {
            let rc = self.params.ark[round * t + i];
            region.assign_fixed(
                || format!("rc_{}_{}", round, i),
                self.config.fixed,
                offset,
                || Value::known(rc),
            )?;

            let state_val = state[i].value().copied();
            let state_copy = region.assign_advice(
                || format!("arc_in_{}_{}", round, i),
                self.config.advice[0],
                offset,
                || state_val,
            )?;
            region.constrain_equal(state[i].cell(), state_copy.cell())?;

            let sum_val = state_val.map(|v| v + rc);
            let sum_cell = region.assign_advice(
                || format!("arc_out_{}_{}", round, i),
                self.config.advice[1],
                offset,
                || sum_val,
            )?;
            self.config.s_add_fix.enable(region, offset)?;
            after_arc.push(sum_cell);
            offset += 1;
        }

        // S-box (x^5)
        let mut after_sbox: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(t);
        for (i, arc_cell) in after_arc.iter().enumerate() {
            if full_sbox || i == 0 {
                let (sboxed, new_offset) = self.apply_sbox(region, offset, arc_cell)?;
                offset = new_offset;
                after_sbox.push(sboxed);
            } else {
                after_sbox.push(after_arc[i].clone());
            }
        }

        // MDS: new_state[j] = sum(mds[j][i] * sboxed[i])
        let mut new_state: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(t);
        for j in 0..t {
            let mut products: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(t);
            for (i, sbox_cell) in after_sbox.iter().enumerate() {
                let coeff = self.params.mds[j][i];
                region.assign_fixed(
                    || format!("mds_{}_{}", j, i),
                    self.config.fixed,
                    offset,
                    || Value::known(coeff),
                )?;

                let sboxed_val = sbox_cell.value().copied();
                let sboxed_copy = region.assign_advice(
                    || format!("mds_in_{}_{}", j, i),
                    self.config.advice[0],
                    offset,
                    || sboxed_val,
                )?;
                region.constrain_equal(sbox_cell.cell(), sboxed_copy.cell())?;

                let prod_val = sboxed_val.map(|v| v * coeff);
                let prod_cell = region.assign_advice(
                    || format!("mds_prod_{}_{}", j, i),
                    self.config.advice[1],
                    offset,
                    || prod_val,
                )?;
                self.config.s_mul_fix.enable(region, offset)?;
                products.push(prod_cell);
                offset += 1;
            }

            let output = self.sum_cells(region, &mut offset, &products)?;
            new_state.push(output);
        }

        *state = new_state;
        Ok(offset)
    }

    /// S-box: x → x^5 via x², x⁴, x⁵
    fn apply_sbox(
        &self,
        region: &mut Region<Fr>,
        mut offset: usize,
        input: &AssignedCell<Fr, Fr>,
    ) -> Result<(AssignedCell<Fr, Fr>, usize), Error> {
        let x_val = input.value().copied();

        // Copy input
        let x = region.assign_advice(|| "sbox_x", self.config.advice[0], offset, || x_val)?;
        region.constrain_equal(input.cell(), x.cell())?;

        // x² = x * x
        let x2_val = x_val.map(|v| v * v);
        region.assign_advice(|| "sbox_x_b", self.config.advice[1], offset, || x_val)?;
        let x2 = region.assign_advice(|| "sbox_x2", self.config.advice[2], offset, || x2_val)?;
        self.config.s_mul.enable(region, offset)?;
        offset += 1;

        // x⁴ = x² * x²
        let x4_val = x2_val.map(|v| v * v);
        let x2a = region.assign_advice(|| "sbox_x2_a", self.config.advice[0], offset, || x2_val)?;
        region.constrain_equal(x2.cell(), x2a.cell())?;
        region.assign_advice(|| "sbox_x2_b", self.config.advice[1], offset, || x2_val)?;
        let x4 = region.assign_advice(|| "sbox_x4", self.config.advice[2], offset, || x4_val)?;
        self.config.s_mul.enable(region, offset)?;
        offset += 1;

        // x⁵ = x⁴ * x
        let x5_val = x4_val.zip(x_val).map(|(a, b)| a * b);
        let x4c = region.assign_advice(|| "sbox_x4_a", self.config.advice[0], offset, || x4_val)?;
        region.constrain_equal(x4.cell(), x4c.cell())?;
        let xc = region.assign_advice(|| "sbox_x_b2", self.config.advice[1], offset, || x_val)?;
        region.constrain_equal(x.cell(), xc.cell())?;
        let x5 = region.assign_advice(|| "sbox_x5", self.config.advice[2], offset, || x5_val)?;
        self.config.s_mul.enable(region, offset)?;
        offset += 1;

        Ok((x5, offset))
    }

    /// Sum cells via chained add gates.
    fn sum_cells(
        &self,
        region: &mut Region<Fr>,
        offset: &mut usize,
        cells: &[AssignedCell<Fr, Fr>],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        if cells.is_empty() {
            let zero = region.assign_advice(
                || "sum_zero",
                self.config.advice[0],
                *offset,
                || Value::known(Fr::ZERO),
            )?;
            return Ok(zero);
        }
        if cells.len() == 1 {
            return Ok(cells[0].clone());
        }

        // acc = cells[0] + cells[1]
        let a_val = cells[0].value().copied();
        let b_val = cells[1].value().copied();
        let sum_val = a_val.zip(b_val).map(|(a, b)| a + b);

        let ac = region.assign_advice(|| "sa", self.config.advice[0], *offset, || a_val)?;
        region.constrain_equal(cells[0].cell(), ac.cell())?;
        let bc = region.assign_advice(|| "sb", self.config.advice[1], *offset, || b_val)?;
        region.constrain_equal(cells[1].cell(), bc.cell())?;
        let sum = region.assign_advice(|| "sc", self.config.advice[2], *offset, || sum_val)?;
        self.config.s_add.enable(region, *offset)?;
        *offset += 1;

        let mut acc = sum;
        for cell in cells.iter().skip(2) {
            let acc_val = acc.value().copied();
            let cell_val = cell.value().copied();
            let new_sum = acc_val.zip(cell_val).map(|(a, b)| a + b);

            let ac = region.assign_advice(|| "sac", self.config.advice[0], *offset, || acc_val)?;
            region.constrain_equal(acc.cell(), ac.cell())?;
            let cc = region.assign_advice(|| "scc", self.config.advice[1], *offset, || cell_val)?;
            region.constrain_equal(cell.cell(), cc.cell())?;
            let new_acc =
                region.assign_advice(|| "sns", self.config.advice[2], *offset, || new_sum)?;
            self.config.s_add.enable(region, *offset)?;
            *offset += 1;
            acc = new_acc;
        }

        Ok(acc)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::PrimeField;
    use halo2_proofs::dev::MockProver;
    use light_poseidon::PoseidonHasher;

    /// Verify that `ark_to_halo2` / `halo2_to_ark` are lossless.
    #[test]
    fn test_field_conversion_roundtrip() {
        for val in [1u64, 42, 255, 10000, 0xFFFFFFFF, u64::MAX] {
            let ark = ark_bn254::Fr::from(val);
            let h = ark_to_halo2(&ark);
            let ark_back = halo2_to_ark(&h);
            assert_eq!(
                ark.into_bigint().to_bytes_be(),
                ark_back.into_bigint().to_bytes_be(),
                "Roundtrip failed for {}",
                val
            );
        }
    }

    /// Verify native Poseidon matches light-poseidon for t=2.
    #[test]
    fn test_native_poseidon_matches_light_poseidon_t2() {
        let params = PoseidonParams::new_circom(1);
        assert_eq!(params.t, 2);
        assert_eq!(params.full_rounds, 8);
        assert_eq!(params.partial_rounds, 56);

        let input_ark = ark_bn254::Fr::from(1u64);
        let input_halo2 = ark_to_halo2(&input_ark);

        let our_output = native_poseidon(&params, &[input_halo2]);
        let our_ark = halo2_to_ark(&our_output);

        let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(1).unwrap();
        let lp_output = hasher.hash(&[input_ark]).unwrap();

        assert_eq!(
            our_ark.into_bigint().to_bytes_be(),
            lp_output.into_bigint().to_bytes_be(),
            "Native Poseidon (t=2) doesn't match light-poseidon"
        );
    }

    /// Verify native Poseidon matches light-poseidon for t=3.
    #[test]
    fn test_native_poseidon_matches_light_poseidon_t3() {
        let params = PoseidonParams::new_circom(2);
        assert_eq!(params.t, 3);
        assert_eq!(params.full_rounds, 8);
        assert_eq!(params.partial_rounds, 57);

        let input1_ark = ark_bn254::Fr::from(1u64);
        let input2_ark = ark_bn254::Fr::from(2u64);
        let input1_halo2 = ark_to_halo2(&input1_ark);
        let input2_halo2 = ark_to_halo2(&input2_ark);

        let our_output = native_poseidon(&params, &[input1_halo2, input2_halo2]);
        let our_ark = halo2_to_ark(&our_output);

        let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap();
        let lp_output = hasher.hash(&[input1_ark, input2_ark]).unwrap();

        assert_eq!(
            our_ark.into_bigint().to_bytes_be(),
            lp_output.into_bigint().to_bytes_be(),
            "Native Poseidon (t=3) doesn't match light-poseidon"
        );
    }

    /// PRD interior hash test vector: poseidon(Fr(1), Fr(2)) = 0x115cc0f5...
    #[test]
    fn test_prd_interior_hash_test_vector() {
        let params = PoseidonParams::new_circom(2);
        let input1 = ark_to_halo2(&ark_bn254::Fr::from(1u64));
        let input2 = ark_to_halo2(&ark_bn254::Fr::from(2u64));

        let output = native_poseidon(&params, &[input1, input2]);
        let output_ark = halo2_to_ark(&output);
        let output_hex = hex::encode(output_ark.into_bigint().to_bytes_be());

        assert_eq!(
            output_hex,
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
        );
    }

    /// PRD leaf hash test vector.
    #[test]
    fn test_prd_leaf_hash_test_vector() {
        let params = PoseidonParams::new_circom(1);
        let addr_bytes: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
            0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(&addr_bytes);
        let input_ark = ark_bn254::Fr::from_be_bytes_mod_order(&padded);
        let input_halo2 = ark_to_halo2(&input_ark);

        let output = native_poseidon(&params, &[input_halo2]);
        let output_ark = halo2_to_ark(&output);
        let output_hex = hex::encode(output_ark.into_bigint().to_bytes_be());

        assert_eq!(
            output_hex,
            "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9",
        );
    }

    /// PRD nullifier test vector.
    #[test]
    fn test_prd_nullifier_test_vector() {
        let params = PoseidonParams::new_circom(2);
        let key_bytes: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let domain_bytes = b"ZKMist_V1_NULLIFIER";
        let mut domain_padded = [0u8; 32];
        domain_padded[..domain_bytes.len()].copy_from_slice(domain_bytes);

        let key_ark = ark_bn254::Fr::from_be_bytes_mod_order(&key_bytes);
        let domain_ark = ark_bn254::Fr::from_be_bytes_mod_order(&domain_padded);
        let key_halo2 = ark_to_halo2(&key_ark);
        let domain_halo2 = ark_to_halo2(&domain_ark);

        let output = native_poseidon(&params, &[key_halo2, domain_halo2]);
        let output_ark = halo2_to_ark(&output);
        let output_hex = hex::encode(output_ark.into_bigint().to_bytes_be());

        assert_eq!(
            output_hex,
            "078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9",
        );
    }

    /// Full Poseidon circuit test with MockProver for t=2.
    #[test]
    fn test_poseidon_circuit_t2_mock() {
        use halo2_proofs::circuit::SimpleFloorPlanner;
        use halo2_proofs::plonk::Circuit;

        let params = PoseidonParams::new_circom(1);
        let input_val = ark_to_halo2(&ark_bn254::Fr::from(1u64));

        #[derive(Clone)]
        struct TestCircuit {
            params: PoseidonParams,
            input: Fr,
        }

        #[derive(Debug, Clone)]
        struct TestConfig {
            poseidon: PoseidonConfig,
            instance: Column<halo2_proofs::plonk::Instance>,
        }

        impl Circuit<Fr> for TestCircuit {
            type Config = TestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                self.clone()
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
                let poseidon = PoseidonConfig::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                TestConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: TestConfig,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let input = layouter.assign_region(
                    || "input",
                    |mut region| {
                        region.assign_advice(
                            || "input",
                            config.poseidon.advice[0],
                            0,
                            || Value::known(self.input),
                        )
                    },
                )?;

                let chip = PoseidonChip::new(config.poseidon, &self.params);
                let output = chip.hash(&mut layouter, &[input])?;

                layouter.constrain_instance(output.cell(), config.instance, 0)?;
                Ok(())
            }
        }

        let circuit = TestCircuit {
            params: params.clone(),
            input: input_val,
        };
        let expected = native_poseidon(&params, &[input_val]);
        let prover = MockProver::run(14, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }

    /// Full Poseidon circuit test with MockProver for t=3.
    #[test]
    fn test_poseidon_circuit_t3_mock() {
        use halo2_proofs::circuit::SimpleFloorPlanner;
        use halo2_proofs::plonk::Circuit;

        let params = PoseidonParams::new_circom(2);
        let input1 = ark_to_halo2(&ark_bn254::Fr::from(1u64));
        let input2 = ark_to_halo2(&ark_bn254::Fr::from(2u64));

        #[derive(Clone)]
        struct TestCircuit {
            params: PoseidonParams,
            input1: Fr,
            input2: Fr,
        }

        #[derive(Debug, Clone)]
        struct TestConfig {
            poseidon: PoseidonConfig,
            instance: Column<halo2_proofs::plonk::Instance>,
        }

        impl Circuit<Fr> for TestCircuit {
            type Config = TestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                self.clone()
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
                let poseidon = PoseidonConfig::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                TestConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: TestConfig,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let (input1, input2) = layouter.assign_region(
                    || "inputs",
                    |mut region| {
                        let i1 = region.assign_advice(
                            || "i1",
                            config.poseidon.advice[0],
                            0,
                            || Value::known(self.input1),
                        )?;
                        let i2 = region.assign_advice(
                            || "i2",
                            config.poseidon.advice[1],
                            0,
                            || Value::known(self.input2),
                        )?;
                        Ok((i1, i2))
                    },
                )?;

                let chip = PoseidonChip::new(config.poseidon, &self.params);
                let output = chip.hash(&mut layouter, &[input1, input2])?;

                layouter.constrain_instance(output.cell(), config.instance, 0)?;
                Ok(())
            }
        }

        let circuit = TestCircuit {
            params: params.clone(),
            input1,
            input2,
        };
        let expected = native_poseidon(&params, &[input1, input2]);
        let prover = MockProver::run(14, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }
}
