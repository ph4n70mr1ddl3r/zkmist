//! Conditional swap gadget for Merkle proof direction handling.
//!
//! Given `(a, b, sel)`, outputs:
//! - `(a, b)` if `sel = 0`
//! - `(b, a)` if `sel = 1`
//!
//! Constraints:
//! 1. `sel` is boolean: `sel * (1 - sel) = 0`
//! 2. `out_left  = sel * b + (1 - sel) * a`
//! 3. `out_right = sel * a + (1 - sel) * b`

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for the conditional swap gadget.
#[derive(Debug, Clone)]
pub struct CondSwapConfig {
    advice: [Column<Advice>; 3],
    s_swap: Selector,
    s_bool: Selector,
}

impl CondSwapConfig {
    /// Add conditional swap gates. Advice columns must already have `enable_equality`.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 3]) -> Self {
        let s_swap = meta.selector();
        let s_bool = meta.selector();

        // Boolean: sel * sel - sel = 0
        meta.create_gate("bool", |meta| {
            let s = meta.query_selector(s_bool);
            let sel = meta.query_advice(advice[0], Rotation::cur());
            vec![s * (sel.clone() * sel.clone() - sel)]
        });

        // Swap: out = term1 + term2
        meta.create_gate("cond_swap", |meta| {
            let s = meta.query_selector(s_swap);
            let out = meta.query_advice(advice[2], Rotation::cur());
            let term1 = meta.query_advice(advice[0], Rotation::cur());
            let term2 = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (term1 + term2 - out)]
        });

        Self {
            advice,
            s_swap,
            s_bool,
        }
    }
}

/// Apply a conditional swap inside a region.
///
/// Uses 3 rows: row 0 for boolean check, rows 1-2 for the two outputs.
#[allow(clippy::type_complexity)]
pub fn cond_swap(
    region: &mut Region<Fr>,
    config: &CondSwapConfig,
    offset: usize,
    a: &AssignedCell<Fr, Fr>,
    b: &AssignedCell<Fr, Fr>,
    sel: &AssignedCell<Fr, Fr>,
) -> Result<(AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>), Error> {
    let sel_val = sel.value().copied();
    let a_val = a.value().copied();
    let b_val = b.value().copied();

    // Row 0: boolean constraint on sel
    let sel_copy = region.assign_advice(|| "sel_bool", config.advice[0], offset, || sel_val)?;
    region.constrain_equal(sel.cell(), sel_copy.cell())?;
    config.s_bool.enable(region, offset)?;

    let one_minus_sel = sel_val.map(|s| Fr::ONE - s);

    // Row 1: out_left = sel*b + (1-sel)*a
    let sel_b = sel_val.zip(b_val).map(|(s, b)| s * b);
    let oms_a = one_minus_sel.zip(a_val).map(|(m, a)| m * a);
    let out_left_val = sel_b.zip(oms_a).map(|(t1, t2)| t1 + t2);

    region.assign_advice(|| "sb", config.advice[0], offset + 1, || sel_b)?;
    region.assign_advice(|| "omsa", config.advice[1], offset + 1, || oms_a)?;
    let out_left = region.assign_advice(|| "ol", config.advice[2], offset + 1, || out_left_val)?;
    config.s_swap.enable(region, offset + 1)?;

    // Row 2: out_right = sel*a + (1-sel)*b
    let sel_a = sel_val.zip(a_val).map(|(s, a)| s * a);
    let oms_b = one_minus_sel.zip(b_val).map(|(m, b)| m * b);
    let out_right_val = sel_a.zip(oms_b).map(|(t1, t2)| t1 + t2);

    region.assign_advice(|| "sa", config.advice[0], offset + 2, || sel_a)?;
    region.assign_advice(|| "omsb", config.advice[1], offset + 2, || oms_b)?;
    let out_right =
        region.assign_advice(|| "or", config.advice[2], offset + 2, || out_right_val)?;
    config.s_swap.enable(region, offset + 2)?;

    Ok((out_left, out_right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_cond_swap_sel0() {
        let a = Fr::from(42u64);
        let b = Fr::from(99u64);
        let sel = Fr::ZERO;
        let (left, right) = native_cond_swap(a, b, sel);
        assert_eq!(left, a);
        assert_eq!(right, b);
    }

    #[test]
    fn test_native_cond_swap_sel1() {
        let a = Fr::from(42u64);
        let b = Fr::from(99u64);
        let sel = Fr::ONE;
        let (left, right) = native_cond_swap(a, b, sel);
        assert_eq!(left, b);
        assert_eq!(right, a);
    }

    fn native_cond_swap(a: Fr, b: Fr, sel: Fr) -> (Fr, Fr) {
        let oms = Fr::ONE - sel;
        let left = sel * b + oms * a;
        let right = sel * a + oms * b;
        (left, right)
    }
}
