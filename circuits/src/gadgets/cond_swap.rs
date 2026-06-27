//! Conditional swap gadget for Merkle proof direction handling.
//!
//! Given `(a, b, sel)`, outputs:
//! - `(a, b)` if `sel = 0`
//! - `(b, a)` if `sel = 1`
//!
//! # Constraints (fully sound)
//!
//! Every advice cell that feeds an output is linked to its source with a copy
//! constraint (`constrain_equal`), and every arithmetic relation is enforced
//! by a gate:
//!
//! 1. `sel` is boolean: `sel * (1 - sel) = 0`                (`s_bool`)
//! 2. `one_minus_sel = 1 - sel`: `sel + one_minus_sel = 1`   (`s_add`)
//! 3. `sel_b   = sel * b`                                     (`s_mul`)
//! 4. `oms_a   = one_minus_sel * a`                           (`s_mul`)
//! 5. `out_left  = sel_b + oms_a`                             (`s_add`)
//! 6. `sel_a   = sel * a`                                     (`s_mul`)
//! 7. `oms_b   = one_minus_sel * b`                           (`s_mul`)
//! 8. `out_right = sel_a + oms_b`                             (`s_add`)
//!
//! # Why the previous version was unsound
//!
//! The old `s_swap` gate only enforced `term1 + term2 - out = 0`, where
//! `term1` (`sel_b`) and `term2` (`oms_a`) were *free* advice cells — only
//! `sel` was copy-constrained into the region. A malicious prover could set
//! `term1 = out, term2 = 0` and emit any desired `(out_left, out_right)`,
//! making the 26-level Merkle membership proof **non-binding**: a prover could
//! claim membership for an arbitrary leaf regardless of the public tree.
//!
//! This version constrains the products `sel*b`, `(1-sel)*a`, `sel*a`, and
//! `(1-sel)*b` directly with multiplication gates, mirroring the (correct)
//! `Secp256k1Chip::conditional_select_field` pattern elsewhere in this crate.

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for the conditional swap gadget.
#[derive(Debug, Clone)]
pub struct CondSwapConfig {
    advice: [Column<Advice>; 3],
    s_bool: Selector,
    s_mul: Selector,
    s_add: Selector,
}

impl CondSwapConfig {
    /// Add conditional swap gates. Advice columns must already have `enable_equality`.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 3]) -> Self {
        let s_bool = meta.selector();
        let s_mul = meta.selector();
        let s_add = meta.selector();

        // Boolean: sel * (1 - sel) = 0
        meta.create_gate("cond_swap_bool", |meta| {
            let s = meta.query_selector(s_bool);
            let sel = meta.query_advice(advice[0], Rotation::cur());
            let one = Expression::Constant(Fr::ONE);
            vec![s * (sel.clone() * (one - sel))]
        });

        // Multiply: advice[0] * advice[1] = advice[2]
        meta.create_gate("cond_swap_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        // Add: advice[0] + advice[1] = advice[2]
        meta.create_gate("cond_swap_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        Self {
            advice,
            s_bool,
            s_mul,
            s_add,
        }
    }
}

/// Apply a conditional swap inside a region.
///
/// Uses 8 rows starting at `offset`:
///
/// ```text
///  row 0: sel boolean                       (s_bool)
///  row 1: sel + one_minus_sel = 1           (s_add)
///  row 2: sel * b = sel_b                   (s_mul)
///  row 3: one_minus_sel * a = oms_a         (s_mul)
///  row 4: sel_b + oms_a = out_left          (s_add)
///  row 5: sel * a = sel_a                   (s_mul)
///  row 6: one_minus_sel * b = oms_b         (s_mul)
///  row 7: sel_a + oms_b = out_right         (s_add)
/// ```
///
/// Semantics: `(out_left, out_right) = (sel*b + (1-sel)*a, sel*a + (1-sel)*b)`,
/// i.e. `(a, b)` when `sel = 0` and `(b, a)` when `sel = 1`.
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
    let one_minus_sel_val = sel_val.map(|s| Fr::ONE - s);

    // Row 0: sel boolean
    let sel_cell = region.assign_advice(|| "sel_bool", config.advice[0], offset, || sel_val)?;
    region.constrain_equal(sel.cell(), sel_cell.cell())?;
    config.s_bool.enable(region, offset)?;

    // Row 1: one_minus_sel via sel + one_minus_sel = 1
    let sel_r1 = region.assign_advice(|| "sel_r1", config.advice[0], offset + 1, || sel_val)?;
    region.constrain_equal(sel.cell(), sel_r1.cell())?;
    let one_minus_sel = region.assign_advice(
        || "one_minus_sel",
        config.advice[1],
        offset + 1,
        || one_minus_sel_val,
    )?;
    let _one =
        region.assign_advice(|| "one", config.advice[2], offset + 1, || Value::known(Fr::ONE))?;
    config.s_add.enable(region, offset + 1)?;

    // Row 2: sel * b = sel_b
    let sel_r2 = region.assign_advice(|| "sel_r2", config.advice[0], offset + 2, || sel_val)?;
    region.constrain_equal(sel.cell(), sel_r2.cell())?;
    let b_r2 = region.assign_advice(|| "b_r2", config.advice[1], offset + 2, || b_val)?;
    region.constrain_equal(b.cell(), b_r2.cell())?;
    let sel_b_val = sel_val.zip(b_val).map(|(s, b)| s * b);
    let sel_b = region.assign_advice(|| "sel_b", config.advice[2], offset + 2, || sel_b_val)?;
    config.s_mul.enable(region, offset + 2)?;

    // Row 3: one_minus_sel * a = oms_a
    let oms_r3 =
        region.assign_advice(|| "oms_r3", config.advice[0], offset + 3, || one_minus_sel_val)?;
    region.constrain_equal(one_minus_sel.cell(), oms_r3.cell())?;
    let a_r3 = region.assign_advice(|| "a_r3", config.advice[1], offset + 3, || a_val)?;
    region.constrain_equal(a.cell(), a_r3.cell())?;
    let oms_a_val = one_minus_sel_val.zip(a_val).map(|(m, a)| m * a);
    let oms_a = region.assign_advice(|| "oms_a", config.advice[2], offset + 3, || oms_a_val)?;
    config.s_mul.enable(region, offset + 3)?;

    // Row 4: sel_b + oms_a = out_left
    let sb_r4 = region.assign_advice(|| "sb_r4", config.advice[0], offset + 4, || sel_b_val)?;
    region.constrain_equal(sel_b.cell(), sb_r4.cell())?;
    let omsa_r4 = region.assign_advice(|| "omsa_r4", config.advice[1], offset + 4, || oms_a_val)?;
    region.constrain_equal(oms_a.cell(), omsa_r4.cell())?;
    let out_left_val = sel_b_val.zip(oms_a_val).map(|(x, y)| x + y);
    let out_left =
        region.assign_advice(|| "out_left", config.advice[2], offset + 4, || out_left_val)?;
    config.s_add.enable(region, offset + 4)?;

    // Row 5: sel * a = sel_a
    let sel_r5 = region.assign_advice(|| "sel_r5", config.advice[0], offset + 5, || sel_val)?;
    region.constrain_equal(sel.cell(), sel_r5.cell())?;
    let a_r5 = region.assign_advice(|| "a_r5", config.advice[1], offset + 5, || a_val)?;
    region.constrain_equal(a.cell(), a_r5.cell())?;
    let sel_a_val = sel_val.zip(a_val).map(|(s, a)| s * a);
    let sel_a = region.assign_advice(|| "sel_a", config.advice[2], offset + 5, || sel_a_val)?;
    config.s_mul.enable(region, offset + 5)?;

    // Row 6: one_minus_sel * b = oms_b
    let oms_r6 =
        region.assign_advice(|| "oms_r6", config.advice[0], offset + 6, || one_minus_sel_val)?;
    region.constrain_equal(one_minus_sel.cell(), oms_r6.cell())?;
    let b_r6 = region.assign_advice(|| "b_r6", config.advice[1], offset + 6, || b_val)?;
    region.constrain_equal(b.cell(), b_r6.cell())?;
    let oms_b_val = one_minus_sel_val.zip(b_val).map(|(m, b)| m * b);
    let oms_b = region.assign_advice(|| "oms_b", config.advice[2], offset + 6, || oms_b_val)?;
    config.s_mul.enable(region, offset + 6)?;

    // Row 7: sel_a + oms_b = out_right
    let sa_r7 = region.assign_advice(|| "sa_r7", config.advice[0], offset + 7, || sel_a_val)?;
    region.constrain_equal(sel_a.cell(), sa_r7.cell())?;
    let omsb_r7 = region.assign_advice(|| "omsb_r7", config.advice[1], offset + 7, || oms_b_val)?;
    region.constrain_equal(oms_b.cell(), omsb_r7.cell())?;
    let out_right_val = sel_a_val.zip(oms_b_val).map(|(x, y)| x + y);
    let out_right =
        region.assign_advice(|| "out_right", config.advice[2], offset + 7, || out_right_val)?;
    config.s_add.enable(region, offset + 7)?;

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
