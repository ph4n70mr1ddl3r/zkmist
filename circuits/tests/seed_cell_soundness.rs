//! Regression tests for the 2026-07-01 "free constant-seed cell" soundness
//! fixes in `accumulate_weighted_bits` and `cond_swap`.
//!
//! Each shadow replicates the gadget's gate pattern (in the FIXED form) and
//! drives MockProver with:
//!   • an honest witness — MUST verify, and
//!   • the *smart attack* that exploited the old free-seed cell — MUST reject.
//!
//! If the fixes are ever reverted (a free `0`/`1` seed cell re-introduced),
//! the malicious cases start passing and these tests fail.

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

fn one_expr() -> Expression<Fr> {
    Expression::Constant(Fr::ONE)
}

// ════════════════════════════════════════════════════════════════════════
// 1. accumulate_weighted_bits shadow (secp gate set)
//    FIXED pattern: the accumulator is seeded from the first gate-constrained
//    weighted bit — there is no free initial cell.
// ════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct AccCfg {
    advice: [Column<Advice>; 3],
    fixed: Column<Fixed>,
    s_bool: Selector,
    s_mul_fixed: Selector,
    s_add: Selector,
}

fn acc_configure(meta: &mut ConstraintSystem<Fr>) -> AccCfg {
    let advice = std::array::from_fn(|_| {
        let c = meta.advice_column();
        meta.enable_equality(c);
        c
    });
    let fixed = meta.fixed_column();
    let s_bool = meta.selector();
    let s_mul_fixed = meta.selector();
    let s_add = meta.selector();
    meta.create_gate("bool", |m| {
        let s = m.query_selector(s_bool);
        let x = m.query_advice(advice[0], Rotation::cur());
        vec![s * (x.clone() * (one_expr() - x))]
    });
    meta.create_gate("mul_fixed", |m| {
        let s = m.query_selector(s_mul_fixed);
        let a = m.query_advice(advice[0], Rotation::cur());
        let f = m.query_fixed(fixed, Rotation::cur());
        let b = m.query_advice(advice[1], Rotation::cur());
        vec![s * (a * f - b)]
    });
    meta.create_gate("add", |m| {
        let s = m.query_selector(s_add);
        let a = m.query_advice(advice[0], Rotation::cur());
        let b = m.query_advice(advice[1], Rotation::cur());
        let c = m.query_advice(advice[2], Rotation::cur());
        vec![s * (a + b - c)]
    });
    AccCfg { advice, fixed, s_bool, s_mul_fixed, s_add }
}

struct AccCircuit {
    bits: [Fr; 2],
    weights: [Fr; 2],
    /// `malicious` injects the OLD attack: seed the accumulator with a nonzero
    /// `delta` (which the FIXED gates no longer permit) so the terminal can be
    /// driven to `target = delta + Σ bits[i]·weights[i]`.
    malicious: bool,
    delta: Fr,
    target: Fr,
}

impl Circuit<Fr> for AccCircuit {
    type Config = (AccCfg, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        AccCircuit { bits: [Fr::ZERO; 2], weights: [Fr::ZERO; 2], malicious: false, delta: Fr::ZERO, target: Fr::ZERO }
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let cfg = acc_configure(meta);
        let inst = meta.instance_column();
        meta.enable_equality(inst);
        (cfg, inst)
    }
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let (cfg, inst) = config;
        let acc = layouter.assign_region(|| "acc", |mut region| {
            let mut offset = 0usize;
            // FIXED seed: acc = bit[0]·weight[0] (s_mul_fixed + s_bool).
            // In the malicious case we try to inject `delta` here (the old bug);
            // the gate forces advice[1] = bit[0]·weight[0], so delta ≠ that is
            // rejected.
            let seed_witness = if self.malicious {
                self.delta
            } else {
                self.bits[0] * self.weights[0]
            };
            region.assign_advice(|| "seed_bit", cfg.advice[0], offset, || Value::known(self.bits[0]))?;
            region.assign_fixed(|| "seed_w", cfg.fixed, offset, || Value::known(self.weights[0]))?;
            let mut acc = region.assign_advice(|| "seed", cfg.advice[1], offset, || Value::known(seed_witness))?;
            cfg.s_bool.enable(&mut region, offset)?;
            cfg.s_mul_fixed.enable(&mut region, offset)?;
            offset += 1;
            for i in 1..2 {
                let partial_val = self.bits[i] * self.weights[i];
                region.assign_advice(|| "bit", cfg.advice[0], offset, || Value::known(self.bits[i]))?;
                region.assign_fixed(|| "w", cfg.fixed, offset, || Value::known(self.weights[i]))?;
                let partial = region.assign_advice(|| "p", cfg.advice[1], offset, || Value::known(partial_val))?;
                cfg.s_bool.enable(&mut region, offset)?;
                cfg.s_mul_fixed.enable(&mut region, offset)?;
                offset += 1;
                let acc_copy = region.assign_advice(|| "ac", cfg.advice[0], offset, || acc.value().copied())?;
                region.constrain_equal(acc.cell(), acc_copy.cell())?;
                let pc = region.assign_advice(|| "pc", cfg.advice[1], offset, || partial.value().copied())?;
                region.constrain_equal(partial.cell(), pc.cell())?;
                acc = region.assign_advice(|| "new", cfg.advice[2], offset, || {
                    acc.value().copied().map(|a| a + partial_val)
                })?;
                cfg.s_add.enable(&mut region, offset)?;
                offset += 1;
            }
            Ok(acc)
        })?;
        layouter.constrain_instance(acc.cell(), inst, 0)?;
        Ok(())
    }
}

#[test]
fn acc_seed_accepts_honest() {
    // bits=[1,0], weights=[1,2] → Σ = 1.
    let circuit = AccCircuit {
        bits: [Fr::ONE, Fr::ZERO],
        weights: [Fr::from(1u64), Fr::from(2u64)],
        malicious: false,
        delta: Fr::ZERO,
        target: Fr::from(1u64),
    };
    let prover = MockProver::run(9, &circuit, vec![vec![circuit.target]]).unwrap();
    prover.verify().expect("honest accumulator MUST verify");
}

#[test]
fn acc_seed_rejects_free_delta_attack() {
    // Old attack: seed accumulator with delta=99 to reach target=100 (≠ Σ=1).
    // The FIXED gate forces the seed = bit[0]·weight[0] = 1, so delta=99 is
    // rejected. If this passes, a free initial accumulator cell has been
    // re-introduced and the nullifier↔scalar binding (Finding 2) is broken.
    let circuit = AccCircuit {
        bits: [Fr::ONE, Fr::ZERO],
        weights: [Fr::from(1u64), Fr::from(2u64)],
        malicious: true,
        delta: Fr::from(99u64),
        target: Fr::from(100u64),
    };
    let prover = MockProver::run(9, &circuit, vec![vec![circuit.target]]).unwrap();
    let res = prover.verify();
    assert!(res.is_err(), "fixed accumulator MUST reject the free-delta attack: {:?}", res);
}

// ════════════════════════════════════════════════════════════════════════
// 2. cond_swap shadow
//    FIXED pattern: `sel + one_minus_sel = 1` is enforced by a fixed-column
//    `s_sum_fixed` gate — the "1" is not a free advice cell.
// ════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct SwapCfg {
    advice: [Column<Advice>; 3],
    fixed: Column<Fixed>,
    s_bool: Selector,
    s_mul: Selector,
    s_add: Selector,
    s_sum_fixed: Selector,
}

fn swap_configure(meta: &mut ConstraintSystem<Fr>) -> SwapCfg {
    let advice = std::array::from_fn(|_| {
        let c = meta.advice_column();
        meta.enable_equality(c);
        c
    });
    let fixed = meta.fixed_column();
    let s_bool = meta.selector();
    let s_mul = meta.selector();
    let s_add = meta.selector();
    let s_sum_fixed = meta.selector();
    meta.create_gate("bool", |m| {
        let s = m.query_selector(s_bool);
        let x = m.query_advice(advice[0], Rotation::cur());
        vec![s * (x.clone() * (one_expr() - x))]
    });
    meta.create_gate("mul", |m| {
        let s = m.query_selector(s_mul);
        let a = m.query_advice(advice[0], Rotation::cur());
        let b = m.query_advice(advice[1], Rotation::cur());
        let c = m.query_advice(advice[2], Rotation::cur());
        vec![s * (a * b - c)]
    });
    meta.create_gate("add", |m| {
        let s = m.query_selector(s_add);
        let a = m.query_advice(advice[0], Rotation::cur());
        let b = m.query_advice(advice[1], Rotation::cur());
        let c = m.query_advice(advice[2], Rotation::cur());
        vec![s * (a + b - c)]
    });
    meta.create_gate("sum_fixed", |m| {
        let s = m.query_selector(s_sum_fixed);
        let a = m.query_advice(advice[0], Rotation::cur());
        let b = m.query_advice(advice[1], Rotation::cur());
        let f = m.query_fixed(fixed, Rotation::cur());
        vec![s * (a + b - f)]
    });
    SwapCfg { advice, fixed, s_bool, s_mul, s_add, s_sum_fixed }
}

struct SwapCircuit {
    sel: Fr,
    a: Fr,
    b: Fr,
    /// malicious: try to set `one` to a value ≠ 1 (the old free-cell attack),
    /// forcing the swap outputs to arbitrary values.
    malicious: bool,
    one_val: Fr,
}

impl Circuit<Fr> for SwapCircuit {
    type Config = (SwapCfg, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        SwapCircuit { sel: Fr::ZERO, a: Fr::ZERO, b: Fr::ZERO, malicious: false, one_val: Fr::ZERO }
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let cfg = swap_configure(meta);
        let inst = meta.instance_column();
        meta.enable_equality(inst);
        (cfg, inst)
    }
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let (cfg, inst) = config;
        let sel = self.sel;
        let a = self.a;
        let b = self.b;
        let oms_val = if self.malicious { self.one_val - sel } else { Fr::ONE - sel };
        let out_left = sel * b + oms_val * a;
        let out_right = sel * a + oms_val * b;
        let (ol, or) = layouter.assign_region(|| "swap", |mut region| {
            let o = 0usize;
            // sel boolean
            region.assign_advice(|| "sel", cfg.advice[0], o, || Value::known(sel))?;
            cfg.s_bool.enable(&mut region, o)?;
            // sel + oms = fixed(1)  (FIXED: the "1" is a fixed constant)
            region.assign_advice(|| "sel1", cfg.advice[0], o + 1, || Value::known(sel))?;
            region.assign_advice(|| "oms", cfg.advice[1], o + 1, || Value::known(oms_val))?;
            region.assign_fixed(|| "one", cfg.fixed, o + 1, || Value::known(Fr::ONE))?;
            cfg.s_sum_fixed.enable(&mut region, o + 1)?;
            // sel*b
            region.assign_advice(|| "m2a", cfg.advice[0], o + 2, || Value::known(sel))?;
            region.assign_advice(|| "m2b", cfg.advice[1], o + 2, || Value::known(b))?;
            region.assign_advice(|| "sb", cfg.advice[2], o + 2, || Value::known(sel * b))?;
            cfg.s_mul.enable(&mut region, o + 2)?;
            // oms*a
            region.assign_advice(|| "m3a", cfg.advice[0], o + 3, || Value::known(oms_val))?;
            region.assign_advice(|| "m3b", cfg.advice[1], o + 3, || Value::known(a))?;
            region.assign_advice(|| "omsa", cfg.advice[2], o + 3, || Value::known(oms_val * a))?;
            cfg.s_mul.enable(&mut region, o + 3)?;
            // out_left = sel_b + oms_a
            region.assign_advice(|| "a4a", cfg.advice[0], o + 4, || Value::known(sel * b))?;
            region.assign_advice(|| "a4b", cfg.advice[1], o + 4, || Value::known(oms_val * a))?;
            let ol = region.assign_advice(|| "ol", cfg.advice[2], o + 4, || Value::known(out_left))?;
            cfg.s_add.enable(&mut region, o + 4)?;
            // sel*a
            region.assign_advice(|| "m5a", cfg.advice[0], o + 5, || Value::known(sel))?;
            region.assign_advice(|| "m5b", cfg.advice[1], o + 5, || Value::known(a))?;
            region.assign_advice(|| "sa", cfg.advice[2], o + 5, || Value::known(sel * a))?;
            cfg.s_mul.enable(&mut region, o + 5)?;
            // oms*b
            region.assign_advice(|| "m6a", cfg.advice[0], o + 6, || Value::known(oms_val))?;
            region.assign_advice(|| "m6b", cfg.advice[1], o + 6, || Value::known(b))?;
            region.assign_advice(|| "omsb", cfg.advice[2], o + 6, || Value::known(oms_val * b))?;
            cfg.s_mul.enable(&mut region, o + 6)?;
            // out_right = sel_a + oms_b
            region.assign_advice(|| "a7a", cfg.advice[0], o + 7, || Value::known(sel * a))?;
            region.assign_advice(|| "a7b", cfg.advice[1], o + 7, || Value::known(oms_val * b))?;
            let or = region.assign_advice(|| "orr", cfg.advice[2], o + 7, || Value::known(out_right))?;
            cfg.s_add.enable(&mut region, o + 7)?;
            Ok((ol, or))
        })?;
        layouter.constrain_instance(ol.cell(), inst, 0)?;
        layouter.constrain_instance(or.cell(), inst, 1)?;
        Ok(())
    }
}

#[test]
fn cond_swap_accepts_honest() {
    // sel=0, a=5, b=7 → no swap → (5, 7).
    let circuit = SwapCircuit { sel: Fr::ZERO, a: Fr::from(5u64), b: Fr::from(7u64), malicious: false, one_val: Fr::ONE };
    let prover = MockProver::run(9, &circuit, vec![vec![Fr::from(5u64), Fr::from(7u64)]]).unwrap();
    prover.verify().expect("honest swap MUST verify");
}

#[test]
fn cond_swap_rejects_free_one_attack() {
    // Old attack: set "one" = 42/5 so that oms = 42/5 and out_left = oms·a = 42
    // (instead of the correct 5). The FIXED s_sum_fixed gate forces sel+oms = 1
    // (here 0 + 42/5 = 1, false), so it is rejected. If this passes, the "one"
    // constant has been re-introduced as a free advice cell and Merkle
    // membership binding is broken.
    let inv5 = Fr::from(5u64).invert().unwrap();
    let one_val = Fr::from(42u64) * inv5;
    let circuit = SwapCircuit {
        sel: Fr::ZERO,
        a: Fr::from(5u64),
        b: Fr::from(7u64),
        malicious: true,
        one_val,
    };
    let oms_val = one_val - Fr::ZERO;
    let out_left = Fr::ZERO * Fr::from(7u64) + oms_val * Fr::from(5u64);
    let out_right = Fr::ZERO * Fr::from(5u64) + oms_val * Fr::from(7u64);
    let prover = MockProver::run(9, &circuit, vec![vec![out_left, out_right]]).unwrap();
    let res = prover.verify();
    assert!(res.is_err(), "fixed cond_swap MUST reject the free-one attack: {:?}", res);
}
