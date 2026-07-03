//! ZKMist binding glue — the three-pillar soundness wiring.
//!
//! This module holds the two ZKMist-specific operations that cryptographically
//! bind the otherwise-independent pillars of the claim proof:
//!
//!   - [`Secp256k1Chip::accumulate_weighted_bits`] — accumulates boolean bit
//!     cells into a field element under existing gates. Used at 4 sites in
//!     `lib.rs`: the nullifier↔scalar binding, the Merkle-leaf↔Keccak-address
//!     binding, the recipient uint160 range, and `bind_limb_to_inputs`.
//!   - [`Secp256k1Chip::assert_nonzero`] — sound non-zero check (the constant
//!     1 lives inside the `s_nonzero` gate polynomial, not a free advice cell).
//!
//! # Why this is its own module (halo2wrong migration, Phase A)
//!
//! `circuits/src/secp256k1.rs` tangles two concerns:
//!   (a) the EC scalar-mul engine (the row hog + audit risk) — to be REPLACED
//!       by `halo2wrong` in Phase B; and
//!   (b) this binding glue — to be RETAINED verbatim.
//!
//! Phase A physically separates (b) into this file so the Phase B diff is
//! minimal and the binding surface is easy to audit in isolation. See
//! `docs/secp256k1-migration-plan.md`.
//!
//! # Digest-neutrality
//!
//! These remain `impl Secp256k1Chip` methods (a second `impl` block, legal in
//! Rust for a same-crate type) and reuse the existing `Secp256k1Config` gates
//! (`s_bool`, `s_mul_fixed`, `s_add`, `s_nonzero`) — so `configure()` is
//! unchanged, the constraint-system digest is unchanged, and the on-chain VK
//! is unaffected. Phase B will give this glue its own independent config once
//! the EC engine (and its config) is replaced by halo2wrong.

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use halo2curves::bn256::Fr;

use crate::secp256k1::Secp256k1Chip;

impl<'a> Secp256k1Chip<'a> {
    /// Accumulate boolean `bits` weighted by `weights` into a single field
    /// element, every step constrained by existing gates.
    ///
    /// Soundness: the accumulator is seeded from the FIRST weighted bit
    /// (constrained by `s_mul_fixed` + `s_bool`), and each subsequent partial
    /// is added under `s_add`. There is no unconstrained cell in the chain, so
    /// `acc = Σ bits[i]·weights[i]` is binding. (The 2026 bug-hunt fixed a free
    /// "zero start" cell here that would have decoupled the nullifier key from
    /// the secp256k1 scalar.)
    pub fn accumulate_weighted_bits(
        &self,
        layouter: &mut impl Layouter<Fr>,
        bits: &[AssignedCell<Fr, Fr>],
        weights: &[Fr],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        assert_eq!(bits.len(), weights.len(), "bits/weights length mismatch");
        layouter.assign_region(
            || "accumulate_weighted_bits",
            |mut region| {
                let mut offset = 0usize;

                // ── Soundness (2026 bug-hunt): no free "zero start" cell. ──
                // The previous version initialized the accumulator with a bare
                // advice cell assigned `Fr::ZERO` but read by NO gate on its
                // row. That cell was free, so a malicious prover could seed it
                // with any `δ` and still satisfy the terminal `constrain_equal`
                // against the caller's target — making the accumulator vacuous.
                // For the nullifier-key binding (Finding 2) this fully decouples
                // `poseidon(key, domain)` from the secp256k1 scalar actually
                // multiplied, enabling unlimited claims with fresh nullifiers.
                //
                // Fix: seed the accumulator from the FIRST weighted bit, which is
                // already constrained by `s_mul_fixed` (advice[0]·fixed = advice[1])
                // and boolean-constrained by `s_bool`. Every subsequent step adds a
                // gate-constrained partial. There is no unconstrained cell in the
                // chain, so `acc = Σ bits[i]·weights[i]` is binding.
                if bits.is_empty() {
                    // Provable zero: `s_mul_fixed` with fixed=0 forces advice[1]=0
                    // regardless of advice[0].
                    region.assign_advice(
                        || "empty_seed_a",
                        self.config.advice[0],
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_fixed(
                        || "empty_seed_fixed",
                        self.config.fixed,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    let zero = region.assign_advice(
                        || "empty_zero",
                        self.config.advice[1],
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    self.config.s_mul_fixed.enable(&mut region, offset)?;
                    return Ok(zero);
                }

                // Seed: acc = bit[0] · weight[0]  (constrained by s_mul_fixed + s_bool).
                let bit0 = bits[0].value().copied();
                let b_copy0 = region.assign_advice(
                    || "ab_seed_bit",
                    self.config.advice[0],
                    offset,
                    || bit0,
                )?;
                region.constrain_equal(bits[0].cell(), b_copy0.cell())?;
                region.assign_fixed(
                    || "ab_seed_weight",
                    self.config.fixed,
                    offset,
                    || Value::known(weights[0]),
                )?;
                let seed_val = bit0.map(|v| v * weights[0]);
                let mut acc = region.assign_advice(
                    || "ab_seed",
                    self.config.advice[1],
                    offset,
                    || seed_val,
                )?;
                self.config.s_bool.enable(&mut region, offset)?;
                self.config.s_mul_fixed.enable(&mut region, offset)?;
                offset += 1;

                for (i, bit) in bits.iter().enumerate().skip(1) {
                    // Row: advice[0] = bit (copy), fixed = weight, advice[1] = bit·weight.
                    let bv = bit.value().copied();
                    let b_copy =
                        region.assign_advice(|| "ab_bit", self.config.advice[0], offset, || bv)?;
                    region.constrain_equal(bit.cell(), b_copy.cell())?;
                    region.assign_fixed(
                        || "ab_weight",
                        self.config.fixed,
                        offset,
                        || Value::known(weights[i]),
                    )?;
                    let partial_val = bv.map(|v| v * weights[i]);
                    let partial = region.assign_advice(
                        || "ab_partial",
                        self.config.advice[1],
                        offset,
                        || partial_val,
                    )?;
                    self.config.s_bool.enable(&mut region, offset)?;
                    self.config.s_mul_fixed.enable(&mut region, offset)?;
                    offset += 1;

                    // Row: acc + partial = new_acc  (s_add: advice[0]+advice[1]=advice[2])
                    let acc_copy = region.assign_advice(
                        || "ab_acc",
                        self.config.advice[0],
                        offset,
                        || acc.value().copied(),
                    )?;
                    region.constrain_equal(acc.cell(), acc_copy.cell())?;
                    let part_copy = region.assign_advice(
                        || "ab_part",
                        self.config.advice[1],
                        offset,
                        || partial.value().copied(),
                    )?;
                    region.constrain_equal(partial.cell(), part_copy.cell())?;
                    acc = region.assign_advice(
                        || "ab_newacc",
                        self.config.advice[2],
                        offset,
                        || acc.value().copied().zip(partial_val).map(|(a, p)| a + p),
                    )?;
                    self.config.s_add.enable(&mut region, offset)?;
                    offset += 1;
                }
                Ok(acc)
            },
        )
    }

    /// Prove that `val` is non-zero by supplying its inverse and enabling the
    /// `s_nonzero` gate (`val · inv − 1 = 0`). Sound: if `val == 0` then
    /// `0 · inv = 0 ≠ 1` for every field element `inv`, so no satisfying
    /// assignment exists. Unlike the inverse-and-constrain-equal-to-one
    /// pattern, the constant 1 lives *inside* the gate polynomial, so the
    /// prover cannot cheat by reassigning the "one" cell.
    pub fn assert_nonzero(
        &self,
        layouter: &mut impl Layouter<Fr>,
        val: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assert_nonzero",
            |mut region| {
                // advice[0] = val (copy); advice[1] = inverse(val) (prover witness).
                let a = region.assign_advice(
                    || "nz_val",
                    self.config.advice[0],
                    0,
                    || val.value().copied(),
                )?;
                region.constrain_equal(val.cell(), a.cell())?;
                let inv = val.value().copied().map(|v| {
                    // 0⁻¹ is undefined; the gate will reject it regardless of
                    // what we put here, so fall back to 0.
                    Option::<Fr>::from(v.invert()).unwrap_or(Fr::ZERO)
                });
                region.assign_advice(|| "nz_inv", self.config.advice[1], 0, || inv)?;
                self.config.s_nonzero.enable(&mut region, 0)?;
                Ok(())
            },
        )
    }
}
