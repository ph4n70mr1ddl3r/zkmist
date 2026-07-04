//! Phase 1 foundation gate (axiom backend migration — see
//! docs/axiom-backend-migration.md): prove the axiom halo2 stack
//! (`halo2-base` eDSL + `halo2-ecc`, on `halo2-axiom` / `halo2curves-axiom`)
//! builds and runs inside this repo. This is the prerequisite for migrating the
//! circuit off the PSE backend toward k=18 (~1 GiB proving) + audited secp256k1.
//!
//! Minimal by design: it only exercises `Context` + `base_test` (axiom's
//! harness) to confirm the stack resolves and MockProver runs. The Poseidon-port
//! and halo2-ecc secp tests are the next sub-steps.

use halo2_base::{
    gates::RangeChip,
    halo2_proofs::halo2curves::bn256::Fr,
    utils::testing::base_test,
    Context,
};

/// Loads a witness via the axiom `Context` and returns its value — proves the
/// axiom stack (halo2-base on halo2-axiom) executes a real circuit here.
fn foundation(ctx: &mut Context<Fr>, _range: &RangeChip<Fr>) -> Fr {
    let x = ctx.load_witness(Fr::from(42u64));
    *x.value()
}

#[test]
fn test_axiom_stack_runs() {
    let res = base_test().k(10).lookup_bits(8).run(foundation);
    assert_eq!(res, Fr::from(42u64), "axiom stack foundation check failed");
}
