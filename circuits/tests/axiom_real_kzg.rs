//! Phase 4 de-risk: confirm the axiom halo2 stack does a **real KZG**
//! round-trip (gen_srs → keygen → create_proof → verify) in this repo, on a
//! small but real axiom circuit (a Poseidon hash). This is the prerequisite
//! unknown before porting the production prover — that the axiom backend's KZG
//! pipeline (SHPLONK multi-open + Blake2b transcript) runs end-to-end here.

use halo2_base::{
    gates::circuit::builder::RangeCircuitBuilder,
    gates::circuit::CircuitBuilderStage,
    gates::RangeChip,
    halo2_proofs::{
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk},
    },
    utils::fs::gen_srs,
    utils::testing::{base_test, check_proof_with_instances, gen_proof_with_instances},
};
use zkmist_circuits::poseidon_axiom::{hash_leaf, native_hash_leaf};

#[test]
fn test_axiom_real_kzg_roundtrip_poseidon() {
    let x = Fr::from(42);
    // bench_builder: gen_srs(k) → keygen_vk → keygen_pk → create_proof →
    // check_proof (asserts the proof verifies against the VK).
    let stats = base_test()
        .k(12)
        .lookup_bits(8)
        .bench_builder(x, x, |pool, range, x| {
            let ctx = pool.main();
            let cell = ctx.load_witness(x);
            hash_leaf(ctx, range, cell);
        });
    eprintln!(
        "axiom real-KZG round-trip OK (Poseidon): proof_size = {} bytes",
        stats.proof_size
    );
}

/// Public-instance mechanism: the circuit exposes its output as a public
/// instance; the proof verifies against the correct instance and is REJECTED
/// against a wrong one (the on-chain verifier model). Validated on a small
/// Poseidon circuit (fast) before scaling to the full claim.
#[test]
fn test_axiom_public_instance_roundtrip() {
    let x = Fr::from(42);
    let expected = native_hash_leaf(x); // the public output

    // keygen stage
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(12)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    let range = RangeChip::new(8, kb.lookup_manager().clone());
    {
        let ctx = kb.pool(0).main();
        let cell = ctx.load_witness(x);
        let h = hash_leaf(ctx, &range, cell);
        kb.assigned_instances[0] = vec![h]; // expose as instance column 0
    }
    let config_params = kb.calculate_params(Some(9));
    let params = gen_srs(12);
    let vk = keygen_vk(&params, &kb).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &kb).unwrap();
    let break_points = kb.break_points();
    drop(kb);

    // prover stage
    let mut pb = RangeCircuitBuilder::prover(config_params, break_points);
    let range = RangeChip::new(8, pb.lookup_manager().clone());
    {
        let ctx = pb.pool(0).main();
        let cell = ctx.load_witness(x);
        let h = hash_leaf(ctx, &range, cell);
        pb.assigned_instances[0] = vec![h];
    }
    let instances = vec![expected];
    let proof = gen_proof_with_instances(&params, &pk, pb, &[instances.as_slice()]);

    // Verifies against the correct instance.
    check_proof_with_instances(&params, &vk, &proof, &[instances.as_slice()], true);
    // Rejected against a wrong instance (the on-chain verifier holds the real
    // value and would reject a proof claiming a different one).
    let wrong = vec![expected + Fr::from(1u64)];
    check_proof_with_instances(&params, &vk, &proof, &[wrong.as_slice()], false);

    eprintln!("axiom public-instance round-trip OK (verifies + wrong-instance rejected)");
}
