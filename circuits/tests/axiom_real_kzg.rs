//! Phase 4 de-risk: confirm the axiom halo2 stack does a **real KZG**
//! round-trip (gen_srs → keygen → create_proof → verify) in this repo, on a
//! small but real axiom circuit (a Poseidon hash). This is the prerequisite
//! unknown before porting the production prover — that the axiom backend's KZG
//! pipeline (SHPLONK multi-open + Blake2b transcript) runs end-to-end here.

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::testing::base_test};
use zkmist_circuits::poseidon_axiom::hash_leaf;

#[test]
fn test_axiom_real_kzg_roundtrip_poseidon() {
    let x = Fr::from(42);
    // bench_builder: gen_srs(k) → keygen_vk → keygen_pk → create_proof →
    // check_proof (asserts the proof verifies against the VK).
    let stats = base_test().k(12).lookup_bits(8).bench_builder(x, x, |pool, range, x| {
        let ctx = pool.main();
        let cell = ctx.load_witness(x);
        hash_leaf(ctx, range, cell);
    });
    eprintln!(
        "axiom real-KZG round-trip OK (Poseidon): proof_size = {} bytes",
        stats.proof_size
    );
}
