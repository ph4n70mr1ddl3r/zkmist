//! Phase 4 step 5 — axiom on-chain Solidity verifier (end-to-end).
//! (see `docs/axiom-backend-migration.md` §14)
//!
//! Generates an on-chain Solidity verifier from a halo2-base circuit via
//! `axiom-crypto/snark-verifier-sdk` (SHPLONK), compiles it, and runs a full
//! EVM round-trip (revm `deploy_and_call`): proof → on-chain verify. This is
//! the production on-chain verification path.
//!
//! ⚠️ Requires `solc` (0.8.19) on `PATH` — `snark_verifier_sdk::compile_solidity`
//! shells out to it. On this machine it's installed at `~/.local/bin/solc`.

use ff::PrimeField;
use halo2_base::{
    gates::circuit::builder::RangeCircuitBuilder,
    gates::circuit::CircuitBuilderStage,
    gates::RangeChip,
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    },
    utils::fs::gen_srs,
};
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    CircuitExt,
};

use zkmist_circuits::poseidon_axiom::{hash_leaf, native_hash_leaf};

/// A `CircuitExt` marker used only for `snark-verifier` EVM-verifier generation
/// (which needs `C::accumulator_indices()` — `None` for a non-aggregated PLONK
/// circuit like ours). The actual circuit instance is `RangeCircuitBuilder`.
struct PoseidonCircuit;

impl Circuit<Fr> for PoseidonCircuit {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self
    }
    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {}
    fn synthesize(&self, _: Self::Config, _: impl Layouter<Fr>) -> Result<(), Error> {
        Ok(())
    }
}

impl CircuitExt<Fr> for PoseidonCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}

#[test]
fn test_solidity_verifier_evm_roundtrip() {
    let x = Fr::from(42);
    let expected = native_hash_leaf(x);

    // keygen stage
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(12)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    {
        let range = RangeChip::new(8, kb.lookup_manager().clone());
        let ctx = kb.pool(0).main();
        let cell = ctx.load_witness(x);
        let h = hash_leaf(ctx, &range, cell);
        kb.assigned_instances[0] = vec![h];
    }
    let config_params = kb.calculate_params(Some(9));
    let params = gen_srs(12);
    let vk = keygen_vk(&params, &kb).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &kb).unwrap();
    let break_points = kb.break_points();
    drop(kb);

    // prover stage
    let mut pb = RangeCircuitBuilder::prover(config_params, break_points);
    {
        let range = RangeChip::new(8, pb.lookup_manager().clone());
        let ctx = pb.pool(0).main();
        let cell = ctx.load_witness(x);
        let h = hash_leaf(ctx, &range, cell);
        pb.assigned_instances[0] = vec![h];
    }

    // EVM-compatible SHPLONK proof.
    let proof = gen_evm_proof_shplonk(&params, &pk, pb, vec![vec![expected]]);

    // Generate + compile the Solidity verifier (calls `solc`).
    let deployment_code = gen_evm_verifier_shplonk::<PoseidonCircuit>(&params, &vk, vec![1], None);

    // On-chain round-trip: deploy the verifier and call it with the proof.
    let gas = evm_verify(deployment_code, vec![vec![expected]], proof).expect("EVM verify failed");
    eprintln!(
        "axiom Solidity verifier on-chain round-trip OK: gas = {}",
        gas
    );
}
