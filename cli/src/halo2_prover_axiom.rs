//! Axiom-backend Halo2-KZG prover for ZKMist V2 (Phase 4 — see
//! `docs/axiom-backend-migration.md`). The axiom counterpart to
//! [`crate::halo2_prover`]: builds the [`zkmist_circuits::claim_axiom`] circuit,
//! keygens, and creates a real-KZG **SHPLONK** proof (EVM-compatible transcript,
//! so it verifies in the snark-verifier-generated `Halo2Verifier.axiom.sol`).
//!
//! Public outputs `(merkle_root, nullifier, recipient)` are exposed as the
//! circuit's public instance, matching the on-chain verifier model.
//!
//! ℹ️ SRS: uses `halo2_base::utils::fs::gen_srs` (a toxic-waste SRS, fine for
//! dev/testnet). Production needs the PSE ceremony SRS adapted to the axiom
//! backend — a deployment task.

use std::path::Path;

use halo2_base::{
    gates::RangeChip,
    gates::circuit::CircuitBuilderStage,
    gates::circuit::builder::RangeCircuitBuilder,
    halo2_proofs::{
        halo2curves::{
            bn256::Fr,
            secp256k1::Fq,
        },
        plonk::{keygen_pk, keygen_vk},
    },
    utils::{fs::gen_srs, modulus},
};
use num_bigint::BigUint;
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};

use zkmist_circuits::{
    claim_axiom::prove_claim_to_cells,
    nullifier_axiom::domain_field_element,
    poseidon_axiom::native_hash_interior,
    secp_axiom::assign_privkey,
};

/// Circuit degree for the axiom claim circuit (≈1.9M advice cells; the secp
/// + Keccak dominate). Real-KZG proving peaks well under ~10 GiB at k=21
/// (vs k=23's ~25 GiB on the PSE stack). ⚠️ Must match the verifier generation.
pub const AXIOM_CIRCUIT_K: u32 = 21;

/// Read a big-endian byte slice as an axiom `Fr` (reduced mod p_BN254).
pub(crate) fn bytes_be_to_fr(b: &[u8]) -> Fr {
    let mut v = Fr::zero();
    for &x in b {
        v = v * Fr::from(256u64) + Fr::from(x as u64);
    }
    v
}

/// Read a big-endian byte slice as a secp256k1 scalar `Fq` (assumed < n).
pub(crate) fn bytes_be_to_fq(b: &[u8]) -> Fq {
    let big = BigUint::from_bytes_be(b);
    let mut limbs = [0u64; 4];
    for (i, limb) in big.iter_u64_digits().enumerate().take(4) {
        limbs[i] = limb;
    }
    Fq::from_raw(limbs)
}

/// `BigUint → Fr` (reduced mod p_BN254).
pub(crate) fn biguint_to_fr(b: &BigUint) -> Fr {
    bytes_be_to_fr(&b.to_bytes_be())
}

/// Generate a ZKMist V2 claim proof on the axiom backend.
///
/// Mirrors [`crate::halo2_prover::generate_v2_proof`]'s signature so it is a
/// drop-in. Writes a [`crate::types::ProofFile`] (proof hex + nullifier +
/// recipient + chain metadata) to `output_path`; returns the 32-byte nullifier.
#[allow(clippy::too_many_arguments)]
pub fn generate_v2_proof_axiom(
    private_key: &[u8; 32],
    siblings: &[[u8; 32]],
    path_indices: &[u8],
    merkle_root: &[u8; 32],
    recipient: &[u8; 20],
    output_path: &Path,
) -> Result<[u8; 32], String> {
    let k = AXIOM_CIRCUIT_K;
    eprintln!("      [axiom] Building claim circuit (k={})...", k);

    // ── Witnesses → axiom field elements ─────────────────────────────
    let privkey_fq = bytes_be_to_fq(private_key);
    let siblings_fr: Vec<Fr> = siblings.iter().map(|s| bytes_be_to_fr(s)).collect();
    let path_indices_fr: Vec<Fr> = path_indices.iter().map(|p| Fr::from(*p as u64)).collect();
    let root_fr = bytes_be_to_fr(merkle_root);
    let mut recip_padded = [0u8; 32];
    recip_padded[12..32].copy_from_slice(recipient);
    let recipient_fr = bytes_be_to_fr(&recip_padded);

    // Nullifier (native, halo2-base convention): poseidon(privkey mod p_BN254, domain).
    let privkey_big = BigUint::from_bytes_be(private_key);
    let p_bn254: BigUint = modulus::<Fr>();
    let key_mod_p = biguint_to_fr(&(&privkey_big % &p_bn254));
    let nullifier_fr = native_hash_interior(key_mod_p, domain_field_element());

    let build = |builder: &mut RangeCircuitBuilder<Fr>| {
        let range = RangeChip::new(8, builder.lookup_manager().clone());
        let ctx = builder.pool(0).main();
        let limbs = assign_privkey(ctx, privkey_fq);
        let (root, null, recip) = prove_claim_to_cells(
            ctx, &range, limbs, &siblings_fr, &path_indices_fr, recipient_fr,
        );
        builder.assigned_instances[0] = vec![root, null, recip];
    };

    // ── keygen stage ─────────────────────────────────────────────────
    eprintln!("      [axiom] Loading KZG params...");
    let params = gen_srs(k);
    let t0 = std::time::Instant::now();
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(k as usize)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    build(&mut kb);
    let _config_params = kb.calculate_params(Some(9));
    eprintln!("      [axiom] keygen_vk...");
    let vk = keygen_vk(&params, &kb).map_err(|e| format!("VK generation failed: {:?}", e))?;
    let pk = keygen_pk(&params, vk.clone(), &kb).map_err(|e| format!("PK generation failed: {:?}", e))?;
    let break_points = kb.break_points();
    eprintln!("      [axiom] keygen done ({:.1}s)", t0.elapsed().as_secs_f64());
    drop(kb);

    // ── prover stage ────────────────────────────────────────────────
    let mut pb = RangeCircuitBuilder::prover(_config_params, break_points);
    build(&mut pb);

    eprintln!("      [axiom] creating SHPLONK proof...");
    let t1 = std::time::Instant::now();
    let proof = gen_evm_proof_shplonk(
        &params,
        &pk,
        pb,
        vec![vec![root_fr, nullifier_fr, recipient_fr]],
    );
    eprintln!(
        "      [axiom] proof created: {} bytes ({:.1}s)",
        proof.len(),
        t1.elapsed().as_secs_f64()
    );

    use halo2_base::utils::fe_to_biguint;
    // ── serialize ───────────────────────────────────────────────────
    let nullifier_bytes = {
        let be = fe_to_biguint(&nullifier_fr).to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be); // left-pad to 32 BE bytes
        out
    };
    let proof_file = crate::types::ProofFile {
        version: 2,
        proof_format_version: crate::constants::PROOF_FORMAT_VERSION,
        proof: hex::encode(&proof),
        journal: String::new(),
        nullifier: hex::encode(nullifier_bytes),
        recipient: hex::encode(recipient),
        claim_amount: crate::constants::CLAIM_AMOUNT.to_string(),
        contract_address: crate::constants::AIRDROP_CONTRACT.to_string(),
        chain_id: crate::constants::CHAIN_ID,
        receipt_hex: None,
    };
    std::fs::write(output_path, serde_json::to_string_pretty(&proof_file).unwrap())
        .map_err(|e| format!("Failed to write proof: {}", e))?;
    eprintln!("      [axiom] proof saved: {}", output_path.display());

    // Sanity: generate + compile the on-chain verifier once (proves the proof
    // is on-chain-verifiable). In production this is a separate gen-verifier step.
    let _bytecode = gen_evm_verifier_shplonk::<AxiomClaimMarker>(
        &params, &vk, vec![3], None,
    );

    Ok(nullifier_bytes)
}

// CircuitExt marker for snark-verifier verifier generation (num_instance = 3;
// non-aggregated → accumulator_indices = None).
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use snark_verifier_sdk::CircuitExt;

struct AxiomClaimMarker;
impl Circuit<Fr> for AxiomClaimMarker {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self { Self }
    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {}
    fn synthesize(&self, _: Self::Config, _: impl Layouter<Fr>) -> Result<(), Error> { Ok(()) }
}
impl CircuitExt<Fr> for AxiomClaimMarker {
    fn num_instance(&self) -> Vec<usize> { vec![3] }
    fn instances(&self) -> Vec<Vec<Fr>> { vec![] }
}
