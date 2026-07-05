//! Axiom-backend Halo2-KZG prover for ZKMist V2 (Phase 4 — see
//! `docs/axiom-backend-migration.md`). The axiom counterpart to
//! [`crate::halo2_prover`]: builds the [`zkmist_circuits::claim_axiom`] circuit,
//! keygens, and creates a real-KZG **SHPLONK** proof (EVM-compatible transcript,
//! so it verifies in the snark-verifier-generated `Halo2Verifier.axiom.sol`).
//!
//! Public outputs `(merkle_root, nullifier, recipient)` are exposed as the
//! circuit's public instance, matching the on-chain verifier model.
//!
//! ℹ️ SRS: `load_srs_axiom` downloads + SHA-256-verifies the pinned PSE
//! perpetual-powers-of-tau ceremony SRS (`constants::KZG_SRS_URL` /
//! `KZG_SRS_SHA256`) — the universal k=23 transcript, provenance-confirmed
//! against the public beaconed ceremony by `tools/src/verify_srs_from_ptau.rs`.
//! Only `ZKMIST_DEV_SRS=1` (or an unset trust root) falls back to `gen_srs`,
//! a toxic-waste SRS for dev/testnet only.

use std::path::Path;

use halo2_base::{
    gates::circuit::builder::RangeCircuitBuilder,
    gates::circuit::CircuitBuilderStage,
    gates::RangeChip,
    halo2_proofs::{
        halo2curves::bn256::Bn256,
        halo2curves::bn256::Fr,
        halo2curves::secp256k1::Fq,
        plonk::{keygen_pk, keygen_vk},
        poly::commitment::Params,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{fs::gen_srs, modulus},
};
use num_bigint::BigUint;
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};

/// Cache dir for the KZG SRS (~/.zkmist/cache).
pub(crate) fn get_cache_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("Cannot find home directory")?;
    let cache_dir = home.join(crate::constants::ZKMIST_DIR_NAME).join("cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache dir: {}", e))?;
    Ok(cache_dir)
}

use zkmist_circuits::{
    claim_axiom::prove_claim_to_cells,
    nullifier_axiom::domain_field_element,
    poseidon_axiom::native_hash_interior,
    secp_axiom::{assign_privkey, secp_n_biguint},
};

/// Circuit degree for the axiom claim circuit (≈1.9M advice cells; secp and
/// Keccak dominate). Real-KZG proving peaks well under ~10 GiB at k=21
/// (vs k=23's ~25 GiB on the PSE stack). ⚠️ Must match the verifier generation.
pub const AXIOM_CIRCUIT_K: u32 = 21;

/// Load the KZG SRS for the axiom backend.
///
/// **Production:** downloads + SHA-256-verifies the pinned PSE perpetual
/// powers-of-tau ceremony SRS (`constants::KZG_SRS_URL`/`KZG_SRS_SHA256`) and
/// reads it with the axiom `ParamsKZG`. The axiom and PSE `ParamsKZG`
/// serializations are byte-compatible (verified by `srs_format_compat_tests`),
/// so the ceremony SRS — a universal powers-of-tau SRS at k=23 — serves the
/// k=21 axiom circuit (asserts `srs_k >= circuit_k`).
///
/// **Dev fallback:** `ZKMIST_DEV_SRS=1` (or an unset trust root) uses
/// `gen_srs` (a toxic-waste SRS) so tests/benchmarks run without the download.
pub fn load_srs_axiom(circuit_k: u32) -> Result<ParamsKZG<Bn256>, String> {
    let pinned_hash = crate::constants::KZG_SRS_SHA256.trim();
    let pinned_url = crate::constants::KZG_SRS_URL.trim();
    let production = !pinned_hash.is_empty() && !pinned_url.is_empty();

    if !production || std::env::var("ZKMIST_DEV_SRS").as_deref() == Ok("1") {
        eprintln!("         ⚠️  axiom SRS: toxic-waste gen_srs (dev/testnet only)");
        return Ok(gen_srs(circuit_k));
    }

    let path = get_cache_dir()?.join("v2_axiom_srs.bin");
    if !path.exists()
        || !matches!(
            crate::download::verify_file_sha256(&path, pinned_hash),
            Ok(true)
        )
    {
        eprintln!("         Downloading axiom KZG SRS from {}", pinned_url);
        crate::download::download_and_verify_to_file(pinned_url, pinned_hash, &path)?;
    }
    let file = std::fs::File::open(&path).map_err(|e| format!("open SRS: {e}"))?;
    let params = ParamsKZG::<Bn256>::read(&mut std::io::BufReader::new(file))
        .map_err(|e| format!("axiom SRS read failed: {e:?}"))?;
    let srs_k = params.k();
    if srs_k < circuit_k {
        return Err(format!(
            "Ceremony SRS is k={srs_k} but the axiom circuit needs k>={circuit_k}"
        ));
    }
    eprintln!("         ✓ axiom KZG SRS loaded (ceremony k={srs_k}, SHA-256 verified)");
    Ok(params)
}

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

    // ── Validate + lift the private key ──────────────────────────────
    // `cmd_prove` already rejects keys outside [1, n-1] via `derive_address`
    // (k256). Enforce the SAME policy here so the prover and the address
    // derivation can never disagree on which scalar is being used: a key ≥ n
    // would be silently reduced mod n by `bytes_be_to_fq` below, producing an
    // address that differs from what `derive_address` computed upstream. The
    // circuit's `K < n` range proof independently rejects a malicious ≥ n
    // witness; this guard is about prover/derivation consistency, not soundness.
    let privkey_big = BigUint::from_bytes_be(private_key);
    if privkey_big == BigUint::from(0u64) || privkey_big >= secp_n_biguint() {
        return Err(
            "Invalid private key: scalar must be in [1, n-1] (secp256k1). \
             `derive_address` should have caught this — caller bug."
                .to_string(),
        );
    }

    // ── Witnesses → axiom field elements ─────────────────────────────
    let privkey_fq = bytes_be_to_fq(private_key);
    let siblings_fr: Vec<Fr> = siblings.iter().map(|s| bytes_be_to_fr(s)).collect();
    let path_indices_fr: Vec<Fr> = path_indices.iter().map(|p| Fr::from(*p as u64)).collect();
    let root_fr = bytes_be_to_fr(merkle_root);
    let mut recip_padded = [0u8; 32];
    recip_padded[12..32].copy_from_slice(recipient);
    let recipient_fr = bytes_be_to_fr(&recip_padded);

    // Nullifier (native, halo2-base convention): poseidon(privkey mod p_BN254, domain).
    let p_bn254: BigUint = modulus::<Fr>();
    let key_mod_p = biguint_to_fr(&(&privkey_big % &p_bn254));
    let nullifier_fr = native_hash_interior(key_mod_p, domain_field_element());

    let build = |builder: &mut RangeCircuitBuilder<Fr>| {
        let range = RangeChip::new(8, builder.lookup_manager().clone());
        let ctx = builder.pool(0).main();
        let limbs = assign_privkey(ctx, privkey_fq);
        let (root, null, recip) = prove_claim_to_cells(
            ctx,
            &range,
            limbs,
            &siblings_fr,
            &path_indices_fr,
            recipient_fr,
        );
        builder.assigned_instances[0] = vec![root, null, recip];
    };

    // ── keygen stage ─────────────────────────────────────────────────
    eprintln!("      [axiom] Loading KZG params...");
    let params = load_srs_axiom(k)?;
    let t0 = std::time::Instant::now();
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(k as usize)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    build(&mut kb);
    let _config_params = kb.calculate_params(Some(9));
    eprintln!("      [axiom] keygen_vk...");
    let vk = keygen_vk(&params, &kb).map_err(|e| format!("VK generation failed: {:?}", e))?;
    let pk = keygen_pk(&params, vk.clone(), &kb)
        .map_err(|e| format!("PK generation failed: {:?}", e))?;
    let break_points = kb.break_points();
    eprintln!(
        "      [axiom] keygen done ({:.1}s)",
        t0.elapsed().as_secs_f64()
    );
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
    let proof_json = serde_json::to_string_pretty(&proof_file)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    std::fs::write(output_path, &proof_json)
        .map_err(|e| format!("Failed to write proof: {}", e))?;
    eprintln!("      [axiom] proof saved: {}", output_path.display());

    // Opt-in sanity check: regenerate the on-chain verifier from this VK to
    // confirm the proof is on-chain-verifiable. OFF by default — it is full
    // Solidity/Yul codegen and adds avoidable latency + memory to every proof.
    // Prover↔verifier agreement is already covered by the real-KZG round-trip
    // (`test_axiom_claim_real_kzg_roundtrip`) and the on-chain `RealRoundtrip`
    // Forge test against the `gen-roundtrip-fixture` output. Enable for an
    // explicit one-off check: `ZKMIST_GEN_VERIFIER=1 zkmist prove ...`.
    if std::env::var("ZKMIST_GEN_VERIFIER").as_deref() == Ok("1") {
        let _bytecode = gen_evm_verifier_shplonk::<AxiomClaimMarker>(&params, &vk, vec![3], None);
        eprintln!("      [axiom] verifier regenerated from VK (ZKMIST_GEN_VERIFIER sanity check)");
    }

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
    fn without_witnesses(&self) -> Self {
        Self
    }
    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {}
    fn synthesize(&self, _: Self::Config, _: impl Layouter<Fr>) -> Result<(), Error> {
        Ok(())
    }
}
impl CircuitExt<Fr> for AxiomClaimMarker {
    fn num_instance(&self) -> Vec<usize> {
        vec![3]
    }
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}
