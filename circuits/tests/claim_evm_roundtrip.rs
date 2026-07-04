//! Full axiom claim-circuit → on-chain verifier → EVM round-trip.
//!
//! The real gate for the FIXED claim circuit (including the Merkle path-index
//! boolean constraint from `merkle_axiom`). It builds the full depth-26 claim
//! circuit, keygens on a dev SRS, creates a real SHPLONK proof, generates the
//! snark-verifier Solidity verifier from the SAME vk, and runs `evm_verify`
//! (revm deploy + call) — proving the prover's transcript/instances match what
//! the on-chain verifier accepts.
//!
//! ⚠️ Heavy: k=21 (~2M advice cells, keygen ~12s + proof ~23s + verifier gen).
//! Gated behind `ZKMIST_RUN_CLAIM_ROUNDTRIP=1` so the default `cargo test`
//! suite stays fast/green; opted-in it is a HARD gate (no silent skip).
//!
//! NOTE: uses `gen_srs` (toxic-waste dev SRS). That validates the
//! circuit↔verifier↔EVM wiring and transcript, NOT proof soundness — the
//! trapdoor holder could forge. Mainnet soundness needs the pinned PSE
//! ceremony SRS (see cli/src/constants.rs KZG_SRS_SHA256).

use ff::PrimeField;
use group::Curve;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    gates::circuit::builder::RangeCircuitBuilder,
    gates::RangeChip,
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::{bn256::{Bn256, Fr}, secp256k1::{Fp, Fq, Secp256k1Affine}, CurveAffine},
        plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
        poly::commitment::Params,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{fs::gen_srs, modulus},
};
use num_bigint::BigUint;
use snark_verifier_sdk::{
    evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk, evm_verify},
    CircuitExt,
};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::{
    claim_axiom::prove_claim_to_cells,
    nullifier_axiom::domain_field_element,
    poseidon_axiom::native_hash_interior,
    secp_axiom::assign_privkey,
};
use zkmist_merkle_tree::halo2base::build_single_leaf_proof;

const TREE_DEPTH: usize = 26;
const K: u32 = 21;

/// `CircuitExt` marker for snark-verifier verifier generation (num_instance =
/// 3; non-aggregated → accumulator_indices = None). Mirrors the prover's
/// `AxiomClaimMarker`.
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

fn bytes_be_to_fr(b: &[u8]) -> Fr {
    let mut v = Fr::zero();
    for &x in b {
        v = v * Fr::from(256u64) + Fr::from(x as u64);
    }
    v
}

fn bytes_be_to_fq(b: &[u8]) -> Fq {
    let big = BigUint::from_bytes_be(b);
    let mut limbs = [0u64; 4];
    for (i, limb) in big.iter_u64_digits().enumerate().take(4) {
        limbs[i] = limb;
    }
    Fq::from_raw(limbs)
}

fn native_pubkey(privkey: Fq) -> (Fp, Fp) {
    let g = Secp256k1Affine::generator();
    let pt = (g * privkey).to_affine();
    let c = pt.coordinates().unwrap();
    (*c.x(), *c.y())
}

fn fp_be_bytes(fp: &Fp) -> [u8; 32] {
    let mut b = fp.to_repr();
    b.reverse();
    b
}

#[test]
fn test_claim_circuit_evm_roundtrip() {
    if !matches!(std::env::var("ZKMIST_RUN_CLAIM_ROUNDTRIP").as_deref(), Ok("1")) {
        eprintln!(
            "claim EVM round-trip: skipped (set ZKMIST_RUN_CLAIM_ROUNDTRIP=1 to enable). \
             Heavy (k=21); validates the fixed claim circuit verifies on-chain."
        );
        return;
    }

    // ── Witness: PRD test key → address → single-leaf depth-26 Merkle proof ──
    let privkey: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let privkey_fq = bytes_be_to_fq(&privkey);
    let (x_fp, y_fp) = native_pubkey(privkey_fq);
    let mut h = Keccak::v256();
    h.update(&fp_be_bytes(&x_fp));
    h.update(&fp_be_bytes(&y_fp));
    let mut digest = [0u8; 32];
    h.finalize(&mut digest);
    let addr: [u8; 20] = digest[12..32].try_into().unwrap();
    assert_eq!(
        hex::encode(addr),
        "fcad0b19bb29d4674531d6f115237e16afce377c",
        "test-vector address mismatch"
    );

    let (root, siblings, path) = build_single_leaf_proof(&addr, TREE_DEPTH);
    let siblings_fr: Vec<Fr> = siblings.iter().map(|s| bytes_be_to_fr(s)).collect();
    let path_fr: Vec<Fr> = path.iter().map(|p| Fr::from(*p as u64)).collect();
    let root_fr = bytes_be_to_fr(&root);

    let mut recipient = [0u8; 20];
    recipient[18] = 0xB0;
    recipient[19] = 0x0B;
    let mut recip_padded = [0u8; 32];
    recip_padded[12..32].copy_from_slice(&recipient);
    let recipient_fr = bytes_be_to_fr(&recip_padded);

    // Nullifier (native): poseidon(privkey mod p_BN254, domain).
    let privkey_big = BigUint::from_bytes_be(&privkey);
    let key_mod_p = bytes_be_to_fr(&(&privkey_big % &modulus::<Fr>()).to_bytes_be());
    let nullifier_fr = native_hash_interior(key_mod_p, domain_field_element());

    let instances = vec![vec![root_fr, nullifier_fr, recipient_fr]];

    let build = |b: &mut RangeCircuitBuilder<Fr>| {
        let range = RangeChip::new(8, b.lookup_manager().clone());
        let ctx = b.pool(0).main();
        let limbs = assign_privkey(ctx, privkey_fq);
        let (r, n, rc) =
            prove_claim_to_cells(ctx, &range, limbs, &siblings_fr, &path_fr, recipient_fr);
        b.assigned_instances[0] = vec![r, n, rc];
    };

    // ── keygen ──
    eprintln!("[roundtrip] keygen stage (k={K})...");
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(K as usize)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    build(&mut kb);
    let config_params = kb.calculate_params(Some(9));
    let params = if std::env::var("ZKMIST_USE_PINNED_SRS").as_deref() == Ok("1") {
        // Load the pinned PSE ceremony SRS (k=23) for the k=21 circuit. A larger
        // KZG SRS transparently serves a smaller circuit (extra powers unused);
        // this is the production path. Provenance of the file itself is an
        // external-trust step (docs/kzg-srs.md §2.2) — not established here.
        let p = std::env::var("ZKMIST_SRS_FILE")
            .unwrap_or_else(|_| "/home/riddler/.zkmist/cache/v2_params_k23.bin".to_string());
        eprintln!("[roundtrip] loading PINNED SRS ({p}) for the k={K} circuit...");
        let f = std::fs::File::open(&p).expect("open pinned SRS");
        let params = ParamsKZG::<Bn256>::read(&mut std::io::BufReader::new(f))
            .expect("read pinned SRS");
        assert!(params.k() >= K, "pinned SRS k={} < circuit k={K}", params.k());
        eprintln!("[roundtrip] pinned SRS loaded (k={})", params.k());
        params
    } else {
        eprintln!("[roundtrip] using toxic-waste gen_srs (dev)...");
        gen_srs(K)
    };
    let vk = keygen_vk(&params, &kb).expect("vk");
    let pk = keygen_pk(&params, vk.clone(), &kb).expect("pk");
    let break_points = kb.break_points();
    drop(kb);

    // ── prover ──
    eprintln!("[roundtrip] prover stage...");
    let mut pb = RangeCircuitBuilder::prover(config_params, break_points);
    build(&mut pb);
    let proof = gen_evm_proof_shplonk(&params, &pk, pb, instances.clone());
    eprintln!("[roundtrip] proof = {} bytes", proof.len());

    // ── generate + compile the on-chain verifier, then evm_verify ──
    eprintln!("[roundtrip] generating Solidity verifier + evm_verify...");
    // If ZKMIST_EMIT_VERIFIER=<path> is set, write the verifier .sol there
    // (banner-marked as dev-SRS / wiring-only — NOT mainnet-sound).
    let emit_path = std::env::var("ZKMIST_EMIT_VERIFIER").ok();
    let deployment = gen_evm_verifier_shplonk::<AxiomClaimMarker>(
        &params,
        &vk,
        vec![3],
        emit_path.as_deref().map(std::path::Path::new),
    );
    if let Some(p) = &emit_path {
        let sol = std::fs::read_to_string(p).expect("read emitted verifier");
        let pinned = std::env::var("ZKMIST_USE_PINNED_SRS").as_deref() == Ok("1");
        let banner = if pinned {
            "/// @dev ⚠️ PINNED-SRS VERIFIER — generated against the file pinned by\n\
///      `KZG_SRS_SHA256` (currently ~/.zkmist/cache/v2_params_k23.bin, derived\n\
///      from ppot_0080_23.ptau). A proof verifies here iff the prover\n\
///      transcript/instances/VK are wired correctly. Soundness (non-forgeability)\n\
///      additionally requires that the pinned file's digest be cross-referenced\n\
///      against the PSE ceremony's published records (docs/kzg-srs.md §2.2) —\n\
///      that EXTERNAL provenance step is NOT yet done; do not deploy to mainnet\n\
///      until it is. Generated by circuits/tests/claim_evm_roundtrip.rs\n\
///      (ZKMIST_EMIT_VERIFIER + ZKMIST_USE_PINNED_SRS).\n"
        } else {
            "/// @dev ⚠️ DEV-SRS WIRING-ONLY VERIFIER — generated against a toxic-waste\n\
///      `gen_srs` SRS, NOT the pinned PSE ceremony SRS. A proof verifies here\n\
///      iff the prover transcript/instances/VK are wired correctly, but the\n\
///      trapdoor holder can forge. Regenerate with the pinned SRS before\n\
///      mainnet (`gen-roundtrip-fixture` + this emitter under ZKMIST_USE_PINNED_SRS=1).\n\
///      Generated by circuits/tests/claim_evm_roundtrip.rs (ZKMIST_EMIT_VERIFIER).\n"
        };
        // Keep SPDX + pragma at the very top (foundry parses them first); sit
        // the banner directly above the contract body. Normalize the codegen's
        // pinned `pragma solidity 0.8.19;` to `^0.8.19` so it compiles under a
        // caret-compatible foundry solc_version (the committed verifier must
        // coexist with the `^0.8.28` app contracts).
        let sol = sol
            .replacen("pragma solidity 0.8.19;", "pragma solidity ^0.8.19;", 1);
        let out = sol.replacen("contract Halo2Verifier", &format!("{banner}contract Halo2Verifier"), 1);
        std::fs::write(p, out).expect("write emitted verifier");
        eprintln!("[roundtrip] wrote verifier → {p}");
    }
    let gas = evm_verify(deployment, instances, proof).expect("EVM verify failed");
    eprintln!("[roundtrip] ✅ claim circuit on-chain round-trip OK: gas = {gas}");
}
