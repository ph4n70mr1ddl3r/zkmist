//! Phase 3 capstone — the axiom ZKMist V2 claim circuit: happy path + the four
//! forgery-rejection negatives (see `docs/axiom-backend-migration.md` §11,
//! `docs/secp256k1-migration-plan.md` §5/§5a).
//!
//! Each negative runs the FULL claim circuit with one input tampered and
//! `expect_satisfied(false)`; `base_test` asserts MockProver rejects it. The
//! `K ≥ n` case (§5a TRAP) is also covered in isolation by the fast tests in
//! `tests/secp_axiom.rs`.

use ff::PrimeField;
use group::Curve;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    gates::circuit::builder::RangeCircuitBuilder,
    gates::RangeChip,
    halo2_proofs::{
        halo2curves::{
            bn256::Fr,
            secp256k1::{Fp, Fq, Secp256k1Affine},
            CurveAffine,
        },
        plonk::{keygen_pk, keygen_vk},
    },
    utils::{biguint_to_fe, fe_to_biguint, fs::gen_srs, modulus, testing::{
        base_test, check_proof_with_instances, gen_proof_with_instances,
    }},
};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::{
    claim_axiom::{prove_claim, prove_claim_to_cells},
    nullifier_axiom::domain_field_element,
    poseidon_axiom::{native_hash_interior, native_hash_leaf},
    secp_axiom::{assign_privkey, assign_scalar_biguint, secp_n_biguint},
};
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

fn address_to_fr(addr: &[u8; 20]) -> Fr {
    let mut v = Fr::zero();
    for &byte in addr {
        v = v * Fr::from(256u64) + Fr::from(byte as u64);
    }
    v
}

#[derive(Clone)]
struct Claim {
    privkey: Fq,
    siblings: Vec<Fr>,
    path_indices: Vec<Fr>,
    root: Fr,
    nullifier: Fr,
    recipient: Fr,
}

/// Build a valid claim natively: privkey → address → 16-leaf Merkle tree →
/// proof → root; nullifier; non-zero recipient.
fn build_valid_claim(depth: usize, claim_idx: usize) -> Claim {
    let privkey = Fq::from(0x0A11CE_5EC7E7u64);
    let (x_fp, y_fp) = native_pubkey(privkey);
    let mut h = Keccak::v256();
    h.update(&fp_be_bytes(&x_fp));
    h.update(&fp_be_bytes(&y_fp));
    let mut digest = [0u8; 32];
    h.finalize(&mut digest);
    let claim_leaf = native_hash_leaf(address_to_fr(digest[12..32].try_into().unwrap()));

    let mut leaf_hashes = Vec::with_capacity(1 << depth);
    for i in 0..(1u64 << depth) {
        if i as usize == claim_idx {
            leaf_hashes.push(claim_leaf);
        } else {
            leaf_hashes.push(native_hash_leaf(Fr::from(1_000_000 + i)));
        }
    }

    // Merkle proof for claim_idx.
    let mut layer = leaf_hashes.clone();
    let mut siblings = Vec::with_capacity(depth);
    let mut path_indices = Vec::with_capacity(depth);
    let mut idx = claim_idx;
    for _ in 0..depth {
        let sib = if idx % 2 == 0 { layer[idx + 1] } else { layer[idx - 1] };
        siblings.push(sib);
        path_indices.push(Fr::from((idx % 2) as u64));
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(native_hash_interior(pair[0], pair[1]));
        }
        layer = next;
        idx /= 2;
    }
    let root = layer[0];

    // Nullifier: poseidon(privkey mod p_BN254, domain).
    let k_big = fe_to_biguint(&privkey);
    let p: num_bigint::BigUint = modulus::<Fr>();
    let key_mod_p = biguint_to_fe(&(k_big % p));
    let nullifier = native_hash_interior(key_mod_p, domain_field_element());

    let mut r = [0u8; 20];
    r[19] = 0x42;
    let recipient = address_to_fr(&r);

    Claim { privkey, siblings, path_indices, root, nullifier, recipient }
}

#[test]
fn test_axiom_claim_happy_path() {
    let c = build_valid_claim(4, 5);
    base_test().k(21).lookup_bits(8).run(|ctx, range| {
        let limbs = assign_privkey(ctx, c.privkey);
        prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices, c.root, c.nullifier, c.recipient);
    });
}

#[test]
fn test_axiom_claim_rejects_wrong_root() {
    let c = build_valid_claim(4, 5);
    base_test()
        .k(21).lookup_bits(8).expect_satisfied(false)
        .run(|ctx, range| {
            let limbs = assign_privkey(ctx, c.privkey);
            prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices,
                        c.root + Fr::from(1u64), c.nullifier, c.recipient);
        });
}

#[test]
fn test_axiom_claim_rejects_wrong_nullifier() {
    let c = build_valid_claim(4, 5);
    base_test()
        .k(21).lookup_bits(8).expect_satisfied(false)
        .run(|ctx, range| {
            let limbs = assign_privkey(ctx, c.privkey);
            prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices,
                        c.root, c.nullifier + Fr::from(1u64), c.recipient);
        });
}

#[test]
fn test_axiom_claim_rejects_zero_recipient() {
    let c = build_valid_claim(4, 5);
    base_test()
        .k(21).lookup_bits(8).expect_satisfied(false)
        .run(|ctx, range| {
            let limbs = assign_privkey(ctx, c.privkey);
            prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices,
                        c.root, c.nullifier, Fr::zero());
        });
}

/// The §5a TRAP at the full-circuit level: a key `K = n + 1 (≥ n)` must be
/// rejected by the range proof (so `scalar·G` can't be decoupled from the
/// nullifier key). `Fq` can't represent K ≥ n, so limbs are injected directly.
#[test]
fn test_axiom_claim_rejects_key_above_n() {
    let c = build_valid_claim(4, 5);
    let n_plus_1 = secp_n_biguint() + 1u32;
    base_test()
        .k(21).lookup_bits(8).expect_satisfied(false)
        .run(|ctx, range| {
            let limbs = assign_scalar_biguint(ctx, n_plus_1);
            prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices,
                        c.root, c.nullifier, c.recipient);
        });
}

/// **Phase 4 de-risk:** a REAL KZG round-trip on the full claim circuit
/// (gen_srs → keygen → create_proof → verify). Proves an axiom proof of an
/// actual ZKMist claim verifies under real SHPLONK KZG — the last big unknown
/// before porting the production prover.
#[test]
fn test_axiom_claim_real_kzg_roundtrip() {
    let c = build_valid_claim(4, 5);
    let stats = base_test()
        .k(21)
        .lookup_bits(8)
        .bench_builder(c.clone(), c, |pool, range, c| {
            let ctx = pool.main();
            let limbs = assign_privkey(ctx, c.privkey);
            prove_claim(ctx, range, limbs, &c.siblings, &c.path_indices,
                        c.root, c.nullifier, c.recipient);
        });
    eprintln!(
        "axiom claim real-KZG round-trip OK: proof_size = {} bytes",
        stats.proof_size
    );
}

/// End-to-end: a tree built by the OFF-CHAIN tooling
/// (`zkmist_merkle_tree::halo2base`) is verified by the IN-CIRCUIT claim logic.
/// This is the real production flow — eligibility list → off-chain tree →
/// circuit proof — and proves the two agree on the Poseidon convention.
#[test]
fn test_axiom_claim_verifies_offchain_tree() {
    use zkmist_merkle_tree::halo2base::{build_tree_with_depth, generate_proof, tree_root};

    let depth = 4usize;
    let privkey = Fq::from(0x0A11CE_5EC7E7u64);

    // privkey → Ethereum address.
    let (x_fp, y_fp) = native_pubkey(privkey);
    let mut h = Keccak::v256();
    h.update(&fp_be_bytes(&x_fp));
    h.update(&fp_be_bytes(&y_fp));
    let mut digest = [0u8; 32];
    h.finalize(&mut digest);
    let claim_addr: [u8; 20] = digest[12..32].try_into().unwrap();
    let claim_idx = 9usize;

    // Off-chain tree (halo2-base convention) containing the claim's address.
    let mut addresses = vec![[0u8; 20]; 1 << depth];
    for (i, a) in addresses.iter_mut().enumerate() {
        a[19] = (i as u8).wrapping_add(1);
    }
    addresses[claim_idx] = claim_addr;
    let layers = build_tree_with_depth(&addresses, depth);
    let root_bytes = tree_root(&layers);
    let (sib_bytes, path_u8) = generate_proof(&layers, claim_idx);

    // Convert the off-chain proof (32-byte BE siblings, u8 indices) → axiom Fr
    // witnesses, exactly as a prover would when filling the circuit.
    let bytes32_to_fr = |b: &[u8; 32]| -> Fr {
        let mut v = Fr::zero();
        for &x in b { v = v * Fr::from(256u64) + Fr::from(x as u64); }
        v
    };
    let siblings: Vec<Fr> = sib_bytes.iter().map(bytes32_to_fr).collect();
    let path_indices: Vec<Fr> = path_u8.iter().map(|p| Fr::from(*p as u64)).collect();
    let root = bytes32_to_fr(&root_bytes);

    // Nullifier (matches the circuit's nullifier↔scalar binding).
    let k_big = fe_to_biguint(&privkey);
    let p: num_bigint::BigUint = modulus::<Fr>();
    let nullifier = native_hash_interior(biguint_to_fe(&(k_big % p)), domain_field_element());

    let mut r = [0u8; 20];
    r[19] = 0x42;
    let recipient = address_to_fr(&r);

    base_test().k(21).lookup_bits(8).run(|ctx, range| {
        let limbs = assign_privkey(ctx, privkey);
        prove_claim(ctx, range, limbs, &siblings, &path_indices, root, nullifier, recipient);
    });
}

// ── Public instances (the on-chain verifier model) ───────────────────────
//
// The claim's (merkle_root, nullifier, recipient) are exposed as a public
// instance column. The proof verifies against the correct instance and is
// REJECTED against a wrong one — exactly what the on-chain verifier (holding
// the real root / checking the nullifier map) does.

/// Full real-KZG round-trip on the claim circuit exposing 1 instance column
/// `[root, nullifier, recipient]`, verified against `instances`.
fn claim_instance_roundtrip(c: &Claim, instances: Vec<Fr>, expect_satisfied: bool) {
    // keygen stage
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(21)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    {
        let range = RangeChip::new(8, kb.lookup_manager().clone());
        let ctx = kb.pool(0).main();
        let limbs = assign_privkey(ctx, c.privkey);
        let (root, null, recip) =
            prove_claim_to_cells(ctx, &range, limbs, &c.siblings, &c.path_indices, c.recipient);
        kb.assigned_instances[0] = vec![root, null, recip];
    }
    let config_params = kb.calculate_params(Some(9));
    let params = gen_srs(21);
    let vk = keygen_vk(&params, &kb).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &kb).unwrap();
    let break_points = kb.break_points();
    drop(kb);

    // prover stage
    let mut pb = RangeCircuitBuilder::prover(config_params, break_points);
    {
        let range = RangeChip::new(8, pb.lookup_manager().clone());
        let ctx = pb.pool(0).main();
        let limbs = assign_privkey(ctx, c.privkey);
        let (root, null, recip) =
            prove_claim_to_cells(ctx, &range, limbs, &c.siblings, &c.path_indices, c.recipient);
        pb.assigned_instances[0] = vec![root, null, recip];
    }
    let proof = gen_proof_with_instances(&params, &pk, pb, &[instances.as_slice()]);
    check_proof_with_instances(&params, &vk, &proof, &[instances.as_slice()], expect_satisfied);
}

#[test]
fn test_axiom_claim_public_instances_verify() {
    let c = build_valid_claim(4, 5);
    claim_instance_roundtrip(&c.clone(), vec![c.root, c.nullifier, c.recipient], true);
}

/// A proof verified against a WRONG merkle root is rejected — the on-chain
/// verifier (holding the real root) would reject a forged claim.
#[test]
fn test_axiom_claim_public_instances_reject_wrong_root() {
    let c = build_valid_claim(4, 5);
    claim_instance_roundtrip(
        &c.clone(),
        vec![c.root + Fr::from(1u64), c.nullifier, c.recipient],
        false,
    );
}

// ── Claim circuit → on-chain Solidity verifier ───────────────────────────
//
// Generates Halo2Verifier.axiom.sol for the claim circuit via snark-verifier-sdk
// (SHPLONK). This is the deployable on-chain verifier. (Compilation + the
// on-chain call are heavy for k≈21; the Poseidon round-trip in
// tests/axiom_solidity_verifier.rs proves the full pipeline end-to-end.)

#[test]
fn test_generate_claim_solidity_verifier() {
    use halo2_base::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use snark_verifier_sdk::{evm::gen_evm_verifier_sol_code, CircuitExt, SHPLONK};

    // CircuitExt marker (num_instance = 3: root, nullifier, recipient;
    // non-aggregated → accumulator_indices = None).
    struct ClaimSolCircuit;
    impl Circuit<Fr> for ClaimSolCircuit {
        type Config = ();
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self { Self }
        fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {}
        fn synthesize(&self, _: Self::Config, _: impl Layouter<Fr>) -> Result<(), Error> { Ok(()) }
    }
    impl CircuitExt<Fr> for ClaimSolCircuit {
        fn num_instance(&self) -> Vec<usize> { vec![3] }
        fn instances(&self) -> Vec<Vec<Fr>> { vec![] }
    }

    let c = build_valid_claim(4, 5);
    let mut kb = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(21)
        .use_instance_columns(1);
    kb.set_lookup_bits(8);
    {
        let range = RangeChip::new(8, kb.lookup_manager().clone());
        let ctx = kb.pool(0).main();
        let limbs = assign_privkey(ctx, c.privkey);
        let (root, null, recip) =
            prove_claim_to_cells(ctx, &range, limbs, &c.siblings, &c.path_indices, c.recipient);
        kb.assigned_instances[0] = vec![root, null, recip];
    }
    let params = gen_srs(21);
    let _config_params = kb.calculate_params(Some(9));
    let vk = keygen_vk(&params, &kb).unwrap();
    drop(kb);

    let sol = gen_evm_verifier_sol_code::<ClaimSolCircuit, SHPLONK>(&params, &vk, vec![3]);
    assert!(sol.contains("pragma solidity"), "not a Solidity source");
    eprintln!("generated claim Halo2Verifier.axiom.sol: {} bytes", sol.len());

    // Write next to the (PSE) vendored verifier, for the contract side to pick up.
    let out = std::env::current_dir()
        .unwrap()
        .join("..")
        .join("contracts")
        .join("Halo2Verifier.axiom.sol");
    std::fs::create_dir_all(out.parent().unwrap()).ok();
    std::fs::write(&out, &sol).expect("write Halo2Verifier.axiom.sol");
    eprintln!("wrote {}", out.display());
}
