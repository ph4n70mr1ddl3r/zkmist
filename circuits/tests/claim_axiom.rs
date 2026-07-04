//! Phase 3 capstone — the axiom ZKMist V2 claim circuit, happy path
//! (see `docs/axiom-backend-migration.md` §11, `docs/secp256k1-migration-plan.md`
//! §5/§5a).
//!
//! Builds a complete valid claim natively (privkey → address → Merkle tree of
//! 16 leaves → proof → root; nullifier), then runs [`claim_axiom::prove_claim`]
//! in-circuit and lets MockProver assert every constraint — including the
//! `root == expected` and `nullifier == expected` bindings.

use ff::PrimeField;
use group::Curve;
use halo2_base::{
    halo2_proofs::halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
        CurveAffine,
    },
    utils::{biguint_to_fe, fe_to_biguint, modulus, testing::base_test},
};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::{
    claim_axiom::prove_claim,
    nullifier_axiom::domain_field_element,
    poseidon_axiom::{native_hash_interior, native_hash_leaf},
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

/// 20-byte big-endian address → Fr (matches the circuit's recomposition).
fn address_to_fr(addr: &[u8; 20]) -> Fr {
    let mut v = Fr::zero();
    for &byte in addr {
        v = v * Fr::from(256u64) + Fr::from(byte as u64);
    }
    v
}

/// Build a depth-`depth` Merkle tree (halo2-base convention) from leaf hashes;
/// return (root, siblings, path_indices) for `claim_idx`.
fn build_tree(
    leaf_hashes: &[Fr],
    claim_idx: usize,
    depth: usize,
) -> (Fr, Vec<Fr>, Vec<Fr>) {
    assert_eq!(leaf_hashes.len(), 1 << depth);
    let mut layer = leaf_hashes.to_vec();
    let mut siblings = Vec::with_capacity(depth);
    let mut indices = Vec::with_capacity(depth);
    let mut idx = claim_idx;
    for _ in 0..depth {
        let sib = if idx % 2 == 0 { layer[idx + 1] } else { layer[idx - 1] };
        siblings.push(sib);
        indices.push(Fr::from((idx % 2) as u64));
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(native_hash_interior(pair[0], pair[1]));
        }
        layer = next;
        idx /= 2;
    }
    (layer[0], siblings, indices)
}

#[test]
fn test_axiom_claim_happy_path() {
    let depth = 4;

    // A valid secp256k1 private key (well below the order).
    let privkey = Fq::from(0x0A11CE_5EC7E7u64);
    let claim_idx = 5usize;

    // privkey → address.
    let (x_fp, y_fp) = native_pubkey(privkey);
    let mut h = Keccak::v256();
    h.update(&fp_be_bytes(&x_fp));
    h.update(&fp_be_bytes(&y_fp));
    let mut digest = [0u8; 32];
    h.finalize(&mut digest);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    let claim_address_fr = address_to_fr(&addr);
    let claim_leaf = native_hash_leaf(claim_address_fr);

    // Build the tree: claim leaf + 15 dummy leaves.
    let mut leaf_hashes = Vec::with_capacity(1 << depth);
    for i in 0..(1u64 << depth) {
        if i as usize == claim_idx {
            leaf_hashes.push(claim_leaf);
        } else {
            leaf_hashes.push(native_hash_leaf(Fr::from(1_000_000 + i)));
        }
    }
    let (root, siblings, path_indices) = build_tree(&leaf_hashes, claim_idx, depth);

    // Nullifier: poseidon(privkey mod p_BN254, domain).
    let key_mod_p = {
        let k_big = fe_to_biguint(&privkey);
        let p: num_bigint::BigUint = modulus::<Fr>();
        biguint_to_fe(&(k_big % p))
    };
    let expected_nullifier = native_hash_interior(key_mod_p, domain_field_element());

    // A non-zero recipient (a 20-byte address as Fr).
    let recipient = address_to_fr(&{
        let mut r = [0u8; 20];
        r[19] = 0x42;
        r
    });

    // Run the circuit. MockProver (via base_test) asserts every constraint,
    // including root==expected and nullifier==expected.
    base_test().k(21).lookup_bits(8).run(|ctx, range| {
        prove_claim(
            ctx,
            range,
            privkey,
            &siblings,
            &path_indices,
            root,
            expected_nullifier,
            recipient,
        );
    });

    eprintln!(
        "Phase 3 claim happy-path OK: privkey 0xA11CE_5EC7E7 → address 0x{}, root ok, nullifier bound.",
        hex::encode(addr)
    );
}
