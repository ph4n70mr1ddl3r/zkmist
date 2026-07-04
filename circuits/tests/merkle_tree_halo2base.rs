//! Cross-check: the off-chain `zkmist-merkle-tree` halo2-base convention
//! (`merkle_tree::halo2base`) produces the same digests as the axiom circuit's
//! native Poseidon (`circuits::poseidon_axiom`). This is the bridge that lets a
//! tree built off-chain be verified by the axiom claim circuit.
//!
//! Also an end-to-end check: a tree built with `merkle_tree::halo2base` has its
//! root recomputed by `merkle_tree::halo2base::verify_merkle_proof`, and (in
//! `tests/claim_axiom.rs`) verified inside the circuit.

use ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use num_bigint::BigUint;

use zkmist_circuits::poseidon_axiom::{native_hash_interior, native_hash_leaf};

fn addr_to_fr_axiom(addr: &[u8; 20]) -> Fr {
    // 20-byte big-endian address → Fr (matches merkle-tree's left-padded BE read
    // and the circuit's recomposition).
    let mut v = Fr::zero();
    for &b in addr {
        v = v * Fr::from(256u64) + Fr::from(b as u64);
    }
    v
}

fn be_bytes_to_biguint(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

fn axiom_fr_to_biguint(f: Fr) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

#[test]
fn test_merkle_tree_halo2base_matches_circuit_leaf() {
    let addr: [u8; 20] = [
        0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
        0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
    ];
    let hasher = zkmist_merkle_tree::halo2base::Hasher::new();
    let mt_leaf = hasher.hash_leaf(&addr); // 32-byte BE

    let circuit_leaf = native_hash_leaf(addr_to_fr_axiom(&addr)); // axiom Fr

    assert_eq!(
        be_bytes_to_biguint(&mt_leaf),
        axiom_fr_to_biguint(circuit_leaf),
        "halo2base hash_leaf(addr) != circuit native_hash_leaf"
    );
}

#[test]
fn test_merkle_tree_halo2base_matches_circuit_interior() {
    let left: [u8; 32] = [0x11; 32];
    let right: [u8; 32] = [0x22; 32];
    let hasher = zkmist_merkle_tree::halo2base::Hasher::new();
    let mt_node = hasher.hash_interior(&left, &right);

    // circuit side: parse left/right (32-byte BE) → axiom Fr, hash.
    let la = bytes_be_to_fr(&left);
    let ra = bytes_be_to_fr(&right);
    let circuit_node = native_hash_interior(la, ra);

    assert_eq!(
        be_bytes_to_biguint(&mt_node),
        axiom_fr_to_biguint(circuit_node),
        "halo2base hash_interior(l,r) != circuit native_hash_interior"
    );
}

fn bytes_be_to_fr(b: &[u8; 32]) -> Fr {
    let mut v = Fr::zero();
    for &x in b {
        v = v * Fr::from(256u64) + Fr::from(x as u64);
    }
    v
}

#[test]
fn test_merkle_tree_halo2base_round_trip() {
    // Build a small tree off-chain, extract a proof, and verify it under the
    // same convention — the off-chain side of what the circuit verifies.
    use zkmist_merkle_tree::halo2base::{build_tree_with_depth, generate_proof, tree_root,
                                       verify_merkle_proof};

    let depth = 4;
    let mut addresses = vec![[0u8; 20]; 1 << depth];
    for (i, a) in addresses.iter_mut().enumerate() {
        a[19] = (i + 1) as u8;
    }
    let claim_idx = 7usize;

    let layers = build_tree_with_depth(&addresses, depth);
    let root = tree_root(&layers);
    let claim_leaf = layers[0][claim_idx];
    let (siblings, path_indices) = generate_proof(&layers, claim_idx);

    assert_eq!(
        verify_merkle_proof(&claim_leaf, &siblings, &path_indices),
        root,
        "halo2base proof does not recompute the root"
    );

    // A tampered sibling must NOT verify.
    let mut bad_siblings = siblings.clone();
    bad_siblings[0] = [0u8; 32];
    assert_ne!(
        verify_merkle_proof(&claim_leaf, &bad_siblings, &path_indices),
        root,
        "tampered proof unexpectedly verified"
    );
}
