//! ZKMist Merkle Tree Builder
//!
//! Builds a 26-level Poseidon Merkle tree from the eligibility list.
//! Must produce the SAME root as the guest program's verification logic.
//!
//! Key invariants:
//!   - Leaf hash: Poseidon t=2 (1 input), R_F=8, R_P=56
//!   - Interior hash: Poseidon t=3 (2 inputs), R_F=8, R_P=57
//!   - Leaf encoding: 12 zero bytes + 20 address bytes → BN254 field element
//!   - Padding: empty leaves = 0xFF..FF (32 bytes, sentinel)
//!   - Direction: path_index=0 → left child, path_index=1 → right child
//!   - Nullifier: poseidon(Fr(key), Fr(domain)) using interior hasher

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

pub const TREE_DEPTH: usize = 26;
pub const TREE_LEAVES: usize = 1 << TREE_DEPTH; // 67,108,864
pub const PADDING_SENTINEL: [u8; 32] = [0xFFu8; 32];

/// Nullifier domain separator. Changing this invalidates all existing proofs
/// and requires redeploying the contract with a new image ID.
pub const NULLIFIER_DOMAIN: &[u8; 19] = b"ZKMist_V1_NULLIFIER";

/// Hash a 20-byte Ethereum address into a Poseidon leaf.
/// The address is zero-padded to 32 bytes (left-padded with zeros).
pub fn hash_leaf(addr: &[u8; 20], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(addr);
    let elem = Fr::from_be_bytes_mod_order(&padded);
    field_element_to_bytes(hasher.hash(&[elem]).expect("Leaf hash failed"))
}

/// Hash two 32-byte children into an interior node.
pub fn hash_interior(left: &[u8; 32], right: &[u8; 32], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let left_elem = Fr::from_be_bytes_mod_order(left);
    let right_elem = Fr::from_be_bytes_mod_order(right);
    field_element_to_bytes(
        hasher
            .hash(&[left_elem, right_elem])
            .expect("Interior hash failed"),
    )
}

/// Convert a BN254 field element to 32-byte big-endian representation.
pub fn field_element_to_bytes(elem: Fr) -> [u8; 32] {
    let bytes = elem.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Compute the claim nullifier: poseidon(Fr(key), Fr(domain)).
///
/// Uses the interior hasher (t=3, 2 inputs). The domain separator prevents
/// cross-version nullifier collisions. This MUST produce the same output as
/// the guest program's `compute_nullifier`.
pub fn compute_nullifier(key: &[u8; 32], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let key_elem = Fr::from_be_bytes_mod_order(key);
    let mut domain_padded = [0u8; 32];
    domain_padded[..NULLIFIER_DOMAIN.len()].copy_from_slice(NULLIFIER_DOMAIN);
    let domain_elem = Fr::from_be_bytes_mod_order(&domain_padded);
    field_element_to_bytes(
        hasher
            .hash(&[key_elem, domain_elem])
            .expect("Nullifier hash failed"),
    )
}

/// Generate a Merkle proof for a leaf at the given index.
///
/// Returns (siblings, path_indices) where:
///   path_indices[i] = 0 → leaf is left child at level i
///   path_indices[i] = 1 → leaf is right child at level i
///
/// This convention MUST match the guest program's `compute_merkle_root_with`.
pub fn generate_proof(
    tree_layers: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> (Vec<[u8; 32]>, Vec<u8>) {
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    let mut path_indices = Vec::with_capacity(TREE_DEPTH);

    let mut index = leaf_index;
    for layer in tree_layers.iter().take(TREE_DEPTH) {
        if index % 2 == 0 {
            // Current is left child (path_index = 0)
            siblings.push(layer[index + 1]);
            path_indices.push(0);
        } else {
            // Current is right child (path_index = 1)
            siblings.push(layer[index - 1]);
            path_indices.push(1);
        }
        index /= 2;
    }

    (siblings, path_indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_sentinel_is_not_valid_field_element() {
        // The sentinel 0xFF..FF is larger than the BN254 field modulus.
        // When reduced mod p, it becomes a different value.
        // The guest program compares raw 32-byte output against sentinel.
        // A Poseidon hash output is always a valid field element (< p < 2^254),
        // so it can never equal 0xFF..FF in raw bytes.
        let sentinel = Fr::from_be_bytes_mod_order(&PADDING_SENTINEL);
        let sentinel_bytes = field_element_to_bytes(sentinel);
        // The reduced sentinel is NOT the same as the raw sentinel bytes
        assert_ne!(sentinel_bytes, PADDING_SENTINEL);
    }

    #[test]
    fn test_leaf_hash_consistency() {
        // Verify that hash_leaf produces the same output as the test vector
        let mut hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid params");
        let addr_bytes: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
            0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        let leaf = hash_leaf(&addr_bytes, &mut hasher);
        assert_eq!(
            hex::encode(leaf),
            "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9"
        );
    }

    #[test]
    fn test_interior_hash_consistency() {
        // Cross-validate against reference value: poseidon(Fr(1), Fr(2))
        let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid params");
        let left = field_element_to_bytes(Fr::from(1u64));
        let right = field_element_to_bytes(Fr::from(2u64));
        let result = hash_interior(&left, &right, &mut hasher);
        assert_eq!(
            hex::encode(result),
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }

    #[test]
    fn test_nullifier_deterministic() {
        let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid params");
        let key = [0x01u8; 32];
        let n1 = compute_nullifier(&key, &mut hasher);
        let n2 = compute_nullifier(&key, &mut hasher);
        assert_eq!(n1, n2, "Nullifier must be deterministic");
        assert_ne!(n1, [0u8; 32], "Nullifier must not be all zeros");
    }

    #[test]
    fn test_nullifier_unique_per_key() {
        let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid params");
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let n1 = compute_nullifier(&key1, &mut hasher);
        let n2 = compute_nullifier(&key2, &mut hasher);
        assert_ne!(n1, n2, "Different keys must produce different nullifiers");
    }

    #[test]
    fn test_nullifier_differs_from_leaf() {
        // Nullifier uses interior hasher (t=3), leaf uses leaf hasher (t=2).
        // Even if they hash the same field element, the different arities mean
        // different Poseidon parameters, so outputs must differ.
        let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid params");
        let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid params");
        let key = [0x01u8; 32];
        let key_elem = Fr::from_be_bytes_mod_order(&key);
        let leaf = field_element_to_bytes(leaf_hasher.hash(&[key_elem]).expect("hash"));
        let nullifier = compute_nullifier(&key, &mut interior_hasher);
        assert_ne!(
            leaf, nullifier,
            "Nullifier must differ from a simple leaf hash of the key"
        );
    }
}
