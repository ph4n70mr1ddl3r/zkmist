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

use std::io::{self, Read, Write};

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

/// Build a complete Merkle tree from a list of Ethereum addresses.
///
/// Returns the tree layers: `layers[0]` = leaves, `layers[1..]` = interior levels,
/// `layers[TREE_DEPTH]` = root (single element).
///
/// Addresses are hashed into leaves using the leaf hasher (Poseidon t=2).
/// Empty slots (beyond the provided addresses) are filled with `PADDING_SENTINEL`.
/// Interior nodes use the interior hasher (Poseidon t=3).
///
/// **Note:** For the full 26-level tree (67M leaves), this requires ~4 GB RAM.
/// Use `build_tree_streaming` for large trees to avoid holding all layers.
pub fn build_tree(addresses: &[[u8; 20]]) -> Vec<Vec<[u8; 32]>> {
    build_tree_with_depth(addresses, TREE_DEPTH)
}

/// Build a complete Merkle tree with a custom depth.
///
/// Same as `build_tree` but allows specifying the tree depth instead of using
/// the default `TREE_DEPTH`. Useful for testing with small trees.
pub fn build_tree_with_depth(addresses: &[[u8; 20]], depth: usize) -> Vec<Vec<[u8; 32]>> {
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

    let num_leaves = 1usize << depth;
    let mut layers = Vec::with_capacity(depth + 1);

    let mut current_layer: Vec<[u8; 32]> = Vec::with_capacity(num_leaves);
    for addr in addresses {
        current_layer.push(hash_leaf(addr, &mut leaf_hasher));
    }
    current_layer.resize(num_leaves, PADDING_SENTINEL);
    layers.push(current_layer);

    for level in 0..depth {
        let prev = &layers[level];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_interior(&chunk[0], &chunk[1], &mut interior_hasher));
        }
        layers.push(next);
    }

    layers
}

/// Extract the Merkle root from a built tree.
pub fn tree_root(layers: &[Vec<[u8; 32]>]) -> [u8; 32] {
    assert!(!layers.is_empty(), "Empty tree has no root");
    let root_layer = &layers[layers.len() - 1];
    assert_eq!(root_layer.len(), 1, "Root layer must have exactly one element");
    root_layer[0]
}

/// Verify a Merkle proof by recomputing the root from leaf + siblings + path.
/// This mirrors the guest program's `compute_merkle_root` exactly.
///
/// Returns the computed root. Compare against the trusted root.
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    path_indices: &[u8],
) -> [u8; 32] {
    assert_eq!(siblings.len(), path_indices.len());
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");
    let mut current = *leaf;
    for i in 0..siblings.len() {
        let (left, right) = if path_indices[i] == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hash_interior(&left, &right, &mut hasher);
    }
    current
}

/// Generate a Merkle proof for a leaf at the given index.
///
/// Returns (siblings, path_indices) where:
///   path_indices[i] = 0 → leaf is left child at level i
///   path_indices[i] = 1 → leaf is right child at level i
///
/// This convention MUST match the guest program's `compute_merkle_root`.
pub fn generate_proof(
    tree_layers: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> (Vec<[u8; 32]>, Vec<u8>) {
    let depth = tree_layers.len().saturating_sub(1); // number of proof levels
    let mut siblings = Vec::with_capacity(depth);
    let mut path_indices = Vec::with_capacity(depth);

    let mut index = leaf_index;
    for layer in tree_layers.iter().take(depth) {
        assert!(index < layer.len(), "leaf_index out of bounds at level");
        if index % 2 == 0 {
            // Current is left child (path_index = 0)
            assert!(index + 1 < layer.len(), "missing sibling at level");
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

// ── Tree cache serialization ────────────────────────────────────────────
//
// Serializes tree layers to/from a binary file so `zkmist prove` can skip
// rebuilding the tree (saves ~1–2 min and 4 GB RAM on the full 26-level tree).
//
// Format:
//   [u32 LE]  number of layers
//   For each layer:
//     [u32 LE]  number of nodes in this layer
//     [bytes]   node data (num_nodes × 32 bytes, contiguous)
//
// Total file size for full tree: 4 + Σ(4 + layer_len×32)
// ≈ 4 + 4 + 67M×32 + 4 + 33M×32 + ... ≈ 8.6 GB.
// In practice, only the proof-relevant layers (siblings for each level) need
// to be kept. However, for correctness we serialize all layers so that
// `generate_proof` works for any leaf index.
//
// For large trees, consider `serialize_proof_cache` which stores only the
// proof for a specific leaf index (much smaller).

/// Magic bytes for the tree cache file format.
const CACHE_MAGIC: [u8; 4] = [b'Z', b'K', b'M', b'T'];

/// Serialize all tree layers to a writer.
///
/// Use this to cache the full tree after `build_tree()` so subsequent runs
/// of `zkmist prove` can skip tree construction.
pub fn serialize_tree<W: Write>(layers: &[Vec<[u8; 32]>], mut writer: W) -> io::Result<()> {
    writer.write_all(&CACHE_MAGIC)?;
    let num_layers = layers.len() as u32;
    writer.write_all(&num_layers.to_le_bytes())?;
    for layer in layers {
        let num_nodes = layer.len() as u32;
        writer.write_all(&num_nodes.to_le_bytes())?;
        for node in layer {
            writer.write_all(node)?;
        }
    }
    Ok(())
}

/// Deserialize tree layers from a reader.
///
/// Returns the reconstructed tree layers. The caller should verify the root
/// matches the expected value.
pub fn deserialize_tree<R: Read>(mut reader: R) -> io::Result<Vec<Vec<[u8; 32]>>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != CACHE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid tree cache file (bad magic)",
        ));
    }
    let mut buf4 = [0u8; 4];
    reader.read_exact(&mut buf4)?;
    let num_layers = u32::from_le_bytes(buf4) as usize;
    let mut layers = Vec::with_capacity(num_layers);
    for _ in 0..num_layers {
        reader.read_exact(&mut buf4)?;
        let num_nodes = u32::from_le_bytes(buf4) as usize;
        let mut layer = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let mut node = [0u8; 32];
            reader.read_exact(&mut node)?;
            layer.push(node);
        }
        layers.push(layer);
    }
    Ok(layers)
}

/// Serialize only the proof data for a specific leaf (compact cache).
///
/// Much smaller than the full tree: just the root + siblings + path indices.
/// Format:
///   [4 bytes] magic b"ZKMP"
///   [32 bytes] root
///   [u32 LE]  leaf_index
///   [u32 LE]  depth (number of proof levels)
///   [depth × 32 bytes] siblings
///   [depth × 1 byte]   path_indices
const PROOF_CACHE_MAGIC: [u8; 4] = [b'Z', b'K', b'M', b'P'];

pub fn serialize_proof<W: Write>(
    root: &[u8; 32],
    leaf_index: usize,
    siblings: &[[u8; 32]],
    path_indices: &[u8],
    mut writer: W,
) -> io::Result<()> {
    writer.write_all(&PROOF_CACHE_MAGIC)?;
    writer.write_all(root)?;
    writer.write_all(&(leaf_index as u32).to_le_bytes())?;
    writer.write_all(&(siblings.len() as u32).to_le_bytes())?;
    for s in siblings {
        writer.write_all(s)?;
    }
    writer.write_all(path_indices)?;
    Ok(())
}

/// Deserialize proof data from a reader.
///
/// Returns (root, leaf_index, siblings, path_indices).
pub fn deserialize_proof<R: Read>(
    mut reader: R,
) -> io::Result<([u8; 32], usize, Vec<[u8; 32]>, Vec<u8>)> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != PROOF_CACHE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid proof cache file (bad magic)",
        ));
    }
    let mut root = [0u8; 32];
    reader.read_exact(&mut root)?;
    let mut buf4 = [0u8; 4];
    reader.read_exact(&mut buf4)?;
    let leaf_index = u32::from_le_bytes(buf4) as usize;
    reader.read_exact(&mut buf4)?;
    let depth = u32::from_le_bytes(buf4) as usize;
    let mut siblings = Vec::with_capacity(depth);
    for _ in 0..depth {
        let mut s = [0u8; 32];
        reader.read_exact(&mut s)?;
        siblings.push(s);
    }
    let mut path_indices = vec![0u8; depth];
    reader.read_exact(&mut path_indices)?;
    Ok((root, leaf_index, siblings, path_indices))
}

/// Build a Merkle tree using streaming (layer-by-layer) construction.
///
/// Unlike `build_tree`, this only keeps two layers in memory at a time
/// (current and next), reducing peak memory from O(2^depth × depth × 32)
/// to O(2^depth × 32). The trade-off is that you cannot generate proofs
/// for arbitrary leaves later — you must extract the proof during construction
/// if needed.
///
/// Returns the root (32 bytes).
///
/// If `target_index` is provided, also returns (siblings, path_indices) for
/// that leaf, enabling proof generation without storing all layers.
pub fn build_tree_streaming(
    addresses: &[[u8; 20]],
    target_index: Option<usize>,
) -> ([u8; 32], Option<(Vec<[u8; 32]>, Vec<u8>)>) {
    build_tree_streaming_with_depth(addresses, TREE_DEPTH, target_index)
}

/// Streaming tree build with a custom depth.
///
/// Same as `build_tree_streaming` but allows specifying the tree depth.
/// Useful for testing with small trees where the full TREE_DEPTH is impractical.
pub fn build_tree_streaming_with_depth(
    addresses: &[[u8; 20]],
    depth: usize,
    target_index: Option<usize>,
) -> ([u8; 32], Option<(Vec<[u8; 32]>, Vec<u8>)>) {
    let num_leaves = 1usize << depth;
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

    let mut current: Vec<[u8; 32]> = Vec::with_capacity(num_leaves);
    for addr in addresses {
        current.push(hash_leaf(addr, &mut leaf_hasher));
    }
    current.resize(num_leaves, PADDING_SENTINEL);

    let mut target_siblings: Option<Vec<[u8; 32]>> =
        target_index.map(|_| Vec::with_capacity(depth));
    let mut target_path: Option<Vec<u8>> =
        target_index.map(|_| Vec::with_capacity(depth));
    let mut idx = target_index.unwrap_or(0);

    for _level in 0..depth {
        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks(2) {
            next.push(hash_interior(&chunk[0], &chunk[1], &mut interior_hasher));
        }

        if let (Some(ref mut sibs), Some(ref mut path)) =
            (&mut target_siblings, &mut target_path)
        {
            if idx % 2 == 0 {
                sibs.push(current[idx + 1]);
                path.push(0);
            } else {
                sibs.push(current[idx - 1]);
                path.push(1);
            }
            idx /= 2;
        }

        current = next;
    }

    assert_eq!(current.len(), 1, "Root layer must have one element");
    let root = current[0];

    let proof = target_siblings.zip(target_path);
    (root, proof)
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

    /// End-to-end integration test: build a small tree, generate proof, verify.
    ///
    /// Uses a reduced tree depth (4 levels, 16 leaves) for fast test execution.
    /// This validates the entire pipeline: address → leaf hash → tree build →
    /// proof generation → proof verification → root match.
    #[test]
    fn test_end_to_end_merkle_proof() {
        // Test addresses (arbitrary valid Ethereum addresses)
        let addresses: [[u8; 20]; 5] = [
            // PRD test vector address
            [0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
             0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c],
            // Address 0x0000...0001 (edge case)
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            // Address 0xFFff...ffFF (edge case)
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            // Arbitrary address
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
             0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44],
            // Another arbitrary address
            [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
             0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01],
        ];

        // Build tree with custom depth
        let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
        let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

        let test_depth = 4usize;
        let num_leaves = 1usize << test_depth;

        // Build leaves
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_leaves);
        for addr in &addresses {
            leaves.push(hash_leaf(addr, &mut leaf_hasher));
        }
        leaves.resize(num_leaves, PADDING_SENTINEL);

        // Build tree layers
        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaves];
        for level in 0..test_depth {
            let prev = &layers[level];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for chunk in prev.chunks(2) {
                next.push(hash_interior(&chunk[0], &chunk[1], &mut interior_hasher));
            }
            layers.push(next);
        }

        let root = layers[test_depth][0];
        assert_ne!(root, [0u8; 32], "Root must not be zero");

        // Generate and verify proof for each address
        for (i, addr) in addresses.iter().enumerate() {
            let leaf = hash_leaf(addr, &mut leaf_hasher);

            // Generate proof
            let (siblings, path_indices) = generate_proof(&layers, i);
            assert_eq!(siblings.len(), test_depth);
            assert_eq!(path_indices.len(), test_depth);

            // Verify proof (mirrors guest program logic)
            let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
            assert_eq!(computed_root, root, "Proof verification failed for address {}", i);
        }

        // Negative test: wrong leaf should NOT produce the same root
        let wrong_addr: [u8; 20] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00];
        let wrong_leaf = hash_leaf(&wrong_addr, &mut leaf_hasher);
        let (siblings, path_indices) = generate_proof(&layers, 0);
        let wrong_root = verify_merkle_proof(&wrong_leaf, &siblings, &path_indices);
        assert_ne!(wrong_root, root, "Wrong leaf must not verify against root");

        // Negative test: wrong sibling should NOT produce the same root
        let leaf = hash_leaf(&addresses[0], &mut leaf_hasher);
        let mut bad_siblings = siblings.clone();
        bad_siblings[0] = [0xAAu8; 32]; // corrupt first sibling
        let bad_root = verify_merkle_proof(&leaf, &bad_siblings, &path_indices);
        assert_ne!(bad_root, root, "Corrupted sibling must not verify");
    }

    /// Test tree cache serialization round-trip.
    #[test]
    fn test_tree_cache_roundtrip() {
        let addresses: [[u8; 20]; 3] = [
            [0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
             0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
             0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01],
        ];

        // Build a small tree with custom depth
        let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
        let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");
        let test_depth = 4usize;
        let num_leaves = 1usize << test_depth;
        let mut leaves: Vec<[u8; 32]> = addresses.iter()
            .map(|a| hash_leaf(a, &mut leaf_hasher))
            .collect();
        leaves.resize(num_leaves, PADDING_SENTINEL);
        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaves];
        for level in 0..test_depth {
            let prev = &layers[level];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for chunk in prev.chunks(2) {
                next.push(hash_interior(&chunk[0], &chunk[1], &mut interior_hasher));
            }
            layers.push(next);
        }
        let root_before = tree_root(&layers);

        // Serialize and deserialize
        let mut buf = Vec::new();
        serialize_tree(&layers, &mut buf).expect("serialize failed");
        let restored = deserialize_tree(&buf[..]).expect("deserialize failed");
        let root_after = tree_root(&restored);

        assert_eq!(root_before, root_after, "Root must match after roundtrip");
        assert_eq!(layers.len(), restored.len(), "Layer count must match");
        for (i, (a, b)) in layers.iter().zip(&restored).enumerate() {
            assert_eq!(a.len(), b.len(), "Layer {} size mismatch", i);
            assert_eq!(a, b, "Layer {} content mismatch", i);
        }
    }

    /// Test proof cache serialization round-trip.
    #[test]
    fn test_proof_cache_roundtrip() {
        let root = [0xABu8; 32];
        let siblings: Vec<[u8; 32]> = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let path_indices: Vec<u8> = vec![0, 1, 0];
        let leaf_index = 42usize;

        let mut buf = Vec::new();
        serialize_proof(&root, leaf_index, &siblings, &path_indices, &mut buf)
            .expect("serialize failed");
        let (r_root, r_idx, r_sibs, r_path) =
            deserialize_proof(&buf[..]).expect("deserialize failed");

        assert_eq!(r_root, root);
        assert_eq!(r_idx, leaf_index);
        assert_eq!(r_sibs, siblings);
        assert_eq!(r_path, path_indices);
    }

    /// Test streaming tree build produces the same root as full build.
    /// Uses `build_tree_with_depth` and `build_tree_streaming_with_depth` at
    /// depth 4 (16 leaves) — small enough for a fast unit test.
    #[test]
    fn test_streaming_matches_full() {
        let addresses: [[u8; 20]; 3] = [
            [0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
             0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
             0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01],
        ];

        let test_depth = 4;

        // Build with full (all layers in memory)
        let full_layers = build_tree_with_depth(&addresses, test_depth);
        let full_root = tree_root(&full_layers);
        assert_ne!(full_root, [0u8; 32], "Root must not be zero");

        // Build with streaming (only 2 layers in memory at a time)
        let (streaming_root, _) = build_tree_streaming_with_depth(
            &addresses,
            test_depth,
            None,
        );

        // Both methods must produce the identical root
        assert_eq!(full_root, streaming_root,
            "Full build and streaming build must produce the same root");

        // Also verify streaming with proof extraction
        let (streaming_root_with_proof, proof) =
            build_tree_streaming_with_depth(&addresses, test_depth, Some(0));
        let (siblings, path_indices) = proof
            .expect("Expected proof for target_index=0");
        assert_eq!(full_root, streaming_root_with_proof,
            "Streaming with proof extraction must produce same root");
        assert_eq!(siblings.len(), test_depth);
        assert_eq!(path_indices.len(), test_depth);

        // Verify the extracted proof is valid
        let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid params");
        let leaf = hash_leaf(&addresses[0], &mut leaf_hasher);
        let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
        assert_eq!(full_root, computed_root,
            "Streaming-extracted proof must verify against root");
    }

    /// Test that build_tree + generate_proof + verify_merkle_proof produces
    /// consistent results for the PRD test vector address.
    #[test]
    fn test_build_tree_and_proof_prd_vector() {
        let addresses: [[u8; 20]; 1] = [
            // PRD test vector: derived from private key 0x0123...cdef
            [0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
             0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c],
        ];

        // Build with reduced depth
        let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
        let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

        let test_depth = 4usize;
        let num_leaves = 1usize << test_depth;

        let mut leaves: Vec<[u8; 32]> = addresses.iter()
            .map(|a| hash_leaf(a, &mut leaf_hasher))
            .collect();
        leaves.resize(num_leaves, PADDING_SENTINEL);

        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaves];
        for level in 0..test_depth {
            let prev = &layers[level];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for chunk in prev.chunks(2) {
                next.push(hash_interior(&chunk[0], &chunk[1], &mut interior_hasher));
            }
            layers.push(next);
        }

        let root = layers[test_depth][0];

        // Verify leaf hash matches PRD test vector
        let expected_leaf = hex::decode("1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9")
            .expect("Invalid hex");
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&expected_leaf);
        assert_eq!(layers[0][0], expected, "Leaf hash must match PRD test vector");

        // Generate proof for index 0
        let (siblings, path_indices) = generate_proof(&layers, 0);

        // Verify proof
        let computed = verify_merkle_proof(&layers[0][0], &siblings, &path_indices);
        assert_eq!(computed, root, "Proof must verify against root");

        // Root is deterministic
        let root2 = verify_merkle_proof(&layers[0][0], &siblings, &path_indices);
        assert_eq!(root, root2, "Root must be deterministic");
    }
}
