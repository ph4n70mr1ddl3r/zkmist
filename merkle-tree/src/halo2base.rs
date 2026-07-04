//! Halo2-base Poseidon convention for the off-chain Merkle tree — the
//! convention the axiom circuit verifies (see `circuits::poseidon_axiom` and
//! `docs/axiom-backend-migration.md` §9.1/§11).
//!
//! The default (`crate::hash_leaf`, etc.) uses `light-poseidon` (Circom
//! convention) for the legacy PSE circuit. This module mirrors that API under
//! the **halo2-base sponge convention** (capacity `2^64`, squeeze permutation,
//! digest at `state[1]`) — the same permutation (Grain-LFSR constants, via
//! `light-poseidon::parameters::bn254_x5`) wrapped differently. Nothing is
//! deployed, so the production tree is rebuilt under this convention rather
//! than hand-rolling an unaudited Circom wrapper in the circuit.
//!
//! `tests/claim_axiom.rs` (in `zkmist-circuits`) cross-checks these against
//! `poseidon_axiom::native_hash_leaf` / `native_hash_interior` byte-for-byte.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use light_poseidon::PoseidonParameters;

use crate::{field_element_to_bytes, PADDING_SENTINEL};

/// Caches the (t=2 leaf, t=3 interior) Poseidon parameters so the Grain-LFSR
/// constants are generated once, not per hash (matters for the 64M-leaf tree).
pub struct Hasher {
    leaf: PoseidonParameters<Fr>,
    interior: PoseidonParameters<Fr>,
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            leaf: get_poseidon_parameters::<Fr>(2).expect("leaf params"),
            interior: get_poseidon_parameters::<Fr>(3).expect("interior params"),
        }
    }

    /// `poseidon(addr)` under the halo2-base convention (t=2). The address is
    /// left-padded to 32 bytes and read big-endian, matching the circuit.
    pub fn hash_leaf(&self, addr: &[u8; 20]) -> [u8; 32] {
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(addr);
        let elem = Fr::from_be_bytes_mod_order(&padded);
        field_element_to_bytes(sponge(&[elem], &self.leaf))
    }

    /// `poseidon(left, right)` under the halo2-base convention (t=3).
    pub fn hash_interior(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let l = Fr::from_be_bytes_mod_order(left);
        let r = Fr::from_be_bytes_mod_order(right);
        field_element_to_bytes(sponge(&[l, r], &self.interior))
    }
}

/// Standard (non-optimized) Poseidon permutation: per round `ARC → sbox(x^α) →
/// MDS`, with the first half full, then partial, then second half full. This is
/// the same permutation `light-poseidon` runs; only the sponge wrapping differs.
fn permute(
    state: &mut [Fr],
    params: &PoseidonParameters<Fr>,
) {
    let t = params.width;
    let half = params.full_rounds / 2;
    let alpha = params.alpha;
    let apply_mds = |state: &mut [Fr]| {
        let mut new_state = vec![Fr::from(0u64); t];
        for i in 0..t {
            for j in 0..t {
                new_state[i] += params.mds[i][j] * state[j];
            }
        }
        state.copy_from_slice(&new_state);
    };
    let mut round = 0usize;
    for _ in 0..half {
        for i in 0..t {
            state[i] += params.ark[round * t + i];
            state[i] = state[i].pow([alpha]);
        }
        apply_mds(state);
        round += 1;
    }
    for _ in 0..params.partial_rounds {
        for i in 0..t {
            state[i] += params.ark[round * t + i];
        }
        state[0] = state[0].pow([alpha]);
        apply_mds(state);
        round += 1;
    }
    for _ in 0..half {
        for i in 0..t {
            state[i] += params.ark[round * t + i];
            state[i] = state[i].pow([alpha]);
        }
        apply_mds(state);
        round += 1;
    }
}

/// Halo2-base sponge: capacity `2^64`, absorb inputs into the rate, one
/// permutation, then a squeeze permutation (since `len % RATE == 0` for ZKMist's
/// full-block inputs), digest at `state[1]`. Mirrors
/// `poseidon_axiom::native_poseidon` exactly.
fn sponge(inputs: &[Fr], params: &PoseidonParameters<Fr>) -> Fr {
    let t = params.width;
    let mut state = vec![Fr::from(0u64); t];
    state[0] = Fr::from(2u64).pow([64u64]); // halo2-base capacity = 2^64
    for (j, inp) in inputs.iter().enumerate() {
        state[1 + j] += inp;
    }
    permute(&mut state, params);
    // squeeze permutation (empty absorb pads the first rate slot with 1)
    state[1] += Fr::from(1u64);
    permute(&mut state, params);
    state[1]
}

/// Build a complete halo2-base-convention Merkle tree (`layers[0]` = leaves,
/// `layers[depth]` = root). Mirrors `crate::build_tree_with_depth`.
pub fn build_tree_with_depth(addresses: &[[u8; 20]], depth: usize) -> Vec<Vec<[u8; 32]>> {
    let hasher = Hasher::new();
    let num_leaves = 1usize << depth;
    let mut layers = Vec::with_capacity(depth + 1);

    let mut current_layer: Vec<[u8; 32]> = Vec::with_capacity(num_leaves);
    for addr in addresses {
        current_layer.push(hasher.hash_leaf(addr));
    }
    current_layer.resize(num_leaves, PADDING_SENTINEL);
    layers.push(current_layer);

    for level in 0..depth {
        let prev = &layers[level];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hasher.hash_interior(&chunk[0], &chunk[1]));
        }
        layers.push(next);
    }
    layers
}

/// `crate::tree_root` — convention-independent (just extracts the last layer).
pub fn tree_root(layers: &[Vec<[u8; 32]>]) -> [u8; 32] {
    crate::tree_root(layers)
}

/// O(N) streaming tree build under the halo2-base convention: processes
/// layer-by-layer (current + next), tracking the target leaf's sibling/path.
/// Mirrors `crate::build_tree_streaming_with_depth` (light-poseidon) but for
/// the axiom circuit. Returns `(root, Option<(siblings, path)>)`.
pub fn build_tree_streaming_with_depth(
    addresses: &[[u8; 20]],
    depth: usize,
    target_index: Option<usize>,
) -> crate::StreamingResult {
    let hasher = Hasher::new();
    let num_leaves = 1usize << depth;

    let mut current: Vec<[u8; 32]> = Vec::with_capacity(num_leaves);
    for addr in addresses {
        current.push(hasher.hash_leaf(addr));
    }
    current.resize(num_leaves, PADDING_SENTINEL);

    let mut target_siblings: Option<Vec<[u8; 32]>> =
        target_index.map(|_| Vec::with_capacity(depth));
    let mut target_path: Option<Vec<u8>> = target_index.map(|_| Vec::with_capacity(depth));
    let mut idx = target_index.unwrap_or(0);

    for _level in 0..depth {
        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks(2) {
            next.push(hasher.hash_interior(&chunk[0], &chunk[1]));
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
    let root = current[0];
    (root, target_siblings.zip(target_path))
}

/// `crate::build_tree_streaming` equivalent under halo2-base (default depth).
pub fn build_tree_streaming(
    addresses: &[[u8; 20]],
    target_index: Option<usize>,
) -> crate::StreamingResult {
    build_tree_streaming_with_depth(addresses, crate::TREE_DEPTH, target_index)
}

/// Compute the claim nullifier `poseidon(key, domain)` under the halo2-base
/// convention (mirrors `crate::compute_nullifier` / `compute_nullifier_with_domain`).
/// `domain` defaults to the V2 separator.
pub fn compute_nullifier(key: &[u8; 32], hasher: &Hasher) -> [u8; 32] {
    compute_nullifier_with_domain(key, crate::NULLIFIER_DOMAIN, hasher)
}

/// Free-function `hash_leaf(addr, &Hasher)` — mirrors the light-poseidon API
/// (`crate::hash_leaf(addr, &mut Poseidon)`) for drop-in CLI compatibility.
pub fn hash_leaf(addr: &[u8; 20], hasher: &Hasher) -> [u8; 32] {
    hasher.hash_leaf(addr)
}

/// Compute a nullifier with an arbitrary domain separator (halo2-base convention).
pub fn compute_nullifier_with_domain(
    key: &[u8; 32],
    domain: &[u8],
    hasher: &Hasher,
) -> [u8; 32] {
    let mut domain_padded = [0u8; 32];
    let len = domain.len().min(32);
    domain_padded[..len].copy_from_slice(&domain[..len]);
    // hash_interior reads both 32-byte args as big-endian field elements —
    // matches crate::compute_nullifier_with_domain's from_be_bytes_mod_order.
    hasher.hash_interior(key, &domain_padded)
}

/// Recompute the root from a leaf + siblings + path under the halo2-base
/// convention. Mirrors `crate::verify_merkle_proof`.
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    path_indices: &[u8],
) -> [u8; 32] {
    assert_eq!(siblings.len(), path_indices.len());
    let hasher = Hasher::new();
    let mut current = *leaf;
    for i in 0..siblings.len() {
        let (left, right) = if path_indices[i] == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hasher.hash_interior(&left, &right);
    }
    current
}

/// `crate::generate_proof` — convention-independent (traverses layers).
pub fn generate_proof(
    layers: &[Vec<[u8; 32]>],
    index: usize,
) -> (Vec<[u8; 32]>, Vec<u8>) {
    crate::generate_proof(layers, index)
}

/// O(depth) single-leaf proof under the halo2-base convention (leaf at index 0,
/// sibling = all-padding subtree root). Mirrors `crate::build_single_leaf_proof`
/// (light-poseidon) but for the axiom circuit — used by `gen-roundtrip-fixture`.
pub fn build_single_leaf_proof(
    addr: &[u8; 20],
    depth: usize,
) -> ([u8; 32], Vec<[u8; 32]>, Vec<u8>) {
    let hasher = Hasher::new();
    let mut node = hasher.hash_leaf(addr);
    let mut padding = PADDING_SENTINEL;
    let mut siblings = Vec::with_capacity(depth);
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        siblings.push(padding);
        path.push(0);
        node = hasher.hash_interior(&node, &padding);
        padding = hasher.hash_interior(&padding, &padding);
    }
    (node, siblings, path)
}
