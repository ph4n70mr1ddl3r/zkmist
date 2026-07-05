//! Axiom-stack Merkle proof gadget — Phase 3 of the axiom backend migration
//! (see `docs/axiom-backend-migration.md`).
//!
//! Verifies a 26-level Poseidon Merkle proof of address membership in the
//! eligibility tree, on the axiom `Context` eDSL, using [`poseidon_axiom`]'s
//! interior hasher. Coexists with the PSE `merkle.rs` until the full circuit is
//! rewritten (Phase 3); the two stacks use different `Fr` types.
//!
//! # Merkle path convention
//!
//! ```text
//! path_index[i] = 0 → current is LEFT child  → parent = poseidon(current, sibling)
//! path_index[i] = 1 → current is RIGHT child → parent = poseidon(sibling, current)
//! ```
//!
//! # Sponge-convention note (RESOLVED)
//!
//! This gadget hashes with halo2-base's Poseidon sponge (see the note in
//! `poseidon_axiom.rs`), which differs from the light-poseidon/Circom
//! convention. The committed tree is rebuilt under halo2-base's convention by
//! the off-chain `zkmist_merkle_tree::halo2base` module — the CLI's production
//! path — so this gadget verifies exactly the tree that is committed on-chain.
//! Agreement is proven end-to-end by
//! `tests/claim_axiom.rs::test_axiom_claim_verifies_offchain_tree`.

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};

use crate::poseidon_axiom::{hash_interior, native_hash_interior};

/// Tree depth for the production eligibility tree.
pub const TREE_DEPTH: usize = 26;

/// Compute the Merkle root natively (halo2-base Poseidon convention).
pub fn native_verify_merkle_proof(leaf: Fr, siblings: &[Fr], path_indices: &[Fr]) -> Fr {
    assert_eq!(siblings.len(), path_indices.len());
    let mut current = leaf;
    for i in 0..siblings.len() {
        let (left, right) = if path_indices[i] == Fr::one() {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = native_hash_interior(left, right);
    }
    current
}

/// Verify a Merkle proof in the axiom circuit. Returns the computed root; the
/// caller should constrain it to equal the expected (public) root.
///
/// `path_indices[i]` are constrained to boolean bits (`0` or `1`) below, then
/// `gate.select` (`sel ? a : b`) routes current/sibling into left/right. The
/// boolean range check is MANDATORY: `gate.select` is `b + sel·(a-b)` — linear
/// in `sel` — so an unconstrained `sel` lets a malicious prover realize
/// arbitrary `(left, right)` pairs at every level (by solving for the
/// `(sibling, index)` witnesses) and forge a membership proof against the
/// public root, whose preimage is public via the eligibility list. With
/// `index ∈ {0,1}`, `(current, sibling)` is forced to `(left, right)` up to
/// swap, restoring a genuine authenticated Merkle path.
pub fn verify_merkle_proof(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    leaf: AssignedValue<Fr>,
    siblings: &[AssignedValue<Fr>],
    path_indices: &[AssignedValue<Fr>],
) -> AssignedValue<Fr> {
    let depth = siblings.len();
    assert_eq!(path_indices.len(), depth);
    let gate = range.gate();

    // Constrain each path index to {0,1} — see the soundness note above.
    for index in path_indices {
        range.range_check(ctx, *index, 1);
    }

    let mut current = leaf;
    for i in 0..depth {
        // left  = idx ? sibling : current ; right = idx ? current : sibling
        let left = gate.select(ctx, siblings[i], current, path_indices[i]);
        let right = gate.select(ctx, current, siblings[i], path_indices[i]);
        current = hash_interior(ctx, range, left, right);
    }
    current
}

// Re-export the native leaf hash so callers building a tree natively (e.g. a
// future halo2-base-convention off-chain tree builder) get the matching digest.
pub use crate::poseidon_axiom::native_hash_leaf as native_leaf_hash;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_axiom::{native_hash_interior, native_hash_leaf};
    use halo2_base::utils::testing::base_test;

    /// In-circuit Merkle verification matches the native computation for a small
    /// tree (depth 4) with a known leaf.
    #[test]
    fn test_axiom_merkle_matches_native() {
        let depth = 4;
        // Random-ish but deterministic leaves (halo2-base Fr).
        let leaves: Vec<Fr> = (0..(1u64 << depth))
            .map(|i| Fr::from((i * 131 + 7) % 1_000_000_007u64))
            .collect();
        let leaf_index = 3usize;

        // Build the tree natively (halo2-base convention): leaf = poseidon(addr),
        // interior = poseidon(left, right).
        let leaf_hashes: Vec<Fr> = leaves.iter().map(|l| native_hash_leaf(*l)).collect();
        let mut layer = leaf_hashes.clone();
        let mut proof_siblings: Vec<Fr> = Vec::with_capacity(depth);
        let mut proof_indices: Vec<Fr> = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        while layer.len() > 1 {
            let sibling = if idx % 2 == 0 {
                layer[idx + 1]
            } else {
                layer[idx - 1]
            };
            proof_siblings.push(sibling);
            proof_indices.push(Fr::from((idx % 2) as u64));
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks(2) {
                next.push(native_hash_interior(pair[0], pair[1]));
            }
            layer = next;
            idx /= 2;
        }
        let native_root = layer[0];

        // Run the circuit.
        let circuit_root = base_test().k(12).lookup_bits(8).run(|ctx, range| {
            let leaf_cell = ctx.load_witness(leaf_hashes[leaf_index]);
            let sib_cells: Vec<_> = proof_siblings
                .iter()
                .map(|s| ctx.load_witness(*s))
                .collect();
            let idx_cells: Vec<_> = proof_indices.iter().map(|i| ctx.load_witness(*i)).collect();
            let root = verify_merkle_proof(ctx, range, leaf_cell, &sib_cells, &idx_cells);
            *root.value()
        });

        assert_eq!(circuit_root, native_root, "axiom Merkle root mismatch");

        // Cross-check native_verify too.
        let native_check =
            native_verify_merkle_proof(leaf_hashes[leaf_index], &proof_siblings, &proof_indices);
        assert_eq!(native_check, native_root);
    }

    /// Regression: a non-boolean path index MUST be rejected. Without the
    /// `range_check(index, 1)` guard, `gate.select` is linear in `index` and a
    /// prover can forge membership (see the soundness note on
    /// [`verify_merkle_proof`]). This feeds an honest path with one index
    /// tampered to `2`; MockProver must reject it.
    #[test]
    fn test_axiom_merkle_rejects_nonboolean_index() {
        let depth = 4;
        let leaves: Vec<Fr> = (0..(1u64 << depth))
            .map(|i| Fr::from((i * 131 + 7) % 1_000_000_007u64))
            .collect();
        let leaf_index = 3usize;
        let leaf_hashes: Vec<Fr> = leaves.iter().map(|l| native_hash_leaf(*l)).collect();

        // Honest path...
        let mut layer = leaf_hashes.clone();
        let mut proof_siblings: Vec<Fr> = Vec::with_capacity(depth);
        let mut proof_indices: Vec<Fr> = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        while layer.len() > 1 {
            let sibling = if idx % 2 == 0 {
                layer[idx + 1]
            } else {
                layer[idx - 1]
            };
            proof_siblings.push(sibling);
            proof_indices.push(Fr::from((idx % 2) as u64));
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks(2) {
                next.push(native_hash_interior(pair[0], pair[1]));
            }
            layer = next;
            idx /= 2;
        }
        // ...then tamper one index to a non-boolean value.
        proof_indices[0] = Fr::from(2u64);

        // `expect_satisfied(false)` ⇒ the tester asserts `MockProver::verify`
        // returns `Err`. If the boolean range check regresses, the bad witness
        // would satisfy the circuit and this assertion panics (test fails).
        base_test()
            .k(12)
            .lookup_bits(8)
            .expect_satisfied(false)
            .run(|ctx, range| {
                let leaf_cell = ctx.load_witness(leaf_hashes[leaf_index]);
                let sib_cells: Vec<_> = proof_siblings
                    .iter()
                    .map(|s| ctx.load_witness(*s))
                    .collect();
                let idx_cells: Vec<_> =
                    proof_indices.iter().map(|i| ctx.load_witness(*i)).collect();
                let _ = verify_merkle_proof(ctx, range, leaf_cell, &sib_cells, &idx_cells);
            });
    }
}
