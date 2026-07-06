//! Axiom-stack ZKMist V2 claim circuit — Phase 3 capstone
//! (see `docs/axiom-backend-migration.md` §11, `docs/secp256k1-migration-plan.md`
//! §5/§5a).
//!
//! Wires together every ported gadget — secp (`secp_axiom`), Keccak
//! (`keccak_axiom`), Poseidon / Merkle / nullifier (`poseidon_axiom`,
//! `merkle_axiom`, `nullifier_axiom`) — into one `Context`-eDSL circuit proving
//! a valid anonymous-airdrop claim:
//!
//! ```text
//! privkey ──► scalar·G ──► pubkey (x,y)
//!                         │
//!                         ▼
//!                  keccak256(x_be‖y_be)[12..] ──► address ──► poseidon(address) = leaf
//!                                                              └─► Merkle proof ──► root (== expected)
//! privkey ──► recompose(key) ──► poseidon(key, domain) = nullifier (== expected)
//! recipient: public input, constrained non-zero uint160
//! ```
//!
//! # Soundness bindings (§5/§5a)
//!
//! - **leaf↔address** (§5a "Leaf ↔ Keccak address"): the address `Fr` recomposed
//!   from `keccak(pubkey)[12..]` is the *same cell* fed to `poseidon` → the
//!   Merkle leaf. Automatic; no separate constraint.
//! - **nullifier↔scalar** (§5a "Nullifier ↔ scalar"): the `Fr` key fed to the
//!   nullifier Poseidon is constrained equal to the scalar's native
//!   recomposition `Σ limb_i · 2^(LIMB_BITS·i)`. The limbs are the very chunks
//!   `fixed_base_scalar_mult` consumes, so the nullifier key is bound to the
//!   scalar that produced the pubkey.
//! - **recipient↔uint160**: recipient is range-checked to `< 2^160` and non-zero.
//!
//! ## The `K < n` range proof (§5a TRAP) — implemented
//!
//! `fixed_base_scalar_mult` reduces the scalar mod the secp256k1 order `n`. For
//! a valid key `K < n` it uses `K`; the nullifier binding is then sound. For
//! `K ≥ n`, `scalar·G` would use `K mod n ≠ K` while the nullifier uses
//! `K mod p_BN254` — decoupling the two. The hand-rolled PSE circuit got this
//! implicitly (the scalar was 256 constrained bits); the axiom circuit enforces
//! it explicitly via [`secp_axiom::enforce_scalar_less_than_n`] (limb range
//! checks + an MSB-first limb-wise `K < n` comparison). The `test_key_above_n`
//! negative proves a `K ≥ n` claim is rejected.

use ff::Field;
use halo2_base::{
    gates::RangeChip,
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use halo2_ecc::{ecc::EccChip, secp256k1::FpChip};

use crate::{
    keccak_axiom::keccak256,
    merkle_axiom::verify_merkle_proof,
    nullifier_axiom::compute_nullifier,
    poseidon_axiom::hash_leaf,
    secp_axiom::{
        enforce_scalar_less_than_n, field_point_to_le_bytes, pubkey_from_privkey, LIMB_BITS,
        NUM_LIMBS,
    },
};

/// Prove one ZKMist V2 claim on the axiom eDSL (positive happy path).
///
/// Compute the claim's public outputs in-circuit: `(merkle_root, nullifier,
/// recipient)`, with all §5/§5a bindings enforced (K<n range proof,
/// leaf↔address, nullifier↔scalar, recipient↔uint160) but **without** asserting
/// them to expected values. A caller exposes them as public instances (on-chain
/// verifier checks) or asserts them as constants (test harness).
#[allow(clippy::too_many_arguments)]
pub fn prove_claim_to_cells(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    privkey_limbs: Vec<AssignedValue<Fr>>,
    siblings: &[Fr],
    path_indices: &[Fr],
    recipient: Fr,
    chain_id: Fr,
) -> (
    AssignedValue<Fr>,
    AssignedValue<Fr>,
    AssignedValue<Fr>,
    AssignedValue<Fr>,
) {
    let gate = range.gate();

    // ── 0. K < n_secp256k1 range proof (§5a TRAP) ──
    enforce_scalar_less_than_n(ctx, range, &privkey_limbs);

    let fp_chip = FpChip::<Fr>::new(range, LIMB_BITS, NUM_LIMBS);
    let ecc = EccChip::new(&fp_chip);

    // ── 1. privkey · G → pubkey ──
    let pt = pubkey_from_privkey(ctx, &ecc, privkey_limbs.clone());

    // ── 2. pubkey bytes → keccak → address ──
    let x_le = field_point_to_le_bytes(ctx, &fp_chip, &pt.x);
    let y_le = field_point_to_le_bytes(ctx, &fp_chip, &pt.y);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend(x_le.iter().rev()); // LE → BE (Ethereum convention)
    preimage.extend(y_le.iter().rev());
    let hash = keccak256(ctx, range, &preimage);

    // address = hash[12..32], recomposed as a 20-byte big-endian Fr.
    let addr_bases: Vec<Fr> = (0..20u32)
        .map(|i| Fr::from(256u64).pow([(19 - i) as u64]))
        .collect();
    let address_fr = gate.inner_product(
        ctx,
        hash[12..32].iter().copied(),
        addr_bases
            .iter()
            .map(|c| halo2_base::QuantumCell::Constant(*c)),
    );

    // ── 3. leaf = poseidon(address); Merkle proof → root ── (leaf↔address binding)
    let leaf = hash_leaf(ctx, range, address_fr);
    let sib_cells: Vec<_> = siblings.iter().map(|s| ctx.load_witness(*s)).collect();
    let idx_cells: Vec<_> = path_indices.iter().map(|i| ctx.load_witness(*i)).collect();
    let root = verify_merkle_proof(ctx, range, leaf, &sib_cells, &idx_cells);

    // ── 4. nullifier = poseidon(key, domain), key bound to the scalar ──
    //    key_mod_p = Σ limb_i · 2^(LIMB_BITS·i)  (= privkey mod p_BN254). The
    //    key cell fed to Poseidon is the scalar's own recomposition, so
    //    nullifier↔scalar binds.
    let limb_bases: Vec<Fr> = (0..NUM_LIMBS)
        .map(|i| Fr::from(2u64).pow([(i * LIMB_BITS) as u64]))
        .collect();
    let key_mod_p = gate.inner_product(
        ctx,
        privkey_limbs.iter().copied(),
        limb_bases
            .iter()
            .map(|c| halo2_base::QuantumCell::Constant(*c)),
    );
    let nullifier = compute_nullifier(ctx, range, key_mod_p);

    // ── 5. recipient: non-zero uint160 ──
    let recipient_cell = ctx.load_witness(recipient);
    range.range_check(ctx, recipient_cell, 160);
    let recipient_is_zero = gate.is_zero(ctx, recipient_cell);
    gate.assert_is_const(ctx, &recipient_is_zero, &Fr::zero());

    // ── 6. chain_id ──
    let chain_id_cell = ctx.load_witness(chain_id);

    (root, nullifier, recipient_cell, chain_id_cell)
}

/// Prove one ZKMist V2 claim and assert the public outputs to the expected
/// values via `assert_is_const` (test-harness convenience; a real circuit uses
/// [`prove_claim_to_cells`] + public instances).
#[allow(clippy::too_many_arguments)]
pub fn prove_claim(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    privkey_limbs: Vec<AssignedValue<Fr>>,
    siblings: &[Fr],
    path_indices: &[Fr],
    expected_root: Fr,
    expected_nullifier: Fr,
    recipient: Fr,
    chain_id: Fr,
) {
    let gate = range.gate();
    let (root, nullifier, _recipient, _chain_id) = prove_claim_to_cells(
        ctx,
        range,
        privkey_limbs,
        siblings,
        path_indices,
        recipient,
        chain_id,
    );
    gate.assert_is_const(ctx, &root, &expected_root);
    gate.assert_is_const(ctx, &nullifier, &expected_nullifier);
}
