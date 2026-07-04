//! Axiom-stack secp256k1 pubkey gadget (`halo2-ecc`) — Phase 2 of the axiom
//! backend migration (see `docs/axiom-backend-migration.md`).
//!
//! Replaces the hand-rolled `secp256k1.rs` (PSE backend) for the future axiom
//! circuit. Two capabilities, both built on halo2-ecc's audited chips:
//!
//! 1. **`pubkey_from_privkey`** — `privkey · G` via `EccChip::fixed_base_scalar_mult`.
//! 2. **`field_point_to_le_bytes`** — the **pubkey byte-bridge**: extract an
//!    secp256k1-Fp coordinate as 32 constrained little-endian bytes, ready to
//!    feed the Keccak-256 → Ethereum-address hash.
//!
//! The byte-bridge is the capability halo2wrong's CRT limbs could NOT provide
//! (their limbs are residues mod *coprime* moduli — not positional byte-slices),
//! and the core reason the axiom migration was chosen. halo2-ecc's
//! `ProperCrtUint` keeps a **positional** truncation (base `2^limb_bits`,
//! little-endian) alongside its CRT native cell, so each limb decomposes
//! cleanly into bytes (see `tests/secp_axiom.rs` for the end-to-end proof).
//!
//! Coexists with the PSE `secp256k1.rs` until the full circuit rewrite (Phase 3);
//! the two stacks use different `Fr` types and cannot mix in one circuit.

use halo2_base::{
    gates::GateInstructions,
    halo2_proofs::halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
    },
    utils::{decompose_biguint, fe_to_biguint},
    AssignedValue, Context, QuantumCell::Constant,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::FieldChip,
    secp256k1::{FpChip, Secp256k1Chip},
};

/// Base-field (secp256k1 Fp) chip configuration. `88`-bit limbs × `3` spans
/// 264 bits (≥ the 256-bit field) and is the configuration halo2-ecc itself
/// ships for secp256k1 (`configs/secp256k1/ecdsa_circuit.config`): it leaves
/// enough headroom for the `carry_mod` overflow bound (`n·k − 1 + Fr::NUM_BITS
/// − 2 = 515 ≥ 512`, the size of a `256×256`-bit product during scalar mult).
/// The byte-bridge below is limb-config-independent (it reads the low 256 bits
/// of the positional truncation), so this choice is purely about soundness/
/// efficiency, not byte alignment.
pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;

/// Window width for fixed-base scalar multiplication (halo2-ecc's recommended
/// default; balances table size vs. number of additions).
pub const WINDOW_BITS: usize = 4;

/// Decompose a secp256k1 private key (`Fq`) into `NUM_LIMBS` little-endian
/// `LIMB_BITS`-bit native limbs and assign them as witnesses. These are the
/// `scalar` chunks `fixed_base_scalar_mult` consumes (one chunk per limb;
/// `max_bits = LIMB_BITS` ≤ bn254 `Fr::NUM_BITS` = 254, so each chunk fits in a
/// native cell).
pub fn assign_privkey(ctx: &mut Context<Fr>, privkey: Fq) -> Vec<AssignedValue<Fr>> {
    let limbs = decompose_biguint::<Fr>(&fe_to_biguint(&privkey), NUM_LIMBS, LIMB_BITS);
    ctx.assign_witnesses(limbs)
}

/// Compute the secp256k1 public key `privkey · G` via halo2-ecc's audited
/// fixed-base scalar multiplication.
///
/// `scalar_limbs` is the private key as returned by [`assign_privkey`].
pub fn pubkey_from_privkey(
    ctx: &mut Context<Fr>,
    ecc: &Secp256k1Chip<'_, Fr>,
    scalar_limbs: Vec<AssignedValue<Fr>>,
) -> EcPoint<Fr, ProperCrtUint<Fr>> {
    let g = Secp256k1Affine::generator();
    // max_bits = LIMB_BITS (per-chunk width); the full scalar is
    // LIMB_BITS * scalar_limbs.len() = 256 bits. (The handoff's "max_bits=256"
    // would violate halo2-ecc's `max_bits <= F::NUM_BITS` (=254) assert; the
    // scalar MUST be chunked — one limb per chunk.)
    ecc.fixed_base_scalar_mult::<Secp256k1Affine>(ctx, &g, scalar_limbs, LIMB_BITS, WINDOW_BITS)
}

/// Extract a secp256k1-Fp coordinate as 32 constrained little-endian bytes —
/// the Keccak-256 preimage bridge.
///
/// Each positional truncation limb is decomposed to `limb_bits` little-endian
/// bits via `num_to_bits` (which both range-checks the limb and constrains its
/// bit decomposition); the low **256** bits of the concatenated stream are then
/// grouped into 32 bytes. Because the truncation is positional and the value is
/// range-checked to 256 bits (so every bit ≥ 256 is constrained to 0), the 32
/// output bytes provably equal the coordinate's little-endian byte
/// representation. This is independent of the limb width, so the chip config
/// can be chosen for soundness/efficiency without affecting the bridge. For the
/// Ethereum address, reverse each half to big-endian before Keccak (see test).
pub fn field_point_to_le_bytes(
    ctx: &mut Context<Fr>,
    fp_chip: &FpChip<'_, Fr>,
    point: &ProperCrtUint<Fr>,
) -> Vec<AssignedValue<Fr>> {
    // Range-check the value to 256 bits so bits ≥ 256 are constrained to 0
    // (and the limbs are valid positional components).
    fp_chip.range_check(ctx, point.clone(), 256);

    let gate = fp_chip.gate();
    let limb_bits = fp_chip.limb_bits();

    // Concatenated little-endian bit stream of the positional truncation.
    let mut all_bits = Vec::with_capacity(limb_bits * point.limbs().len());
    for limb in point.limbs() {
        all_bits.extend(gate.num_to_bits(ctx, *limb, limb_bits));
    }
    assert!(
        all_bits.len() >= 256,
        "limb config ({}×{}) does not span 256 bits",
        limb_bits,
        point.limbs().len()
    );

    // Low 256 bits → 32 little-endian bytes.
    let byte_bases = [1u64, 2, 4, 8, 16, 32, 64, 128].map(Fr::from);
    let mut bytes = Vec::with_capacity(32);
    for j in 0..32 {
        let byte = gate.inner_product(
            ctx,
            all_bits[j * 8..(j + 1) * 8].iter().copied(),
            byte_bases.iter().map(|c| Constant(*c)),
        );
        bytes.push(byte);
    }
    bytes
}
