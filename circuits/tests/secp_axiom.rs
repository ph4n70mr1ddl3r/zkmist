//! Phase 2 verification (axiom backend migration — see
//! `docs/axiom-backend-migration.md`): the halo2-ecc secp256k1 pubkey
//! **byte-bridge** — the capability halo2wrong's CRT limbs could not provide,
//! and the core reason the axiom migration was chosen.
//!
//! Proves, in an isolated circuit, that:
//! 1. **`scalar·G` via halo2-ecc is correct** — the computed pubkey `(x, y)` is
//!    constrained equal to the native `privkey · G`.
//! 2. **The pubkey coordinates can be extracted as constrained bytes** — 32
//!    little-endian bytes per coordinate, soundly derived from halo2-ecc's
//!    positional truncation limbs.
//! 3. **Those bytes are the correct Keccak-256 preimage** — reversing each half
//!    to big-endian, `keccak256(x_be || y_be)[12..32]` equals the Ethereum
//!    address derived from the private key.
//!
//! (The in-circuit Keccak hash itself is Phase 3 — the Keccak gadget must first
//! be ported to the axiom `Context` eDSL. Here the Keccak check is native,
//! proving the extracted bytes are the right preimage.)

use ff::PrimeField;
use group::Curve;
use halo2_base::{
    halo2_proofs::halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
        CurveAffine,
    },
    utils::{fe_to_biguint, testing::base_test},
};
use halo2_ecc::{ecc::EccChip, fields::FieldChip, secp256k1::FpChip};
use num_bigint::BigUint;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::secp_axiom::{
    assign_privkey, enforce_scalar_less_than_n, field_point_to_le_bytes, pubkey_from_privkey,
    secp_n_biguint, LIMB_BITS, NUM_LIMBS,
};

/// Native `privkey · G` → `(x, y)` on secp256k1.
fn native_pubkey(privkey: Fq) -> (Fp, Fp) {
    let g = Secp256k1Affine::generator();
    let pt = (g * privkey).to_affine();
    let coords = pt.coordinates().expect("privkey · G is not identity for a valid privkey");
    (*coords.x(), *coords.y())
}

/// 32 big-endian bytes of a secp256k1-Fp element (the Ethereum convention).
fn fp_to_be_bytes(fp: &Fp) -> [u8; 32] {
    let mut bytes = fp.to_repr();
    bytes.reverse();
    bytes
}

/// `keccak256(x_be || y_be)[12..32]` — the Ethereum address of the pubkey.
fn eth_address(x: &Fp, y: &Fp) -> [u8; 20] {
    let mut hasher = Keccak::v256();
    hasher.update(&fp_to_be_bytes(x));
    hasher.update(&fp_to_be_bytes(y));
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// Ground-truth anchor: privkey = 1 must yield the canonical Ethereum address
/// `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` (the address of secp256k1
/// generator G, documented across the ecosystem). This pins the native
/// `privkey·G → keccak(pubkey)` derivation to Ethereum ground truth, so the
/// in-circuit-vs-native comparison in the main test is anchored (not merely
/// self-consistent).
#[test]
fn test_eth_address_known_vector_privkey_one() {
    let (x, y) = native_pubkey(Fq::one());
    let addr = eth_address(&x, &y);
    let expected: [u8; 20] = hex::decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        .expect("16 hex bytes")
        .try_into()
        .expect("20 bytes");
    assert_eq!(addr, expected, "privkey=1 did not yield the canonical address");
}

#[test]
fn test_halo2ecc_secp256k1_pubkey_byte_bridge() {
    // A valid secp256k1 private key (well below the scalar-field order).
    let privkey = Fq::from(0x1234_5678_9ABC_DEF0u64);

    let (x_fp, y_fp) = native_pubkey(privkey);
    let expected_addr = eth_address(&x_fp, &y_fp);

    // Run the isolated circuit; return the 64 extracted LE byte VALUES (witness
    // side). MockProver (via base_test) asserts every constraint is satisfied.
    let byte_values: Vec<Fr> = base_test()
        .k(18)
        .lookup_bits(17)
        .run(|ctx, range| {
            let fp_chip = FpChip::<Fr>::new(range, LIMB_BITS, NUM_LIMBS);
            let ecc = EccChip::new(&fp_chip);

            let scalar_limbs = assign_privkey(ctx, privkey);
            let pt = pubkey_from_privkey(ctx, &ecc, scalar_limbs);

            // (1) scalar·G correctness: constrain the computed pubkey to the
            //     native privkey · G.
            let expected_x = fp_chip.load_private(ctx, x_fp);
            let expected_y = fp_chip.load_private(ctx, y_fp);
            fp_chip.assert_equal(ctx, pt.x.clone(), expected_x);
            fp_chip.assert_equal(ctx, pt.y.clone(), expected_y);

            // (2) byte-bridge: 32 LE bytes per coordinate.
            let mut bytes = field_point_to_le_bytes(ctx, &fp_chip, &pt.x);
            bytes.extend(field_point_to_le_bytes(ctx, &fp_chip, &pt.y));
            bytes.into_iter().map(|c| *c.value()).collect::<Vec<_>>()
        });

    // ── Native verification of the extracted bytes ─────────────────────────
    assert_eq!(byte_values.len(), 64, "expected 64 pubkey bytes (32 + 32)");

    let le_bytes: Vec<u8> = byte_values
        .iter()
        .map(|f| {
            let v = fe_to_biguint(f);
            assert!(v < BigUint::from(256u64), "extracted byte >= 256 (range check failed)");
            v.iter_u64_digits().next().unwrap() as u8
        })
        .collect();
    let (x_le, y_le) = le_bytes.split_at(32);

    // The extracted LE bytes must recompose to the exact coordinates.
    assert_eq!(
        BigUint::from_bytes_le(x_le),
        fe_to_biguint(&x_fp),
        "extracted x bytes do not recompose to x"
    );
    assert_eq!(
        BigUint::from_bytes_le(y_le),
        fe_to_biguint(&y_fp),
        "extracted y bytes do not recompose to y"
    );

    // And they must be the correct Keccak preimage (x_be || y_be → address).
    let mut preimage = Vec::with_capacity(64);
    preimage.extend(x_le.iter().rev()); // LE → BE
    preimage.extend(y_le.iter().rev());
    let mut hasher = Keccak::v256();
    hasher.update(&preimage);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    assert_eq!(
        addr, expected_addr,
        "byte-bridge: keccak256(pubkey) did not yield the Ethereum address"
    );

    eprintln!(
        "Phase 2 byte-bridge OK: privkey 0x1234…DEF0 → address 0x{}",
        hex::encode(addr)
    );
}

// ── §5a TRAP: the K < n_secp256k1 range proof (fast, isolated) ────────────

/// A valid key (K < n) is accepted by the range proof.
#[test]
fn test_enforce_scalar_less_than_n_accepts_valid_key() {
    base_test().k(12).lookup_bits(8).run(|ctx, range| {
        let limbs = assign_privkey(ctx, Fq::from(0x0A11CE_5EC7E7u64));
        enforce_scalar_less_than_n(ctx, range, &limbs);
    });
}

/// A key K = n + 1 (≥ n) is rejected — the §5a TRAP. An `Fq` cannot represent
/// K ≥ n (it's already reduced mod n), so we inject the limbs directly via
/// `assign_scalar_biguint`.
#[test]
fn test_enforce_scalar_less_than_n_rejects_key_above_n() {
    use zkmist_circuits::secp_axiom::assign_scalar_biguint;
    let n_plus_1 = secp_n_biguint() + 1u32;
    base_test()
        .k(12)
        .lookup_bits(8)
        .expect_satisfied(false)
        .run(|ctx, range| {
            let limbs = assign_scalar_biguint(ctx, n_plus_1);
            enforce_scalar_less_than_n(ctx, range, &limbs);
        });
}
