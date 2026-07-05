//! Phase 3 integration — the `keccak(pubkey) → address` bridge, fully
//! in-circuit (see `docs/axiom-backend-migration.md`). This is the crux the
//! whole axiom migration exists to enable: proving `address =
//! keccak256(privkey·G)[12..]` inside one axiom circuit, wiring together the
//! Phase-2 secp byte-bridge (`secp_axiom`) and the Phase-3 Keccak port
//! (`keccak_axiom`).
//!
//! The circuit: `privkey → scalar·G → (x, y) → 64 LE bytes → reverse to BE →
//! keccak256 → address[12..]`, and each of the 20 address bytes is constrained
//! equal to the native Ethereum derivation. MockProver (k=21) asserts every
//! constraint; the test also cross-checks the digest against `tiny_keccak`.

use ff::PrimeField;
use group::Curve;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
        CurveAffine,
    },
    utils::testing::base_test,
};
use halo2_ecc::{ecc::EccChip, secp256k1::FpChip};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::{
    keccak_axiom::keccak256,
    secp_axiom::{
        assign_privkey, field_point_to_le_bytes, pubkey_from_privkey, LIMB_BITS, NUM_LIMBS,
    },
};

fn native_pubkey(privkey: Fq) -> (Fp, Fp) {
    let g = Secp256k1Affine::generator();
    let pt = (g * privkey).to_affine();
    let c = pt.coordinates().unwrap();
    (*c.x(), *c.y())
}

fn be_bytes(fp: &Fp) -> [u8; 32] {
    let mut b = fp.to_repr();
    b.reverse();
    b
}

#[test]
fn test_address_bridge_in_circuit() {
    let privkey = Fq::from(0x1234_5678_9ABC_DEF0u64);
    let (x_fp, y_fp) = native_pubkey(privkey);

    // Native expected address.
    let mut h = Keccak::v256();
    h.update(&be_bytes(&x_fp));
    h.update(&be_bytes(&y_fp));
    let mut expected_hash = [0u8; 32];
    h.finalize(&mut expected_hash);
    let expected_addr: [u8; 20] = expected_hash[12..32].try_into().unwrap();

    // In-circuit: privkey → pubkey → LE bytes → BE preimage → keccak → address,
    // with each address byte constrained to the native value.
    base_test().k(21).lookup_bits(8).run(|ctx, range| {
        let fp_chip = FpChip::<Fr>::new(range, LIMB_BITS, NUM_LIMBS);
        let ecc = EccChip::new(&fp_chip);

        let scalar_limbs = assign_privkey(ctx, privkey);
        let pt = pubkey_from_privkey(ctx, &ecc, scalar_limbs);

        // 32 LE bytes per coordinate.
        let x_le = field_point_to_le_bytes(ctx, &fp_chip, &pt.x);
        let y_le = field_point_to_le_bytes(ctx, &fp_chip, &pt.y);

        // Keccak preimage = x_be ‖ y_be (reverse each LE half).
        let mut preimage = Vec::with_capacity(64);
        preimage.extend(x_le.iter().rev());
        preimage.extend(y_le.iter().rev());

        let hash = keccak256(ctx, range, &preimage);

        // Constrain the address bytes (hash[12..32]) to the native address.
        let gate = range.gate();
        for (i, &expected) in expected_addr.iter().enumerate() {
            let got = hash[12 + i];
            gate.assert_is_const(ctx, &got, &Fr::from(expected as u64));
        }
    });

    // If we reach here, MockProver asserted every constraint AND all 20 address
    // bytes matched the native derivation — the bridge is proven sound.
    eprintln!(
        "Phase 3 address-bridge OK: privkey 0x1234…DEF0 → 0x{}",
        hex::encode(expected_addr)
    );
}
