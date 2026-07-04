//! Phase 3 step 1 — axiom Keccak-256 port verification
//! (see `docs/axiom-backend-migration.md`).
//!
//! Proves the bit-level axiom Keccak-f[1600] (`circuits/src/keccak_axiom.rs`)
//! matches the reference `tiny_keccak` keccak256:
//! 1. Empty-input known vector: `keccak256("") = c5d2…a470`.
//! 2. A 64-byte input (the ZKMist pubkey preimage shape) matches `tiny_keccak`.
//! 3. The 64-byte pubkey → address path matches the native Ethereum derivation,
//!    closing the loop with the Phase-2 secp byte-bridge: in-circuit
//!    `keccak256(pubkey)[12..]` equals the address.

use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    utils::{fe_to_biguint, testing::base_test},
};
use num_bigint::BigUint;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use zkmist_circuits::keccak_axiom::keccak256;

/// Run in-circuit `keccak256(input)` (single block, ≤ 135 bytes), return the 32
/// hash bytes.
fn circuit_keccak256(input: &[u8]) -> Vec<u8> {
    let cells: Vec<Fr> = base_test()
        .k(19)
        .lookup_bits(8)
        .run(|ctx, range| {
            let input_cells: Vec<_> = input.iter().map(|b| ctx.load_witness(Fr::from(*b as u64))).collect();
            let hash = keccak256(ctx, range, &input_cells);
            hash.into_iter().map(|c| *c.value()).collect()
        });
    cells
        .iter()
        .map(|f| {
            let v = fe_to_biguint(f);
            assert!(v < BigUint::from(256u64), "hash byte >= 256");
            v.iter_u64_digits().next().unwrap_or(0) as u8
        })
        .collect()
}

#[test]
fn test_keccak256_empty_known_vector() {
    // keccak256("") — the canonical empty-input digest.
    let expected = hex_decode(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
    let got = circuit_keccak256(&[]);
    assert_eq!(got, expected, "keccak256(\"\") mismatch");
}

#[test]
fn test_keccak256_64_byte_input_matches_tiny_keccak() {
    // A pseudo-public-key-shaped 64-byte input (the ZKMist preimage).
    let mut input = [0u8; 64];
    for (i, b) in input.iter_mut().enumerate() {
        *b = ((i as u64 * 7 + 3) & 0xFF) as u8;
    }
    let mut h = Keccak::v256();
    h.update(&input);
    let mut expected = [0u8; 32];
    h.finalize(&mut expected);

    let got = circuit_keccak256(&input);
    assert_eq!(got, expected.to_vec(), "keccak256(64-byte) != tiny_keccak");
}

#[test]
fn test_keccak256_pubkey_to_address() {
    // Close the loop with the Phase-2 byte-bridge: a known pubkey → address.
    // privkey = 1 ⇒ pubkey = G ⇒ address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
    // G coordinates (uncompressed, big-endian):
    let gx = hex_decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    let gy = hex_decode(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&gx);
    preimage[32..].copy_from_slice(&gy);

    let hash = circuit_keccak256(&preimage);
    let addr = &hash[12..32];
    let expected_addr = hex_decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    assert_eq!(addr, expected_addr, "keccak256(G) address != canonical privkey=1 address");

    // Cross-check the full hash against tiny_keccak too.
    let mut h = Keccak::v256();
    h.update(&preimage);
    let mut expected = [0u8; 32];
    h.finalize(&mut expected);
    assert_eq!(hash, expected.to_vec());
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}
