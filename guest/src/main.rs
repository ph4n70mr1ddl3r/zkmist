//! ZKMist Airdrop Claim — RISC Zero Guest Program
//!
//! Proves:
//!   1. The claimant holds a private key that derives an eligible Ethereum address
//!   2. The address is in the Merkle tree of eligible addresses
//!   3. The nullifier is correctly computed from the private key
//!   4. The recipient address is not zero
//!
//! Journal layout (84 bytes):
//!   [0:32]   merkleRoot    (bytes32)
//!   [32:64]  nullifier     (bytes32)
//!   [64:84]  recipient     (address — raw 20 bytes)
//!
//! The Solidity contract slices the journal by these exact offsets.

#![no_main]
risc0_zkvm::guest::entry!(main);

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use k256::ecdsa::{SigningKey, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::guest::env;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

// ── Atomic shim for riscv32 ──────────────────────────────────────────────
//
// `tracing-core` (pulled transitively through ark-relations → ark-groth16 →
// risc0-zkvm) requires 1-byte atomics. The riscv32im ISA has no native
// 1-byte atomic instructions, so the linker fails without these shims.
//
// These are safe because the RISC Zero zkVM is strictly single-threaded —
// there are no other threads that could observe a data race. The `volatile`
// reads/writes prevent the compiler from optimizing them away.
//
// If risc0-zkvm or ark-relations ever removes the `tracing` dependency,
// these shims can be deleted entirely.

/// # Safety
/// Safe in the RISC Zero zkVM because it is single-threaded.
#[no_mangle]
pub unsafe extern "C" fn __atomic_load_1(ptr: *const u8, _ordering: i32) -> u8 {
    core::ptr::read_volatile(ptr)
}

/// # Safety
/// Safe in the RISC Zero zkVM because it is single-threaded.
#[no_mangle]
pub unsafe extern "C" fn __atomic_store_1(ptr: *mut u8, val: u8, _ordering: i32) {
    core::ptr::write_volatile(ptr, val)
}

// ── Constants ────────────────────────────────────────────────────────────

const TREE_DEPTH: usize = 26;

/// Nullifier domain separator: b"ZKMist_V1_NULLIFIER" (20 bytes), zero-padded
/// to 32 bytes (left-aligned), then interpreted as a BN254 field element via
/// `Fr::from_be_bytes_mod_order`. This MUST match the CLI's nullifier
/// computation exactly. Changing this value invalidates all proofs and
/// requires redeploying the contract with a new image ID.
const NULLIFIER_DOMAIN_BYTES: &[u8; 19] = b"ZKMist_V1_NULLIFIER";

/// Padding sentinel for empty leaves. Raw bytes 0xFF..FF exceed the BN254
/// field modulus, so a Poseidon output (always a valid field element < p < 2^254)
/// can never equal this value in raw bytes. Compare bytes, not field elements.
const PADDING_SENTINEL: [u8; 32] = [0xFFu8; 32];

// ── Entry point ──────────────────────────────────────────────────────────

pub fn main() {
    // === Public inputs (committed to journal) ===
    let merkle_root: [u8; 32] = env::read();
    let nullifier: [u8; 32] = env::read();
    let recipient: [u8; 20] = env::read();

    // Validate recipient is not zero address — tokens minted to address(0)
    // are irreversibly burned. Defense-in-depth alongside the Solidity
    // contract's require(_recipient != address(0)).
    assert!(recipient != [0u8; 20], "Recipient cannot be zero address");

    // === Private inputs ===
    let private_key: [u8; 32] = env::read();

    // Derive Ethereum address from private key
    let address = derive_address(&private_key);

    // Merkle membership proof.
    //
    // path_index convention:
    //   path_index[i] = 0 → current node is the LEFT child at level i
    //                     → parent = poseidon(current, sibling)
    //   path_index[i] = 1 → current node is the RIGHT child at level i
    //                     → parent = poseidon(sibling, current)
    let mut siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices: [u8; TREE_DEPTH] = [0u8; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        siblings[i] = env::read();
        path_indices[i] = env::read();
    }

    // Pre-construct Poseidon hashers once. Each hasher construction involves
    // fixed-string round constant allocation; reusing a single instance saves
    // ~2.6M–5.2M RISC-V cycles across 27+ hash invocations.
    //
    // light-poseidon v0.4.x: hash() requires &mut self (sponge absorption).
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

    // Compute leaf and verify Merkle membership
    let leaf = poseidon_hash_address(&address, &mut leaf_hasher);
    assert!(
        leaf != PADDING_SENTINEL,
        "Padding leaf — not a valid claimant"
    );
    let computed_root = compute_merkle_root(&leaf, &siblings, &path_indices, &mut interior_hasher);
    assert_eq!(computed_root, merkle_root, "Not in eligibility tree");

    // Verify nullifier: poseidon(Fr(key), Fr(domain)) using the interior hasher.
    // Same hasher as Merkle proof — each hash() call is independent.
    let expected = compute_nullifier(&private_key, &mut interior_hasher);
    assert_eq!(nullifier, expected, "Invalid nullifier");

    // Commit outputs to journal (84 bytes total).
    //
    // ⚠️  CRITICAL: The Solidity contract slices the journal bytes directly:
    //     journal[0:32]   = merkleRoot   (bytes32)
    //     journal[32:64]  = nullifier    (bytes32)
    //     journal[64:84]  = recipient    (bytes20 — raw address, NOT padded)
    // Any mismatch = all proofs rejected on-chain.
    //
    // env::commit() for [u8; N] arrays writes N raw bytes, no length prefix.
    // Verified for risc0-zkvm v5.0.0.
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

// ── Address derivation ───────────────────────────────────────────────────

fn derive_address(key: &[u8; 32]) -> [u8; 20] {
    let sk = SigningKey::from_slice(key).expect("Invalid key");
    let vk = VerifyingKey::from(&sk);
    let point = vk.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    hasher.update(&point.as_bytes()[1..65]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

// ── Nullifier ────────────────────────────────────────────────────────────

/// Compute nullifier as poseidon(Fr(key), Fr(domain)) using the interior
/// hasher (t=3, 2 inputs). Domain separation prevents nullifier collisions
/// across protocol versions (V1/V2 use different domain strings).
///
/// This MUST produce the same output as `zkmist_merkle_tree::compute_nullifier`.
fn compute_nullifier(key: &[u8; 32], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let key_elem = Fr::from_be_bytes_mod_order(key);
    let mut domain_padded = [0u8; 32];
    domain_padded[..NULLIFIER_DOMAIN_BYTES.len()].copy_from_slice(NULLIFIER_DOMAIN_BYTES);
    let domain_elem = Fr::from_be_bytes_mod_order(&domain_padded);
    field_element_to_bytes(
        hasher
            .hash(&[key_elem, domain_elem])
            .expect("Nullifier hash failed"),
    )
}

// ── Poseidon hashing ─────────────────────────────────────────────────────

/// Hash a 20-byte Ethereum address into a 32-byte Poseidon leaf.
/// Address is left-padded with 12 zero bytes to 32 bytes, then interpreted
/// as a BN254 field element. Uses leaf hasher (t=2, 1 input).
fn poseidon_hash_address(addr: &[u8; 20], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(addr);
    field_element_to_bytes(
        hasher
            .hash(&[Fr::from_be_bytes_mod_order(&padded)])
            .expect("Leaf hash failed"),
    )
}

/// Compute the Merkle root by hashing siblings up the tree.
///
/// Direction convention:
///   path_index[i] = 0 → current is LEFT child  → parent = poseidon(current, sibling)
///   path_index[i] = 1 → current is RIGHT child → parent = poseidon(sibling, current)
fn compute_merkle_root(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    path_indices: &[u8; TREE_DEPTH],
    hasher: &mut Poseidon<Fr>,
) -> [u8; 32] {
    let mut current = *leaf;
    for i in 0..TREE_DEPTH {
        let (left, right) = if path_indices[i] == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        let left_elem = Fr::from_be_bytes_mod_order(&left);
        let right_elem = Fr::from_be_bytes_mod_order(&right);
        current = field_element_to_bytes(
            hasher
                .hash(&[left_elem, right_elem])
                .expect("Interior hash failed"),
        );
    }
    current
}

/// Convert a BN254 field element to 32-byte big-endian representation.
fn field_element_to_bytes(elem: Fr) -> [u8; 32] {
    let bytes = elem.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}
