//! ZKMist Airdrop Claim — RISC Zero Guest Program
//!
//! Proves:
//!   1. The claimant holds a private key that derives an eligible Ethereum address
//!   2. The address is in the Merkle tree of eligible addresses
//!   3. The nullifier is correctly computed from the private key
//!   4. The recipient address is not zero

#![no_main]
risc0_zkvm::guest::entry!(main);

use ark_bn254::Fr;
use k256::ecdsa::{SigningKey, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

// Atomix shim for riscv32 — tracing_core requires 1-byte atomics which riscv32im lacks.
#[no_mangle]
pub extern "C" fn __atomic_store_1(ptr: *mut u8, val: u8, _ordering: i32) {
    unsafe { core::ptr::write_volatile(ptr, val) }
}

const TREE_DEPTH: usize = 26;
const DOMAIN_SEPARATOR: &[u8] = b"ZKMist_V1_NULLIFIER";
const PADDING_SENTINEL: [u8; 32] = [0xFFu8; 32];

pub fn main() {
    // === Public inputs (committed to journal) ===
    let merkle_root: [u8; 32] = env::read();
    let nullifier: [u8; 32] = env::read();
    let recipient: [u8; 20] = env::read();

    // Validate recipient is not zero address — tokens minted to address(0)
    // are irreversibly burned. This check is defense-in-depth alongside the
    // Solidity contract's require(_recipient != address(0)).
    assert!(recipient != [0u8; 20], "Recipient cannot be zero address");

    // === Private inputs ===
    let private_key: [u8; 32] = env::read();

    // Derive Ethereum address
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

    // Pre-construct Poseidon hashers once (not per-call) to avoid redundant
    // initialization overhead inside the 26-level Merkle path verification.
    //
    // NOTE: Poseidon::hash() requires &mut self (light-poseidon v0.4.x internal
    // state mutation for sponge absorption). Hashers MUST be declared mutable.
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

    // Compute leaf and verify Merkle membership
    let leaf = poseidon_hash_address_with(&address, &mut leaf_hasher);
    assert!(leaf != PADDING_SENTINEL, "Padding leaf — not a valid claimant");
    let computed_root =
        compute_merkle_root_with(&leaf, &siblings, &path_indices, &mut interior_hasher);
    assert_eq!(computed_root, merkle_root, "Not in eligibility tree");

    // Verify nullifier
    let expected = compute_nullifier(&private_key);
    assert_eq!(nullifier, expected, "Invalid nullifier");

    // Commit outputs to journal.
    // ⚠️  CRITICAL: The Solidity contract slices the journal bytes directly:
    //     journal[0:32]   = merkleRoot
    //     journal[32:64]  = nullifier
    //     journal[64:84]  = recipient (raw 20 bytes, NOT padded to 32)
    // Total journal must be exactly 84 bytes.
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

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

fn compute_nullifier(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(DOMAIN_SEPARATOR);
    h.finalize().into()
}

/// Hash a 20-byte Ethereum address into a 32-byte Poseidon leaf.
/// The address is zero-padded to 32 bytes and interpreted as a BN254 field element.
/// Uses light-poseidon (t=2, R_F=8, R_P=56) — same crate as CLI tree builder.
fn poseidon_hash_address_with(addr: &[u8; 20], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
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
fn compute_merkle_root_with(
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
