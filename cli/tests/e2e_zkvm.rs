//! End-to-end integration test for the ZKMist claim pipeline.
//!
//! Tier 1 (this file, runs in CI):
//!   - Execute the guest program via dev-mode proving (RISC0_DEV_MODE=1)
//!   - Verify journal layout (84 bytes: root + nullifier + recipient)
//!   - Verify guest assertions pass (valid key, correct nullifier, merkle membership)
//!
//! Tier 2 (manual, pre-mainnet):
//!   - Set ZKMIST_FULL_PROVE=1 to generate a real STARK proof (30+ min)
//!   - Required before mainnet deployment
//!
//! Build instructions for guest binaries:
//!
//!   Test guest (depth=4, for Tier 1 dev-mode tests):
//!     cargo risczero build --manifest-path guest/Cargo.toml --features test-small-tree
//!     # The test binary must be at TEST_GUEST_BIN_PATH (see below).
//!     # If the standard output location differs, copy/rename accordingly.
//!
//!   Production guest (depth=26, for Tier 2 full STARK proof):
//!     cargo risczero build --manifest-path guest/Cargo.toml
//!     # The prod binary must be at PROD_GUEST_BIN_PATH (see below).
//!
//! ⚠️  The test guest MUST be built with `--features test-small-tree` (TREE_DEPTH=4).
//!     Without this feature the guest expects 26 sibling pairs, but Tier 1 tests
//!     provide only 4. This causes a deserialization error, not a useful assertion
//!     failure. Verify the binary is correct before running tests.
//!
//! Prerequisites:
//!   - Guest binary built via: cargo risczero build --manifest-path guest/Cargo.toml
//!   - Located at: target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest-test.bin

use ark_bn254::Fr;
use light_poseidon::Poseidon;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv};
use zkmist_merkle_tree::{
    build_tree_streaming_with_depth, compute_nullifier, hash_leaf, verify_merkle_proof, TREE_DEPTH,
};

/// Path to the test guest binary (built with `--features test-small-tree`, depth=4).
/// Used by Tier 1 dev-mode tests.
///
/// Build with:
///   cargo risczero build --manifest-path guest/Cargo.toml --features test-small-tree
///
/// If `cargo risczero build` outputs to a different location, adjust this path
/// or copy the binary here. The binary should start with the R0BF magic bytes.
const TEST_GUEST_BIN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest-test.bin"
);

/// Alternative search paths for the test guest binary, tried if the primary
/// path doesn't exist. Covers the standard `cargo risczero build` output
/// locations and naming conventions.
const TEST_GUEST_ALT_PATHS: &[&str] = &[
    // Docker reproducible build output
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest"
    ),
    // Standard release build output
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/riscv32im-risc0-zkvm-elf/release/zkmist-guest"
    ),
];

/// Path to the production guest binary (depth=26, no test features).
/// Used by Tier 2 full-STARK proof test.
///
/// Build with:
///   cargo risczero build --manifest-path guest/Cargo.toml
const PROD_GUEST_BIN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/riscv32im-risc0-zkvm-elf/release/zkmist-guest"
);

/// Tree depth for the test guest (4 instead of 26 for fast execution).
const TEST_TREE_DEPTH: usize = 4;

/// PRD Appendix D test vector private key.
const TEST_PRIVATE_KEY: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// Derived from TEST_PRIVATE_KEY via secp256k1 + Keccak-256.
const TEST_ADDRESS: [u8; 20] = [
    0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16,
    0xaf, 0xce, 0x37, 0x7c,
];

/// Expected nullifier from PRD test vector.
const EXPECTED_NULLIFIER: &str = "078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9";

/// Expected leaf hash from PRD test vector.
const EXPECTED_LEAF: &str = "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9";

/// Load the test guest binary (built with `--features test-small-tree`, depth=4).
/// Skips the test if the binary hasn't been built yet.
///
/// ⚠️  This binary MUST be built with `--features test-small-tree`. Without it,
///     the guest expects 26 sibling pairs instead of 4, causing opaque errors.
fn load_test_guest_binary() -> Vec<u8> {
    load_guest_binary_at(TEST_GUEST_BIN_PATH)
}

/// Load the production guest binary (depth=26, no test features).
/// Skips the test if the binary hasn't been built yet.
fn load_prod_guest_binary() -> Vec<u8> {
    load_guest_binary_at(PROD_GUEST_BIN_PATH)
}

/// Load a guest binary from the given path, validating R0BF format.
/// If the primary path doesn't exist, tries alternative search paths.
/// Skips the test (exits with 0) if no binary is found.
fn load_guest_binary_at(path: &str) -> Vec<u8> {
    // Try the primary path first
    if let Ok(data) = std::fs::read(path) {
        assert_valid_guest_binary(&data, path);
        return data;
    }

    // Try alternative paths
    for alt_path in TEST_GUEST_ALT_PATHS {
        if let Ok(data) = std::fs::read(alt_path) {
            eprintln!("NOTE: Guest binary found at alternative path: {}", alt_path);
            assert_valid_guest_binary(&data, alt_path);
            return data;
        }
    }

    eprintln!("SKIPPED: Guest binary not found.");
    eprintln!("  Tried:");
    eprintln!("    {}", path);
    for alt in TEST_GUEST_ALT_PATHS {
        eprintln!("    {}", alt);
    }
    eprintln!("  Build with: cargo risczero build --manifest-path guest/Cargo.toml --features test-small-tree");
    std::process::exit(0);
}

/// Validate that a guest binary is in R0BF format.
fn assert_valid_guest_binary(data: &[u8], path: &str) {
    assert!(
        data.len() >= 4 && &data[0..4] == b"R0BF",
        "Guest binary at {} is not in R0BF format. Build with: cargo risczero build",
        path
    );
}

/// Build the ExecutorEnv for the guest program with the given claim parameters.
fn build_env(
    root: &[u8; 32],
    nullifier: &[u8; 32],
    recipient: &[u8; 20],
    private_key: &[u8; 32],
    siblings: &[[u8; 32]],
    path_indices: &[u8],
) -> ExecutorEnv<'static> {
    let mut builder = ExecutorEnv::builder();
    builder
        .write(root)
        .unwrap()
        .write(nullifier)
        .unwrap()
        .write(recipient)
        .unwrap()
        .write(private_key)
        .unwrap();
    for i in 0..siblings.len() {
        builder.write(&siblings[i]).unwrap();
        builder.write(&path_indices[i]).unwrap();
    }
    builder.build().unwrap()
}

/// Run the guest with dev mode (fast, no real proving). Returns the journal bytes.
fn execute_guest(env: ExecutorEnv<'static>, guest: &[u8]) -> Vec<u8> {
    // RISC0_DEV_MODE=1 must be set in the environment
    let prover = default_prover();
    let prove_info = prover
        .prove(env, guest)
        .expect("Guest execution/proving failed");
    prove_info.receipt.journal.bytes
}

// ── Tier 1: Dev-mode execution tests (fast, CI-friendly) ────────────────

#[test]
fn test_guest_execute_valid_claim() {
    let guest = load_test_guest_binary();

    // Build Merkle tree with PRD test address at full depth (26)
    let addresses = [TEST_ADDRESS];
    let (root, proof) = build_tree_streaming_with_depth(&addresses, TEST_TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    // Compute nullifier
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let nullifier = compute_nullifier(&TEST_PRIVATE_KEY, &mut hasher);
    assert_eq!(
        hex::encode(nullifier),
        EXPECTED_NULLIFIER,
        "Nullifier mismatch"
    );

    // Verify leaf hash matches PRD test vector
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).unwrap();
    let leaf = hash_leaf(&TEST_ADDRESS, &mut leaf_hasher);
    assert_eq!(hex::encode(leaf), EXPECTED_LEAF, "Leaf hash mismatch");

    // Verify Merkle proof locally
    let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
    assert_eq!(
        computed_root, root,
        "Local Merkle proof verification failed"
    );

    // Build env and execute guest (dev mode)
    let recipient: [u8; 20] = [0xB0; 20];
    let env = build_env(
        &root,
        &nullifier,
        &recipient,
        &TEST_PRIVATE_KEY,
        &siblings,
        &path_indices,
    );
    let journal = execute_guest(env, &guest);

    // Verify journal
    assert_eq!(
        journal.len(),
        84,
        "Journal must be 84 bytes, got {}",
        journal.len()
    );

    // Slice journal: [0:32] root, [32:64] nullifier, [64:84] recipient
    assert_eq!(&journal[0..32], root, "Journal root mismatch");
    assert_eq!(&journal[32..64], nullifier, "Journal nullifier mismatch");
    assert_eq!(&journal[64..84], recipient, "Journal recipient mismatch");

    eprintln!("✅ Guest execution successful");
    eprintln!("   Root:        {}", hex::encode(root));
    eprintln!("   Nullifier:   {}", hex::encode(nullifier));
    eprintln!("   Recipient:   {}", hex::encode(recipient));
    eprintln!("   Journal:     84 bytes ✓");
}

#[test]
fn test_guest_rejects_wrong_merkle_root() {
    let guest = load_test_guest_binary();

    let addresses = [TEST_ADDRESS];
    let (_root, proof) = build_tree_streaming_with_depth(&addresses, TEST_TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let nullifier = compute_nullifier(&TEST_PRIVATE_KEY, &mut hasher);
    let recipient: [u8; 20] = [0xB0; 20];

    // Pass a WRONG root
    let wrong_root = [0xAAu8; 32];
    let env = build_env(
        &wrong_root,
        &nullifier,
        &recipient,
        &TEST_PRIVATE_KEY,
        &siblings,
        &path_indices,
    );

    let prover = default_prover();
    let result = prover.prove(env, &guest);
    assert!(result.is_err(), "Guest should reject wrong Merkle root");
}

#[test]
fn test_guest_rejects_wrong_nullifier() {
    let guest = load_test_guest_binary();

    let addresses = [TEST_ADDRESS];
    let (root, proof) = build_tree_streaming_with_depth(&addresses, TEST_TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    let wrong_nullifier = [0xBBu8; 32];
    let recipient: [u8; 20] = [0xB0; 20];

    let env = build_env(
        &root,
        &wrong_nullifier,
        &recipient,
        &TEST_PRIVATE_KEY,
        &siblings,
        &path_indices,
    );

    let prover = default_prover();
    let result = prover.prove(env, &guest);
    assert!(result.is_err(), "Guest should reject wrong nullifier");
}

#[test]
fn test_guest_rejects_zero_recipient() {
    let guest = load_test_guest_binary();

    let addresses = [TEST_ADDRESS];
    let (root, proof) = build_tree_streaming_with_depth(&addresses, TEST_TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let nullifier = compute_nullifier(&TEST_PRIVATE_KEY, &mut hasher);
    let zero_recipient: [u8; 20] = [0u8; 20];

    let env = build_env(
        &root,
        &nullifier,
        &zero_recipient,
        &TEST_PRIVATE_KEY,
        &siblings,
        &path_indices,
    );

    let prover = default_prover();
    let result = prover.prove(env, &guest);
    assert!(result.is_err(), "Guest should reject zero recipient");
}

#[test]
fn test_guest_rejects_ineligible_address() {
    let guest = load_test_guest_binary();

    let tree_addresses: [[u8; 20]; 1] = [TEST_ADDRESS];
    let (root, proof) = build_tree_streaming_with_depth(&tree_addresses, TEST_TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    // Different private key whose address is NOT in the tree
    let wrong_key: [u8; 32] = [0xFFu8; 32];
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let nullifier = compute_nullifier(&wrong_key, &mut hasher);
    let recipient: [u8; 20] = [0xB0; 20];

    let env = build_env(
        &root,
        &nullifier,
        &recipient,
        &wrong_key,
        &siblings,
        &path_indices,
    );

    let prover = default_prover();
    let result = prover.prove(env, &guest);
    assert!(result.is_err(), "Guest should reject ineligible address");
}

// ── Tier 2: Full STARK proof generation (slow, manual only) ──────────────
//
// This test builds a full 26-level Merkle tree (67M leaves, most padding)
// and generates a real STARK + Groth16 proof via the RISC Zero prover.
//
// Expected runtime: 30–90 minutes on a modern machine (single-threaded).
// Requirements: ~4 GB RAM for the prover, ~2 GB for the Merkle tree.
//
// The proof is cryptographically verified locally against the guest image ID.
// This test should be run before mainnet deployment to validate the full
// pipeline end-to-end with real (non-dev-mode) proofs.

#[test]
#[ignore] // Run with: cargo test --package zkmist-cli --test e2e_zkvm -- --ignored
fn test_guest_full_stark_proof() {
    let guest = load_prod_guest_binary();

    let image_id = compute_image_id(&guest).expect("Failed to compute image ID");
    eprintln!("Image ID: {}", hex::encode(image_id.as_bytes()));

    let addresses = [TEST_ADDRESS];
    let (root, proof) = build_tree_streaming_with_depth(&addresses, TREE_DEPTH, Some(0));
    let (siblings, path_indices) = proof.expect("proof extraction failed");

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let nullifier = compute_nullifier(&TEST_PRIVATE_KEY, &mut hasher);
    let recipient: [u8; 20] = [0xB0; 20];

    let env = build_env(
        &root,
        &nullifier,
        &recipient,
        &TEST_PRIVATE_KEY,
        &siblings,
        &path_indices,
    );

    eprintln!("Generating STARK proof (30+ minutes for full 26-level tree)...");
    let prover = default_prover();
    let prove_info = prover.prove(env, &guest).expect("Proving failed");

    let receipt = &prove_info.receipt;
    eprintln!(
        "✅ Proof generated! Segments: {}",
        prove_info.stats.segments
    );
    assert_eq!(receipt.journal.bytes.len(), 84, "Journal must be 84 bytes");

    let journal = &receipt.journal.bytes;
    assert_eq!(&journal[0..32], root, "Journal root mismatch");
    assert_eq!(&journal[32..64], nullifier, "Journal nullifier mismatch");
    assert_eq!(&journal[64..84], recipient, "Journal recipient mismatch");

    // Verify cryptographically
    receipt
        .verify(image_id)
        .expect("Receipt verification failed");
    eprintln!("✅ Cryptographic verification PASSED");
}
