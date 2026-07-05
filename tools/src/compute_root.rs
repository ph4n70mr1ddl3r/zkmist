//! Compute the ZKMist Merkle root from the eligibility list.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin compute-root -- /path/to/addresses.csv
//!   cargo run --release -p zkmist-tools --bin compute-root -- /path/to/addresses.csv --output /path/to/root.txt
//!
//! Requirements: parallel halo2-base build (rayon) — ~5-10 min and ~4-6 GB
//! RAM for 64M addresses on a modern multicore box.

use std::io::Write;
use std::path::Path;

// IMPORTANT: build with the HALO2-BASE Poseidon sponge convention
// (`zkmist_merkle_tree::halo2base`) — the SAME convention the axiom circuit
// verifies (capacity 2^64, squeeze permutation, digest at state[1]). The
// crate-root `zkmist_merkle_tree::{build_tree_streaming, ...}` helpers use the
// LEGACY light-poseidon / Circom convention (capacity 0, digest state[0]),
// which produces a DIFFERENT root the circuit can never verify. A prior
// revision imported those, so a root (re)derived here would silently mismatch
// the committed `KNOWN_MERKLE_ROOT` and the on-chain verifier.
use zkmist_merkle_tree::halo2base::{build_tree_streaming, compute_nullifier, hash_leaf, Hasher};
use zkmist_merkle_tree::TREE_DEPTH;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: compute-root <addresses_file> [--output <output_file>]");
        std::process::exit(1);
    }

    let path = &args[1];
    if !Path::new(path).exists() {
        eprintln!("File not found: {}", path);
        std::process::exit(1);
    }

    // Parse optional --output flag
    let output_path = if let Some(idx) = args.iter().position(|a| a == "--output") {
        args.get(idx + 1).cloned()
    } else {
        None
    };

    let tree_depth = TREE_DEPTH;
    let num_leaves = 1usize << tree_depth;

    eprintln!("ZKMist Merkle Root Computation");
    eprintln!("══════════════════════════════════");
    eprintln!("Tree depth:     {} levels", tree_depth);
    eprintln!(
        "Max leaves:     {} ({:.1}M)",
        num_leaves,
        num_leaves as f64 / 1e6
    );
    eprintln!();

    // ── Read addresses ────────────────────────────────────────────────
    eprintln!("[1/2] Reading addresses...");
    let file = std::fs::File::open(path).expect("Failed to open file");
    let reader = std::io::BufReader::with_capacity(64 * 1024 * 1024, file);

    let mut addresses: Vec<[u8; 20]> = Vec::with_capacity(65_000_000);
    let mut line_num: u64 = 0;

    for line in std::io::BufRead::lines(reader) {
        let line = line.expect("Failed to read line");
        let line = line.trim();
        if line.is_empty() || line.starts_with("address") || line.starts_with("qualified") {
            continue;
        }
        let hex_str = line.strip_prefix("0x").unwrap_or(line);
        if hex_str.len() != 40 {
            eprintln!(
                "WARNING: Invalid address at line {}: '{}'",
                line_num + 1,
                line
            );
            continue;
        }
        let mut addr = [0u8; 20];
        hex::decode_to_slice(hex_str, &mut addr)
            .unwrap_or_else(|e| panic!("Invalid hex at line {}: {} ({})", line_num + 1, line, e));
        addresses.push(addr);
        line_num += 1;

        if line_num.is_multiple_of(10_000_000) {
            eprintln!("      Read {}M addresses...", line_num / 1_000_000);
        }
    }

    eprintln!(
        "      Loaded {} addresses ({:.1}M)",
        addresses.len(),
        addresses.len() as f64 / 1e6
    );

    if addresses.is_empty() {
        eprintln!("ERROR: No addresses loaded");
        std::process::exit(1);
    }

    // Validate sorting
    let mut sorting_ok = true;
    for i in 1..addresses.len() {
        if addresses[i] <= addresses[i - 1] {
            eprintln!("WARNING: Not sorted at index {}", i);
            sorting_ok = false;
            break;
        }
    }
    if sorting_ok {
        eprintln!("      ✓ Sorted");
    }

    // Validate no duplicates
    let mut dup_count = 0u64;
    for i in 1..addresses.len() {
        if addresses[i] == addresses[i - 1] {
            dup_count += 1;
        }
    }
    if dup_count > 0 {
        eprintln!("      WARNING: {} duplicates!", dup_count);
    } else {
        eprintln!("      ✓ No duplicates");
    }
    eprintln!();

    // ── Build tree ────────────────────────────────────────────────────
    eprintln!("[2/2] Building Merkle tree (streaming, ~2 GB RAM)...");
    let start = std::time::Instant::now();
    let (root, _) = build_tree_streaming(&addresses, None);
    let elapsed = start.elapsed();

    eprintln!();
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!("  MERKLE ROOT: 0x{}", hex::encode(root));
    eprintln!("  Addresses:   {}", addresses.len());
    eprintln!(
        "  Padding:     {} empty leaves",
        num_leaves - addresses.len()
    );
    eprintln!("  Tree depth:  {} levels", tree_depth);
    eprintln!("  Build time:  {:.1}s", elapsed.as_secs_f64());
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!();

    // Save root
    if let Some(ref out) = output_path {
        let mut f = std::fs::File::create(out)
            .unwrap_or_else(|e| panic!("Failed to create {}: {}", out, e));
        writeln!(f, "0x{}", hex::encode(root)).unwrap();
        writeln!(f, "# Addresses: {}", addresses.len()).unwrap();
        writeln!(f, "# Tree depth: {}", tree_depth).unwrap();
        eprintln!("Root saved to: {}", out);
    }

    // Verify PRD test vector address is in the list
    let test_addr: [u8; 20] = [
        0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23, 0x7e,
        0x16, 0xaf, 0xce, 0x37, 0x7c,
    ];
    match addresses.binary_search(&test_addr) {
        Ok(idx) => eprintln!("✓ PRD test vector address found at index {}", idx),
        Err(_) => eprintln!("⚠ PRD test vector address NOT in eligibility list"),
    }

    // Verify test vector leaf hash (halo2-base convention — same as the circuit).
    let hasher = Hasher::new();
    let leaf = hash_leaf(&test_addr, &hasher);
    let leaf_hex = hex::encode(leaf);
    eprintln!("  PRD test leaf: 0x{}", leaf_hex);
    // Expected vector computed under the halo2-base sponge convention
    // (`Hasher::hash_leaf`), which is what the axiom circuit verifies. The
    // legacy light-poseidon value (1b074e63…) is a DIFFERENT convention and
    // would never match the circuit.
    if leaf_hex == "229aea1f7386e8e4fd3a84fe9ee12a1d16c480842d143416a34f28551fabae34" {
        eprintln!("  ✓ Leaf hash matches halo2-base PRD test vector");
    } else {
        eprintln!("  ✗ Leaf hash MISMATCH!");
    }

    // Verify test vector nullifier against the CIRCUIT's reference, LIVE.
    //
    // The off-chain nullifier and the circuit derive the domain field element
    // independently (a 32-byte buffer vs `nullifier_axiom::domain_field_element`).
    // A drift silently breaks `zkmist prove`'s displayed nullifier and any
    // relayer/UI that predicts nullifiers off-chain. The domain encoding was
    // fixed in commit e1a2b80 (LEFT-align → RIGHT-align to match the circuit);
    // a prior revision of THIS self-check hard-coded the PRE-fix nullifier hex
    // (`17492a09…`) and went stale when the encoding changed — silently
    // printing "MISMATCH" for the CORRECT value, and (worse) tempting an
    // operator to "correct" the implementation to match it, re-breaking
    // off-chain↔circuit agreement.
    //
    // Instead of re-pinning another brittle hex constant, derive the expected
    // nullifier LIVE from the circuit's authoritative `native_compute_nullifier`,
    // so this check can NEVER drift from the circuit again. The byte-for-byte
    // cross-check across multiple keys (incl. one ≥ p_BN254) lives in
    // `circuits/tests/claim_axiom.rs::test_offchain_nullifier_matches_circuit`.
    let test_key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let nullifier = compute_nullifier(&test_key, &hasher);
    let expected_nullifier: [u8; 32] = {
        // Build the key as `halo2curves-axiom::bn256::Fr` = (test_key mod p_BN254),
        // then run the circuit's native nullifier (halo2-base Poseidon sponge
        // + `domain_field_element()`). Field arithmetic reduces mod p
        // automatically, matching what the circuit + prover commit to.
        // `halo2curves-axiom` is the axiom fork the circuit (via `halo2-base`)
        // uses — the SAME `Fr` type `native_compute_nullifier` expects. (The
        // workspace's crates.io `halo2curves` 0.6.1 is a distinct type.)
        use ff::PrimeField;
        use halo2curves_axiom::bn256::Fr as CircuitFr;
        let mut key_mod_p = CircuitFr::zero();
        for &b in &test_key {
            key_mod_p = key_mod_p * CircuitFr::from(256u64) + CircuitFr::from(b as u64);
        }
        let nfr = zkmist_circuits::nullifier_axiom::native_compute_nullifier(key_mod_p);
        let mut be = nfr.to_repr();
        be.as_mut().reverse(); // halo2curves repr is little-endian → big-endian
        let mut out = [0u8; 32];
        out.copy_from_slice(be.as_ref());
        out
    };
    if nullifier == expected_nullifier {
        eprintln!("  ✓ Nullifier matches the circuit's native_compute_nullifier (V2 domain)");
    } else {
        eprintln!("  ✗ Nullifier MISMATCH vs circuit:");
        eprintln!("    off-chain (merkle-tree): {}", hex::encode(nullifier));
        eprintln!(
            "    circuit  (native)      : {}",
            hex::encode(expected_nullifier)
        );
    }
}
