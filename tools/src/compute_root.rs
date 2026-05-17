//! Compute the ZKMist Merkle root from the eligibility list.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin compute-root -- /path/to/all_addresses.txt
//!
//! Requirements: ~2 GB RAM, ~5-15 minutes for 64M addresses.

use std::io::Write;
use std::path::Path;

use ark_bn254::Fr;
use light_poseidon::Poseidon;
use zkmist_merkle_tree::{build_tree_streaming, compute_nullifier, hash_leaf, TREE_DEPTH};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: compute-root <addresses_file>");
        std::process::exit(1);
    }

    let path = &args[1];
    if !Path::new(path).exists() {
        eprintln!("File not found: {}", path);
        std::process::exit(1);
    }

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
    let root_file = "/home/riddler/zkmistdata/merkle_root.txt";
    let mut f = std::fs::File::create(root_file).expect("Failed to create root file");
    writeln!(f, "0x{}", hex::encode(root)).unwrap();
    writeln!(f, "# Addresses: {}", addresses.len()).unwrap();
    writeln!(f, "# Tree depth: {}", tree_depth).unwrap();
    eprintln!("Root saved to: {}", root_file);

    // Verify PRD test vector address is in the list
    let test_addr: [u8; 20] = [
        0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23, 0x7e,
        0x16, 0xaf, 0xce, 0x37, 0x7c,
    ];
    match addresses.binary_search(&test_addr) {
        Ok(idx) => eprintln!("✓ PRD test vector address found at index {}", idx),
        Err(_) => eprintln!("⚠ PRD test vector address NOT in eligibility list"),
    }

    // Verify test vector leaf hash
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let leaf = hash_leaf(&test_addr, &mut leaf_hasher);
    let leaf_hex = hex::encode(leaf);
    eprintln!("  PRD test leaf: 0x{}", leaf_hex);
    if leaf_hex == "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9" {
        eprintln!("  ✓ Leaf hash matches PRD test vector");
    } else {
        eprintln!("  ✗ Leaf hash MISMATCH!");
    }

    // Verify test vector nullifier
    let test_key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");
    let nullifier = compute_nullifier(&test_key, &mut interior_hasher);
    let nullifier_hex = hex::encode(nullifier);
    if nullifier_hex == "078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9" {
        eprintln!("  ✓ Nullifier matches PRD test vector");
    } else {
        eprintln!("  ✗ Nullifier MISMATCH: 0x{}", nullifier_hex);
    }
}
