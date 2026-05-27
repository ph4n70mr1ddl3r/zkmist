//! Compute the RISC Zero image ID from the guest binary.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin compute-image-id
//!   cargo run --release -p zkmist-tools --bin compute-image-id -- /path/to/guest.bin

use std::path::Path;

/// Primary default path (Docker reproducible build output with .bin extension).
const DEFAULT_PATH: &str = "target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest.bin";

/// Fallback search paths, tried in order when the primary path doesn't exist.
/// Covers the standard `cargo risczero build` output locations and naming
/// conventions (with and without .bin extension, Docker vs local release).
const FALLBACK_PATHS: &[&str] = &[
    // Docker reproducible build output (no .bin extension)
    "target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest",
    // Standard local release build output
    "target/riscv32im-risc0-zkvm-elf/release/zkmist-guest",
    // Standard local debug build output
    "target/riscv32im-risc0-zkvm-elf/debug/zkmist-guest",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 {
        // User-provided path — use exactly as given
        args[1].clone()
    } else {
        // Try primary path, then fallbacks
        match resolve_guest_path() {
            Some(p) => p,
            None => {
                eprintln!("Guest binary not found. Tried:");
                eprintln!("  {}", DEFAULT_PATH);
                for p in FALLBACK_PATHS {
                    eprintln!("  {}", p);
                }
                eprintln!();
                eprintln!("Build the guest with: cargo risczero build --manifest-path guest/Cargo.toml");
                std::process::exit(1);
            }
        }
    };

    if !Path::new(&path).exists() {
        eprintln!("File not found: {}", path);
        std::process::exit(1);
    }

    let elf_data = std::fs::read(&path).expect("Failed to read guest binary");

    // Verify R0BF format
    if elf_data.len() >= 4 && &elf_data[0..4] == b"R0BF" {
        eprintln!("Format: R0BF ✓");
    } else if elf_data.len() >= 4 && &elf_data[0..4] == b"\x7fELF" {
        eprintln!("Format: ELF (note: compute_image_id works with ELF too)");
    } else {
        eprintln!("WARNING: Unknown format");
    }

    eprintln!(
        "Size: {} bytes ({:.1} MB)",
        elf_data.len(),
        elf_data.len() as f64 / 1e6
    );

    let image_id = risc0_zkvm::compute_image_id(&elf_data).expect("Failed to compute image ID");
    let bytes = image_id.as_bytes();
    let hex_id = hex::encode(bytes);

    eprintln!();
    println!("{}", hex_id);
    eprintln!();
    eprintln!("Image ID: 0x{}", hex_id);
    eprintln!();
    eprintln!("Use this as IMAGE_ID for contract deployment:");
    eprintln!("  export IMAGE_ID=0x{}", hex_id);
}

/// Resolve the guest binary path by trying the primary default, then fallbacks.
fn resolve_guest_path() -> Option<String> {
    if Path::new(DEFAULT_PATH).exists() {
        return Some(DEFAULT_PATH.to_string());
    }
    for fallback in FALLBACK_PATHS {
        if Path::new(fallback).exists() {
            eprintln!("NOTE: Using guest binary at fallback path: {}", fallback);
            return Some(fallback.to_string());
        }
    }
    None
}
