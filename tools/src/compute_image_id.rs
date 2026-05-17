//! Compute the RISC Zero image ID from the guest binary.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin compute-image-id
//!   cargo run --release -p zkmist-tools --bin compute-image-id -- /path/to/guest.bin

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let default_path = "target/riscv32im-risc0-zkvm-elf/docker/zkmist-guest.bin";
    let path = if args.len() > 1 {
        &args[1]
    } else {
        default_path
    };

    if !Path::new(path).exists() {
        eprintln!("File not found: {}", path);
        eprintln!("Build the guest with: cargo risczero build --manifest-path guest/Cargo.toml");
        std::process::exit(1);
    }

    let elf_data = std::fs::read(path).expect("Failed to read guest binary");

    // Verify R0BF format
    if elf_data.len() >= 4 && &elf_data[0..4] == b"R0BF" {
        eprintln!("Format: R0BF ✓");
    } else if elf_data.len() >= 4 && &elf_data[0..4] == b"\x7fELF" {
        eprintln!("Format: ELF (note: compute_image_id works with ELF too)");
    } else {
        eprintln!("WARNING: Unknown format");
    }

    eprintln!("Size: {} bytes ({:.1} MB)", elf_data.len(), elf_data.len() as f64 / 1e6);

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
