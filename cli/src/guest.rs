//! Guest program ELF loading, hash verification, and proof seal encoding.

use sha2::{Digest as Sha2Digest, Sha256};

use crate::helpers::*;

/// Get the guest program ELF binary with SHA-256 hash verification.
///
/// Looks for the ELF in the following locations:
/// 1. `~/.zkmist/guest.elf`
/// 2. Next to the CLI binary (for development)
/// 3. In RISC Zero build output directory
///
/// After loading, verifies the ELF's SHA-256 against `~/.zkmist/guest.sha256`
/// if that file exists. This catches corruption or tampering before the
/// expensive (45–90s) zkVM proving step.
pub fn get_guest_elf() -> Result<Vec<u8>, String> {
    let guest_path = zkmist_dir().join("guest.elf");
    let elf_data = if guest_path.exists() {
        std::fs::read(&guest_path)
            .map_err(|e| format!("Failed to read guest ELF {}: {}", guest_path.display(), e))?
    } else if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling_path = dir.join("zkmist-guest");
            if sibling_path.exists() {
                std::fs::read(&sibling_path)
                    .map_err(|e| format!("Failed to read guest ELF: {}", e))?
            } else {
                try_build_paths()?
            }
        } else {
            try_build_paths()?
        }
    } else {
        try_build_paths()?
    };

    // Verify SHA-256 hash against expected hash file (if present)
    let hash_path = guest_hash_path();
    let mut hasher = Sha256::new();
    hasher.update(&elf_data);
    let computed_hash = hex::encode(hasher.finalize());

    if hash_path.exists() {
        let expected = std::fs::read_to_string(&hash_path)
            .map_err(|e| format!("Failed to read {}: {}", hash_path.display(), e))?;
        let expected = expected.trim();
        if computed_hash != expected {
            return Err(format!(
                "Guest ELF hash mismatch!\n  Computed: {}\n  Expected: {}\n  \
                 The ELF may be corrupted or tampered. Rebuild with: \
                 cargo risczero build --manifest-path guest/Cargo.toml",
                computed_hash, expected
            ));
        }
        eprintln!("      ✓ Guest ELF hash verified");
    } else {
        eprintln!(
            "      ⚠️  No hash file at {}. To enable verification, run:",
            hash_path.display()
        );
        eprintln!("          echo {} > {}", computed_hash, hash_path.display());
    }

    Ok(elf_data)
}

/// Try standard RISC Zero build output paths for the guest ELF.
fn try_build_paths() -> Result<Vec<u8>, String> {
    let build_paths = [
        // Release build (standard)
        std::path::PathBuf::from("target/riscv32im-risc0-zkvm-elf/release/zkmist-guest"),
        // Relative to workspace root (when run via cargo run)
        std::path::PathBuf::from("../target/riscv32im-risc0-zkvm-elf/release/zkmist-guest"),
    ];
    for path in &build_paths {
        if path.exists() {
            return std::fs::read(path)
                .map_err(|e| format!("Failed to read guest ELF {}: {}", path.display(), e));
        }
    }

    Err(
        "Guest program ELF not found. Place the compiled guest binary at:\n\
         ~/.zkmist/guest.elf\n\
         \n\
         Build it with: cargo risczero build --manifest-path guest/Cargo.toml"
            .to_string(),
    )
}

/// Encode the receipt seal as a hex string suitable for on-chain submission.
///
/// The Solidity contract expects the Groth16 seal bytes.
/// Returns an error for non-Groth16 receipt types that require compression.
pub fn encode_receipt_seal(receipt: &risc0_zkvm::Receipt) -> Result<String, String> {
    use risc0_zkvm::InnerReceipt;
    match &receipt.inner {
        InnerReceipt::Groth16(groth16_receipt) => {
            // The seal is the Groth16 proof, which is what the on-chain verifier expects
            Ok(hex::encode(&groth16_receipt.seal))
        }
        InnerReceipt::Fake(_) => {
            eprintln!(
                "      ⚠️  Warning: proof was generated in dev/fake mode. \
                 This proof will NOT be accepted by the on-chain verifier."
            );
            Ok("FAKE_SEAL_DEV_MODE".to_string())
        }
        InnerReceipt::Succinct(_) | InnerReceipt::Composite(_) => {
            Err("Received Succinct/Composite receipt instead of Groth16. \
                 The on-chain verifier requires a Groth16 proof. \
                 Ensure the prover is configured for Groth16 compression. \
                 With risc0-zkvm v3.x, the default prover should produce Groth16 receipts."
                .to_string())
        }
        _ => Err("Unknown receipt type. Cannot encode seal for on-chain submission.".to_string()),
    }
}
