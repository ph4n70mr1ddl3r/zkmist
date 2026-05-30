//! ZKMist CLI helper functions.
//!
//! Path resolution, address/key parsing, display formatting, manifest helpers,
//! and eligibility list loading.

use std::io::{self, Write};
use std::path::PathBuf;

use indicatif::{ProgressBar, ProgressStyle};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use crate::constants::*;
use crate::types::Manifest;

// ── Path helpers ─────────────────────────────────────────────────────────

pub fn zkmist_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(ZKMIST_DIR_NAME)
}

pub fn eligibility_dir() -> PathBuf {
    zkmist_dir().join(ELIGIBILITY_DIR_NAME)
}

pub fn manifest_path() -> PathBuf {
    eligibility_dir().join("manifest.json")
}

pub fn proofs_dir() -> PathBuf {
    zkmist_dir().join(PROOFS_DIR_NAME)
}

/// Proof cache path for a specific address. Stores the Merkle proof data
/// (root, siblings, path_indices) so subsequent `prove` calls skip tree building.
/// ~900 bytes per file instead of ~8.6 GB for a full tree cache.
pub fn proof_cache_path(addr: &[u8; 20]) -> PathBuf {
    proofs_dir().join(format!("{}.bin", hex::encode(addr)))
}

/// Path for cached file hashes (legacy name, no longer actively used).
pub fn _guest_hash_path() -> PathBuf {
    zkmist_dir().join("guest.sha256")
}

// ── Address / key helpers ────────────────────────────────────────────────

/// Parse a hex Ethereum address (with or without 0x prefix) into 20 bytes.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.len() != 40 {
        return Err(format!(
            "Invalid address length: {} (expected 40 hex chars)",
            hex_str.len()
        ));
    }
    let mut addr = [0u8; 20];
    hex::decode_to_slice(hex_str, &mut addr)
        .map_err(|e| format!("Invalid hex in address '{}': {}", s, e))?;
    Ok(addr)
}

/// Parse an Ethereum address string and validate its EIP-55 checksum.
///
/// EIP-55 mixed-case encoding provides a lightweight integrity check:
/// the hex characters are mixed upper/lowercase based on the Keccak-256 hash
/// of the lowercase address. A single typo in the address will almost
/// certainly fail this check.
///
/// All-lowercase or all-uppercase addresses are accepted without checksum
/// validation (per EIP-55 spec).
pub fn validate_address_checksum(addr_str: &str) -> Result<[u8; 20], String> {
    let hex_part = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let addr = parse_address(addr_str)?;

    // All lowercase or all uppercase hex is valid without checksum
    if hex_part == hex_part.to_lowercase() || hex_part == hex_part.to_uppercase() {
        return Ok(addr);
    }

    // Mixed case → validate EIP-55 checksum
    let mut hasher = Keccak::v256();
    hasher.update(hex_part.to_lowercase().as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    for (i, c) in hex_part.chars().enumerate() {
        if c.is_ascii_digit() {
            continue;
        }
        let hash_byte = hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if c.is_ascii_uppercase() && hash_nibble < 8 {
            return Err(format!(
                "Invalid EIP-55 checksum for address '{}'. \
                 Check the address carefully — a typo could send tokens to the wrong address.",
                addr_str
            ));
        }
        if c.is_ascii_lowercase() && hash_nibble >= 8 {
            return Err(format!(
                "Invalid EIP-55 checksum for address '{}'. \
                 Check the address carefully — a typo could send tokens to the wrong address.",
                addr_str
            ));
        }
    }

    Ok(addr)
}

/// Read a hex-encoded private key from hidden input.
pub fn read_private_key() -> Result<[u8; 32], String> {
    eprint!("Private key (hidden): ");
    io::stderr().flush().ok();
    let input = rpassword::read_password().map_err(|e| format!("Failed to read input: {}", e))?;
    let hex_str = input.strip_prefix("0x").unwrap_or(&input);
    if hex_str.len() != 64 {
        return Err(format!(
            "Invalid private key length: {} hex chars (expected 64)",
            hex_str.len()
        ));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut key)
        .map_err(|e| format!("Invalid hex in private key: {}", e))?;
    Ok(key)
}

/// Read a hex-encoded private key from a file.
/// The file should contain a 64-character hex string (with or without 0x prefix).
///
/// ⚠️ Checks that the file has restrictive permissions (not world-readable on Unix).
/// Ensure the file has restricted permissions (e.g., chmod 600).
pub fn read_private_key_from_file(path: &str) -> Result<[u8; 32], String> {
    // Check file permissions (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to stat key file '{}': {}", path, e))?;
        let mode = metadata.permissions().mode();
        if mode & 0o007 != 0 {
            return Err(format!(
                "Key file '{}' is world-readable (mode={:o}). \
                 Restrict permissions: chmod 600 {}",
                path,
                mode & 0o777,
                path
            ));
        }
        if mode & 0o070 != 0 {
            eprintln!(
                "      ⚠️  WARNING: Key file '{}' is group-readable (mode={:o}). \
                 Recommend: chmod 600 {}",
                path,
                mode & 0o777,
                path
            );
        }
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file '{}': {}", path, e))?;
    let hex_str = content.trim().strip_prefix("0x").unwrap_or(content.trim());
    if hex_str.len() != 64 {
        return Err(format!(
            "Invalid private key length in file: {} hex chars (expected 64)",
            hex_str.len()
        ));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut key)
        .map_err(|e| format!("Invalid hex in private key file: {}", e))?;
    Ok(key)
}

/// Read a recipient address from input with EIP-55 checksum validation.
pub fn read_recipient_address() -> Result<[u8; 20], String> {
    eprint!("Recipient address: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    let addr = validate_address_checksum(input.trim())?;
    if addr == [0u8; 20] {
        return Err("Recipient cannot be the zero address. Tokens would be burned.".to_string());
    }
    Ok(addr)
}

/// Derive Ethereum address from a secp256k1 private key using Keccak-256.
///
/// Uses `tiny-keccak` (same crate as the guest program) to ensure identical
/// address derivation. ⚠️ This is Keccak-256 (original NIST submission), NOT
/// NIST SHA3-256 — they produce different outputs.
pub fn derive_address(key: &[u8; 32]) -> Result<[u8; 20], String> {
    use k256::ecdsa::{SigningKey, VerifyingKey};

    let sk = SigningKey::from_slice(key).map_err(|e| format!("Invalid private key: {}", e))?;
    let vk: &VerifyingKey = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let pubkey_bytes = point.as_bytes();
    // Uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes
    let mut hasher = Keccak::v256();
    hasher.update(&pubkey_bytes[1..65]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

// ── Display helpers ──────────────────────────────────────────────────────

pub fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

pub fn format_bytes32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Create a Poseidon hasher for the given number of inputs.
pub fn ark_poseidon_hasher(nr_inputs: usize) -> Option<light_poseidon::Poseidon<ark_bn254::Fr>> {
    light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs).ok()
}

pub fn timestamp_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

pub fn format_deadline(timestamp: u64) -> String {
    // Unix epoch to approximate UTC date string (no chrono dependency needed).
    let days = (timestamp / 86400) as i64;
    let (year, month, day) = days_to_ymd(days);
    let secs = (timestamp % 86400) as u32;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, h, m, s
    )
}

/// Convert days since Unix epoch to (year, month, day).
pub fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Shift to era starting March 1, year 0 (simplifies month arithmetic).
    days += 719468; // days from year 0 to 1970-03-01
    let era = (if days >= 0 { days } else { days - 146096 }) / 146097;
    let doe = days - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index from March [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Build a progress bar styled for ZKMist.
pub fn progress_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "{{msg}} {{bar:40.cyan/blue}} {{pos}}/{{len}} ({}) ETA: {{eta}}",
            msg
        ))
        .expect("valid template")
        .progress_chars("█▓░"),
    );
    pb
}

// ── Eligibility list ─────────────────────────────────────────────────────

/// Load addresses from eligibility CSV files.
///
/// Validates that the list is sorted (required for binary search in `cmd_prove`).
/// An unsorted list indicates a corrupted or tampered download.
///
/// Note: For the full 64M addresses, this loads ~1.2 GB into memory.
/// A future optimization could memory-map the files and perform binary
/// search directly on the mapped data, but the current approach is simpler
/// and the memory is needed anyway for streaming tree construction.
pub fn load_eligibility_list() -> Result<Vec<[u8; 20]>, String> {
    let dir = eligibility_dir();
    if !dir.exists() {
        return Err(format!(
            "Eligibility list not found. Run `zkmist fetch` first.\n\
             Expected directory: {}",
            dir.display()
        ));
    }

    let mut addresses = Vec::new();
    let mut csv_files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("Failed to read eligibility dir: {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "csv"))
        .map(|e| e.path())
        .collect();
    csv_files.sort();

    for path in &csv_files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("address") {
                continue; // skip header
            }
            let addr = parse_address(line)?;
            addresses.push(addr);
        }
    }

    if addresses.is_empty() {
        return Err("Eligibility list is empty. No addresses found.".to_string());
    }

    // Validate sorted order (required for binary search in cmd_prove).
    // An unsorted list would produce false negatives during address lookup.
    for i in 1..addresses.len() {
        if addresses[i] < addresses[i - 1] {
            return Err(format!(
                "Eligibility list is not sorted (violation at index {}). \
                 This could indicate a corrupted or tampered download. \
                 Run `zkmist fetch` to re-download.",
                i
            ));
        }
    }

    Ok(addresses)
}

// ── Memory-efficient eligibility check ──────────────────────────────────

/// Check if an address is eligible by searching through CSV files one at a time.
///
/// Unlike `load_eligibility_list` which loads ALL addresses into a single Vec
/// (~1.2 GB), this function processes one file at a time (~20 MB peak memory)
/// and uses binary search within each file. Files whose address range doesn't
/// include the target are loaded but immediately freed.
///
/// Returns `Ok(Some(global_index))` if eligible, `Ok(None)` if not.
/// The global index is the 0-based position across all files (cosmetic, for display).
pub fn check_address_in_files(target: &[u8; 20]) -> Result<Option<usize>, String> {
    let dir = eligibility_dir();
    if !dir.exists() {
        return Err(format!(
            "Eligibility list not found. Run `zkmist fetch` first.\n\
             Expected directory: {}",
            dir.display()
        ));
    }

    let mut csv_files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("Failed to read eligibility dir: {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "csv"))
        .map(|e| e.path())
        .collect();
    csv_files.sort();

    if csv_files.is_empty() {
        return Err("No CSV files found in eligibility directory. Run `zkmist fetch`.".to_string());
    }

    let mut global_offset = 0usize;

    for path in &csv_files {
        let addrs = load_addresses_from_file(path)?;

        if addrs.is_empty() {
            continue;
        }

        // Range check: skip file if target falls outside its address range.
        // Since files are sorted lexicographically and non-overlapping (enforced
        // by the eligibility pipeline), this eliminates most files quickly.
        let first = &addrs[0];
        let last = &addrs[addrs.len() - 1];
        if target < first || target > last {
            global_offset += addrs.len();
            continue;
        }

        // Target is within this file's range — binary search.
        // If not found here, it's not in any file (ranges don't overlap).
        match addrs.binary_search(target) {
            Ok(local_idx) => return Ok(Some(global_offset + local_idx)),
            Err(_) => return Ok(None),
        }
    }

    // Target is before the first file or after the last file.
    Ok(None)
}

/// Load addresses from a single CSV file.
///
/// Returns addresses in file order (assumed sorted by the eligibility pipeline).
/// Skips header lines starting with "address" or "qualified", and empty lines.
fn load_addresses_from_file(path: &std::path::Path) -> Result<Vec<[u8; 20]>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let mut addresses = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("address") || line.starts_with("qualified") {
            continue;
        }
        addresses.push(parse_address(line)?);
    }
    Ok(addresses)
}

// ── Manifest helpers ─────────────────────────────────────────────────────

/// Load and parse the manifest.json from the eligibility directory.
pub fn load_manifest() -> Result<Option<Manifest>, String> {
    let path = manifest_path();
    if !path.exists() {
        return Ok(None);
    }
    let json =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read manifest: {}", e))?;
    let manifest: Manifest =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse manifest: {}", e))?;
    Ok(Some(manifest))
}

/// Extract the expected merkle root bytes from a manifest.
pub fn manifest_root(manifest: &Manifest) -> Result<[u8; 32], String> {
    let hex_str = manifest
        .merkle_root
        .strip_prefix("0x")
        .unwrap_or(&manifest.merkle_root);
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("Invalid merkle root in manifest: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid merkle root length in manifest: {} bytes",
            bytes.len()
        ));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}

/// Verify that a computed root matches the manifest's expected root.
pub fn verify_root_against_manifest(root: &[u8; 32], manifest: &Manifest) -> Result<(), String> {
    let expected = manifest_root(manifest)?;
    if *root != expected {
        return Err(format!(
            "Merkle root mismatch!\n  Computed: {}\n  Manifest: {}\n  \
             The eligibility list may be corrupted or incomplete. Run `zkmist fetch` to re-download.",
            format_bytes32(root),
            format_bytes32(&expected)
        ));
    }
    Ok(())
}
