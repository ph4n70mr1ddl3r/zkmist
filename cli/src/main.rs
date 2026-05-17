//! ZKMist CLI — claim tool for the ZKMist airdrop
//!
//! Commands:
//!   zkmist fetch    — Download eligibility list from IPFS
//!   zkmist prove    — Generate ZK proof locally
//!   zkmist submit   — Submit proof to ZKMAirdrop contract
//!   zkmist verify   — Verify proof locally
//!   zkmist check    — Check if address is eligible
//!   zkmist status   — Show claim window status

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};
use zkmist_merkle_tree::{
    build_tree_streaming, compute_nullifier, deserialize_proof, hash_leaf, serialize_proof,
    verify_merkle_proof, PADDING_SENTINEL,
};

// ABI bindings for the ZKMAirdrop and ZKMToken contracts.
// alloy's sol! macro computes selectors, handles offset/padding for dynamic
// types, and generates type-safe call/response structs — eliminating a class
// of encoding bugs and fragile raw storage-slot reads.
alloy::sol! {
    function claim(bytes calldata _proof, bytes calldata _journal, bytes32 _nullifier, address _recipient);

    interface IZKMAirdrop {
        function token() external view returns (address);
        function totalClaims() external view returns (uint256);
        function claimsRemaining() external view returns (uint256);
        function isClaimWindowOpen() external view returns (bool);
        function isClaimed(bytes32 nullifier) external view returns (bool);
        function CLAIM_AMOUNT() external view returns (uint256);
        function MAX_CLAIMS() external view returns (uint256);
        function CLAIM_DEADLINE() external view returns (uint256);
        function merkleRoot() external view returns (bytes32);
        function imageId() external view returns (bytes32);
    }

    interface IZKMToken {
        function totalSupply() external view returns (uint256);
        function MAX_SUPPLY() external view returns (uint256);
    }
}

use alloy::sol_types::SolCall;

#[derive(Parser)]
#[command(name = "zkmist", version, about = "ZKMist (ZKM) claim tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download eligibility list (~2.8 GB). Verifies integrity via SHA-256 + Merkle root.
    Fetch {
        /// Download source: "github" (GitHub Releases), "ipfs", or "auto" (GitHub first, IPFS fallback).
        #[arg(long, default_value = "auto")]
        source: String,
        /// IPFS CID override (only used with --source ipfs)
        #[arg(long)]
        cid: Option<String>,
        /// Skip Merkle root verification (faster; still checks per-file SHA-256 integrity)
        #[arg(long)]
        no_verify: bool,
    },

    /// Generate ZK proof (interactive). Uses cached proof data when available.
    Prove {
        /// Read private key from file instead of interactive prompt.
        /// ⚠️ The key file contains your claimant private key — use with caution.
        /// Ensure the file has restricted permissions (e.g., chmod 600).
        #[arg(long)]
        key_file: Option<String>,
    },

    /// Submit proof to ZKMAirdrop contract on Base.
    Submit {
        /// Path to proof.json
        proof_file: String,
        /// RPC URL (defaults to Base public RPC)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Private key for transaction (hidden prompt if not provided)
        #[arg(long)]
        private_key: Option<String>,
        /// Read submitter's private key from file instead of prompt.
        #[arg(long, conflicts_with = "private_key")]
        key_file: Option<String>,
    },

    /// Verify proof locally: validates the STARK proof and checks journal contents.
    Verify {
        /// Path to proof.json
        proof_file: String,
    },

    /// Check if an address is eligible (requires downloaded eligibility list).
    Check {
        /// Ethereum address to check
        address: String,
    },

    /// Show claim window status, claims remaining, total supply.
    Status {
        /// RPC URL (defaults to Base public RPC)
        #[arg(long)]
        rpc_url: Option<String>,
    },
}

// ── Constants ────────────────────────────────────────────────────────────

const ZKMIST_DIR_NAME: &str = ".zkmist";
const ELIGIBILITY_DIR_NAME: &str = "eligibility";
const PROOFS_DIR_NAME: &str = "proofs";
const GUEST_HASH_FILE: &str = "guest.sha256";

/// PRD §11: Contract parameters
const CLAIM_AMOUNT: u64 = 10_000;
const MAX_CLAIMS: u64 = 1_000_000;
const CLAIM_DEADLINE: u64 = 1_798_761_600; // 2027-01-01 00:00:00 UTC
const CHAIN_ID: u64 = 8453; // Base

/// Default Base RPC URL
const DEFAULT_RPC_URL: &str = "https://mainnet.base.org";

/// GitHub Release tag hosting the official eligibility list.
/// Immutable once published — a GitHub release tag cannot be moved to a
/// different commit without force-pushing (which is auditable).
/// Assets (CSV files, manifest) are content-addressed by SHA-256 in manifest.json.
const ELIGIBILITY_RELEASE_TAG: &str = "v1.0.0-eligibility";

/// GitHub repository hosting the eligibility list release.
const GITHUB_REPO: &str = "ph4n70mr1ddl3r/zkmist";

/// IPFS gateway for fallback downloads.
/// Pinata's gateway is fast for our pinned content.
/// ipfs.io is an alternative but often times out on large files (43 MB CSVs).
const IPFS_GATEWAY: &str = "https://gateway.pinata.cloud/ipfs";

/// Published IPFS CID for the eligibility list.
/// Pinata-pinned directory (2.76 GB, 66 files).
/// This is the fallback source if GitHub Releases is unavailable.
const FALLBACK_IPFS_CID: &str = "QmTTit9vDbzRjCffeKsd3LV3YFvdX4Kobm3uZwNd5zDUZb";

/// Known Merkle root for the v1.0.0 eligibility list.
/// Sourced from the GitHub Release manifest, the IPFS manifest, and the
/// `compute-root` tool output. This compile-time constant provides an
/// out-of-band integrity check: even if the download source is compromised,
/// the manifest root must match this value or the CLI refuses to proceed.
///
/// 64,116,228 qualified addresses (≥0.004 ETH gas fees, mainnet, before 2026-01-01).
const KNOWN_MERKLE_ROOT: &str = "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844";

/// ZKMAirdrop contract address on Base.
/// Set after deployment.
const AIRDROP_CONTRACT: &str = "0x000000000000000000000000000000000000dEaD"; // placeholder

// ── Data structures ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFile {
    version: u64,
    proof: String,     // hex-encoded STARK seal (Groth16-wrapped)
    journal: String,   // hex-encoded journal bytes (84 bytes)
    nullifier: String, // hex-encoded 32 bytes
    recipient: String, // hex-encoded 20 bytes
    claim_amount: String,
    contract_address: String,
    chain_id: u64,
    /// Hex-encoded bincode-serialized risc0_zkvm::Receipt.
    /// Present for proofs generated by this CLI; allows local cryptographic verification.
    /// May be absent in proof files from external tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u64,
    cutoff_timestamp: String,
    fee_threshold_eth: String,
    total_qualified: u64,
    merkle_root: String,
    merkle_tree_depth: usize,
    #[serde(default)]
    files: Vec<ManifestFile>,
}

#[derive(Serialize, Deserialize)]
struct ManifestFile {
    file: String,
    sha256: String,
}

// ── Path helpers ─────────────────────────────────────────────────────────

fn zkmist_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(ZKMIST_DIR_NAME)
}

fn eligibility_dir() -> PathBuf {
    zkmist_dir().join(ELIGIBILITY_DIR_NAME)
}

fn manifest_path() -> PathBuf {
    eligibility_dir().join("manifest.json")
}

fn proofs_dir() -> PathBuf {
    zkmist_dir().join(PROOFS_DIR_NAME)
}

/// Proof cache path for a specific address. Stores the Merkle proof data
/// (root, siblings, path_indices) so subsequent `prove` calls skip tree building.
/// ~900 bytes per file instead of ~8.6 GB for a full tree cache.
fn proof_cache_path(addr: &[u8; 20]) -> PathBuf {
    proofs_dir().join(format!("{}.bin", hex::encode(addr)))
}

fn guest_hash_path() -> PathBuf {
    zkmist_dir().join(GUEST_HASH_FILE)
}

// ── Eligibility list ─────────────────────────────────────────────────────

/// Load addresses from eligibility CSV files.
fn load_eligibility_list() -> Result<Vec<[u8; 20]>, String> {
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

    Ok(addresses)
}

// ── Address / key helpers ────────────────────────────────────────────────

/// Parse a hex Ethereum address (with or without 0x prefix) into 20 bytes.
fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 40 {
        return Err(format!(
            "Invalid address length: {} (expected 40 hex chars)",
            hex.len()
        ));
    }
    let mut addr = [0u8; 20];
    hex::decode_to_slice(hex, &mut addr)
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
fn validate_address_checksum(addr_str: &str) -> Result<[u8; 20], String> {
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
fn read_private_key() -> Result<[u8; 32], String> {
    eprint!("Private key (hidden): ");
    io::stderr().flush().ok();
    let input = rpassword::read_password().map_err(|e| format!("Failed to read input: {}", e))?;
    let hex = input.strip_prefix("0x").unwrap_or(&input);
    if hex.len() != 64 {
        return Err(format!(
            "Invalid private key length: {} hex chars (expected 64)",
            hex.len()
        ));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key)
        .map_err(|e| format!("Invalid hex in private key: {}", e))?;
    Ok(key)
}

/// Read a hex-encoded private key from a file.
/// The file should contain a 64-character hex string (with or without 0x prefix).
/// ⚠️ Ensure the file has restricted permissions to protect the private key.
fn read_private_key_from_file(path: &str) -> Result<[u8; 32], String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file '{}': {}", path, e))?;
    let hex = content.trim().strip_prefix("0x").unwrap_or(content.trim());
    if hex.len() != 64 {
        return Err(format!(
            "Invalid private key length in file: {} hex chars (expected 64)",
            hex.len()
        ));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key)
        .map_err(|e| format!("Invalid hex in private key file: {}", e))?;
    Ok(key)
}

/// Read a recipient address from input with EIP-55 checksum validation.
fn read_recipient_address() -> Result<[u8; 20], String> {
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
fn derive_address(key: &[u8; 32]) -> Result<[u8; 20], String> {
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

fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

fn format_bytes32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Create a Poseidon hasher for the given number of inputs.
fn ark_poseidon_hasher(nr_inputs: usize) -> Option<light_poseidon::Poseidon<ark_bn254::Fr>> {
    light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs).ok()
}

fn timestamp_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn format_deadline(timestamp: u64) -> String {
    // Unix epoch to approximate UTC date string (no chrono dependency needed).
    // Days since epoch → year/month/day via algorithm adapted from chrono.
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
fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
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
fn progress_bar(total: u64, msg: &str) -> ProgressBar {
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

// ── Manifest helpers ─────────────────────────────────────────────────────

/// Load and parse the manifest.json from the eligibility directory.
fn load_manifest() -> Result<Option<Manifest>, String> {
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
fn manifest_root(manifest: &Manifest) -> Result<[u8; 32], String> {
    let hex = manifest
        .merkle_root
        .strip_prefix("0x")
        .unwrap_or(&manifest.merkle_root);
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid merkle root in manifest: {}", e))?;
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
fn verify_root_against_manifest(root: &[u8; 32], manifest: &Manifest) -> Result<(), String> {
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


// ── Command: fetch ───────────────────────────────────────────────────────

/// Download source for the eligibility list.
#[derive(Clone, Copy, PartialEq)]
enum DownloadSource {
    /// Try GitHub Releases first, fall back to IPFS on failure.
    Auto,
    /// GitHub Releases only.
    Github,
    /// IPFS only.
    Ipfs,
}

fn parse_source(s: &str) -> Result<DownloadSource, String> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(DownloadSource::Auto),
        "github" | "gh" => Ok(DownloadSource::Github),
        "ipfs" => Ok(DownloadSource::Ipfs),
        other => Err(format!(
            "Unknown source '{}'. Use: github, ipfs, or auto",
            other
        )),
    }
}

fn cmd_fetch(cid: Option<&str>, source: &str, no_verify: bool) -> Result<(), String> {
    let download_source = parse_source(source)?;
    let dir = eligibility_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;

    // Resolve which CID to use for IPFS downloads.
    let ipfs_cid = cid.unwrap_or(FALLBACK_IPFS_CID);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;

    // ── Step 1: Fetch manifest and verify against known Merkle root ──────
    //
    // We try GitHub Releases first (immutable tag, cryptographically signed
    // by GitHub's TLS certificate, content-addressed assets), then fall back
    // to IPFS if GitHub is unreachable. In both cases, the manifest's Merkle
    // root is checked against the compile-time KNOWN_MERKLE_ROOT constant
    // before any per-file downloads proceed.

    let manifest = fetch_manifest(&rt, download_source, ipfs_cid)?;

    // Verify manifest merkle root against our compile-time constant.
    // This catches a compromised download source: even if an attacker
    // replaces the manifest in transit (TLS should prevent this), the root
    // won't match the baked-in value.
    let known_root = KNOWN_MERKLE_ROOT
        .strip_prefix("0x")
        .unwrap_or(KNOWN_MERKLE_ROOT);
    if manifest.merkle_root.strip_prefix("0x").unwrap_or(&manifest.merkle_root) != known_root {
        return Err(format!(
            "⚠️  Merkle root mismatch — download source may be compromised!\n\
               Manifest root:  {}\n\
               Expected root:  0x{}\n\
               \n\
               Do NOT proceed. Verify your network and try again.\n\
               If this persists, check the project GitHub for announcements.",
            manifest.merkle_root, known_root
        ));
    }
    eprintln!("      ✓ Merkle root matches known value");

    eprintln!("      Version: {}", manifest.version);
    eprintln!("      Qualified addresses: {}", manifest.total_qualified);
    eprintln!("      Merkle root: {}", manifest.merkle_root);
    eprintln!("      Files: {}", manifest.files.len());

    // Save manifest
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    std::fs::write(manifest_path(), &manifest_json)
        .map_err(|e| format!("Failed to write manifest: {}", e))?;

    // ── Step 2: Download each file with integrity verification ───────────
    eprintln!("[2/3] Downloading eligibility files...");
    let pb = progress_bar(manifest.files.len() as u64, "files");

    for file_entry in &manifest.files {
        let filename = &file_entry.file;
        let expected_hash = file_entry
            .sha256
            .strip_prefix("0x")
            .unwrap_or(&file_entry.sha256);
        let dest = dir.join(filename);

        if dest.exists() {
            // Verify existing file hash — skip re-download if intact
            let data = std::fs::read(&dest)
                .map_err(|e| format!("Failed to read {}: {}", dest.display(), e))?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hex::encode(hasher.finalize());
            if hash == expected_hash {
                pb.inc(1);
                continue;
            }
        }

        // Try download sources in priority order
        let downloaded = try_download_file(
            &rt,
            filename,
            &dest,
            expected_hash,
            download_source,
            ipfs_cid,
        )?;
        if !downloaded {
            return Err(format!(
                "Failed to download {} from any source",
                filename
            ));
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // ── Step 3: Verify Merkle root via streaming tree (optional) ─────────
    if no_verify {
        eprintln!("[3/3] Root verification skipped (--no-verify).");
        eprintln!("      File-level SHA-256 integrity verified ✓");
    } else {
        eprintln!("[3/3] Verifying Merkle root (streaming build)...");
        eprintln!("      ⚠️  This requires ~2 GB RAM and may take 1–2 minutes.");

        let addresses = load_eligibility_list()?;
        eprintln!("      Loaded {} addresses", addresses.len());

        let (root, _) = build_tree_streaming(&addresses, None);
        eprintln!("      Root: {}", format_bytes32(&root));

        verify_root_against_manifest(&root, &manifest)?;
        eprintln!("      ✓ Root matches manifest");
    }

    eprintln!();
    eprintln!("✅ Fetch complete. Run `zkmist prove` to generate a claim proof.");
    Ok(())
}

/// Fetch and validate the manifest from the appropriate source(s).
fn fetch_manifest(
    rt: &tokio::runtime::Runtime,
    source: DownloadSource,
    ipfs_cid: &str,
) -> Result<Manifest, String> {
    let sources = match source {
        DownloadSource::Auto => &["github", "ipfs"] as &[&str],
        DownloadSource::Github => &["github"] as &[&str],
        DownloadSource::Ipfs => &["ipfs"] as &[&str],
    };

    eprintln!("[1/3] Fetching manifest...");

    let mut last_error = String::new();
    for &src in sources {
        let url = match src {
            "github" => {
                eprintln!(
                    "      Source: GitHub Releases ({}/{})",
                    GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
                );
                format!(
                    "https://github.com/{}/{}/releases/download/{}/manifest.json",
                    GITHUB_REPO, GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
                )
            }
            "ipfs" => {
                eprintln!("      Source: IPFS (CID: {})", ipfs_cid);
                format!("{}/{}/manifest.json", IPFS_GATEWAY, ipfs_cid)
            }
            _ => unreachable!(),
        };

        match rt.block_on(fetch_json::<Manifest>(&url)) {
            Ok(manifest) => {
                eprintln!("      ✓ Manifest fetched from {}", src);
                return Ok(manifest);
            }
            Err(e) => {
                last_error = e.clone();
                eprintln!("      ✗ {} failed: {}", src, e);
                if sources.len() > 1 {
                    eprintln!("      Trying next source...");
                }
            }
        }
    }

    Err(format!(
        "All download sources failed. Last error: {}\n\
         \n\
         Manual alternatives:\n\
         1. Download from: https://github.com/{}/{}/releases/tag/{}\n\
         2. IPFS direct: {}/{}/manifest.json\n\
         3. Place CSV files manually in: {}",
        last_error,
        GITHUB_REPO,
        GITHUB_REPO,
        ELIGIBILITY_RELEASE_TAG,
        IPFS_GATEWAY,
        ipfs_cid,
        eligibility_dir().display(),
    ))
}

/// Fetch and deserialize JSON from a URL.
async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {}", resp.status(), url));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Try downloading a single file from the available sources.
/// Returns Ok(true) if downloaded successfully, Ok(false) if all sources failed.
fn try_download_file(
    rt: &tokio::runtime::Runtime,
    filename: &str,
    dest: &std::path::Path,
    expected_hash: &str,
    source: DownloadSource,
    ipfs_cid: &str,
) -> Result<bool, String> {
    let sources = match source {
        DownloadSource::Auto => &["github", "ipfs"] as &[&str],
        DownloadSource::Github => &["github"] as &[&str],
        DownloadSource::Ipfs => &["ipfs"] as &[&str],
    };

    for &src in sources {
        let url = match src {
            "github" => format!(
                "https://github.com/{}/{}/releases/download/{}/{}",
                GITHUB_REPO, GITHUB_REPO, ELIGIBILITY_RELEASE_TAG, filename
            ),
            "ipfs" => format!("{}/{}/{}", IPFS_GATEWAY, ipfs_cid, filename),
            _ => unreachable!(),
        };

        match rt.block_on(download_and_verify(&url, expected_hash)) {
            Ok(data) => {
                std::fs::write(dest, &data)
                    .map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;
                return Ok(true);
            }
            Err(e) => {
                // Log failure but try next source
                eprintln!("      ⚠ {} download of {} failed: {}", src, filename, e);
                continue;
            }
        }
    }
    Ok(false)
}

/// Download a file from a URL and verify its SHA-256 hash.
async fn download_and_verify(url: &str, expected_hash: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120)) // large files need generous timeout
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let data = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());
    if hash != expected_hash {
        return Err(format!(
            "SHA-256 mismatch: expected {}, got {}",
            expected_hash, hash
        ));
    }

    Ok(data.to_vec())
}

// ── Command: prove ───────────────────────────────────────────────────────

fn cmd_prove(key_file: Option<&str>) -> Result<(), String> {
    // ── Step 1: Credentials ──────────────────────────────────────────────
    eprintln!("[1/4] Enter credentials:");
    let private_key = if let Some(path) = key_file {
        eprintln!("      Reading private key from: {}", path);
        read_private_key_from_file(path)?
    } else {
        read_private_key()?
    };
    let address = derive_address(&private_key)?;
    eprintln!("      → Address: {}", format_address(&address));

    // ── Step 2: Merkle proof (cached or streaming) ───────────────────────
    //
    // Strategy: check for a per-address proof cache file (~900 bytes) first.
    // If cached, load proof data (root, siblings, path_indices) without
    // loading the full eligibility list or building the tree.
    // If not cached, load the list and use streaming tree construction
    // (keeps only 2 layers in memory at a time, ~2 GB vs ~8 GB for full tree),
    // then save the proof cache for future use.
    eprintln!("[2/4] Preparing Merkle proof...");

    let cache_path = proof_cache_path(&address);
    let (root, siblings, path_indices) = if cache_path.exists() {
        // Load cached proof data
        eprintln!("      Loading cached proof...");
        let file = std::fs::File::open(&cache_path)
            .map_err(|e| format!("Failed to open proof cache: {}", e))?;
        let reader = std::io::BufReader::new(file);
        let (cached_root, _leaf_index, cached_siblings, cached_path) =
            deserialize_proof(reader).map_err(|e| format!("Failed to read proof cache: {}", e))?;

        eprintln!(
            "      ✓ Proof cache loaded ({} levels)",
            cached_siblings.len()
        );
        eprintln!("      Root: {}", format_bytes32(&cached_root));

        // Verify cached root against manifest
        if let Some(manifest) = load_manifest()? {
            verify_root_against_manifest(&cached_root, &manifest)?;
            eprintln!("      ✓ Root matches manifest");
        }

        (cached_root, cached_siblings, cached_path)
    } else {
        // No cache — build proof via streaming tree construction
        eprintln!("      No cached proof — building via streaming tree...");
        eprintln!("      ⚠️  This requires ~2 GB RAM. The result will be cached for future use.");

        let addresses = load_eligibility_list()?;
        eprintln!("      Loaded {} eligible addresses", addresses.len());

        // Find address index via binary search (list must be sorted)
        let leaf_index = match addresses.binary_search(&address) {
            Ok(idx) => idx,
            Err(_) => {
                return Err(format!(
                    "Address {} is NOT in the eligibility tree. \
                     If you believe this is an error, verify the eligibility list.",
                    format_address(&address)
                ));
            }
        };

        // Streaming build with target index: computes root + extracts Merkle proof
        // without storing all tree layers. Peak memory: O(2^depth × 32 bytes).
        let (streaming_root, proof) = build_tree_streaming(&addresses, Some(leaf_index));
        let (streaming_siblings, streaming_path) =
            proof.ok_or("Streaming build failed to produce proof for target index")?;

        eprintln!(
            "      ✓ Tree built (streaming, {} levels)",
            streaming_siblings.len()
        );
        eprintln!("      Root: {}", format_bytes32(&streaming_root));
        eprintln!("      Found at index: {}", leaf_index);

        // Verify root against manifest
        if let Some(manifest) = load_manifest()? {
            verify_root_against_manifest(&streaming_root, &manifest)?;
            eprintln!("      ✓ Root matches manifest");
        }

        // Verify Merkle proof locally before caching
        let mut leaf_hasher = ark_poseidon_hasher(1).ok_or("Failed to create leaf hasher")?;
        let leaf = hash_leaf(&address, &mut leaf_hasher);
        let computed_root = verify_merkle_proof(&leaf, &streaming_siblings, &streaming_path);
        if computed_root != streaming_root {
            return Err(format!(
                "INTERNAL ERROR: Merkle proof verification failed. \
                 Computed root {} != tree root {}",
                format_bytes32(&computed_root),
                format_bytes32(&streaming_root)
            ));
        }
        eprintln!("      ✓ Merkle proof verified locally");

        // Save proof cache (~900 bytes instead of ~8.6 GB full tree)
        std::fs::create_dir_all(proofs_dir())
            .map_err(|e| format!("Failed to create proofs dir: {}", e))?;
        let file = std::fs::File::create(&cache_path)
            .map_err(|e| format!("Failed to create proof cache: {}", e))?;
        let writer = std::io::BufWriter::new(file);
        serialize_proof(
            &streaming_root,
            leaf_index,
            &streaming_siblings,
            &streaming_path,
            writer,
        )
        .map_err(|e| format!("Failed to write proof cache: {}", e))?;
        eprintln!(
            "      Proof cached: {} (~{} bytes)",
            cache_path.display(),
            cache_path.metadata().map(|m| m.len()).unwrap_or(0)
        );

        (streaming_root, streaming_siblings, streaming_path)
    };

    // Verify the leaf is not a padding sentinel
    let mut leaf_hasher = ark_poseidon_hasher(1).ok_or("Failed to create leaf hasher")?;
    let leaf = hash_leaf(&address, &mut leaf_hasher);
    if leaf == PADDING_SENTINEL {
        return Err("Address produced a padding leaf — this should not happen".to_string());
    }

    // Compute nullifier
    let mut interior_hasher = ark_poseidon_hasher(2).ok_or("Failed to create interior hasher")?;
    let nullifier = compute_nullifier(&private_key, &mut interior_hasher);
    eprintln!("      → Nullifier: {}", format_bytes32(&nullifier));

    // ── Step 3: Recipient ────────────────────────────────────────────────
    eprintln!("[3/4] Enter recipient:");
    let recipient = read_recipient_address()?;
    eprintln!("      → Recipient: {}", format_address(&recipient));

    // ── Step 4: ZK proving ───────────────────────────────────────────────
    eprintln!("[4/4] Generating proof...");

    // Final local verification before expensive zkVM proving
    let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
    if computed_root != root {
        return Err(format!(
            "INTERNAL ERROR: Merkle proof verification failed. \
             Computed root {} != tree root {}",
            format_bytes32(&computed_root),
            format_bytes32(&root)
        ));
    }
    eprintln!("      ✓ Merkle proof verified locally");

    // ── RISC Zero zkVM proving ──────────────────────────────────────────
    eprintln!("      Running RISC Zero zkVM...");

    // Build the executor environment with guest inputs.
    //
    // IMPORTANT: sibling/path_index pairs must be written interleaved
    // (sibling[0], path_index[0], sibling[1], path_index[1], ...) to match
    // the guest program's alternating read loop:
    //   for i in 0..TREE_DEPTH {
    //       siblings[i] = env::read();
    //       path_indices[i] = env::read();
    //   }
    // DO NOT use write_slice for siblings and path_indices separately —
    // that would write [s0,s1,...,s25,p0,p1,...,p25] but the guest reads
    // [s0,p0,s1,p1,...,s25,p25].
    let mut builder = risc0_zkvm::ExecutorEnv::builder();
    builder
        // Public inputs (committed to journal)
        .write(&root)
        .map_err(|e| format!("Failed to write merkle_root to env: {}", e))?
        .write(&nullifier)
        .map_err(|e| format!("Failed to write nullifier to env: {}", e))?
        .write(&recipient)
        .map_err(|e| format!("Failed to write recipient to env: {}", e))?
        // Private inputs
        .write(&private_key)
        .map_err(|e| format!("Failed to write private_key to env: {}", e))?;
    for i in 0..siblings.len() {
        builder
            .write(&siblings[i])
            .map_err(|e| format!("Failed to write sibling[{}]: {}", i, e))?
            .write(&path_indices[i])
            .map_err(|e| format!("Failed to write path_index[{}]: {}", i, e))?;
    }
    let env = builder
        .build()
        .map_err(|e| format!("Failed to build ExecutorEnv: {}", e))?;

    // Get the guest ELF binary and validate image ID.
    let guest_elf = get_guest_elf()?;
    let computed_image_id = risc0_zkvm::compute_image_id(&guest_elf)
        .map_err(|e| format!("Failed to compute image ID: {}", e))?;
    eprintln!(
        "      Guest image ID: {}",
        hex::encode(computed_image_id.as_bytes())
    );
    eprintln!(
        "      ⚠️  Verify this matches the image ID in the airdrop contract before submitting."
    );

    // Prove with Groth16 compression for on-chain verification (~510K gas)
    let prover = risc0_zkvm::default_prover();
    let prove_info = prover
        .prove(env, &guest_elf)
        .map_err(|e| format!("zkVM proving failed: {}", e))?;

    let receipt = &prove_info.receipt;
    let journal_bytes = &receipt.journal.bytes;

    eprintln!("      ✓ Proof generated");
    eprintln!("      Journal: {} bytes", journal_bytes.len());
    eprintln!("      Segments: {}", prove_info.stats.segments);

    // Verify journal is exactly 84 bytes as expected
    if journal_bytes.len() != 84 {
        return Err(format!(
            "Journal length mismatch: got {} bytes, expected 84. \
             Guest program journal layout may have changed.",
            journal_bytes.len()
        ));
    }

    // Extract journal fields for verification
    let journal_root = &journal_bytes[0..32];
    let journal_nullifier = &journal_bytes[32..64];
    let journal_recipient = &journal_bytes[64..84];

    if journal_root != root {
        return Err("Journal merkle_root doesn't match input root".to_string());
    }
    if journal_nullifier != nullifier {
        return Err("Journal nullifier doesn't match input nullifier".to_string());
    }
    if journal_recipient != recipient {
        return Err("Journal recipient doesn't match input recipient".to_string());
    }
    eprintln!("      ✓ Journal contents verified");

    // Encode the proof seal (Groth16) as hex for the proof file
    let seal_hex = encode_receipt_seal(receipt)?;

    // Save proof file to ~/.zkmist/proofs/
    std::fs::create_dir_all(proofs_dir())
        .map_err(|e| format!("Failed to create proofs dir: {}", e))?;
    let timestamp = timestamp_string();
    let proof_filename = proofs_dir().join(format!("zkmist_proof_{}.json", timestamp));

    // Serialize the receipt for local verification (bincode → hex)
    let receipt_bytes = bincode::serialize(&prove_info.receipt)
        .map_err(|e| format!("Failed to serialize receipt: {}", e))?;
    let receipt_hex = hex::encode(&receipt_bytes);

    let proof_file = ProofFile {
        version: 1,
        proof: seal_hex,
        journal: hex::encode(journal_bytes),
        nullifier: hex::encode(nullifier),
        recipient: hex::encode(recipient),
        claim_amount: (CLAIM_AMOUNT as u128 * 1_000_000_000_000_000_000).to_string(),
        contract_address: AIRDROP_CONTRACT.to_string(),
        chain_id: CHAIN_ID,
        receipt_hex: Some(receipt_hex),
    };

    let json = serde_json::to_string_pretty(&proof_file)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    std::fs::write(&proof_filename, &json)
        .map_err(|e| format!("Failed to write {}: {}", proof_filename.display(), e))?;

    eprintln!();
    eprintln!("      ⚠️  RECIPIENT IS IRREVOCABLE — triple-check before submitting.");
    eprintln!(
        "      {} ZKM will be minted to {} on claim.",
        CLAIM_AMOUNT,
        format_address(&recipient)
    );
    eprintln!("      Proof saved: {}", proof_filename.display());
    eprintln!("      Run: zkmist submit {}", proof_filename.display());
    eprintln!("      Or send to any relayer.");

    Ok(())
}

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
fn get_guest_elf() -> Result<Vec<u8>, String> {
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
fn encode_receipt_seal(receipt: &risc0_zkvm::Receipt) -> Result<String, String> {
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

// ── Command: submit ──────────────────────────────────────────────────────

fn cmd_submit(
    proof_file: &str,
    rpc_url: Option<&str>,
    private_key_hex: Option<&str>,
    key_file: Option<&str>,
) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_file)
        .map_err(|e| format!("Failed to read {}: {}", proof_file, e))?;
    let proof: ProofFile =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse proof file: {}", e))?;

    eprintln!("Loading proof from: {}", proof_file);
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);
    eprintln!("  Chain ID:  {}", proof.chain_id);

    if proof.chain_id != CHAIN_ID {
        return Err(format!(
            "Proof chain ID ({}) doesn't match expected ({})",
            proof.chain_id, CHAIN_ID
        ));
    }

    // Get submitter's private key for gas
    let submitter_key = if let Some(key_hex) = private_key_hex {
        let hex = key_hex.strip_prefix("0x").unwrap_or(key_hex);
        if hex.len() != 64 {
            return Err("Invalid private key length (expected 64 hex chars)".to_string());
        }
        hex.to_string()
    } else if let Some(path) = key_file {
        let key = read_private_key_from_file(path)?;
        hex::encode(key)
    } else {
        eprint!("Submitter private key (for gas, hidden): ");
        io::stderr().flush().ok();
        let input =
            rpassword::read_password().map_err(|e| format!("Failed to read input: {}", e))?;
        input.strip_prefix("0x").unwrap_or(&input).to_string()
    };

    let rpc = rpc_url.unwrap_or(DEFAULT_RPC_URL);
    eprintln!("Connecting to Base via: {}", rpc);

    // Build and submit the claim transaction using alloy
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;
    rt.block_on(async {
        use alloy::primitives::{Address, Bytes, FixedBytes};
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::signers::local::PrivateKeySigner;

        // Create provider with signer
        let signer: PrivateKeySigner = submitter_key
            .parse()
            .map_err(|e| format!("Invalid private key: {}", e))?;
        let url: reqwest::Url = rpc.parse().map_err(|e| format!("Invalid RPC URL: {}", e))?;
        let provider = ProviderBuilder::new().wallet(signer).connect_http(url);

        let contract_address: Address = proof.contract_address.parse().map_err(|e| {
            format!(
                "Invalid contract address '{}': {}",
                proof.contract_address, e
            )
        })?;
        let nullifier_bytes: FixedBytes<32> = format!("0x{}", proof.nullifier)
            .parse()
            .map_err(|e| format!("Invalid nullifier: {}", e))?;
        let recipient_address: Address = format!("0x{}", proof.recipient)
            .parse()
            .map_err(|e| format!("Invalid recipient: {}", e))?;

        // Decode hex proof and journal
        let proof_bytes: Bytes = hex::decode(&proof.proof)
            .map_err(|e| format!("Invalid proof hex: {}", e))?
            .into();
        let journal_bytes: Bytes = hex::decode(&proof.journal)
            .map_err(|e| format!("Invalid journal hex: {}", e))?
            .into();

        // ABI-encode the claim call using alloy's sol! macro.
        // This handles the function selector, offset calculation, and padding automatically.
        let call = claimCall {
            _proof: proof_bytes.clone(),
            _journal: journal_bytes.clone(),
            _nullifier: nullifier_bytes,
            _recipient: recipient_address,
        };
        let call_data = call.abi_encode();

        // Build transaction with gas estimation.
        // Estimate with a 20% buffer, fall back to 600K on failure.
        // Groth16 verification involves precompile calls (ECADD, ECMUL, pairing)
        // that some RPCs underestimate during gas estimation.
        let base_tx = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(contract_address)
            .input(call_data.into());

        let gas_limit = match provider.estimate_gas(base_tx.clone()).await {
            Ok(base) => {
                let buffered = (base as u128 * 12 / 10) as u64;
                eprintln!(
                    "  Gas estimate: {} (using {} with 20% buffer)",
                    base, buffered
                );
                buffered
            }
            Err(e) => {
                eprintln!(
                    "  ⚠️  Gas estimation failed ({}): using 700,000 fallback",
                    e
                );
                700_000
            }
        };

        let mut tx = base_tx;
        tx.gas = Some(gas_limit);

        eprintln!("Submitting claim transaction (gas limit: {})...", gas_limit);
        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("Failed to send transaction: {}", e))?;
        let tx_hash = *pending.tx_hash();
        eprintln!("  TX hash: {}", tx_hash);

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| format!("Failed to get receipt: {}", e))?;

        if receipt.status() {
            eprintln!("  ✅ Claim successful!");
            if let Some(block) = receipt.block_number {
                eprintln!("  Block: {}", block);
            }
            eprintln!("  Gas used: {}", receipt.gas_used);
        } else {
            return Err("Transaction reverted on-chain".to_string());
        }

        Ok::<(), String>(())
    })?;

    Ok(())
}

// ── Command: verify ──────────────────────────────────────────────────────

fn cmd_verify(proof_file: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_file)
        .map_err(|e| format!("Failed to read {}: {}", proof_file, e))?;
    let proof: ProofFile =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse proof file: {}", e))?;

    eprintln!("Verifying proof from: {}", proof_file);
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);
    eprintln!();

    // Parse journal
    let journal_bytes =
        hex::decode(&proof.journal).map_err(|e| format!("Failed to decode journal hex: {}", e))?;

    if journal_bytes.len() != 84 {
        return Err(format!(
            "Invalid journal length: {} bytes (expected 84)",
            journal_bytes.len()
        ));
    }

    // Parse journal fields
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&journal_bytes[0..32]);
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&journal_bytes[32..64]);
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&journal_bytes[64..84]);

    eprintln!("Journal contents:");
    eprintln!("  merkle_root: {}", format_bytes32(&merkle_root));
    eprintln!("  nullifier:   {}", format_bytes32(&nullifier));
    eprintln!("  recipient:   {}", format_address(&recipient));
    eprintln!();

    // Verify journal fields match proof file fields
    let proof_nullifier =
        hex::decode(&proof.nullifier).map_err(|e| format!("Invalid nullifier hex: {}", e))?;
    if proof_nullifier.len() != 32 {
        return Err("Proof nullifier must be 32 bytes".to_string());
    }
    let mut proof_nullifier_arr = [0u8; 32];
    proof_nullifier_arr.copy_from_slice(&proof_nullifier);
    if nullifier != proof_nullifier_arr {
        return Err("Journal nullifier does not match proof file nullifier".to_string());
    }

    let proof_recipient =
        hex::decode(&proof.recipient).map_err(|e| format!("Invalid recipient hex: {}", e))?;
    if proof_recipient.len() != 20 {
        return Err("Proof recipient must be 20 bytes".to_string());
    }
    let mut proof_recipient_arr = [0u8; 20];
    proof_recipient_arr.copy_from_slice(&proof_recipient);
    if recipient != proof_recipient_arr {
        return Err("Journal recipient does not match proof file recipient".to_string());
    }

    eprintln!("✓ Journal layout valid (84 bytes)");
    eprintln!("✓ Nullifier matches proof file");
    eprintln!("✓ Recipient matches proof file");

    // Verify the STARK proof using risc0-zkvm
    eprintln!();
    eprintln!("Verifying STARK proof...");

    // We need the image ID of the guest program to verify against.
    // This is computed from the guest ELF binary.
    let guest_elf = get_guest_elf();
    let image_id = if let Ok(elf) = &guest_elf {
        let id = risc0_zkvm::compute_image_id(elf)
            .map_err(|e| format!("Failed to compute image ID: {}", e))?;
        eprintln!("  Image ID: {}", hex::encode(id.as_bytes()));
        Some(id)
    } else {
        eprintln!("  ⚠️  Guest ELF not available — skipping cryptographic proof verification");
        eprintln!("      To verify cryptographically, place the guest ELF at ~/.zkmist/guest.elf");
        None
    };

    // Track the level of verification achieved so the final summary is accurate.
    //   0 = journal layout + field consistency only
    //   1 = cryptographic proof verified against image ID
    let mut verification_level: u8 = 0;

    if let Some(img_id) = image_id {
        eprintln!("  Image ID: {}", hex::encode(img_id.as_bytes()));

        // Try to verify the full cryptographic proof using the serialized receipt.
        if let Some(ref receipt_hex) = proof.receipt_hex {
            let receipt_bytes = hex::decode(receipt_hex)
                .map_err(|e| format!("Failed to decode receipt hex: {}", e))?;
            let receipt: risc0_zkvm::Receipt = bincode::deserialize(&receipt_bytes)
                .map_err(|e| format!("Failed to deserialize receipt: {}", e))?;

            // Verify the receipt cryptographically: checks the Groth16 proof
            // binds the image ID and journal together correctly.
            match receipt.verify(img_id) {
                Ok(()) => {
                    eprintln!("  ✅ Proof verified cryptographically against image ID");
                    verification_level = 1;
                }
                Err(e) => {
                    return Err(format!(
                        "❌ Cryptographic proof verification FAILED: {}\n\
                         The proof is invalid. Do NOT submit this proof.",
                        e
                    ));
                }
            }
        } else if proof.proof == "FAKE_SEAL_DEV_MODE"
            || proof.proof == "NEEDS_GROTH16_COMPRESSION"
            || proof.proof == "UNKNOWN_RECEIPT_TYPE"
        {
            eprintln!("  ⚠️  Proof was generated in dev/fake mode — cryptographic verification not possible.");
            eprintln!("      Only journal integrity has been verified.");
        } else {
            // Proof file has a real seal but no embedded receipt (e.g., from an external tool).
            eprintln!("  ⚠️  No embedded receipt in proof file — cannot perform local cryptographic verification.");
            eprintln!("      What was verified:");
            eprintln!("        ✓ Journal layout (84 bytes)");
            eprintln!("        ✓ Journal fields match proof file");
            eprintln!("        ✓ Guest ELF image ID computed");
            eprintln!("      What requires on-chain verification:");
            eprintln!("        ✗ Groth16 proof validity (checked by RiscZeroGroth16Verifier)");
        }
    } else {
        eprintln!("  ⚠️  Guest ELF not available — cannot compute image ID.");
        eprintln!("      Place guest ELF at ~/.zkmist/guest.elf for full verification.");
    }

    eprintln!();
    match verification_level {
        1 => {
            eprintln!("✅ Proof is valid (cryptographically verified). Safe to submit.");
        }
        _ => {
            eprintln!("⚠️  Journal layout and field consistency verified, but cryptographic");
            eprintln!("   proof was NOT verified locally. On-chain verification by the");
            eprintln!("   RiscZeroGroth16Verifier will catch an invalid proof — but you may");
            eprintln!("   waste gas if the proof is bad. For full local verification, place");
            eprintln!("   the guest ELF at ~/.zkmist/guest.elf.");
        }
    }
    Ok(())
}

// ── Command: check ───────────────────────────────────────────────────────

fn cmd_check(address_str: &str) -> Result<(), String> {
    let address = parse_address(address_str)?;

    eprintln!("Checking eligibility for: {}", format_address(&address));
    eprintln!();

    // Load eligibility list
    let addresses = load_eligibility_list()?;
    eprintln!("Loaded {} eligible addresses", addresses.len());

    // Binary search (list must be sorted — enforced by eligibility list generation)
    match addresses.binary_search(&address) {
        Ok(idx) => {
            eprintln!("✅ ELIGIBLE (found at index {})", idx);
            eprintln!();
            eprintln!("Run `zkmist prove` to generate a claim proof.");
        }
        Err(_) => {
            eprintln!("❌ NOT ELIGIBLE");
            eprintln!();
            eprintln!("This address did not pay ≥0.004 ETH in cumulative gas fees");
            eprintln!("on Ethereum mainnet before 2026-01-01.");
        }
    }

    Ok(())
}

// ── Command: status ──────────────────────────────────────────────────────

fn cmd_status(rpc_url: Option<&str>) -> Result<(), String> {
    let rpc = rpc_url.unwrap_or(DEFAULT_RPC_URL);

    eprintln!("ZKMist (ZKM) on Base");
    eprintln!("──────────────────────────────────────");
    eprintln!("Claim amount:   {} ZKM per claim", CLAIM_AMOUNT);
    eprintln!("Max claims:     {}", MAX_CLAIMS);
    eprintln!(
        "Deadline:       {} ({})",
        CLAIM_DEADLINE,
        format_deadline(CLAIM_DEADLINE)
    );
    eprintln!("Chain:          Base (chain ID: {})", CHAIN_ID);
    eprintln!();

    // Query on-chain state via alloy using type-safe contract bindings.
    // This calls the actual view functions (totalClaims, isClaimWindowOpen, etc.)
    // instead of reading raw storage slots — robust against storage layout changes.
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;
    rt.block_on(async {
        use alloy::primitives::Address;
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::sol_types::SolCall as _;

        let url: reqwest::Url = rpc.parse().map_err(|e| format!("Invalid RPC URL: {}", e))?;
        let provider = ProviderBuilder::new().connect_http(url);

        let contract: Address = AIRDROP_CONTRACT
            .parse()
            .map_err(|e| format!("Invalid contract address: {}", e))?;

        if contract == Address::ZERO
            || contract
                == "0x000000000000000000000000000000000000dEaD"
                    .parse::<Address>()
                    .unwrap()
        {
            eprintln!("⚠️  Contract not deployed yet (address is placeholder).");
            eprintln!("   On-chain status unavailable until deployment.");
            return Ok::<(), String>(());
        }

        // Call totalClaims() — returns (uint256)
        let total_claims_call = IZKMAirdrop::totalClaimsCall {};
        let tx = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(contract)
            .input(total_claims_call.abi_encode().into());
        let resp = provider
            .call(tx)
            .await
            .map_err(|e| format!("totalClaims call failed: {}", e))?;
        let total_claims_return = IZKMAirdrop::totalClaimsCall::abi_decode_returns(&resp)
            .map_err(|e| format!("totalClaims decode failed: {}", e))?;
        let total_claims_u64: u64 = total_claims_return.try_into().map_err(
            |e: alloy::primitives::ruint::FromUintError<u64>| {
                format!("totalClaims overflow: {}", e)
            },
        )?;

        // Call isClaimWindowOpen() — returns (bool)
        let is_open_call = IZKMAirdrop::isClaimWindowOpenCall {};
        let tx2 = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(contract)
            .input(is_open_call.abi_encode().into());
        let resp2 = provider
            .call(tx2)
            .await
            .map_err(|e| format!("isClaimWindowOpen call failed: {}", e))?;
        let is_open_return = IZKMAirdrop::isClaimWindowOpenCall::abi_decode_returns(&resp2)
            .map_err(|e| format!("isClaimWindowOpen decode failed: {}", e))?;
        let is_open: bool = is_open_return;

        // Call token() on airdrop to get the ZKMToken address
        let token_call = IZKMAirdrop::tokenCall {};
        let token_tx = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(contract)
            .input(token_call.abi_encode().into());
        let token_resp = provider
            .call(token_tx)
            .await
            .map_err(|e| format!("token() call failed: {}", e))?;
        let token_addr_return = IZKMAirdrop::tokenCall::abi_decode_returns(&token_resp)
            .map_err(|e| format!("token() decode failed: {}", e))?;
        let token_addr: alloy::primitives::Address = token_addr_return;

        // Call totalSupply() on ZKMToken for actual on-chain supply (accounts for burns)
        let supply_call = IZKMToken::totalSupplyCall {};
        let supply_tx = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(token_addr)
            .input(supply_call.abi_encode().into());
        let supply_resp = provider
            .call(supply_tx)
            .await
            .map_err(|e| format!("totalSupply() call failed: {}", e))?;
        let supply_return = IZKMToken::totalSupplyCall::abi_decode_returns(&supply_resp)
            .map_err(|e| format!("totalSupply() decode failed: {}", e))?;
        let on_chain_supply = supply_return;

        let remaining = MAX_CLAIMS.saturating_sub(total_claims_u64);
        let minted_supply = total_claims_u64 * CLAIM_AMOUNT;
        let pct = (total_claims_u64 as f64 / MAX_CLAIMS as f64) * 100.0;

        // Format on-chain supply for display (convert from wei to whole ZKM)
        let on_chain_supply_u128: u128 = on_chain_supply.try_into().map_err(
            |e: alloy::primitives::ruint::FromUintError<u128>| {
                format!("totalSupply overflow: {}", e)
            },
        )?;
        let on_chain_zkm = on_chain_supply_u128 as f64 / 1e18;
        let burned = minted_supply as f64 - on_chain_zkm;

        eprintln!("Total claimed:  {}", total_claims_u64);
        eprintln!("Claims left:    {} / {}", remaining, MAX_CLAIMS);
        eprintln!("Minted supply:  {} ZKM ({:.1}% of max)", minted_supply, pct);
        if burned > 0.5 {
            eprintln!(
                "On-chain supply: {:.0} ZKM ({:.0} ZKM burned)",
                on_chain_zkm, burned
            );
        } else {
            eprintln!("On-chain supply: {:.0} ZKM", on_chain_zkm);
        }
        eprintln!(
            "Status:         {}",
            if is_open {
                "✅ OPEN"
            } else if total_claims_u64 >= MAX_CLAIMS {
                "🔴 CAP REACHED"
            } else {
                "⏰ DEADLINE PASSED"
            }
        );

        Ok::<(), String>(())
    })?;

    Ok(())
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Fetch {
            cid,
            source,
            no_verify,
        } => cmd_fetch(cid.as_deref(), &source, no_verify),
        Commands::Prove { key_file } => cmd_prove(key_file.as_deref()),
        Commands::Submit {
            proof_file,
            rpc_url,
            private_key,
            key_file,
        } => cmd_submit(
            &proof_file,
            rpc_url.as_deref(),
            private_key.as_deref(),
            key_file.as_deref(),
        ),
        Commands::Verify { proof_file } => cmd_verify(&proof_file),
        Commands::Check { address } => cmd_check(&address),
        Commands::Status { rpc_url } => cmd_status(rpc_url.as_deref()),
    };

    if let Err(e) = result {
        eprintln!("\n❌ Error: {}", e);
        std::process::exit(1);
    }
}
