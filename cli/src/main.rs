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
use serde::{Deserialize, Serialize};
use zkmist_merkle_tree::{
    compute_nullifier, generate_proof, hash_leaf, verify_merkle_proof, PADDING_SENTINEL,
};

#[derive(Parser)]
#[command(name = "zkmist", version, about = "ZKMist (ZKM) claim tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download eligibility list from IPFS (~1.3 GB). Builds and caches the Merkle tree.
    Fetch,

    /// Generate ZK proof (interactive). Uses cached Merkle tree from `fetch`.
    Prove,

    /// Submit proof to ZKMAirdrop contract on Base.
    Submit {
        /// Path to proof.json
        proof_file: String,
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
    Status,
}

// ── Constants ────────────────────────────────────────────────────────────

const ZKMIST_DIR_NAME: &str = ".zkmist";
const ELIGIBILITY_DIR_NAME: &str = "eligibility";
const TREE_CACHE_FILE: &str = "tree_cache.bin";

/// PRD §11: Contract parameters
const CLAIM_AMOUNT: u64 = 10_000;
const MAX_CLAIMS: u64 = 1_000_000;
const CLAIM_DEADLINE: u64 = 1_798_761_600; // 2027-01-01 00:00:00 UTC
const CHAIN_ID: u64 = 8453; // Base

// ── Data structures ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct ProofFile {
    version: u64,
    proof: String,      // hex-encoded STARK proof
    journal: String,    // hex-encoded journal bytes
    nullifier: String,  // hex-encoded 32 bytes
    recipient: String,  // hex-encoded 20 bytes
    claim_amount: String,
    contract_address: String,
    chain_id: u64,
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
struct Manifest {
    version: u64,
    cutoff_timestamp: String,
    fee_threshold_eth: String,
    total_qualified: u64,
    merkle_root: String,
    merkle_tree_depth: usize,
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn zkmist_dir() -> PathBuf {
    dirs_home().join(ZKMIST_DIR_NAME)
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn eligibility_dir() -> PathBuf {
    zkmist_dir().join(ELIGIBILITY_DIR_NAME)
}

fn tree_cache_path() -> PathBuf {
    zkmist_dir().join(TREE_CACHE_FILE)
}

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
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "csv")
        })
        .map(|e| e.path())
        .collect();
    csv_files.sort();

    for path in &csv_files {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
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

/// Parse a hex Ethereum address (with or without 0x prefix) into 20 bytes.
fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 40 {
        return Err(format!("Invalid address length: {} (expected 40 hex chars)", hex.len()));
    }
    let mut addr = [0u8; 20];
    hex::decode_to_slice(hex, &mut addr)
        .map_err(|e| format!("Invalid hex in address '{}': {}", s, e))?;
    Ok(addr)
}

/// Read a hex-encoded private key from hidden input.
fn read_private_key() -> Result<[u8; 32], String> {
    eprint!("Private key (hidden): ");
    io::stderr().flush().ok();
    let input = rpassword::read_password().map_err(|e| format!("Failed to read input: {}", e))?;
    let hex = input.strip_prefix("0x").unwrap_or(&input);
    if hex.len() != 64 {
        return Err(format!("Invalid private key length: {} hex chars (expected 64)", hex.len()));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key)
        .map_err(|e| format!("Invalid hex in private key: {}", e))?;
    Ok(key)
}

/// Read a recipient address from input.
fn read_recipient_address() -> Result<[u8; 20], String> {
    eprint!("Recipient address: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    let addr = parse_address(input.trim())?;
    if addr == [0u8; 20] {
        return Err("Recipient cannot be the zero address. Tokens would be burned.".to_string());
    }
    Ok(addr)
}

/// Derive Ethereum address from a secp256k1 private key.
fn derive_address(key: &[u8; 32]) -> Result<[u8; 20], String> {
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let sk = SigningKey::from_slice(key).map_err(|e| format!("Invalid private key: {}", e))?;
    let vk: &VerifyingKey = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let pubkey_bytes = point.as_bytes();
    // Uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes
    let hash = Keccak256::digest(&pubkey_bytes[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

fn format_bytes32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

// ── Command implementations ──────────────────────────────────────────────

fn cmd_fetch() -> Result<(), String> {
    let dir = eligibility_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;

    eprintln!("[1/3] Downloading eligibility list...");
    eprintln!("      Source: IPFS (CID to be published)");
    eprintln!("      Size:   ~1.3 GB");
    eprintln!();
    eprintln!("TODO: Implement IPFS download.");
    eprintln!("      For now, place eligibility CSV files in:");
    eprintln!("      {}", dir.display());
    eprintln!();
    eprintln!("      Expected format: addresses_XXXXX.csv");
    eprintln!("      Each file: one address per line (0x-prefixed)");

    Ok(())
}

fn cmd_prove() -> Result<(), String> {
    let use_tree_cache = tree_cache_path().exists();

    eprintln!("[1/4] Loading eligibility list...");
    let addresses = load_eligibility_list()?;
    eprintln!("      Loaded {} eligible addresses", addresses.len());

    eprintln!("[2/4] Building Merkle tree...");
    if use_tree_cache {
        eprintln!("      Using cached tree: {}", tree_cache_path().display());
        eprintln!("      TODO: Load cached tree layers from disk");
        return Err("Tree cache loading not yet implemented".to_string());
    }

    let tree_layers = zkmist_merkle_tree::build_tree(&addresses);
    let root = zkmist_merkle_tree::tree_root(&tree_layers);
    eprintln!("      Tree built ({} levels)", tree_layers.len() - 1);
    eprintln!("      Root: {}", format_bytes32(&root));

    // Prompt for credentials
    eprintln!("[3/4] Enter credentials:");
    let private_key = read_private_key()?;
    let address = derive_address(&private_key)?;
    eprintln!("      → Address: {}", format_address(&address));

    // Check eligibility
    let mut leaf_hasher =
        ark_poseidon_hasher(1).ok_or("Failed to create leaf hasher")?;
    let leaf = hash_leaf(&address, &mut leaf_hasher);

    if leaf == PADDING_SENTINEL {
        return Err("Address produced a padding leaf — this should not happen".to_string());
    }

    // Find the leaf in the tree
    let leaves = &tree_layers[0];
    let leaf_index = leaves
        .iter()
        .position(|l| *l == leaf)
        .ok_or_else(|| {
            format!(
                "Address {} is NOT in the eligibility tree. \
                 If you believe this is an error, verify the eligibility list.",
                format_address(&address)
            )
        })?;

    eprintln!("      ✓ Eligible (index: {})", leaf_index);

    // Compute nullifier
    let mut interior_hasher =
        ark_poseidon_hasher(2).ok_or("Failed to create interior hasher")?;
    let nullifier = compute_nullifier(&private_key, &mut interior_hasher);
    eprintln!("      → Nullifier: {}", format_bytes32(&nullifier));

    // Get recipient
    let recipient = read_recipient_address()?;

    // Generate Merkle proof
    eprintln!("[4/4] Generating proof...");
    let (siblings, path_indices) = generate_proof(&tree_layers, leaf_index);

    // Verify proof locally before expensive zkVM proving
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

    // TODO: Run RISC Zero zkVM with these inputs
    eprintln!("      Running RISC Zero zkVM...");
    eprintln!("      TODO: Implement zkVM proving");
    eprintln!();
    eprintln!("      Guest program inputs would be:");
    eprintln!("        merkle_root: {}", format_bytes32(&root));
    eprintln!("        nullifier:   {}", format_bytes32(&nullifier));
    eprintln!("        recipient:   {}", format_address(&recipient));
    eprintln!("        private_key: [HIDDEN]");
    eprintln!("        siblings:    {} × 32 bytes", siblings.len());
    eprintln!("        path_indices: {} bytes", path_indices.len());

    // Save placeholder proof file
    let timestamp = chrono_now_string();
    let proof_filename = format!("zkmist_proof_{}.json", timestamp);

    let proof_file = ProofFile {
        version: 1,
        proof: "TODO_STARK_PROOF".to_string(),
        journal: format!(
            "{}{}{}",
            hex::encode(root),
            hex::encode(nullifier),
            hex::encode(recipient)
        ),
        nullifier: hex::encode(nullifier),
        recipient: hex::encode(recipient),
        claim_amount: format!("{}000000000000000000", CLAIM_AMOUNT), // 18 decimals
        contract_address: "TODO_DEPLOY".to_string(),
        chain_id: CHAIN_ID,
    };

    let json = serde_json::to_string_pretty(&proof_file)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    std::fs::write(&proof_filename, &json)
        .map_err(|e| format!("Failed to write {}: {}", proof_filename, e))?;

    eprintln!();
    eprintln!("      ⚠️  RECIPIENT IS IRREVOCABLE — triple-check before submitting.");
    eprintln!("      {} ZKM will be minted to {} on claim.", CLAIM_AMOUNT, format_address(&recipient));
    eprintln!("      Draft proof saved: {}", proof_filename);
    eprintln!("      Run: zkmist submit {}", proof_filename);
    eprintln!("      Or send to any relayer.");

    Ok(())
}

fn cmd_submit(proof_file: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_file)
        .map_err(|e| format!("Failed to read {}: {}", proof_file, e))?;
    let proof: ProofFile = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse proof file: {}", e))?;

    eprintln!("Loading proof from: {}", proof_file);
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);
    eprintln!("  Chain ID:  {}", proof.chain_id);
    eprintln!();

    // TODO: Submit to ZKMAirdrop contract on Base
    eprintln!("TODO: Implement on-chain submission via alloy.");
    eprintln!("      Contract: {}", proof.contract_address);
    eprintln!("      Would call claim(proof, journal, nullifier, recipient)");

    Ok(())
}

fn cmd_verify(proof_file: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_file)
        .map_err(|e| format!("Failed to read {}: {}", proof_file, e))?;
    let proof: ProofFile = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse proof file: {}", e))?;

    eprintln!("Verifying proof from: {}", proof_file);
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);
    eprintln!();

    // Parse journal
    let journal_bytes = hex::decode(&proof.journal)
        .map_err(|e| format!("Failed to decode journal hex: {}", e))?;

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
    let proof_nullifier = hex::decode(&proof.nullifier)
        .map_err(|e| format!("Invalid nullifier hex: {}", e))?;
    if proof_nullifier.len() != 32 {
        return Err("Proof nullifier must be 32 bytes".to_string());
    }
    let mut proof_nullifier_arr = [0u8; 32];
    proof_nullifier_arr.copy_from_slice(&proof_nullifier);
    if nullifier != proof_nullifier_arr {
        return Err("Journal nullifier does not match proof file nullifier".to_string());
    }

    let proof_recipient = hex::decode(&proof.recipient)
        .map_err(|e| format!("Invalid recipient hex: {}", e))?;
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

    // TODO: Verify the actual STARK proof using risc0-zkvm
    eprintln!();
    eprintln!("TODO: Verify STARK proof with risc0-zkvm::Receipt::verify()");
    eprintln!("      (Requires the image ID to verify against)");

    Ok(())
}

fn cmd_check(address_str: &str) -> Result<(), String> {
    let address = parse_address(address_str)?;

    eprintln!("Checking eligibility for: {}", format_address(&address));
    eprintln!();

    // Load eligibility list
    let addresses = load_eligibility_list()?;
    eprintln!("Loaded {} eligible addresses", addresses.len());

    // Binary search (list should be sorted)
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

fn cmd_status() -> Result<(), String> {
    eprintln!("ZKMist (ZKM) on Base");
    eprintln!("──────────────────────────────────────");
    eprintln!("Claim amount:   {} ZKM per claim", CLAIM_AMOUNT);
    eprintln!("Max claims:     {}", MAX_CLAIMS);
    eprintln!(
        "Deadline:       {} UTC ({})",
        CLAIM_DEADLINE,
        format_deadline(CLAIM_DEADLINE)
    );
    eprintln!("Chain:          Base (chain ID: {})", CHAIN_ID);
    eprintln!();

    // TODO: Query on-chain state via alloy
    eprintln!("TODO: Query on-chain status via RPC");
    eprintln!("      Would read: totalClaims, claimsRemaining, isClaimWindowOpen");
    eprintln!("      Contract address: TBD (not deployed yet)");

    Ok(())
}

// ── Utility helpers ──────────────────────────────────────────────────────

/// Create a Poseidon hasher for the given number of inputs.
/// This is a thin wrapper to avoid depending on ark-bn254 in CLI code.
fn ark_poseidon_hasher(nr_inputs: usize) -> Option<light_poseidon::Poseidon<ark_bn254::Fr>> {
    light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs).ok()
}

fn chrono_now_string() -> String {
    // Simple timestamp without chrono dependency
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn format_deadline(timestamp: u64) -> &'static str {
    if timestamp == CLAIM_DEADLINE {
        "2027-01-01 00:00:00"
    } else {
        "unknown"
    }
}

// ── Hex encoding/decoding (minimal, no dependency) ───────────────────────

mod hex {
    fn decode_hex_char(c: char) -> Result<u8, String> {
        match c {
            '0'..='9' => Ok(c as u8 - b'0'),
            'a'..='f' => Ok(c as u8 - b'a' + 10),
            'A'..='F' => Ok(c as u8 - b'A' + 10),
            _ => Err(format!("Invalid hex character: {}", c)),
        }
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() % 2 != 0 {
            return Err("Hex string has odd length".to_string());
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let hi = decode_hex_char(chunk[0] as char)?;
            let lo = decode_hex_char(chunk[1] as char)?;
            bytes.push(hi << 4 | lo);
        }
        Ok(bytes)
    }

    pub fn decode_to_slice(s: &str, out: &mut [u8]) -> Result<(), String> {
        let bytes = decode(s)?;
        if bytes.len() != out.len() {
            return Err(format!(
                "Decoded {} bytes, expected {}",
                bytes.len(),
                out.len()
            ));
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }

    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

// ── Main ─────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Fetch => cmd_fetch(),
        Commands::Prove => cmd_prove(),
        Commands::Submit { proof_file } => cmd_submit(&proof_file),
        Commands::Verify { proof_file } => cmd_verify(&proof_file),
        Commands::Check { address } => cmd_check(&address),
        Commands::Status => cmd_status(),
    };

    if let Err(e) = result {
        eprintln!("\n❌ Error: {}", e);
        std::process::exit(1);
    }
}
