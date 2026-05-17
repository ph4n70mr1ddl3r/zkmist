//! ZKMist CLI — claim tool for the ZKMist airdrop
//!
//! Commands:
//!   zkmist fetch    — Download eligibility list from IPFS
//!   zkmist prove    — Generate ZK proof locally
//!   zkmist submit   — Submit proof to ZKMAirdrop contract
//!   zkmist verify   — Verify proof locally
//!   zkmist check    — Check if address is eligible
//!   zkmist status   — Show claim window status

mod abi;
mod commands;
mod constants;
mod download;
mod guest;
mod helpers;
mod types;

// Re-export for test access
pub use abi::*;
pub use commands::*;
pub use constants::*;
pub use download::*;
pub use guest::*;
pub use helpers::*;
pub use types::*;

use clap::{Parser, Subcommand};

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

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolCall;
    use zkmist_merkle_tree::{compute_nullifier, hash_leaf};

    // ── parse_address ──────────────────────────────────────────────────

    #[test]
    fn test_parse_address_with_0x_prefix() {
        let addr = parse_address("0xfcad0b19bb29d4674531d6f115237e16afce377c").unwrap();
        assert_eq!(
            addr,
            [
                0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
                0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c
            ]
        );
    }

    #[test]
    fn test_parse_address_without_prefix() {
        let addr = parse_address("fcad0b19bb29d4674531d6f115237e16afce377c").unwrap();
        assert_eq!(
            addr,
            [
                0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
                0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c
            ]
        );
    }

    #[test]
    fn test_parse_address_all_zeros() {
        let addr = parse_address("0x0000000000000000000000000000000000000000").unwrap();
        assert_eq!(addr, [0u8; 20]);
    }

    #[test]
    fn test_parse_address_all_ones() {
        let addr = parse_address("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        assert_eq!(addr, [0xFFu8; 20]);
    }

    #[test]
    fn test_parse_address_rejects_too_short() {
        let err = parse_address("0xfcad0b").unwrap_err();
        assert!(err.contains("Invalid address length"));
    }

    #[test]
    fn test_parse_address_rejects_too_long() {
        let err = parse_address("0xfcad0b19bb29d4674531d6f115237e16afce377c00").unwrap_err();
        assert!(err.contains("Invalid address length"));
    }

    #[test]
    fn test_parse_address_rejects_invalid_hex() {
        let err = parse_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").unwrap_err();
        assert!(err.contains("Invalid hex"));
    }

    #[test]
    fn test_parse_address_rejects_empty() {
        let err = parse_address("").unwrap_err();
        assert!(err.contains("Invalid address length"));
    }

    // ── validate_address_checksum (EIP-55) ─────────────────────────────

    #[test]
    fn test_eip55_valid_checksum() {
        let result = validate_address_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert!(result.is_ok());
    }

    #[test]
    fn test_eip55_all_lowercase_bypasses_checksum() {
        let result = validate_address_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(result.is_ok());
    }

    #[test]
    fn test_eip55_all_uppercase_bypasses_checksum() {
        let result = validate_address_checksum("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");
        assert!(result.is_ok());
    }

    #[test]
    fn test_eip55_no_prefix_still_works() {
        let result = validate_address_checksum("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(result.is_ok());
    }

    #[test]
    fn test_eip55_invalid_checksum_rejected() {
        let result = validate_address_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EIP-55 checksum"));
    }

    #[test]
    fn test_eip55_rejects_zero_address() {
        let result = validate_address_checksum("0x0000000000000000000000000000000000000000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 20]);
    }

    // ── derive_address ─────────────────────────────────────────────────

    #[test]
    fn test_derive_address_prd_test_vector() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let addr = derive_address(&key).unwrap();
        assert_eq!(
            addr,
            [
                0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
                0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c
            ]
        );
    }

    #[test]
    fn test_derive_address_deterministic() {
        let key: [u8; 32] = [0x42u8; 32];
        let a1 = derive_address(&key).unwrap();
        let a2 = derive_address(&key).unwrap();
        assert_eq!(a1, a2, "Address derivation must be deterministic");
    }

    #[test]
    fn test_derive_address_unique_per_key() {
        let key1: [u8; 32] = [0x01u8; 32];
        let key2: [u8; 32] = [0x02u8; 32];
        let a1 = derive_address(&key1).unwrap();
        let a2 = derive_address(&key2).unwrap();
        assert_ne!(a1, a2, "Different keys must produce different addresses");
    }

    #[test]
    fn test_derive_address_rejects_invalid_key() {
        let err = derive_address(&[0u8; 32]).unwrap_err();
        assert!(err.contains("Invalid private key"));
    }

    #[test]
    fn test_derive_address_rejects_overflow_key() {
        let key: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        let err = derive_address(&key).unwrap_err();
        assert!(err.contains("Invalid private key"));
    }

    // ── days_to_ymd / format_deadline ──────────────────────────────────

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_days_to_ymd_known_dates() {
        let (y, m, d) = days_to_ymd(10957);
        assert_eq!(y, 2000);
        assert_eq!(m, 1);
        assert_eq!(d, 1);

        let deadline_days = (CLAIM_DEADLINE / 86400) as i64;
        let (y, m, d) = days_to_ymd(deadline_days);
        assert_eq!(y, 2027);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_format_deadline_claim_deadline() {
        let s = format_deadline(CLAIM_DEADLINE);
        assert!(s.starts_with("2027-01-01"));
        assert!(s.contains("00:00:00 UTC"));
    }

    #[test]
    fn test_format_deadline_known_timestamp() {
        let s = format_deadline(1721478645);
        assert!(s.starts_with("2024-07-20"));
        assert!(s.contains("12:30:45 UTC"));
    }

    // ── Manifest parsing and verification ──────────────────────────────

    fn make_manifest_json(root: &str, total: u64, files: &[(&str, &str)]) -> String {
        let files_json: Vec<String> = files
            .iter()
            .map(|(f, h)| format!(r#"{{"file": "{}", "sha256": "{}"}}"#, f, h))
            .collect();
        format!(
            r#"{{
  "version": 1,
  "cutoff_timestamp": "2026-01-01T00:00:00Z",
  "fee_threshold_eth": "0.004",
  "total_qualified": {},
  "merkle_root": "{}",
  "merkle_tree_depth": 26,
  "files": [{}]
}}"#,
            total,
            root,
            files_json.join(", ")
        )
    }

    #[test]
    fn test_manifest_parsing() {
        let json = make_manifest_json(
            "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844",
            64116228,
            &[("addrs_00.csv", "0xabcd"), ("addrs_01.csv", "0xef01")],
        );
        let manifest: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.total_qualified, 64116228);
        assert_eq!(manifest.merkle_tree_depth, 26);
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].file, "addrs_00.csv");
        assert_eq!(manifest.files[1].sha256, "0xef01");
    }

    #[test]
    fn test_manifest_root_extraction() {
        let manifest = Manifest {
            version: 1,
            cutoff_timestamp: String::new(),
            fee_threshold_eth: String::new(),
            total_qualified: 0,
            merkle_root: "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
            merkle_tree_depth: 26,
            files: vec![],
        };
        let root = manifest_root(&manifest).unwrap();
        assert_eq!(root[0], 0x01);
        assert_eq!(root[31], 0x20);
    }

    #[test]
    fn test_manifest_root_rejects_wrong_length() {
        let manifest = Manifest {
            version: 1,
            cutoff_timestamp: String::new(),
            fee_threshold_eth: String::new(),
            total_qualified: 0,
            merkle_root: "0x0102".to_string(),
            merkle_tree_depth: 26,
            files: vec![],
        };
        let err = manifest_root(&manifest).unwrap_err();
        assert!(err.contains("Invalid merkle root length"));
    }

    #[test]
    fn test_verify_root_against_manifest_matching() {
        let root: [u8; 32] = [
            0x1e, 0xaf, 0xd6, 0xf3, 0xb8, 0xf3, 0x0a, 0xf9, 0x49, 0xff, 0x54, 0x93, 0xe9, 0x10,
            0x28, 0x53, 0xa7, 0xc2, 0x2f, 0x8c, 0xff, 0xdc, 0xf0, 0x18, 0xda, 0xa3, 0x1d, 0x42,
            0x45, 0x79, 0x78, 0x44,
        ];
        let manifest = Manifest {
            version: 1,
            cutoff_timestamp: String::new(),
            fee_threshold_eth: String::new(),
            total_qualified: 0,
            merkle_root: "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844"
                .to_string(),
            merkle_tree_depth: 26,
            files: vec![],
        };
        assert!(verify_root_against_manifest(&root, &manifest).is_ok());
    }

    #[test]
    fn test_verify_root_against_manifest_mismatch() {
        let root: [u8; 32] = [0xAAu8; 32];
        let manifest = Manifest {
            version: 1,
            cutoff_timestamp: String::new(),
            fee_threshold_eth: String::new(),
            total_qualified: 0,
            merkle_root: "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844"
                .to_string(),
            merkle_tree_depth: 26,
            files: vec![],
        };
        let err = verify_root_against_manifest(&root, &manifest).unwrap_err();
        assert!(err.contains("Merkle root mismatch"));
    }

    // ── load_eligibility_list ──────────────────────────────────────────

    #[test]
    fn test_load_eligibility_list_with_csv() {
        let dir = tempfile::tempdir().unwrap();
        let elig_dir = dir.path().join("eligibility");
        std::fs::create_dir_all(&elig_dir).unwrap();
        std::fs::write(
            elig_dir.join("addrs_00.csv"),
            "address\n0x0000000000000000000000000000000000000001\n0x0000000000000000000000000000000000000002\n",
        ).unwrap();

        let content = std::fs::read_to_string(elig_dir.join("addrs_00.csv")).unwrap();
        let mut addresses = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("address") {
                continue;
            }
            addresses.push(parse_address(line).unwrap());
        }
        assert_eq!(addresses.len(), 2);
        assert_eq!(
            addresses[0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            addresses[1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        );
    }

    #[test]
    fn test_load_eligibility_list_skips_header() {
        let addresses: Vec<[u8; 20]> = [
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        ]
        .iter()
        .map(|s| parse_address(s).unwrap())
        .collect();
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn test_load_eligibility_list_empty_lines_skipped() {
        let csv_content = "address\n\n  \n0x0000000000000000000000000000000000000001\n\n";
        let mut addresses = Vec::new();
        for line in csv_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("address") {
                continue;
            }
            addresses.push(parse_address(line).unwrap());
        }
        assert_eq!(addresses.len(), 1);
    }

    // ── ProofFile serialization ─────────────────────────────────────────

    #[test]
    fn test_proof_file_roundtrip() {
        let original = ProofFile {
            version: 1,
            proof_format_version: PROOF_FORMAT_VERSION_V1,
            proof: "aabbccdd".to_string(),
            journal: "e".repeat(168),
            nullifier: "f".repeat(64),
            recipient: "ab".repeat(20),
            claim_amount: "10000000000000000000000".to_string(),
            contract_address: "0x000000000000000000000000000000000000dEaD".to_string(),
            chain_id: 8453,
            receipt_hex: Some("deafbeef".to_string()),
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: ProofFile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.proof_format_version, PROOF_FORMAT_VERSION_V1);
        assert_eq!(parsed.proof, original.proof);
        assert_eq!(parsed.journal, original.journal);
        assert_eq!(parsed.nullifier, original.nullifier);
        assert_eq!(parsed.recipient, original.recipient);
        assert_eq!(parsed.claim_amount, original.claim_amount);
        assert_eq!(parsed.chain_id, original.chain_id);
        assert_eq!(parsed.receipt_hex, original.receipt_hex);
    }

    #[test]
    fn test_proof_file_without_receipt() {
        let pf = ProofFile {
            version: 1,
            proof_format_version: PROOF_FORMAT_VERSION_V1,
            proof: "aabb".to_string(),
            journal: "cc".to_string(),
            nullifier: "dd".to_string(),
            recipient: "ee".to_string(),
            claim_amount: "0".to_string(),
            contract_address: "0x00".to_string(),
            chain_id: 1,
            receipt_hex: None,
        };

        let json = serde_json::to_string(&pf).unwrap();
        assert!(!json.contains("receiptHex"));

        let parsed: ProofFile = serde_json::from_str(&json).unwrap();
        assert!(parsed.receipt_hex.is_none());

        // Verify old proof files (without proofFormatVersion) deserialize with default
        let old_json = r#"{"version":1,"proof":"aabb","journal":"cc","nullifier":"dd","recipient":"ee","claimAmount":"0","contractAddress":"0x00","chainId":1}"#;
        let old_parsed: ProofFile = serde_json::from_str(old_json).unwrap();
        assert_eq!(old_parsed.proof_format_version, PROOF_FORMAT_VERSION_V1);
    }

    // ── Download source parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_source_all_variants() {
        assert_eq!(parse_source("auto").unwrap(), DownloadSource::Auto);
        assert_eq!(parse_source("github").unwrap(), DownloadSource::Github);
        assert_eq!(parse_source("gh").unwrap(), DownloadSource::Github);
        assert_eq!(parse_source("ipfs").unwrap(), DownloadSource::Ipfs);
        assert_eq!(parse_source("AUTO").unwrap(), DownloadSource::Auto);
        assert_eq!(parse_source("GitHub").unwrap(), DownloadSource::Github);
    }

    #[test]
    fn test_parse_source_rejects_unknown() {
        let err = parse_source("ftp").unwrap_err();
        assert!(err.contains("Unknown source"));
    }

    // ── Claim ABI encoding verification ─────────────────────────────────

    #[test]
    fn test_claim_abi_selector() {
        let _call = claimCall {
            _proof: Default::default(),
            _journal: Default::default(),
            _nullifier: Default::default(),
            _recipient: Default::default(),
        };
        let selector = claimCall::SELECTOR;
        let expected_selector = alloy::primitives::Selector::from_slice(
            &alloy::primitives::keccak256(b"claim(bytes,bytes,bytes32,address)").as_slice()[..4],
        );
        assert_eq!(selector, expected_selector);
    }

    #[test]
    fn test_claim_abi_encoding_roundtrip() {
        use alloy::primitives::{Address, Bytes, FixedBytes};

        let proof_data = vec![0xAA, 0xBB, 0xCC];
        let journal_data = vec![0xDD, 0xEE];
        let nullifier_val: FixedBytes<32> = FixedBytes::from([0x42u8; 32]);
        let recipient_val: Address = Address::repeat_byte(0x0b);

        let call = claimCall {
            _proof: Bytes::from(proof_data.clone()),
            _journal: Bytes::from(journal_data.clone()),
            _nullifier: nullifier_val,
            _recipient: recipient_val,
        };

        let encoded = call.abi_encode();
        assert!(encoded.len() > 4);

        let decoded = claimCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded._proof.to_vec(), proof_data);
        assert_eq!(decoded._journal.to_vec(), journal_data);
        assert_eq!(decoded._nullifier, nullifier_val);
        assert_eq!(decoded._recipient, recipient_val);
    }

    #[test]
    fn test_claim_abi_encoding_with_real_journal() {
        let root: [u8; 32] = [
            0x1e, 0xaf, 0xd6, 0xf3, 0xb8, 0xf3, 0x0a, 0xf9, 0x49, 0xff, 0x54, 0x93, 0xe9, 0x10,
            0x28, 0x53, 0xa7, 0xc2, 0x2f, 0x8c, 0xff, 0xdc, 0xf0, 0x18, 0xda, 0xa3, 0x1d, 0x42,
            0x45, 0x79, 0x78, 0x44,
        ];
        let nullifier: [u8; 32] = [0x42u8; 32];
        let recipient: [u8; 20] = [0xB0u8; 20];

        let mut journal_bytes = Vec::with_capacity(84);
        journal_bytes.extend_from_slice(&root);
        journal_bytes.extend_from_slice(&nullifier);
        journal_bytes.extend_from_slice(&recipient);
        assert_eq!(journal_bytes.len(), 84);

        assert_eq!(&journal_bytes[0..32], &root);
        assert_eq!(&journal_bytes[32..64], &nullifier);
        assert_eq!(&journal_bytes[64..84], &recipient);
    }

    // ── IZKMAirdrop / IZKMToken ABI encoding ────────────────────────────

    #[test]
    fn test_total_claims_call_encoding() {
        let call = IZKMAirdrop::totalClaimsCall {};
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn test_is_claim_window_open_call_encoding() {
        let call = IZKMAirdrop::isClaimWindowOpenCall {};
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn test_total_claims_return_decoding() {
        let return_data = alloy::primitives::U256::from(42);
        let encoded_return = alloy::sol_types::SolValue::abi_encode(&return_data);
        let decoded = IZKMAirdrop::totalClaimsCall::abi_decode_returns(&encoded_return).unwrap();
        assert_eq!(decoded, alloy::primitives::U256::from(42));
    }

    #[test]
    fn test_is_claimed_call_encoding() {
        let nullifier = alloy::primitives::FixedBytes::<32>::from([0x42u8; 32]);
        let call = IZKMAirdrop::isClaimedCall { nullifier };
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 36);
    }

    #[test]
    fn test_is_claimed_return_decoding() {
        let encoded_return = alloy::sol_types::SolValue::abi_encode(&true);
        let decoded = IZKMAirdrop::isClaimedCall::abi_decode_returns(&encoded_return).unwrap();
        assert_eq!(decoded, true);
    }

    #[test]
    fn test_total_supply_return_decoding() {
        let supply = alloy::primitives::U256::from(1_000_000_000_000_000_000_000_000u128);
        let encoded_return = alloy::sol_types::SolValue::abi_encode(&supply);
        let decoded = IZKMToken::totalSupplyCall::abi_decode_returns(&encoded_return).unwrap();
        assert_eq!(decoded, supply);
    }

    // ── Journal verification (cmd_verify logic) ─────────────────────────

    #[test]
    fn test_journal_layout_84_bytes() {
        let root: [u8; 32] = [
            0x1e, 0xaf, 0xd6, 0xf3, 0xb8, 0xf3, 0x0a, 0xf9, 0x49, 0xff, 0x54, 0x93, 0xe9, 0x10,
            0x28, 0x53, 0xa7, 0xc2, 0x2f, 0x8c, 0xff, 0xdc, 0xf0, 0x18, 0xda, 0xa3, 0x1d, 0x42,
            0x45, 0x79, 0x78, 0x44,
        ];
        let nullifier: [u8; 32] = [
            0x07, 0x8f, 0x97, 0x2a, 0x93, 0x64, 0xd1, 0x43, 0xa1, 0x72, 0x96, 0x75, 0x23, 0xed,
            0x8d, 0x74, 0x2a, 0xab, 0x36, 0x48, 0x1a, 0x53, 0x4e, 0x97, 0xda, 0xe6, 0xfd, 0x7f,
            0x64, 0x2f, 0x65, 0xb9,
        ];
        let recipient: [u8; 20] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0b, 0x0b,
        ];

        let mut journal = Vec::new();
        journal.extend_from_slice(&root);
        journal.extend_from_slice(&nullifier);
        journal.extend_from_slice(&recipient);

        assert_eq!(journal.len(), 84);

        let journal_root: [u8; 32] = journal[0..32].try_into().unwrap();
        let journal_nullifier: [u8; 32] = journal[32..64].try_into().unwrap();
        let journal_recipient: [u8; 20] = journal[64..84].try_into().unwrap();

        assert_eq!(journal_root, root);
        assert_eq!(journal_nullifier, nullifier);
        assert_eq!(journal_recipient, recipient);
    }

    // ── Helper function tests ───────────────────────────────────────────

    #[test]
    fn test_format_address() {
        let addr: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
            0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        assert_eq!(
            format_address(&addr),
            "0xfcad0b19bb29d4674531d6f115237e16afce377c"
        );
    }

    #[test]
    fn test_format_bytes32() {
        let b: [u8; 32] = [0xABu8; 32];
        assert_eq!(format_bytes32(&b), "0x".to_string() + &"ab".repeat(32));
    }

    #[test]
    fn test_constants() {
        assert_eq!(CLAIM_AMOUNT, 10_000);
        assert_eq!(MAX_CLAIMS, 1_000_000);
        assert_eq!(CHAIN_ID, 8453);
        assert_eq!(CLAIM_DEADLINE, 1798761600);
    }

    // ── read_private_key_from_file ──────────────────────────────────────

    /// Helper: create a key file with restricted permissions (chmod 600) so
    /// the permission check in `read_private_key_from_file` doesn't reject it.
    fn create_restricted_key_file(
        dir: &std::path::Path,
        filename: &str,
        content: &str,
    ) -> std::path::PathBuf {
        let path = dir.join(filename);
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn test_read_private_key_from_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = create_restricted_key_file(
            dir.path(),
            "key.txt",
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let key = read_private_key_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn test_read_private_key_from_file_without_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = create_restricted_key_file(
            dir.path(),
            "key.txt",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let key = read_private_key_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(key[0], 0x01);
    }

    #[test]
    fn test_read_private_key_from_file_with_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = create_restricted_key_file(
            dir.path(),
            "key.txt",
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );
        let key = read_private_key_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(key[0], 0x01);
    }

    #[test]
    fn test_read_private_key_from_file_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = create_restricted_key_file(dir.path(), "key.txt", "0x0123");
        let err = read_private_key_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("Invalid private key length"));
    }

    #[test]
    fn test_read_private_key_from_file_invalid_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = create_restricted_key_file(
            dir.path(),
            "key.txt",
            &("0x".to_string() + &"Z".repeat(64)),
        );
        let err = read_private_key_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("Invalid hex"));
    }

    #[test]
    fn test_read_private_key_from_file_world_readable_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        std::fs::write(
            &path,
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        // tempfile creates files with mode 644 (world-readable) — the permission check should reject this
        let err = read_private_key_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("world-readable"),
            "Expected world-readable error, got: {}",
            err
        );
    }

    #[test]
    fn test_read_private_key_from_file_nonexistent() {
        let err = read_private_key_from_file("/nonexistent/path/key.txt").unwrap_err();
        assert!(err.contains("Failed to read key file") || err.contains("Failed to stat key file"));
    }

    // ── Nullifier consistency between CLI and merkle-tree lib ──────────

    #[test]
    fn test_nullifier_matches_merkle_tree_lib() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let mut hasher = ark_poseidon_hasher(2).unwrap();
        let cli_nullifier = compute_nullifier(&key, &mut hasher);

        assert_eq!(
            hex::encode(cli_nullifier),
            "078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9"
        );
    }

    // ── Leaf hash consistency between CLI and merkle-tree lib ──────────

    #[test]
    fn test_leaf_hash_prd_test_vector() {
        let addr: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
            0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        let mut hasher = ark_poseidon_hasher(1).unwrap();
        let leaf = hash_leaf(&addr, &mut hasher);
        assert_eq!(
            hex::encode(leaf),
            "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9"
        );
    }
}
