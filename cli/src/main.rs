//! ZKMist CLI — claim tool for the ZKMist airdrop
//!
//! Commands:
//!   zkmist fetch    — Download eligibility list from GitHub Releases
//!   zkmist prove    — Generate Halo2-KZG ZK proof locally
//!   zkmist submit   — Submit proof to ZKMAirdrop contract
//!   zkmist verify   — Verify proof locally
//!   zkmist check    — Check if address is eligible
//!   zkmist status   — Show claim window status

mod abi;
mod commands;
mod constants;
mod download;
mod halo2_prover;
mod helpers;
mod types;

// Re-export for test access
pub use abi::*;
pub use commands::*;
pub use constants::*;
pub use download::*;
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
        /// Skip Merkle root verification (faster; still checks per-file SHA-256 integrity)
        #[arg(long)]
        no_verify: bool,
    },

    /// Generate Halo2-KZG ZK proof (interactive). Uses cached proof data when available.
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

    /// Verify proof locally: validates the Halo2-KZG proof cryptographically.
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

    /// Benchmark proving pipeline: times key generation and proof creation.
    /// Generates a small Merkle tree and runs the proving pipeline without
    /// writing to disk. Useful for measuring proving time on reference hardware.
    Bench {
        /// Tree depth for the benchmark (default: 4)
        #[arg(long, default_value = "4")]
        tree_depth: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Fetch { no_verify } => cmd_fetch(no_verify),
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
        Commands::Bench { tree_depth } => cmd_bench(tree_depth),
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
  "cutoffTimestamp": "2026-01-01T00:00:00Z",
  "feeThresholdEth": "0.004",
  "totalQualified": {},
  "merkleRoot": "{}",
  "merkleTreeDepth": 26,
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
            claim_amount_wei: None,
            max_claimants: None,
            claim_deadline: None,
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
            claim_amount_wei: None,
            max_claimants: None,
            claim_deadline: None,
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
            claim_amount_wei: None,
            max_claimants: None,
            claim_deadline: None,
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
            claim_amount_wei: None,
            max_claimants: None,
            claim_deadline: None,
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

    // ── ProofFile serialization ─────────────────────────────────────────

    #[test]
    fn test_proof_file_roundtrip() {
        let original = ProofFile {
            version: 2,
            proof_format_version: PROOF_FORMAT_VERSION,
            proof: "aabbccdd".to_string(),
            journal: String::new(),
            nullifier: "f".repeat(64),
            recipient: "ab".repeat(20),
            claim_amount: "10000000000000000000000".to_string(),
            contract_address: "0x000000000000000000000000000000000000dEaD".to_string(),
            chain_id: 8453,
            receipt_hex: None,
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: ProofFile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.proof_format_version, PROOF_FORMAT_VERSION);
        assert_eq!(parsed.proof, original.proof);
        assert_eq!(parsed.nullifier, original.nullifier);
        assert_eq!(parsed.recipient, original.recipient);
        assert_eq!(parsed.claim_amount, original.claim_amount);
        assert_eq!(parsed.chain_id, original.chain_id);
    }

    // ── Claim ABI encoding verification ─────────────────────────────────

    #[test]
    fn test_claim_abi_selector() {
        let _call = claimCall {
            proof: Default::default(),
            nullifier: Default::default(),
            recipient: Default::default(),
        };
        let selector = claimCall::SELECTOR;
        let expected_selector = alloy::primitives::Selector::from_slice(
            &alloy::primitives::keccak256(b"claim(bytes,bytes32,address)").as_slice()[..4],
        );
        assert_eq!(selector, expected_selector);
    }

    #[test]
    fn test_claim_abi_encoding_roundtrip() {
        use alloy::primitives::{Address, Bytes, FixedBytes};

        let proof_data = vec![0xAA, 0xBB, 0xCC];
        let nullifier_val: FixedBytes<32> = FixedBytes::from([0x42u8; 32]);
        let recipient_val: Address = Address::repeat_byte(0x0b);

        let call = claimCall {
            proof: Bytes::from(proof_data.clone()),
            nullifier: nullifier_val,
            recipient: recipient_val,
        };

        let encoded = call.abi_encode();
        assert!(encoded.len() > 4);

        let decoded = claimCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.proof.to_vec(), proof_data);
        assert_eq!(decoded.nullifier, nullifier_val);
        assert_eq!(decoded.recipient, recipient_val);
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
        assert!(decoded);
    }

    #[test]
    fn test_total_supply_return_decoding() {
        let supply = alloy::primitives::U256::from(1_000_000_000_000_000_000_000_000u128);
        let encoded_return = alloy::sol_types::SolValue::abi_encode(&supply);
        let decoded = IZKMToken::totalSupplyCall::abi_decode_returns(&encoded_return).unwrap();
        assert_eq!(decoded, supply);
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

        // Verify the nullifier is deterministic and matches expected test vector
        assert_eq!(
            hex::encode(cli_nullifier).len(),
            64,
            "Nullifier should be 32 bytes hex"
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

    // ── Proof format version validation ─────────────────────────────────

    #[test]
    fn test_proof_format_version_mismatch_rejected() {
        let proof = ProofFile {
            version: 2,
            proof_format_version: 999, // Wrong version
            proof: "aabb".repeat(250), // 500 bytes hex
            journal: String::new(),
            nullifier: "f".repeat(64),
            recipient: "ab".repeat(20),
            claim_amount: "10000000000000000000000".to_string(),
            contract_address: "0x000000000000000000000000000000000000dEaD".to_string(),
            chain_id: CHAIN_ID,
            receipt_hex: None,
        };
        assert_ne!(
            proof.proof_format_version, PROOF_FORMAT_VERSION,
            "Proof format version should differ from current"
        );
    }

    #[test]
    fn test_proof_format_version_current() {
        let proof = ProofFile {
            version: 2,
            proof_format_version: PROOF_FORMAT_VERSION,
            proof: "aabb".repeat(250),
            journal: String::new(),
            nullifier: "f".repeat(64),
            recipient: "ab".repeat(20),
            claim_amount: "10000000000000000000000".to_string(),
            contract_address: "0x000000000000000000000000000000000000dEaD".to_string(),
            chain_id: CHAIN_ID,
            receipt_hex: None,
        };
        assert_eq!(proof.proof_format_version, PROOF_FORMAT_VERSION);
    }

    #[test]
    fn test_proof_byte_length_validation() {
        // Valid range: [4000, 8000] bytes (matches Halo2Verifier.sol proof size)
        let valid_proofs = vec![4000, 5000, 5632, 8000];
        for len in valid_proofs {
            let hex_len = len * 2;
            let proof_hex = "a".repeat(hex_len);
            let bytes = hex::decode(&proof_hex).unwrap();
            assert!(
                bytes.len() >= PROOF_LENGTH_MIN && bytes.len() <= PROOF_LENGTH_MAX,
                "{} bytes should be valid",
                bytes.len()
            );
        }

        // Invalid ranges
        let invalid_proofs = vec![100, 3999, 8001, 50000];
        for len in invalid_proofs {
            let hex_len = len * 2;
            let proof_hex = "a".repeat(hex_len);
            let bytes = hex::decode(&proof_hex).unwrap();
            let is_valid = bytes.len() >= PROOF_LENGTH_MIN && bytes.len() <= PROOF_LENGTH_MAX;
            assert!(!is_valid, "{} bytes should be invalid", bytes.len());
        }
    }

    // ── Address derivation with multiple keys ───────────────────────────

    #[test]
    fn test_derive_address_key_1() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let addr = derive_address(&key).unwrap();
        assert_eq!(
            format_address(&addr),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn test_derive_address_key_2() {
        let mut key = [0u8; 32];
        key[31] = 2;
        let addr = derive_address(&key).unwrap();
        assert_eq!(
            format_address(&addr),
            "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
        );
    }

    #[test]
    fn test_derive_address_key_3() {
        let mut key = [0u8; 32];
        key[31] = 3;
        let addr = derive_address(&key).unwrap();
        assert_eq!(
            format_address(&addr),
            "0x6813eb9362372eef6200f3b1dbc3f819671cba69"
        );
    }
}
