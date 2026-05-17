//! ZKMist CLI command implementations.
//!
//! Each function corresponds to a CLI subcommand and returns `Result<(), String>`
//! with a human-readable error message on failure.

use std::io::{self, Write};

use sha2::{Digest as Sha2Digest, Sha256};
use zkmist_merkle_tree::{
    build_tree_streaming, compute_nullifier, deserialize_proof, hash_leaf, serialize_proof,
    verify_merkle_proof, PADDING_SENTINEL,
};

use crate::abi::*;
use crate::constants::*;
use crate::download::*;
use crate::guest::*;
use crate::helpers::*;
use crate::types::*;

use alloy::sol_types::SolCall;

// ── Command: fetch ───────────────────────────────────────────────────────

pub fn cmd_fetch(cid: Option<&str>, source: &str, no_verify: bool) -> Result<(), String> {
    let download_source = parse_source(source)?;
    let dir = eligibility_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;

    // Resolve which CID to use for IPFS downloads.
    let ipfs_cid = cid.unwrap_or(FALLBACK_IPFS_CID);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;

    // ── Step 1: Fetch manifest and verify against known Merkle root ──────
    let manifest = fetch_manifest(&rt, download_source, ipfs_cid)?;

    // Verify manifest merkle root against our compile-time constant.
    let known_root = KNOWN_MERKLE_ROOT
        .strip_prefix("0x")
        .unwrap_or(KNOWN_MERKLE_ROOT);
    if manifest
        .merkle_root
        .strip_prefix("0x")
        .unwrap_or(&manifest.merkle_root)
        != known_root
    {
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
            return Err(format!("Failed to download {} from any source", filename));
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

// ── Command: prove ───────────────────────────────────────────────────────

pub fn cmd_prove(key_file: Option<&str>) -> Result<(), String> {
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

        // Find address index via binary search (list must be sorted — enforced by load_eligibility_list)
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

    // Serialize the receipt for local verification.
    //
    // ⚠️ Uses bincode v1 which is tied to risc0-zkvm v3's internal serialization.
    // If risc0-zkvm upgrades to bincode v2, this serialized format will break
    // for cross-version proof files. Proof files generated by one CLI version
    // should be verified by the same version. The receipt_hex field is optional
    // and local verification degrades gracefully if deserialization fails.
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

// ── Command: submit ──────────────────────────────────────────────────────

pub fn cmd_submit(
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
        let hex_str = key_hex.strip_prefix("0x").unwrap_or(key_hex);
        if hex_str.len() != 64 {
            return Err("Invalid private key length (expected 64 hex chars)".to_string());
        }
        hex_str.to_string()
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
        let call = claimCall {
            _proof: proof_bytes.clone(),
            _journal: journal_bytes.clone(),
            _nullifier: nullifier_bytes,
            _recipient: recipient_address,
        };
        let call_data = call.abi_encode();

        // Build transaction with gas estimation.
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

pub fn cmd_verify(proof_file: &str) -> Result<(), String> {
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

    // Track the level of verification achieved.
    let mut verification_level: u8 = 0;

    if let Some(img_id) = image_id {
        eprintln!("  Image ID: {}", hex::encode(img_id.as_bytes()));

        if let Some(ref receipt_hex) = proof.receipt_hex {
            let receipt_bytes = hex::decode(receipt_hex)
                .map_err(|e| format!("Failed to decode receipt hex: {}", e))?;
            let receipt: risc0_zkvm::Receipt = bincode::deserialize(&receipt_bytes)
                .map_err(|e| format!("Failed to deserialize receipt: {}", e))?;

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

pub fn cmd_check(address_str: &str) -> Result<(), String> {
    let address = parse_address(address_str)?;

    eprintln!("Checking eligibility for: {}", format_address(&address));
    eprintln!();

    // Load eligibility list
    let addresses = load_eligibility_list()?;
    eprintln!("Loaded {} eligible addresses", addresses.len());

    // Binary search (list must be sorted — enforced by load_eligibility_list)
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

pub fn cmd_status(rpc_url: Option<&str>) -> Result<(), String> {
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

        // Call totalClaims()
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

        // Call isClaimWindowOpen()
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

        // Convert from wei (10^18) to whole ZKM using integer arithmetic
        // to avoid f64 precision loss for large values (up to 10^28 wei).
        // f64 has 53-bit mantissa; 10^28 requires ~93 bits — too much precision loss.
        const WEI_PER_ZKM: u128 = 1_000_000_000_000_000_000;
        let on_chain_supply_u128: u128 = on_chain_supply.try_into().map_err(
            |e: alloy::primitives::ruint::FromUintError<u128>| {
                format!("totalSupply overflow: {}", e)
            },
        )?;
        let on_chain_zkm_whole = on_chain_supply_u128 / WEI_PER_ZKM;
        let minted_zkm_whole = minted_supply as u128; // already in whole ZKM

        eprintln!("Total claimed:  {}", total_claims_u64);
        eprintln!("Claims left:    {} / {}", remaining, MAX_CLAIMS);
        eprintln!("Minted supply:  {} ZKM ({:.1}% of max)", minted_supply, pct);

        let burned_zkm = minted_zkm_whole.saturating_sub(on_chain_zkm_whole);
        if burned_zkm > 0 {
            eprintln!(
                "On-chain supply: {} ZKM ({} ZKM burned)",
                on_chain_zkm_whole, burned_zkm
            );
        } else {
            eprintln!("On-chain supply: {} ZKM", on_chain_zkm_whole);
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
