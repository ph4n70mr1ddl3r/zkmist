//! ZKMist CLI command implementations.
//!
//! Each function corresponds to a CLI subcommand and returns `Result<(), String>`
//! with a human-readable error message on failure.

use std::io::{self, Write};

use sha2::{Digest as Sha2Digest, Sha256};
use zkmist_merkle_tree::{
    build_tree_streaming, compute_nullifier, deserialize_proof,
    hash_leaf, serialize_proof, verify_merkle_proof, TREE_DEPTH,
};

use crate::abi::*;
use crate::constants::*;
use crate::download::*;
use crate::helpers::*;
use crate::types::*;

use alloy::sol_types::SolCall;

// ── Command: fetch ───────────────────────────────────────────────────────

pub fn cmd_fetch(no_verify: bool) -> Result<(), String> {
    let dir = eligibility_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;

    // ── Step 1: Fetch manifest and verify against known Merkle root ──────
    let manifest = fetch_manifest(&rt)?;

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
        let downloaded = try_download_file(&rt, filename, &dest, expected_hash)?;
        if !downloaded {
            return Err(format!("Failed to download {} from GitHub", filename));
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

// ── Command: prove (Halo2-KZG) ──────────────────────────────────────────

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
        eprintln!("      Loading cached proof...");
        let file = std::fs::File::open(&cache_path)
            .map_err(|e| format!("Failed to open proof cache: {}", e))?;
        let reader = std::io::BufReader::new(file);
        let (cached_root, _leaf_index, cached_siblings, cached_path) =
            deserialize_proof(reader).map_err(|e| format!("Failed to read proof cache: {}", e))?;

        eprintln!("      ✓ Proof cache loaded ({} levels)", cached_siblings.len());
        eprintln!("      Root: {}", format_bytes32(&cached_root));

        if let Some(manifest) = load_manifest()? {
            verify_root_against_manifest(&cached_root, &manifest)?;
            eprintln!("      ✓ Root matches manifest");
        }

        (cached_root, cached_siblings, cached_path)
    } else {
        eprintln!("      No cached proof — building via streaming tree...");
        eprintln!("      ⚠️  This requires ~2 GB RAM. The result will be cached for future use.");

        let addresses = load_eligibility_list()?;
        eprintln!("      Loaded {} eligible addresses", addresses.len());

        let leaf_index = match addresses.binary_search(&address) {
            Ok(idx) => idx,
            Err(_) => {
                return Err(format!(
                    "Address {} is NOT in the eligibility tree.",
                    format_address(&address)
                ));
            }
        };

        let (streaming_root, proof) = build_tree_streaming(&addresses, Some(leaf_index));
        let (streaming_siblings, streaming_path) =
            proof.ok_or("Streaming build failed to produce proof")?;

        eprintln!("      ✓ Tree built ({} levels)", streaming_siblings.len());
        eprintln!("      Root: {}", format_bytes32(&streaming_root));

        if let Some(manifest) = load_manifest()? {
            verify_root_against_manifest(&streaming_root, &manifest)?;
            eprintln!("      ✓ Root matches manifest");
        }

        // Cache the proof
        std::fs::create_dir_all(proofs_dir())
            .map_err(|e| format!("Failed to create proofs dir: {}", e))?;
        let file = std::fs::File::create(&cache_path)
            .map_err(|e| format!("Failed to create proof cache: {}", e))?;
        let writer = std::io::BufWriter::new(file);
        serialize_proof(&streaming_root, leaf_index, &streaming_siblings, &streaming_path, writer)
            .map_err(|e| format!("Failed to write proof cache: {}", e))?;

        (streaming_root, streaming_siblings, streaming_path)
    };

    // Validate sibling count
    let expected_depth = zkmist_merkle_tree::TREE_DEPTH;
    if siblings.len() != expected_depth || path_indices.len() != expected_depth {
        return Err(format!(
            "Sibling/path count mismatch: {} siblings, {} path indices (expected {})",
            siblings.len(), path_indices.len(), expected_depth
        ));
    }

    // Verify Merkle proof locally
    let mut leaf_hasher = ark_poseidon_hasher(1).ok_or("Failed to create leaf hasher")?;
    let leaf = hash_leaf(&address, &mut leaf_hasher);
    let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
    if computed_root != root {
        return Err(format!(
            "Merkle proof verification failed: {} != {}",
            format_bytes32(&computed_root), format_bytes32(&root)
        ));
    }
    eprintln!("      ✓ Merkle proof verified locally");

    // Compute nullifier
    let mut interior_hasher = ark_poseidon_hasher(2).ok_or("Failed to create interior hasher")?;
    let nullifier = compute_nullifier(&private_key, &mut interior_hasher);
    eprintln!("      → Nullifier: {}", format_bytes32(&nullifier));

    // ── Step 3: Recipient ────────────────────────────────────────────────
    eprintln!("[3/4] Enter recipient:");
    let recipient = read_recipient_address()?;
    eprintln!("      → Recipient: {}", format_address(&recipient));

    // ── Step 4: Halo2-KZG proving ────────────────────────────────────────
    eprintln!("[4/4] Generating Halo2-KZG proof...");

    eprintln!();
    eprintln!("      ╔══════════════════════════════════════════════════════════╗");
    eprintln!("      ║  Ready to generate Halo2-KZG proof.                     ║");
    eprintln!("      ║  • Recipient: {}  ║", format_address(&recipient));
    eprintln!("      ║  • Amount:    {} ZKM                           ║", CLAIM_AMOUNT);
    eprintln!("      ║  • Duration:  ~10-30 seconds                           ║");
    eprintln!("      ║  • ⚠️  RECIPIENT IS IRREVOCABLE after proof generation   ║");
    eprintln!("      ╚══════════════════════════════════════════════════════════╝");
    eprint!("      Proceed? [y/N] ");
    io::stderr().flush().ok();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    if confirm.trim().to_lowercase() != "y" && confirm.trim().to_lowercase() != "yes" {
        return Err("Proof generation cancelled.".to_string());
    }

    // Convert siblings/path_indices to fixed arrays for the circuit
    let mut sibling_arr = [[0u8; 32]; TREE_DEPTH];
    let mut path_arr = [0u8; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        sibling_arr[i] = siblings[i];
        path_arr[i] = path_indices[i];
    }

    // Generate proof via Halo2
    std::fs::create_dir_all(proofs_dir())
        .map_err(|e| format!("Failed to create proofs dir: {}", e))?;
    let timestamp = timestamp_string();
    let proof_path = proofs_dir().join(format!("zkmist_proof_{}.json", timestamp));

    let _nullifier_result = crate::halo2_prover::generate_v2_proof(
        &private_key,
        &sibling_arr,
        &path_arr,
        &root,
        &recipient,
        &proof_path,
    )?;

    eprintln!();
    eprintln!("      ✓ Proof saved: {}", proof_path.display());
    eprintln!("      {} ZKM will be minted to {} on claim.", CLAIM_AMOUNT, format_address(&recipient));
    eprintln!("      Run: zkmist submit {}", proof_path.display());
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

    // Reject submission to the placeholder contract address.
    if proof.contract_address == "0x000000000000000000000000000000000000dEaD"
        || proof.contract_address.parse::<alloy::primitives::Address>() == Ok(alloy::primitives::Address::ZERO)
    {
        return Err(
            "Proof file contains a placeholder contract address. \
             The airdrop contract has not been deployed yet, \
             or this CLI version is outdated. \
             Update AIRDROP_CONTRACT in cli/src/constants.rs after deployment."
                .to_string(),
        );
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

        // Decode hex proof
        let proof_bytes: Bytes = hex::decode(&proof.proof)
            .map_err(|e| format!("Invalid proof hex: {}", e))?
            .into();

        // ABI-encode the claim call.
        // claim(bytes proof, bytes32 nullifier, address recipient)
        let call = claimCall {
            proof: proof_bytes,
            nullifier: nullifier_bytes,
            recipient: recipient_address,
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
                    "  ⚠️  Gas estimation failed: {}",
                    e
                );
                eprintln!(
                    "      Using fallback gas limit: {}",
                    FALLBACK_GAS_LIMIT
                );
                FALLBACK_GAS_LIMIT
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
    crate::halo2_prover::verify_v2_proof(std::path::Path::new(proof_file))
}

// ── Command: check ───────────────────────────────────────────────────────

pub fn cmd_check(address_str: &str) -> Result<(), String> {
    let address = parse_address(address_str)?;

    eprintln!("Checking eligibility for: {}", format_address(&address));
    eprintln!();

    // Load eligibility list
    match check_address_in_files(&address)? {
        Some(idx) => {
            eprintln!("✅ ELIGIBLE (found at index {})", idx);
            eprintln!();
            eprintln!("Run `zkmist prove` to generate a claim proof.");
        }
        None => {
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

        // ── Fire independent RPC calls concurrently ─────────────────────
        let total_claims_fut = async {
            let call = IZKMAirdrop::totalClaimsCall {};
            let tx = alloy::rpc::types::transaction::TransactionRequest::default()
                .to(contract)
                .input(call.abi_encode().into());
            let resp = provider.call(tx).await.map_err(|e| format!("totalClaims call failed: {}", e))?;
            IZKMAirdrop::totalClaimsCall::abi_decode_returns(&resp)
                .map_err(|e| format!("totalClaims decode failed: {}", e))
        };

        let is_open_fut = async {
            let call = IZKMAirdrop::isClaimWindowOpenCall {};
            let tx = alloy::rpc::types::transaction::TransactionRequest::default()
                .to(contract)
                .input(call.abi_encode().into());
            let resp = provider.call(tx).await.map_err(|e| format!("isClaimWindowOpen call failed: {}", e))?;
            IZKMAirdrop::isClaimWindowOpenCall::abi_decode_returns(&resp)
                .map_err(|e| format!("isClaimWindowOpen decode failed: {}", e))
        };

        let token_fut = async {
            let call = IZKMAirdrop::tokenCall {};
            let tx = alloy::rpc::types::transaction::TransactionRequest::default()
                .to(contract)
                .input(call.abi_encode().into());
            let resp = provider.call(tx).await.map_err(|e| format!("token() call failed: {}", e))?;
            IZKMAirdrop::tokenCall::abi_decode_returns(&resp)
                .map_err(|e| format!("token() decode failed: {}", e))
        };

        let (total_claims_result, is_open_result, token_result) =
            tokio::join!(total_claims_fut, is_open_fut, token_fut);

        let total_claims_return = total_claims_result?;
        let total_claims_u64: u64 = total_claims_return.try_into().map_err(
            |e: alloy::primitives::ruint::FromUintError<u64>| {
                format!("totalClaims overflow: {}", e)
            },
        )?;

        let is_open: bool = is_open_result?;
        let token_addr: alloy::primitives::Address = token_result?;

        // Call totalSupply() on ZKMToken (depends on token_addr from above)
        let supply_call = IZKMToken::totalSupplyCall {};
        let supply_tx = alloy::rpc::types::transaction::TransactionRequest::default()
            .to(token_addr)
            .input(supply_call.abi_encode().into());
        let supply_resp = provider
            .call(supply_tx)
            .await
            .map_err(|e| format!("totalSupply() call failed: {}", e))?;
        let on_chain_supply = IZKMToken::totalSupplyCall::abi_decode_returns(&supply_resp)
            .map_err(|e| format!("totalSupply() decode failed: {}", e))?;

        let remaining = MAX_CLAIMS.saturating_sub(total_claims_u64);
        let minted_supply = total_claims_u64 * CLAIM_AMOUNT;
        let pct = (total_claims_u64 as f64 / MAX_CLAIMS as f64) * 100.0;

        // Convert from wei (10^18) to whole ZKM using integer arithmetic
        const WEI_PER_ZKM: u128 = 1_000_000_000_000_000_000;
        let on_chain_supply_u128: u128 = on_chain_supply.try_into().map_err(
            |e: alloy::primitives::ruint::FromUintError<u128>| {
                format!("totalSupply overflow: {}", e)
            },
        )?;
        let on_chain_zkm_whole = on_chain_supply_u128 / WEI_PER_ZKM;
        let minted_zkm_whole = minted_supply as u128;

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
