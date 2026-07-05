//! ZKMist CLI command implementations.
//!
//! Each function corresponds to a CLI subcommand and returns `Result<(), String>`
//! with a human-readable error message on failure.

use std::io::{self, Write};

use zkmist_merkle_tree::halo2base::{
    build_tree_streaming, compute_nullifier, hash_leaf, verify_merkle_proof, Hasher,
};
use zkmist_merkle_tree::{deserialize_proof, serialize_proof, TREE_DEPTH};

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
        // Defense-in-depth path-traversal guard. `filename` drives
        // `dir.join(filename)` below and is read from the manifest (each file
        // is SHA-256 verified, but the manifest itself is not integrity-pinned
        // at fetch time). The compile-time `KNOWN_MERKLE_ROOT` check blocks a
        // *fake eligibility list*, but a crafted name like `../../.bashrc`
        // could still write outside the eligibility dir on a compromised
        // release. Require a bare basename (no separators, not `.`/`..`).
        let is_bare_basename = std::path::Path::new(filename)
            .file_name()
            .map(|f| f == std::ffi::OsStr::new(filename.as_str()))
            .unwrap_or(false);
        if !is_bare_basename {
            return Err(format!(
                "manifest contains a filename that is not a bare basename \
                 (path-traversal guard): {:?}",
                filename
            ));
        }
        // Normalize the manifest's expected hash to bare lowercase hex so the
        // comparison against `hex::encode(...)` (always lowercase) is robust to
        // a manifest that carries a `0x` prefix, surrounding whitespace, or
        // uppercase hex digits. The KZG-SRS path already normalizes this way
        // (`expected_hash.trim().to_lowercase()`); this aligns the eligibility
        // path so a stray uppercase/whitespace hash never falsely rejects a
        // valid download with a "SHA-256 mismatch".
        let expected_hash = file_entry
            .sha256
            .trim()
            .strip_prefix("0x")
            .unwrap_or(file_entry.sha256.trim())
            .to_lowercase();
        let dest = dir.join(filename);

        if dest.exists() {
            // Verify the existing file's hash by STREAMING it in 64 KiB chunks
            // (`verify_file_sha256` — the same streaming verifier the KZG-SRS
            // cache path uses), NOT by buffering the whole (~1.4 GB) CSV into
            // RAM via `std::fs::read`. Each eligibility file can be hundreds of
            // MB; the previous whole-file read OOM-killed `zkmist fetch` on
            // memory-constrained claimant hosts (the same class of unnecessary
            // whole-file buffering the SRS download avoids by streaming). On a
            // mismatch or unreadable file, fall through to re-download.
            match verify_file_sha256(&dest, &expected_hash) {
                Ok(true) => {
                    pb.inc(1);
                    continue;
                }
                Ok(false) => {
                    eprintln!(
                        "      ⚠  {} present but SHA-256 mismatch (stale/corrupt); re-downloading",
                        filename
                    );
                }
                Err(e) => {
                    eprintln!(
                        "      ⚠  Cannot verify existing {} ({}); re-downloading",
                        filename, e
                    );
                }
            }
        }

        // Try download sources in priority order
        let downloaded = try_download_file(filename, &dest, &expected_hash)?;
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
        eprintln!("      ⚠️  Builds the full 2^26 Poseidon tree (halo2-base). Parallel across");
        eprintln!("         CPU cores (~5-10 min on a modern multicore box); needs ~4-6 GB RAM.");

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
    let mut use_cache = false;
    let mut cached_data = None;

    if cache_path.exists() {
        eprintln!("      Loading cached proof...");
        if let Ok(file) = std::fs::File::open(&cache_path) {
            let reader = std::io::BufReader::new(file);
            if let Ok(data) = deserialize_proof(reader) {
                let (cached_root, _leaf_index, cached_siblings, cached_path) = data.clone();
                let mut valid = true;

                if let Some(manifest) = load_manifest()? {
                    if verify_root_against_manifest(&cached_root, &manifest).is_err() {
                        eprintln!(
                            "      ⚠ Cached proof root does not match manifest. Rebuilding..."
                        );
                        valid = false;
                    } else {
                        eprintln!("      ✓ Root matches manifest");
                    }
                }

                if valid {
                    eprintln!(
                        "      ✓ Proof cache loaded ({} levels)",
                        cached_siblings.len()
                    );
                    eprintln!("      Root: {}", format_bytes32(&cached_root));
                    use_cache = true;
                    cached_data = Some((cached_root, cached_siblings, cached_path));
                }
            } else {
                eprintln!("      ⚠ Failed to read proof cache. Rebuilding...");
            }
        }
    }

    let (root, siblings, path_indices) = if use_cache {
        cached_data.unwrap()
    } else {
        eprintln!("      No cached proof — building via streaming tree...");
        eprintln!("      ⚠️  Builds the full 2^26 Poseidon tree (halo2-base), parallel across CPU");
        eprintln!(
            "         cores (~5-10 min on a modern multicore box, ~4-6 GB RAM). Cached after."
        );

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
        serialize_proof(
            &streaming_root,
            leaf_index,
            &streaming_siblings,
            &streaming_path,
            writer,
        )
        .map_err(|e| format!("Failed to write proof cache: {}", e))?;

        (streaming_root, streaming_siblings, streaming_path)
    };

    // Validate sibling count
    let expected_depth = zkmist_merkle_tree::TREE_DEPTH;
    if siblings.len() != expected_depth || path_indices.len() != expected_depth {
        return Err(format!(
            "Sibling/path count mismatch: {} siblings, {} path indices (expected {})",
            siblings.len(),
            path_indices.len(),
            expected_depth
        ));
    }

    // Verify Merkle proof locally
    let leaf_hasher = Hasher::new();
    let leaf = hash_leaf(&address, &leaf_hasher);
    let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);
    if computed_root != root {
        return Err(format!(
            "Merkle proof verification failed: {} != {}",
            format_bytes32(&computed_root),
            format_bytes32(&root)
        ));
    }
    eprintln!("      ✓ Merkle proof verified locally");

    // Compute nullifier
    let interior_hasher = Hasher::new();
    let nullifier = compute_nullifier(&private_key, &interior_hasher);
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
    eprintln!(
        "      ║  • Amount:    {} ZKM                           ║",
        CLAIM_AMOUNT
    );
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
    sibling_arr[..TREE_DEPTH].copy_from_slice(&siblings[..TREE_DEPTH]);
    path_arr[..TREE_DEPTH].copy_from_slice(&path_indices[..TREE_DEPTH]);

    // Generate proof via Halo2
    std::fs::create_dir_all(proofs_dir())
        .map_err(|e| format!("Failed to create proofs dir: {}", e))?;
    let timestamp = timestamp_string();
    let proof_path = proofs_dir().join(format!("zkmist_proof_{}.json", timestamp));

    let _nullifier_result = crate::halo2_prover_axiom::generate_v2_proof_axiom(
        &private_key,
        &sibling_arr[..TREE_DEPTH],
        &path_arr[..TREE_DEPTH],
        &root,
        &recipient,
        &proof_path,
    )?;

    eprintln!();
    eprintln!("      ✓ Proof saved: {}", proof_path.display());
    eprintln!(
        "      {} ZKM will be minted to {} on claim.",
        CLAIM_AMOUNT,
        format_address(&recipient)
    );
    eprintln!("      Run: zkmist submit {}", proof_path.display());
    eprintln!("      Or send to any relayer.");
    eprintln!();
    eprintln!("      ⚠️  This proof file contains your nullifier and is traceable");
    eprintln!("         to your claim. Store securely and only share with trusted");
    eprintln!("         relayers. The qualified address is NOT revealed on-chain.");

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

    // Validate proof format version to catch outdated proof files
    if proof.proof_format_version != PROOF_FORMAT_VERSION {
        return Err(format!(
            "Proof format version {} doesn't match expected {}. \
             Regenerate the proof with the current CLI version.",
            proof.proof_format_version, PROOF_FORMAT_VERSION
        ));
    }

    // Validate proof byte length is within the expected range
    let proof_bytes_len = hex::decode(&proof.proof)
        .map_err(|e| format!("Invalid proof hex: {}", e))?
        .len();
    if !(PROOF_LENGTH_MIN..=PROOF_LENGTH_MAX).contains(&proof_bytes_len) {
        return Err(format!(
            "Proof length {} bytes is outside expected range [{}, {}]. \
             The proof may be corrupted or generated with wrong parameters.",
            proof_bytes_len, PROOF_LENGTH_MIN, PROOF_LENGTH_MAX
        ));
    }

    // ── Contract-address trust model ─────────────────────────────────
    // Pre-deployment (`AIRDROP_CONTRACT` is still the placeholder): reject any
    // proof file that carries the placeholder / zero address — there is no
    // contract to submit to yet.
    //
    // Post-deployment (once `AIRDROP_CONTRACT` is the real address): ALSO
    // require the proof file's address to equal the pinned constant, so the
    // JSON's `contract_address` is pure metadata, not a routing instruction.
    // This closes the footgun where a stale/tampered proof file silently
    // submits to the wrong contract after mainnet. `AIRDROP_CONTRACT` is the
    // single source of truth; the proof file must agree.
    let normalize_addr = |s: &str| -> String {
        s.trim()
            .strip_prefix("0x")
            .unwrap_or(s.trim())
            .to_lowercase()
    };
    let proof_addr = normalize_addr(&proof.contract_address);
    let pinned_addr = normalize_addr(AIRDROP_CONTRACT);
    let pinned_is_placeholder = pinned_addr == "000000000000000000000000000000000000dead";

    if proof_addr == "000000000000000000000000000000000000dead"
        || proof_addr == "0000000000000000000000000000000000000000"
    {
        return Err("Proof file contains a placeholder contract address. \
             The airdrop contract has not been deployed yet, \
             or this CLI version is outdated. \
             Update AIRDROP_CONTRACT in cli/src/constants.rs after deployment."
            .to_string());
    }
    if !pinned_is_placeholder && proof_addr != pinned_addr {
        return Err(format!(
            "Proof file's contract address (0x{proof_addr}) does not match the CLI's pinned \
             AIRDROP_CONTRACT (0x{pinned_addr}). The proof was generated for a different \
             deployment. Regenerate the proof with the current CLI, or — if you intentionally \
             deployed a new contract — update AIRDROP_CONTRACT in cli/src/constants.rs."
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
                // +20% buffer over the RPC estimate (a claim reverts on gas
                // underestimation, so pad generously). Computed in u128 to stay
                // overflow-proof regardless of the estimate's integer width.
                let buffered = (base as u128 + (base as u128) / 5) as u64;
                eprintln!(
                    "  Gas estimate: {} (using {} with 20% buffer)",
                    base, buffered
                );
                buffered
            }
            Err(e) => {
                eprintln!("  ⚠️  Gas estimation failed: {}", e);
                eprintln!("      Using fallback gas limit: {}", FALLBACK_GAS_LIMIT);
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

// ── Command: bench ───────────────────────────────────────────────────────

/// Benchmark the proving pipeline with a small Merkle tree.
///
/// Generates a proof for a synthetic tree and reports timing for each phase:
///   1. Merkle tree construction
///   2. KZG params loading/generation
///   3. VK/PK generation
///   4. Proof creation
///   5. Local verification
pub fn cmd_bench(tree_depth: usize) -> Result<(), String> {
    use zkmist_circuits::merkle_axiom::TREE_DEPTH;
    use zkmist_merkle_tree::halo2base::{build_single_leaf_proof, build_tree_streaming_with_depth};

    let depth = tree_depth.clamp(1, 26);

    eprintln!("ZKMist Proving Benchmark");
    eprintln!("────────────────────────");
    eprintln!("Tree depth: {}", depth);
    eprintln!();

    // Use the standard test key
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    // Derive address
    let address = derive_address(&key)?;
    eprintln!("Address: {}", format_address(&address));

    // Phase 1: Build Merkle tree
    eprintln!();
    eprintln!(
        "[1/4] Building Merkle tree (dense build depth={})...",
        depth
    );
    let t1 = std::time::Instant::now();
    // INFORMATIONAL dense-tree-construction benchmark only: times a streaming
    // build at the caller-requested `depth` so Merkle-build scalability can be
    // measured. Its output is intentionally NOT used for the proof — see below.
    let addresses = vec![address];
    let (_dense_root, _dense_proof) = build_tree_streaming_with_depth(&addresses, depth, Some(0));

    // Build the VALID full-depth Merkle proof the circuit requires.
    //
    // The circuit ALWAYS iterates 0..TREE_DEPTH (26 levels), so the proof MUST
    // be a full-depth path. The previous code built a depth-`depth` tree and
    // zero-padded the siblings to TREE_DEPTH — but a depth-`depth` root is NOT
    // equal to the depth-26 root the circuit computes over the padded path
    // (the extra levels hash `poseidon(node, Fr(0))`, not the padding sentinel),
    // so the circuit's root-binding constraint `constrain_instance(computed,
    // instance)` was unsatisfiable and `generate_v2_proof` ALWAYS failed for
    // any `depth < 26` (i.e. the documented default and every e2e-test.sh
    // invocation). `build_single_leaf_proof` yields the O(depth) full-depth
    // path the circuit expects — the same builder the E2E circuit test and
    // `gen-roundtrip-fixture` use — so the emitted proof verifies.
    let (root_ark, siblings_ark, path_indices_u8) = build_single_leaf_proof(&address, TREE_DEPTH);
    let tree_build_time = t1.elapsed();
    eprintln!(
        "      ✓ Merkle proof built ({:.2}s)",
        tree_build_time.as_secs_f64()
    );

    let mut sibling_arr = [[0u8; 32]; TREE_DEPTH];
    let mut path_arr = [0u8; TREE_DEPTH];
    sibling_arr.copy_from_slice(&siblings_ark);
    path_arr.copy_from_slice(&path_indices_u8);

    // Phase 2-4: Proving pipeline via halo2_prover
    eprintln!("[2/4] Running proving pipeline...");
    let bench_dir = std::path::PathBuf::from("/tmp/zkmist_bench");
    std::fs::create_dir_all(&bench_dir).ok();
    let proof_path = bench_dir.join("bench_proof.json");

    let mut recipient = [0u8; 20];
    recipient[19] = 0x0B;
    recipient[18] = 0xB0;

    let total_start = std::time::Instant::now();
    crate::halo2_prover_axiom::generate_v2_proof_axiom(
        &key,
        &sibling_arr,
        &path_arr,
        &root_ark,
        &recipient,
        &proof_path,
    )?;
    let total_time = total_start.elapsed();

    // Report proof file size
    let proof_content = std::fs::read_to_string(&proof_path)
        .map_err(|e| format!("Failed to read bench proof: {}", e))?;
    let proof_file: crate::types::ProofFile = serde_json::from_str(&proof_content)
        .map_err(|e| format!("Failed to parse bench proof: {}", e))?;
    let proof_bytes = hex::decode(&proof_file.proof)
        .map_err(|e| format!("bench proof is not valid hex: {}", e))?;

    // Cleanup
    std::fs::remove_file(&proof_path).ok();

    eprintln!();
    eprintln!("══════════════════════════════════════════════════════");
    eprintln!("  Benchmark Results");
    eprintln!("══════════════════════════════════════════════════════");
    eprintln!("  Total proving time:  {:.2}s", total_time.as_secs_f64());
    eprintln!(
        "  Tree build time:     {:.2}s",
        tree_build_time.as_secs_f64()
    );
    eprintln!("  Proof size:          {} bytes", proof_bytes.len());
    eprintln!(
        "  Proof in range:      {}",
        if proof_bytes.len() >= PROOF_LENGTH_MIN && proof_bytes.len() <= PROOF_LENGTH_MAX {
            "✅ YES"
        } else {
            "❌ NO"
        }
    );
    eprintln!("  Tree depth:          {}", depth);
    eprintln!("══════════════════════════════════════════════════════");
    eprintln!();
    if total_time.as_secs() < 60 {
        eprintln!("  ✅ Proving time under 60s target");
    } else {
        eprintln!(
            "  ⚠️  Proving time exceeds 60s target ({:.0}s)",
            total_time.as_secs_f64()
        );
    }
    if proof_bytes.len() >= PROOF_LENGTH_MIN && proof_bytes.len() <= PROOF_LENGTH_MAX {
        eprintln!(
            "  ✅ Proof size in expected range [{}, {}]",
            PROOF_LENGTH_MIN, PROOF_LENGTH_MAX
        );
    } else {
        eprintln!(
            "  ⚠️  Proof size {} outside expected range [{}, {}]",
            proof_bytes.len(),
            PROOF_LENGTH_MIN,
            PROOF_LENGTH_MAX
        );
    }

    Ok(())
}

// ── Command: gen-roundtrip-fixture ────────────────────────────────────────
//
// Generates the fixture consumed by the Forge on-chain round-trip test
// (contracts/test/ZKM.realroundtrip.t.sol). It builds a FULL-DEPTH
// (TREE_DEPTH=26) eligibility tree containing the test-vector address,
// generates a REAL Halo2-KZG proof against it, and writes a single JSON the
// Forge test can parse straight into `ZKMAirdrop.claim(proof, nullifier,
// recipient)`.
//
// This is the prover side of the "real-KZG → on-chain verifier" loop.
// The on-chain verifier (`contracts/src/Halo2Verifier.axiom.sol`, emitted by
// `circuits/tests/claim_evm_roundtrip.rs` at circuit k=21) is already real; once
// this fixture exists, `RUN_REAL_ROUNDTRIP=1 forge test` performs the honest
// on-chain verification.
//
// Requires either a pinned PSE KZG SRS (KZG_SRS_URL/KZG_SRS_SHA256 in
// constants.rs) or ZKMIST_DEV_SRS=1 for a local forgeable SRS (dev/test
// only — the proof verifies but is forgeable, so it validates the verifier
// code path, not soundness).
pub fn cmd_gen_roundtrip_fixture(out_path: &str) -> Result<(), String> {
    use serde::Serialize;
    use zkmist_circuits::merkle_axiom::TREE_DEPTH;

    eprintln!("ZKMist real-KZG round-trip fixture generator");
    eprintln!("─\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    eprintln!(
        "Builds a full-depth (TREE_DEPTH={}) eligibility tree containing the",
        TREE_DEPTH
    );
    eprintln!("test-vector address, generates a REAL Halo2-KZG proof, and writes a");
    eprintln!("fixture JSON for contracts/test/ZKM.realroundtrip.t.sol.");
    eprintln!();
    eprintln!("Requires a pinned PSE KZG SRS (constants.rs) OR ZKMIST_DEV_SRS=1.");
    eprintln!();

    // Standard test-vector private key (matches `zkmist bench` + the circuit's
    // address test: 0xfcad0b19bb29d4674531d6f115237e16afce377c).
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let address = derive_address(&key)?;
    eprintln!(
        "[1/4] Eligible address (test vector): {}",
        format_address(&address)
    );

    // The fixture places a SINGLE address at leaf index 0, so use the
    // O(depth) single-leaf builder instead of materializing the full 2^depth
    // dense tree. `build_single_leaf_proof` reproduces
    // `build_tree_streaming_with_depth(&[addr], depth, Some(0))` exactly (see
    // `test_single_leaf_proof_matches_streaming` in zkmist-merkle-tree) but
    // does 26 hashes instead of 67M — the dense build wastes ~3 GiB RAM and
    // ~12 min single-threaded for a proof that is fully determined by the
    // all-padding subtree roots. Same root, same siblings, same path indices.
    eprintln!(
        "[2/4] Building full-depth Merkle proof (depth={}, single leaf at index 0)...",
        TREE_DEPTH
    );
    let (root, siblings_ark, path_indices_u8) =
        zkmist_merkle_tree::halo2base::build_single_leaf_proof(&address, TREE_DEPTH);
    let mut sibling_arr = [[0u8; 32]; TREE_DEPTH];
    let mut path_arr = [0u8; TREE_DEPTH];
    let copy_len = siblings_ark.len().min(TREE_DEPTH);
    sibling_arr[..copy_len].copy_from_slice(&siblings_ark[..copy_len]);
    path_arr[..copy_len].copy_from_slice(&path_indices_u8[..copy_len]);

    // Fixed, clearly-test recipient (matches `zkmist bench`).
    let mut recipient = [0u8; 20];
    recipient[18] = 0xB0;
    recipient[19] = 0x0B;

    // Generate the REAL KZG proof. Under a pinned SRS this is mainnet-grade;
    // under ZKMIST_DEV_SRS it is forgeable but still exercises the full
    // create_proof → transcript path (sufficient to validate the verifier).
    eprintln!("[3/4] Generating real Halo2-KZG proof (heavy; real-KZG proving peaks well under ~10 GiB at k=21 on the axiom backend)...");
    let tmp = std::env::temp_dir().join("zkmist_roundtrip_proof.json");
    let nullifier = crate::halo2_prover_axiom::generate_v2_proof_axiom(
        &key,
        &sibling_arr,
        &path_arr,
        &root,
        &recipient,
        &tmp,
    )?;
    let proof_json = std::fs::read_to_string(&tmp)
        .map_err(|e| format!("Failed to read generated proof: {}", e))?;
    let proof_file: ProofFile = serde_json::from_str(&proof_json)
        .map_err(|e| format!("Failed to parse generated proof: {}", e))?;
    let _ = std::fs::remove_file(&tmp);
    let proof_hex = proof_file.proof.trim_start_matches("0x");

    #[derive(Serialize)]
    struct Fixture {
        version: u64,
        tree_depth: u32,
        merkle_root: String,
        nullifier: String,
        recipient: String,
        proof: String,
        claim_amount: String,
        note: String,
    }
    let fixture = Fixture {
        version: PROOF_FORMAT_VERSION,
        tree_depth: TREE_DEPTH as u32,
        merkle_root: format!("0x{}", hex::encode(root)),
        nullifier: format!("0x{}", hex::encode(nullifier)),
        recipient: format!("0x{}", hex::encode(recipient)),
        proof: format!("0x{}", proof_hex),
        claim_amount: format!("{}", (CLAIM_AMOUNT as u128) * 10u128.pow(18)),
        note: "Generated by `zkmist gen-roundtrip-fixture`. Real Halo2-KZG proof \
               over the full production circuit (TREE_DEPTH=26). Consumed by \
               contracts/test/ZKM.realroundtrip.t.sol with RUN_REAL_ROUNDTRIP=1."
            .to_string(),
    };

    eprintln!("[4/4] Writing fixture to {}", out_path);
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create fixture dir: {}", e))?;
    }
    let json = serde_json::to_string_pretty(&fixture)
        .map_err(|e| format!("Failed to serialize fixture: {}", e))?;
    // Atomic write: render to a sibling .partial, then `rename()` (atomic on
    // the same filesystem). A crash mid-write therefore never leaves a
    // truncated/half-written real_roundtrip.json that the Forge test would
    // parse as junk — the worst case is a leftover .partial, not corruption.
    let partial = format!("{}.partial", out_path);
    std::fs::write(&partial, &json)
        .map_err(|e| format!("Failed to write fixture (partial {}): {}", partial, e))?;
    std::fs::rename(&partial, out_path).map_err(|e| {
        let _ = std::fs::remove_file(&partial);
        format!("Failed to finalize fixture (rename → {}): {}", out_path, e)
    })?;

    eprintln!();
    eprintln!("\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}");
    eprintln!("  Fixture written: {}", out_path);
    eprintln!("\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}");
    eprintln!("  merkleRoot : {}", fixture.merkle_root);
    eprintln!("  nullifier  : {}", fixture.nullifier);
    eprintln!("  recipient  : {}", fixture.recipient);
    eprintln!("  proof bytes: {}", proof_hex.len() / 2);
    eprintln!();
    eprintln!("Next: run the on-chain round-trip against this fixture:");
    eprintln!("  RUN_REAL_ROUNDTRIP=1 forge test --match-contract RealRoundtrip -vvv");
    Ok(())
}

// ── Command: verify ──────────────────────────────────────────────────────

pub fn cmd_verify(_proof_file: &str) -> Result<(), String> {
    // The PSE Rust-side verifier was removed with the PSE stack. On-chain
    // verification (ZKMAirdrop.claim → axiom Halo2Verifier) is authoritative;
    // for off-chain checks use `RUN_REAL_ROUNDTRIP=1 forge test --match-contract
    // RealRoundtrip`.
    Err("local proof verification is on-chain only (the PSE verifier was removed)".into())
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
                    .expect("hardcoded dead address is valid")
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
            let resp = provider
                .call(tx)
                .await
                .map_err(|e| format!("totalClaims call failed: {}", e))?;
            IZKMAirdrop::totalClaimsCall::abi_decode_returns(&resp)
                .map_err(|e| format!("totalClaims decode failed: {}", e))
        };

        let is_open_fut = async {
            let call = IZKMAirdrop::isClaimWindowOpenCall {};
            let tx = alloy::rpc::types::transaction::TransactionRequest::default()
                .to(contract)
                .input(call.abi_encode().into());
            let resp = provider
                .call(tx)
                .await
                .map_err(|e| format!("isClaimWindowOpen call failed: {}", e))?;
            IZKMAirdrop::isClaimWindowOpenCall::abi_decode_returns(&resp)
                .map_err(|e| format!("isClaimWindowOpen decode failed: {}", e))
        };

        let token_fut = async {
            let call = IZKMAirdrop::tokenCall {};
            let tx = alloy::rpc::types::transaction::TransactionRequest::default()
                .to(contract)
                .input(call.abi_encode().into());
            let resp = provider
                .call(tx)
                .await
                .map_err(|e| format!("token() call failed: {}", e))?;
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
