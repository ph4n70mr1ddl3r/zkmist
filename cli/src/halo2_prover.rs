//! Halo2-KZG prover integration for ZKMist V2.
//!
//! Generates Halo2-KZG proofs using the `zkmist-circuits` crate.
//! The full circuit enforces: secp256k1 key→address, Poseidon leaf hash,
//! 26-level Merkle proof, nullifier (V2 domain), and non-zero recipient.

use std::path::Path;

use ark_ff::{BigInteger, PrimeField};
use zkmist_circuits::{
    merkle::TREE_DEPTH, nullifier::domain_field_element, poseidon::ark_to_halo2, ZKMistV2Claim,
};
use zkmist_merkle_tree::compute_nullifier;

use crate::constants::*;
use crate::types::ProofFile;

/// Default k parameter for the circuit (2^23 = 8.4M rows).
///
/// The full circuit (secp256k1 + Keccak + Poseidon + Merkle) measures
/// **8,028,779 rows** (pinned by `test_measure_circuit_rows`), which fits in
/// 2^23 = 8,388,608 with ~360K rows of headroom. k=22 (4.2M rows) does not fit.
///
/// k was 24 (16M rows) until the secp256k1 `point_add_mixed` optimization
/// (mixed Jacobian+affine addition: 16→11 `field_mul` per scalar-mul step,
/// ~1,280 fewer `field_mul` across the 256-step double-and-add), which shaved
/// the ~360K rows that had pushed it just over 2^23. This halved the peak RSS
/// (~30 GiB → ~15 GiB), letting the prover run on a 32 GiB host.
///
/// Validated end-to-end (`test_circuit_merkle_nullifier_e2e` PASSES at k=23).
/// ⚠️  This MUST match the k used to generate Halo2VerifyingKey.sol.
/// Run gen-production-verifier with --k 23 to regenerate the VK.
const CIRCUIT_K: u32 = 23;

// ── KZG SRS loading ───────────────────────────────────────────────────
//
// Halo2-KZG commits against a Structured Reference String (SRS). The prover
// LOADS it via `Params::read` from a transcript file rather than generating
// one, because a self-generated SRS is a 1-of-1 trust root (whoever ran it
// knows the trapdoor and can forge proofs).
//
// Production path (KZG_SRS_URL + KZG_SRS_SHA256 pinned in constants.rs):
//   1. stream-download the PSE perpetual powers-of-tau halo2 params file to
//      ~/.zkmist/cache/ (never buffered in memory — it's hundreds of MB);
//   2. verify its SHA-256 against the pinned KZG_SRS_SHA256;
//   3. `Params::read` it.
// Each claimant does this ONCE; the cached file is re-verified against the
// pinned hash on every run, so a tampered cache is rejected. The deployer
// cannot forge proofs because they do not know the PSE ceremony's trapdoor.
//
// Dev path: if the trust root is not pinned AND `ZKMIST_DEV_SRS=1` is set,
// fall back to `Params::new(k)` (a RANDOM SRS) so local tests/benchmarks run
// without the large download. This is dev/test ONLY and is surfaced by the
// readiness checker. See docs/kzg-srs.md for obtaining/verifying the real
// transcript.

fn get_cache_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("Cannot find home directory")?;
    let cache_dir = home.join(ZKMIST_DIR_NAME).join("cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache dir: {}", e))?;
    Ok(cache_dir)
}

fn cached_params_path(k: u32) -> Result<std::path::PathBuf, String> {
    Ok(get_cache_dir()?.join(format!("v2_params_k{}.bin", k)))
}

/// Assert the loaded SRS params are at exactly the circuit's k.
///
/// `Params::read` takes the file's embedded k as-is (no truncation), and the
/// prover allocates a witness grid of `2^params.k()` rows. So a file at the
/// WRONG k is not benign:
///   - `params.k() < CIRCUIT_K` → halo2 rejects with `NotEnoughRowsAvailable`
///     (the circuit doesn't fit).
///   - `params.k() > CIRCUIT_K` → `create_proof` still allocates `2^params.k()`
///     rows (e.g. a k=26 file with the k=23 circuit → 64M rows → ~120 GiB RSS,
///     OOM), AND every proof verifies against a domain the on-chain verifier
///     (which embeds the VK's k) does not expect → proofs fail on-chain with a
///     confusing error.
///
/// The on-chain `Halo2Verifier` embeds `k` as a constant derived from the VK,
/// so the prover, the VK generator, and the verifier MUST all share the exact
/// same k. This check turns a silent misconfiguration into a loud, clear error.
///
/// Common cause of a mismatch after a k bump: a stale cache file
/// (`~/.zkmist/cache/v2_params_k{k}.bin`) left over from a previous version,
/// or a pinned `KZG_SRS_URL` pointing at a file extracted at the wrong k.
fn ensure_params_k(
    params: &halo2_proofs::poly::commitment::Params<halo2curves::bn256::G1Affine>,
    expected_k: u32,
) -> Result<(), String> {
    let actual_k = params.k();
    if actual_k == expected_k {
        return Ok(());
    }
    Err(format!(
        "KZG SRS k mismatch: file is k={} ({} rows) but this build expects k={} ({} rows). \
         The prover, the verifying-key generator, and the on-chain verifier must all use the \
         SAME k. A larger-k file would allocate {}× more memory during proving and produce \
         proofs the on-chain verifier rejects. Delete the stale cache \
         (~/.zkmist/cache/v2_params_k*.bin) or re-pin KZG_SRS_URL to a k={} file. \
         See docs/kzg-srs.md.",
        actual_k,
        1u64 << actual_k,
        expected_k,
        1u64 << expected_k,
        1u64 << (actual_k - expected_k),
        expected_k,
    ))
}

/// Load the KZG SRS: cache → download+verify → dev fallback.
///
/// Production (KZG_SRS_URL + KZG_SRS_SHA256 pinned in constants.rs): stream
/// the pinned PSE halo2 params file to the cache dir, verify its SHA-256, and
/// `Params::read` it. A cached file is re-verified against the pinned hash so
/// a tampered cache is rejected. This is the only path that produces proofs
/// safe for mainnet.
///
/// Dev fallback (ZKMIST_DEV_SRS=1, trust root NOT pinned): generate a RANDOM
/// SRS via `Params::new` so local tests/benchmarks work without the large
/// download. Dev/test ONLY — proofs are forgeable by the operator.
fn load_or_download_params(
    k: u32,
) -> Result<halo2_proofs::poly::commitment::Params<halo2curves::bn256::G1Affine>, String> {
    use halo2_proofs::poly::commitment::Params;
    use halo2curves::bn256::G1Affine;
    use std::io::{BufReader, BufWriter};

    let path = cached_params_path(k)?;
    let pinned_hash = KZG_SRS_SHA256.trim();
    let pinned_url = KZG_SRS_URL.trim();
    let production = !pinned_hash.is_empty() && !pinned_url.is_empty();

    // ── 1. Cache hit (re-verify against the pinned hash in production) ──
    if path.exists() {
        if production {
            match crate::download::verify_file_sha256(&path, pinned_hash) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "         ⚠️  Cached KZG SRS SHA-256 mismatch (tampered or stale); re-downloading"
                    );
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    eprintln!(
                        "         ⚠️  Cannot verify cached SRS ({}); ignoring cache",
                        e
                    );
                }
            }
        }
        if path.exists() {
            eprintln!("         Loading KZG SRS from {}...", path.display());
            match std::fs::File::open(&path) {
                Ok(file) => match Params::<G1Affine>::read(&mut BufReader::new(file)) {
                    Ok(params) => {
                        ensure_params_k(&params, k)?;
                        eprintln!(
                            "         ✓ KZG SRS loaded{}",
                            if production {
                                " (SHA-256 verified)"
                            } else {
                                ""
                            }
                        );
                        return Ok(params);
                    }
                    Err(e) => eprintln!("         ⚠️  Cached SRS unreadable ({}); re-fetching", e),
                },
                Err(e) => {
                    eprintln!("         ⚠️  Cannot open cached SRS ({}); re-fetching", e)
                }
            }
        }
    }

    // ── 2. Production: stream-download + verify + cache ────────────────
    if production {
        eprintln!(
            "         Downloading KZG SRS (k={}, {} rows)...",
            k,
            1u64 << k
        );
        let bytes = crate::download::download_and_verify_to_file(pinned_url, pinned_hash, &path)?;
        eprintln!("         ✓ Downloaded and verified ({} bytes)", bytes);
        let file =
            std::fs::File::open(&path).map_err(|e| format!("Cannot open downloaded SRS: {e}"))?;
        let params = Params::<G1Affine>::read(&mut BufReader::new(file))
            .map_err(|e| format!("Downloaded SRS failed to parse: {e}"))?;
        ensure_params_k(&params, k)?;
        return Ok(params);
    }

    // ── 3. Dev fallback (RANDOM SRS) ──────────────────────────────────
    if std::env::var("ZKMIST_DEV_SRS").is_ok() {
        eprintln!("         ⚠️  ZKMIST_DEV_SRS=1 — generating a RANDOM SRS (dev/test ONLY)");
        eprintln!(
            "            Do NOT use proofs from this SRS on mainnet — they are forgeable by you."
        );
        let params = Params::<G1Affine>::new(k);
        // Cache for dev convenience (no hash to pin).
        if let Ok(file) = std::fs::File::create(&path) {
            if params.write(&mut BufWriter::new(file)).is_err() {
                let _ = std::fs::remove_file(&path);
            }
        }
        return Ok(params);
    }

    Err(
        "No KZG SRS configured. Either:\n  \
             (a) pin KZG_SRS_URL + KZG_SRS_SHA256 in cli/src/constants.rs (production — see docs/kzg-srs.md), or\n  \
             (b) set ZKMIST_DEV_SRS=1 for local dev/test (generates a RANDOM, forgeable SRS)."
            .to_string(),
    )
}

/// Generate a Halo2-KZG proof for a V2 claim.
///
/// # Arguments
///
/// * `private_key` - The claimant's secp256k1 private key (32 bytes)
/// * `siblings` - Merkle proof sibling hashes (26 × 32 bytes)
/// * `path_indices` - Merkle proof direction flags (26 bytes, each 0 or 1)
/// * `merkle_root` - The eligibility tree root (32 bytes)
/// * `recipient` - The recipient address (20 bytes)
/// * `output_path` - Where to save the proof file
///
/// # Returns
///
/// The nullifier (32 bytes) on success.
pub fn generate_v2_proof(
    private_key: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    path_indices: &[u8; TREE_DEPTH],
    merkle_root: &[u8; 32],
    recipient: &[u8; 20],
    output_path: &Path,
) -> Result<[u8; 32], String> {
    // ── Compute public inputs natively ───────────────────────────────
    let root_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(merkle_root));

    // Compute nullifier using domain separator ("ZKMist_V2_NULLIFIER").
    // This MUST match the domain used inside the Halo2 circuit's nullifier gadget.
    let mut interior_hasher =
        crate::helpers::ark_poseidon_hasher(2).ok_or("Failed to create Poseidon hasher")?;
    let nullifier_bytes = compute_nullifier(private_key, &mut interior_hasher);
    let nullifier_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&nullifier_bytes));

    // Cross-check: the circuit's native nullifier must match
    {
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(private_key));
        let domain = domain_field_element();
        let circuit_nullifier_params = zkmist_circuits::PoseidonParams::new_circom(2);
        let circuit_nullifier = zkmist_circuits::poseidon::native_poseidon(
            &circuit_nullifier_params,
            &[key_field, domain],
        );
        let circuit_nullifier_ark = zkmist_circuits::poseidon::halo2_to_ark(&circuit_nullifier);
        let cli_nullifier_ark = ark_bn254::Fr::from_be_bytes_mod_order(&nullifier_bytes);
        if circuit_nullifier_ark != cli_nullifier_ark {
            let circuit_bytes: Vec<u8> = circuit_nullifier_ark.into_bigint().to_bytes_be().to_vec();
            let cli_bytes: Vec<u8> = cli_nullifier_ark.into_bigint().to_bytes_be().to_vec();
            return Err(format!(
                "Nullifier mismatch between CLI and circuit! CLI: 0x{}, Circuit: 0x{}",
                hex::encode(cli_bytes),
                hex::encode(circuit_bytes),
            ));
        }
    }

    // Recipient as field element (left-padded to 32 bytes)
    let mut recipient_padded = [0u8; 32];
    recipient_padded[12..32].copy_from_slice(recipient);
    let recipient_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&recipient_padded));

    // ── Build the circuit ────────────────────────────────────────────
    let circuit = ZKMistV2Claim {
        private_key: *private_key,
        siblings: *siblings,
        path_indices: *path_indices,
        merkle_root: root_fr,
        nullifier: nullifier_fr,
        recipient: recipient_fr,
    };

    // ── Generate proof ───────────────────────────────────────────────
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use halo2curves::bn256::G1Affine;

    let k = CIRCUIT_K;
    let start = std::time::Instant::now();

    eprintln!("      [1/5] Loading KZG parameters (k={})...", k);
    let params = load_or_download_params(k)?;
    eprintln!(
        "      [1/5] KZG params ready ({:.1}s)",
        start.elapsed().as_secs_f64()
    );

    eprintln!("      [2/5] Generating verification key...");
    let vk_start = std::time::Instant::now();
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("VK generation failed: {:?}", e))?;
    let pk =
        keygen_pk(&params, vk, &circuit).map_err(|e| format!("PK generation failed: {:?}", e))?;
    eprintln!(
        "      [2/5] VK/PK generated ({:.1}s)",
        vk_start.elapsed().as_secs_f64()
    );

    let public_inputs = [root_fr, nullifier_fr, recipient_fr];
    let mut rng = rand::rngs::OsRng;

    eprintln!("      [3/5] Creating Halo2-KZG proof...");
    let prove_start = std::time::Instant::now();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&public_inputs[..]]],
        &mut rng,
        &mut transcript,
    )
    .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    let proof_bytes = transcript.finalize();
    let prove_time = prove_start.elapsed();
    eprintln!(
        "      [3/5] Proof generated: {} bytes ({:.1}s)",
        proof_bytes.len(),
        prove_time.as_secs_f64()
    );

    // ── Verify locally before saving ─────────────────────────────────
    eprintln!("      [4/5] Verifying proof locally...");
    let verify_start = std::time::Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut read_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());
    let vk_ref = pk.get_vk();
    verify_proof(
        &params,
        vk_ref,
        strategy,
        &[&[&public_inputs[..]]],
        &mut read_transcript,
    )
    .map_err(|e| format!("Local verification failed: {:?}", e))?;
    eprintln!(
        "      [4/5] Proof verified locally ({:.1}s)",
        verify_start.elapsed().as_secs_f64()
    );

    // ── Save proof file ─────────────────────────────────────────────
    eprintln!("      [5/5] Saving proof file...");
    let proof_file = ProofFile {
        version: 2,
        proof_format_version: PROOF_FORMAT_VERSION,
        proof: hex::encode(&proof_bytes),
        journal: String::new(), // V2 has no journal — public inputs are direct
        nullifier: hex::encode(nullifier_bytes),
        recipient: hex::encode(recipient),
        claim_amount: (CLAIM_AMOUNT as u128 * 1_000_000_000_000_000_000).to_string(),
        contract_address: AIRDROP_CONTRACT.to_string(),
        chain_id: CHAIN_ID,
        receipt_hex: None,
    };

    let json = serde_json::to_string_pretty(&proof_file)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    std::fs::write(output_path, &json).map_err(|e| format!("Failed to write proof: {}", e))?;

    let total_time = start.elapsed();
    eprintln!(
        "      Total proving pipeline: {:.1}s",
        total_time.as_secs_f64()
    );
    eprintln!(
        "      Breakdown: params={:.1}s, keygen={:.1}s, prove={:.1}s, verify={:.1}s",
        0.0, // params time included in start
        vk_start.elapsed().as_secs_f64(),
        prove_time.as_secs_f64(),
        verify_start.elapsed().as_secs_f64(),
    );

    Ok(nullifier_bytes)
}

/// Verify a Halo2-KZG proof locally.
///
/// Performs cryptographic verification by regenerating the VK from the
/// circuit and verifying the proof against it. This is the same
/// verification that the on-chain Halo2Verifier performs, but locally.
pub fn verify_v2_proof(proof_path: &Path) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_path)
        .map_err(|e| format!("Failed to read {}: {}", proof_path.display(), e))?;
    let proof: ProofFile =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse proof file: {}", e))?;

    if proof.version != 2 {
        return Err(format!("Expected version 2 proof, got {}", proof.version));
    }

    if proof.proof_format_version != PROOF_FORMAT_VERSION {
        return Err(format!(
            "Expected proof format version {}, got {}",
            PROOF_FORMAT_VERSION, proof.proof_format_version
        ));
    }

    eprintln!("Verifying Halo2-KZG proof...");
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);

    // Validate proof file structure
    if proof.proof.is_empty() {
        return Err("Proof is empty".to_string());
    }

    let proof_bytes = hex::decode(&proof.proof).map_err(|e| format!("Invalid proof hex: {}", e))?;

    if proof_bytes.len() < PROOF_LENGTH_MIN || proof_bytes.len() > PROOF_LENGTH_MAX {
        return Err(format!(
            "Proof length {} outside expected range [{}, {}]",
            proof_bytes.len(),
            PROOF_LENGTH_MIN,
            PROOF_LENGTH_MAX
        ));
    }

    // Perform full cryptographic verification by regenerating the VK
    // and verifying the proof against it.
    //
    // This approach re-derives the VK from the circuit definition, which
    // ensures the proof was generated for the correct circuit. The VK
    // uniquely identifies the circuit's constraint system.
    //
    // NOTE: VK caching is not possible with halo2_proofs 0.3.x as
    // VerifyingKey does not implement serialization. Future versions
    // may support this. The VK derivation takes ~5-10 seconds.
    eprintln!("  Regenerating verification key...");
    let start = std::time::Instant::now();

    use halo2_proofs::{
        plonk::{keygen_vk, verify_proof, SingleVerifier},
        transcript::{Blake2bRead, Challenge255},
    };
    use halo2curves::bn256::G1Affine;

    // Create a dummy circuit to derive the VK
    let circuit = ZKMistV2Claim {
        private_key: [0u8; 32],
        siblings: [[0u8; 32]; TREE_DEPTH],
        path_indices: [0u8; TREE_DEPTH],
        merkle_root: halo2curves::bn256::Fr::from(0u64),
        nullifier: halo2curves::bn256::Fr::from(0u64),
        recipient: halo2curves::bn256::Fr::from(1u64), // non-zero
    };

    let k = CIRCUIT_K;
    let params = load_or_download_params(k)?;
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("VK generation failed: {:?}", e))?;

    eprintln!("  VK regenerated ({:.1}s)", start.elapsed().as_secs_f64());

    // Reconstruct public inputs from the proof file
    let nullifier_bytes =
        hex::decode(&proof.nullifier).map_err(|e| format!("Invalid nullifier hex: {}", e))?;
    let recipient_bytes =
        hex::decode(&proof.recipient).map_err(|e| format!("Invalid recipient hex: {}", e))?;

    if nullifier_bytes.len() != 32 {
        return Err(format!(
            "Nullifier must be 32 bytes, got {}",
            nullifier_bytes.len()
        ));
    }
    if recipient_bytes.len() != 20 {
        return Err(format!(
            "Recipient must be 20 bytes, got {}",
            recipient_bytes.len()
        ));
    }

    let mut nullifier_arr = [0u8; 32];
    nullifier_arr.copy_from_slice(&nullifier_bytes);
    let nullifier_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&nullifier_arr));

    let mut recipient_padded = [0u8; 32];
    recipient_padded[12..32].copy_from_slice(&recipient_bytes);
    let recipient_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&recipient_padded));

    // The merkle root is a known constant — extract from proof file or use known value
    let known_root_hex = KNOWN_MERKLE_ROOT
        .strip_prefix("0x")
        .unwrap_or(KNOWN_MERKLE_ROOT);
    let root_bytes =
        hex::decode(known_root_hex).map_err(|e| format!("Invalid known merkle root hex: {}", e))?;
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&root_bytes);
    let root_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_arr));

    let public_inputs = [root_fr, nullifier_fr, recipient_fr];

    // Verify the proof
    eprintln!("  Verifying proof cryptographically...");
    let strategy = SingleVerifier::new(&params);
    let mut read_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());

    match verify_proof(
        &params,
        &vk,
        strategy,
        &[&[&public_inputs[..]]],
        &mut read_transcript,
    ) {
        Ok(()) => {
            eprintln!(
                "  ✅ Proof is cryptographically valid ({:.1}s total)",
                start.elapsed().as_secs_f64()
            );
            eprintln!("     Merkle root: 0x{}", KNOWN_MERKLE_ROOT);
            eprintln!("     Nullifier:   0x{}", proof.nullifier);
            eprintln!("     Recipient:   0x{}", proof.recipient);
            eprintln!("     Proof size:  {} bytes", proof_bytes.len());
            Ok(())
        }
        Err(e) => Err(format!(
            "❌ Cryptographic proof verification FAILED: {:?}\n\
                 The proof is invalid. Do NOT submit this proof.",
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::poly::commitment::Params;
    use halo2curves::bn256::G1Affine;

    /// `ensure_params_k` accepts a params at the expected k (the happy path
    /// every production run takes).
    #[test]
    fn test_ensure_params_k_match() {
        // Params::new(8) is tiny (256 rows) — instant, no memory risk.
        let params = Params::<G1Affine>::new(8);
        assert!(ensure_params_k(&params, 8).is_ok());
    }

    /// `ensure_params_k` REJECTS a params at the wrong k with a message that
    /// names both k values and the memory multiplier. This is the guard against
    /// a stale cache or a pinned SRS extracted at the wrong k — both of which
    /// would otherwise silently produce on-chain-invalid (or OOM-causing) proofs.
    #[test]
    fn test_ensure_params_k_mismatch_rejects() {
        let params = Params::<G1Affine>::new(10); // file claims k=10
        let err = ensure_params_k(&params, 8).expect_err("mismatch must reject");
        // Message must surface both k values and the memory blowup factor.
        assert!(
            err.contains("k=10"),
            "error should name the file's k: {}",
            err
        );
        assert!(
            err.contains("k=8"),
            "error should name the expected k: {}",
            err
        );
        assert!(
            err.contains("4x") || err.contains("4×"),
            "error should state the memory multiplier (2^(10-8)=4): {}",
            err
        );
        assert!(
            err.contains("kzg-srs.md"),
            "error should point to the doc: {}",
            err
        );
    }

    /// REAL end-to-end Halo2-KZG proof round-trip on the FULL ZKMist circuit.
    ///
    /// Unlike `test_circuit_merkle_nullifier_e2e` in zkmist-circuits (which uses
    /// `MockProver` — it checks only that the gates are satisfiable), this test
    /// generates a REAL KZG proof through the production `generate_v2_proof`
    /// path: `keygen_vk` → `keygen_pk` → `create_proof` (polynomial commitment +
    /// opening proofs) → `verify_proof` (pairing-based `SingleVerifier`). This is
    /// the exact cryptographic code path claimants hit, and the part MockProver
    /// cannot exercise — it is what was previously COMPLETELY untested.
    ///
    /// The flow: generate a proof for a known-good claim, confirm it verifies
    /// with the correct public inputs, then confirm a TAMPERED Merkle root is
    /// REJECTED by the pairing check (the real soundness guarantee — a forged
    /// public input must fail verification, not just fail a gate check).
    ///
    /// ⚠️ Uses a RANDOM dev SRS (`ZKMIST_DEV_SRS=1` → `Params::new`). Proofs
    /// from a dev SRS are forgeable by whoever generated the SRS — fine for a
    /// test, NEVER for mainnet. The pinned PSE SRS (`docs/kzg-srs.md`) is what
    /// makes production proofs unforgeable; this test validates only the
    /// proving/verifying CODE PATH, not the trust root.
    ///
    /// Heavy: ~15–25 GiB RSS at k=23 (keygen + prove + re-keygen + 2 verifies).
    /// Run ALONE:
    ///   ZKMIST_DEV_SRS=1 cargo test --release -p zkmist-cli \
    ///     test_real_kzg_proof_round_trip -- --ignored --nocapture --test-threads=1
    #[test]
    #[ignore = "heavy: real KZG proof at k=23 (~min, ~15-25 GiB). Run with --ignored --test-threads=1 and ZKMIST_DEV_SRS=1."]
    fn test_real_kzg_proof_round_trip() {
        use zkmist_circuits::secp256k1::native_derive_address;
        use zkmist_merkle_tree::build_single_leaf_proof;

        // Dev SRS — random, forgeable, test-only. Must be set before params load.
        // Safe: this test is `#[ignore]`d, so it only runs when invoked explicitly
        // (and --test-threads=1 keeps it the only test in the process).
        std::env::set_var("ZKMIST_DEV_SRS", "1");

        // Same key + derivation as the E2E MockProver test in zkmist-circuits,
        // so the two tests validate the SAME claim via two different mechanisms.
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let (address, _, _) = native_derive_address(&key);
        // Sanity: same address the secp256k1 MockProver test pins.
        assert_eq!(
            hex::encode(address),
            "fcad0b19bb29d4674531d6f115237e16afce377c"
        );

        let (root, siblings_ark, path_u8) = build_single_leaf_proof(&address, TREE_DEPTH);
        assert_eq!(siblings_ark.len(), TREE_DEPTH);
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        let mut path_indices = [0u8; TREE_DEPTH];
        siblings.copy_from_slice(&siblings_ark);
        path_indices.copy_from_slice(&path_u8);

        let recipient: [u8; 20] = [0xB0; 20]; // non-zero recipient

        // Use a temp dir so the proof file outlives generation + re-verify.
        let dir = tempfile::tempdir().expect("temp dir");
        let proof_path = dir.path().join("proof.json");

        // ── [1] Generate the real proof via the PRODUCTION entry point. ──
        // generate_v2_proof internally does keygen_vk → keygen_pk →
        // create_proof → verify_proof and returns Err if any step fails, so a
        // successful return already proves the full round trip works.
        eprintln!("   [1/3] generate_v2_proof (real keygen + create_proof + verify)...");
        let t0 = std::time::Instant::now();
        let nullifier = generate_v2_proof(
            &key,
            &siblings,
            &path_indices,
            &root,
            &recipient,
            &proof_path,
        )
        .expect("real KZG proof generation failed");
        eprintln!("   [1/3] ✅ proof generated ({:.1}s)", t0.elapsed().as_secs_f64());

        // ── Load the emitted proof bytes + public inputs. ──
        let proof_file: crate::types::ProofFile =
            serde_json::from_str(&std::fs::read_to_string(&proof_path).unwrap())
                .expect("parse proof file");
        let proof_bytes = hex::decode(&proof_file.proof).expect("decode proof hex");
        eprintln!(
            "        proof bytes: {} (production expects {} = 0x1600)",
            proof_bytes.len(),
            PROOF_LENGTH_EXPECTED
        );
        // The on-chain verifier hardcodes an EXACT length (0x1600 = 5632); a
        // proof whose length differs is rejected. Confirm we land in range.
        assert!(
            proof_bytes.len() >= PROOF_LENGTH_MIN && proof_bytes.len() <= PROOF_LENGTH_MAX,
            "proof length {} outside [{}, {}]",
            proof_bytes.len(),
            PROOF_LENGTH_MIN,
            PROOF_LENGTH_MAX
        );

        // Reconstruct the SAME public inputs the prover committed against.
        let nullifier_fr =
            ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&nullifier));
        let mut recip_padded = [0u8; 32];
        recip_padded[12..32].copy_from_slice(&recipient);
        let recipient_fr =
            ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&recip_padded));
        let root_fr = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root));
        let public_inputs = [root_fr, nullifier_fr, recipient_fr];

        // Load the (now-cached) dev SRS + regenerate the VK for direct verify.
        let k = CIRCUIT_K;
        let params = load_or_download_params(k).expect("load params");
        let dummy = ZKMistV2Claim {
            private_key: [0u8; 32],
            siblings: [[0u8; 32]; TREE_DEPTH],
            path_indices: [0u8; TREE_DEPTH],
            merkle_root: halo2curves::bn256::Fr::from(0u64),
            nullifier: halo2curves::bn256::Fr::from(0u64),
            recipient: halo2curves::bn256::Fr::from(1u64), // non-zero
        };
        let vk = halo2_proofs::plonk::keygen_vk(&params, &dummy).expect("keygen_vk");

        // Helper: verify the proof bytes against given public inputs.
        let verify = |inputs: &[halo2curves::bn256::Fr]| -> Result<(), halo2_proofs::plonk::Error> {
            use halo2_proofs::{
                plonk::{verify_proof, SingleVerifier},
                transcript::{Blake2bRead, Challenge255},
            };
            use halo2curves::bn256::G1Affine;
            let strategy = SingleVerifier::new(&params);
            let mut rt =
                Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());
            verify_proof(&params, &vk, strategy, &[&[inputs]], &mut rt)
        };

        // ── [2] Positive: correct public inputs MUST verify. ──
        eprintln!("   [2/3] verify with correct public inputs...");
        verify(&public_inputs).expect("honest proof must verify via the real pairing check");
        eprintln!("   [2/3] ✅ REAL KZG proof verified (pairing check passed)");

        // ── [3] Negative: a tampered Merkle root MUST be rejected. ──
        // This is the soundness guarantee MockProver cannot test: a proof
        // generated for root R must NOT verify against root R'. The pairing
        // equation depends on the public inputs, so any change fails it.
        eprintln!("   [3/3] verify with TAMPERED Merkle root (must reject)...");
        let mut tampered_root = root;
        tampered_root[0] ^= 0x01; // ≠ root, still a valid field element
        let tampered_root_fr =
            ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&tampered_root));
        let mut tampered = public_inputs;
        tampered[0] = tampered_root_fr;
        let neg = verify(&tampered);
        assert!(
            neg.is_err(),
            "tampered Merkle root must be REJECTED by the pairing check — \
             a proof for one root must not verify against another"
        );
        eprintln!("   [3/3] ✅ tampered root correctly rejected");
        eprintln!("✅ Real KZG proof round-trip PASS (k={}, {} proof bytes)",
            k, proof_bytes.len());
    }
}
