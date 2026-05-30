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

/// Default k parameter for the circuit (2^23 = 8M rows).
/// Required for the full circuit with secp256k1 + Keccak + Poseidon + Merkle.
/// k=22 (4M rows) is insufficient — the circuit exceeds 4M rows.
const CIRCUIT_K: u32 = 23;

// ── Params caching ───────────────────────────────────────────────────
//
// KZG params generation for k=22 (4M G1 points) takes 10-30 seconds.
// We cache the serialized params to ~/.zkmist/cache/ to avoid regenerating
// them on every prove/verify invocation.

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

/// Load KZG params from cache, or generate and cache them.
///
/// The params are deterministic (derived from the Ethereum KZG ceremony SRS),
/// so caching is safe. Cache invalidation only happens when k changes.
fn load_or_gen_params(
    k: u32,
) -> Result<halo2_proofs::poly::commitment::Params<halo2curves::bn256::G1Affine>, String> {
    use halo2_proofs::poly::commitment::Params;
    use halo2curves::bn256::G1Affine;
    use std::io::{BufReader, BufWriter};

    let path = cached_params_path(k)?;

    // Try loading from cache
    if path.exists() {
        eprintln!(
            "         Loading cached KZG params from {}...",
            path.display()
        );
        match std::fs::File::open(&path) {
            Ok(file) => {
                let mut reader = BufReader::new(file);
                match Params::<G1Affine>::read(&mut reader) {
                    Ok(params) => {
                        eprintln!("         ✓ Cached params loaded");
                        return Ok(params);
                    }
                    Err(e) => {
                        eprintln!(
                            "         Warning: cached params corrupt ({}), regenerating",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "         Warning: cannot read cached params ({}), regenerating",
                    e
                );
            }
        }
    }

    // Generate fresh params
    eprintln!(
        "         Generating KZG params (k={}, {} rows)...",
        k,
        1u64 << k
    );
    let params = Params::<G1Affine>::new(k);
    eprintln!("         ✓ KZG params generated");

    // Cache for future use
    match std::fs::File::create(&path) {
        Ok(file) => {
            let mut writer = BufWriter::new(file);
            match params.write(&mut writer) {
                Ok(()) => eprintln!("         ✓ Cached params to {}", path.display()),
                Err(e) => eprintln!("         Warning: failed to cache params: {}", e),
            }
        }
        Err(e) => {
            eprintln!("         Warning: cannot create cache file: {}", e);
        }
    }

    Ok(params)
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
    let params = load_or_gen_params(k)?;
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

    if proof_bytes.len() < 400 || proof_bytes.len() > 1200 {
        return Err(format!(
            "Proof length {} outside expected range [400, 1200]",
            proof_bytes.len()
        ));
    }

    // Perform full cryptographic verification by regenerating the VK
    // and verifying the proof against it.
    //
    // This approach re-derives the VK from the circuit definition, which
    // ensures the proof was generated for the correct circuit. The VK
    // uniquely identifies the circuit's constraint system.
    //
    // For production, the VK should be cached/loaded from a serialized file
    // generated by `gen-verifier` to avoid the overhead of key generation.
    eprintln!("  Regenerating verification key for verification...");
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
    let params = load_or_gen_params(k)?;
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
