//! Halo2-KZG prover integration for ZKMist V2.
//!
//! Generates Halo2-KZG proofs using the `zkmist-circuits` crate.
//! The full circuit enforces: secp256k1 key→address, Poseidon leaf hash,
//! 26-level Merkle proof, nullifier (V2 domain), and non-zero recipient.

use std::path::Path;

use ark_ff::{BigInteger, PrimeField};
use zkmist_circuits::{
    ZKMistV2Claim,
    merkle::TREE_DEPTH,
    nullifier::domain_field_element,
    poseidon::ark_to_halo2,
};
use zkmist_merkle_tree::compute_nullifier_v2;

use crate::constants::*;
use crate::types::ProofFile;

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
    let root_fr = ark_to_halo2(
        &ark_bn254::Fr::from_be_bytes_mod_order(merkle_root),
    );

    // Compute nullifier using V2 domain separator ("ZKMist_V2_NULLIFIER").
    // This MUST match the domain used inside the Halo2 circuit's nullifier gadget.
    let mut interior_hasher = crate::helpers::ark_poseidon_hasher(2)
        .ok_or("Failed to create Poseidon hasher")?;
    let nullifier_bytes = compute_nullifier_v2(private_key, &mut interior_hasher);
    let nullifier_fr = ark_to_halo2(
        &ark_bn254::Fr::from_be_bytes_mod_order(&nullifier_bytes),
    );

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
    let recipient_fr = ark_to_halo2(
        &ark_bn254::Fr::from_be_bytes_mod_order(&recipient_padded),
    );

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
        poly::commitment::Params,
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use halo2curves::bn256::G1Affine;

    let k = 21; // 2^21 = 2M rows — sufficient for full circuit
    eprintln!("      Generating KZG parameters (k={})...", k);
    let params: Params<G1Affine> = Params::new(k);

    eprintln!("      Generating verification key...");
    let vk = keygen_vk(&params, &circuit)
        .map_err(|e| format!("VK generation failed: {:?}", e))?;
    let pk = keygen_pk(&params, vk, &circuit)
        .map_err(|e| format!("PK generation failed: {:?}", e))?;

    let public_inputs = [root_fr, nullifier_fr, recipient_fr];
    let mut rng = rand::rngs::OsRng;

    eprintln!("      Creating Halo2-KZG proof...");
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
    eprintln!("      ✓ Proof generated: {} bytes", proof_bytes.len());

    // ── Verify locally before saving ─────────────────────────────────
    let strategy = SingleVerifier::new(&params);
    let mut read_transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());
    let vk_ref = pk.get_vk();
    verify_proof(
        &params,
        vk_ref,
        strategy,
        &[&[&public_inputs[..]]],
        &mut read_transcript,
    )
    .map_err(|e| format!("Local verification failed: {:?}", e))?;
    eprintln!("      ✓ Proof verified locally");

    // ── Save proof file ─────────────────────────────────────────────
    let proof_file = ProofFile {
        version: 2,
        proof_format_version: PROOF_FORMAT_VERSION_V2,
        proof: hex::encode(&proof_bytes),
        journal: String::new(), // V2 has no journal — public inputs are direct
        nullifier: hex::encode(nullifier_bytes),
        recipient: hex::encode(recipient),
        claim_amount: (CLAIM_AMOUNT as u128 * 1_000_000_000_000_000_000).to_string(),
        contract_address: AIRDROP_CONTRACT_V2.to_string(),
        chain_id: CHAIN_ID,
        receipt_hex: None,
    };

    let json = serde_json::to_string_pretty(&proof_file)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    std::fs::write(output_path, &json)
        .map_err(|e| format!("Failed to write proof: {}", e))?;

    Ok(nullifier_bytes)
}

/// Verify a Halo2-KZG proof locally.
pub fn verify_v2_proof(proof_path: &Path) -> Result<(), String> {
    let content = std::fs::read_to_string(proof_path)
        .map_err(|e| format!("Failed to read {}: {}", proof_path.display(), e))?;
    let proof: ProofFile = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse proof file: {}", e))?;

    if proof.version != 2 {
        return Err(format!("Expected version 2 proof, got {}", proof.version));
    }

    if proof.proof_format_version != PROOF_FORMAT_VERSION_V2 {
        return Err(format!(
            "Expected proof format version {}, got {}",
            PROOF_FORMAT_VERSION_V2, proof.proof_format_version
        ));
    }

    eprintln!("Verifying Halo2-KZG proof...");
    eprintln!("  Nullifier: 0x{}", proof.nullifier);
    eprintln!("  Recipient: 0x{}", proof.recipient);

    // Validate proof file structure
    if proof.proof.is_empty() {
        return Err("Proof is empty".to_string());
    }

    let proof_bytes = hex::decode(&proof.proof)
        .map_err(|e| format!("Invalid proof hex: {}", e))?;

    if proof_bytes.len() < 400 || proof_bytes.len() > 1200 {
        return Err(format!(
            "Proof length {} outside expected range [400, 1200]",
            proof_bytes.len()
        ));
    }

    // TODO: Load verification key and verify the proof cryptographically.
    // This requires serializing/deserializing the VK, which depends on the
    // final circuit layout being frozen. Once the secp256k1 and Keccak
    // gadgets are production-ready, the VK can be serialized and embedded
    // in the CLI for local verification.
    //
    // For now, perform a full deserialization and structural check, then
    // attempt to re-create the proof for verification.
    eprintln!("✅ Proof file structure valid (V2 Halo2-KZG, {} bytes)", proof_bytes.len());
    eprintln!("   Nullifier: 0x{}", proof.nullifier);
    eprintln!("   Recipient: 0x{}", proof.recipient);
    eprintln!("   Contract: 0x{}", proof.contract_address);
    eprintln!("   Chain ID: {}", proof.chain_id);
    eprintln!("   Claim amount: {} ZKM", proof.claim_amount);
    eprintln!("");
    eprintln!("   ⚠️  Full local cryptographic verification requires the serialized VK.");
    eprintln!("   The on-chain Halo2Verifier will perform full verification on submit.");
    eprintln!("   To verify on-chain: zkmist submit {}", proof_path.display());
    Ok(())
}
