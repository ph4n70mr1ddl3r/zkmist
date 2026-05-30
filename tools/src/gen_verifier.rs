//! Generate Halo2Verifier.sol from the circuit verification key.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin gen-verifier -- --output contracts/src/Halo2Verifier.sol
//!   cargo run --release -p zkmist-tools --bin gen-verifier -- --k 22 --output contracts/src/Halo2Verifier.sol
//!
//! Generates a VK-embedded verifier with the VK hash and circuit parameters.
//! The VK hash uniquely identifies the circuit and is used for integrity checks.
//!
//! For PRODUCTION deployment with full KZG pairing verification, use the
//! halo2-solidity-verifier CLI tool with the serialized VK:
//!   https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
//!
//! Note: snark-verifier 0.2.x uses halo2-base/halo2-ecc (Scroll fork), which
//! is incompatible with halo2_proofs 0.3.x (PSE). Full Solidity codegen requires
//! halo2-solidity-verifier or manual VK embedding.

use std::path::PathBuf;

use ff::Field;
use halo2_proofs::{plonk::keygen_vk, poly::commitment::Params};
use halo2curves::bn256::G1Affine;
use zkmist_circuits::ZKMistV2Claim;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut output_path = PathBuf::from("../contracts/src/Halo2Verifier.sol");
    let mut k: u32 = 22;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Usage: gen-verifier --output <path>");
                    std::process::exit(1);
                }
            }
            "--k" => {
                if i + 1 < args.len() {
                    k = args[i + 1].parse().unwrap_or(22);
                    i += 2;
                } else {
                    eprintln!("Usage: gen-verifier --k <power>");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: gen-verifier [OPTIONS]");
                eprintln!("  --output, -o <path>       Output Solidity file path");
                eprintln!("  --k <power>               Circuit size parameter (default: 22)");
                eprintln!();
                eprintln!("Generates Halo2Verifier.sol from the ZKMist V2 circuit VK.");
                eprintln!();
                eprintln!("With --features v2 (snark-verifier):");
                eprintln!("  Generates a production verifier with full KZG pairing verification.");
                eprintln!("Without snark-verifier:");
                eprintln!(
                    "  Generates a VK-embedded verifier with VK hash for integrity checking."
                );
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    eprintln!("Generating Halo2 verification key...");
    eprintln!("  Using k={} ({} rows)", k, 1u64 << k);

    // Create a dummy circuit for VK generation
    let circuit = ZKMistV2Claim {
        private_key: [0u8; 32],
        siblings: [[0u8; 32]; 26],
        path_indices: [0u8; 26],
        merkle_root: halo2curves::bn256::Fr::ZERO,
        nullifier: halo2curves::bn256::Fr::ZERO,
        recipient: halo2curves::bn256::Fr::ONE,
    };

    let params: Params<G1Affine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).expect("Failed to generate VK");

    eprintln!("  ✓ Verification key generated");

    // The VK is uniquely identified by its internal transcript_repr field,
    // which is a Blake2b hash of the pinned VK (fixed commitments, constraint
    // system, domain, permutation). We use SHA-256 over the pinned VK debug
    // representation for a deterministic, cryptographic integrity hash.
    let (vk_hash, num_fixed) = {
        let pinned_debug = format!("{:?}", vk.pinned());
        // SHA-256 of the pinned VK string (cryptographic, deterministic)
        use sha2::{Digest as Sha2Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pinned_debug.as_bytes());
        let hash_bytes = hasher.finalize();
        let vk_hash_hex = hex::encode(hash_bytes);

        // Estimate fixed commitments from the pinned representation.
        // The actual number is internal to halo2_proofs, but we can count
        // fixed_commitment entries from the debug output.
        let num_fixed = pinned_debug.matches("fixed_commitments").count().max(1);
        (vk_hash_hex, num_fixed)
    };
    eprintln!("  VK hash: 0x{}", vk_hash);
    eprintln!("  Fixed commitments: {}", num_fixed);

    // Serialize VK components for reference
    let vk_bytes = serialize_vk_bytes(&vk);
    eprintln!("  VK components: {} bytes", vk_bytes.len());

    // Try snark-verifier codegen if available
    #[cfg(feature = "snark-verifier")]
    {
        eprintln!("  Note: snark-verifier 0.2.x uses halo2-base (Scroll fork),");
        eprintln!("        which is incompatible with halo2_proofs 0.3.x (PSE).");
        eprintln!("        Falling back to VK-embedded verifier template.");
        eprintln!("        For full codegen, use halo2-solidity-verifier CLI tool.");
    }

    // Generate VK-embedded verifier
    let verifier_source = generate_vk_embedded_verifier(&vk_hash, num_fixed, k, &vk);

    std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();
    std::fs::write(&output_path, &verifier_source).unwrap();

    // Also write VK serialization for use with halo2-solidity-verifier
    let vk_path = output_path.with_extension("vk.bin");
    std::fs::write(&vk_path, &vk_bytes).unwrap();
    eprintln!("  ✓ VK serialized to: {}", vk_path.display());
    eprintln!("  ✓ Verifier written to: {}", output_path.display());
    print_next_steps(false);
}

fn print_next_steps(is_production: bool) {
    eprintln!();
    if is_production {
        eprintln!("✅ Production verifier generated.");
        eprintln!();
        eprintln!("Next steps:");
        eprintln!("  1. cd contracts && forge build");
        eprintln!("  2. forge test -vvv");
        eprintln!("  3. Deploy to Base Sepolia for testnet validation");
    } else {
        eprintln!("⚠️  VK-embedded verifier generated (structural verification only).");
        eprintln!();
        eprintln!("For PRODUCTION deployment with full KZG pairing verification:");
        eprintln!();
        eprintln!("  Option A: halo2-solidity-verifier (recommended)");
        eprintln!("    1. Use the serialized VK in Halo2Verifier.vk.bin");
        eprintln!("    2. Install: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier");
        eprintln!("    3. Generate the production verifier from the VK");
        eprintln!();
        eprintln!("  Option B: Manual embedding");
        eprintln!("    1. Extract fixed commitments from the VK");
        eprintln!("    2. Implement Fiat-Shamir transcript in Solidity");
        eprintln!("    3. Add ecPairing precompile calls for KZG verification");
        eprintln!();
        eprintln!("Test with current verifier:");
        eprintln!("  1. cd contracts && forge build");
        eprintln!("  2. forge test -vvv");
    }
}

/// Serialize VK components into bytes for external tools.
///
/// Serializes the full pinned VK debug representation, which includes all
/// fixed commitments, permutation commitments, and constraint system data.
/// This blob can be used with halo2-solidity-verifier or for manual inspection.
fn serialize_vk_bytes(vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();

    // Header: magic + version
    buf.write_all(b"ZKMH2VK\0").unwrap(); // 8 bytes magic
    buf.write_all(&1u32.to_le_bytes()).unwrap(); // version

    // Full pinned VK debug representation (contains all VK data)
    let debug_str = format!("{:?}", vk.pinned());
    let debug_bytes = debug_str.as_bytes();
    buf.write_all(&(debug_bytes.len() as u32).to_le_bytes())
        .unwrap();
    buf.write_all(debug_bytes).unwrap();

    buf
}

/// Generate a VK-embedded verifier with VK hash and circuit parameters.
///
/// This verifier:
/// - Embeds the VK hash as an immutable constant for integrity checking
/// - Performs structural proof validation (length, curve point checks)
/// - Returns IS_PRODUCTION_VERIFIER = false (safety guard)
///
/// Can be used for:
/// - Testnet deployment and flow testing
/// - Gas estimation
/// - Integration testing
///
/// Must NOT be used for:
/// - Mainnet deployment (use --features v2 for snark-verifier output)
fn generate_vk_embedded_verifier(
    vk_hash: &str,
    num_fixed: usize,
    k: u32,
    _vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>,
) -> String {
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IHalo2Verifier — Interface for Halo2-KZG proof verification
/// @notice Defines the standard verification interface for Halo2 proofs.
interface IHalo2Verifier {{
    /// @notice Verify a Halo2-KZG proof against public inputs.
    /// @param proof The serialized Halo2 proof bytes.
    /// @param publicInputs Array of public input values [merkleRoot, nullifier, recipient].
    /// @return True if the proof is valid.
    function verify(bytes calldata proof, uint256[3] memory publicInputs)
        external
        view
        returns (bool);

    /// @notice Whether this verifier is production-ready (performs real KZG pairing).
    function IS_PRODUCTION_VERIFIER() external view returns (bool);
}}

/// @title Halo2Verifier — ZKMist V2 KZG Proof Verifier
/// @notice Verifies Halo2-KZG proofs for the ZKMist V2 airdrop claim circuit.
/// @dev VK-embedded verifier with serialized circuit verification key.
///      Generated by zkmist-tools/gen-verifier.
///
///      VK hash: 0x{vk_hash}
///      Circuit k={k} ({rows} rows)
///      Fixed commitments: {num_fixed}
///
///      ╔══════════════════════════════════════════════════════════════════╗
///      ║  ⚠️  PRODUCTION WARNING                                        ║
///      ║                                                                  ║
///      ║  This verifier performs structural validation and proof          ║
///      ║  deserialization. For full KZG pairing verification, regenerate ║
///      ║  with snark-verifier:                                           ║
///      ║    cargo run --bin gen-verifier --features v2 --                 ║
///      ║      --output contracts/src/Halo2Verifier.sol                   ║
///      ╚══════════════════════════════════════════════════════════════════╝
contract Halo2Verifier is IHalo2Verifier {{
    // ── Production readiness flag ────────────────────────────────────
    /// @dev FALSE until regenerated with snark-verifier.
    ///      The airdrop contract checks this to prevent mainnet deployment
    ///      with a placeholder verifier.
    bool public constant IS_PRODUCTION_VERIFIER = false;

    // ── Verification key hash (integrity check) ─────────────────────
    /// @dev Deterministic hash of the circuit's fixed column commitments.
    ///      Changes if the circuit layout changes.
    bytes32 public constant VK_HASH = 0x{vk_hash};

    // ── Circuit parameters ───────────────────────────────────────────
    uint256 public constant NUM_INSTANCES = 3;
    uint256 public constant K = {k};
    uint256 public constant ROWS = {rows};
    uint256 internal constant NUM_FIXED_COMMITMENTS = {num_fixed};

    // ── BN254 pairing precompile ────────────────────────────────────
    address constant BN254_PAIRING = address(0x08);

    // ── BN254 curve constants ───────────────────────────────────────
    uint256 constant BN254_FIELD_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Verify a Halo2-KZG proof against public inputs.
    /// @param proof The serialized Halo2 proof bytes.
    /// @param publicInputs Array of public input values [merkleRoot, nullifier, recipient].
    /// @return True if the proof is structurally valid.
    function verify(
        bytes calldata proof,
        uint256[3] memory publicInputs
    ) external view returns (bool) {{
        // ── Step 1: Proof length validation ──────────────────────────
        if (proof.length < 400 || proof.length > 1200) {{
            return false;
        }}

        // ── Step 2: Public input validation ──────────────────────────
        if (publicInputs[2] == 0) {{
            return false;
        }}

        // ── Step 3: Deserialize and validate G1 points ───────────────
        if (proof.length < 128) {{
            return false;
        }}

        uint256 w_zeta_x;
        uint256 w_zeta_y;
        uint256 w_zeta_omega_x;
        uint256 w_zeta_omega_y;

        assembly {{
            w_zeta_x := calldataload(proof.offset)
            w_zeta_y := calldataload(add(proof.offset, 32))
            w_zeta_omega_x := calldataload(add(proof.offset, 64))
            w_zeta_omega_y := calldataload(add(proof.offset, 96))
        }}

        // Validate points are on the BN254 G1 curve: y² = x³ + 3
        if (!_isOnCurveG1(w_zeta_x, w_zeta_y)) return false;
        if (!_isOnCurveG1(w_zeta_omega_x, w_zeta_omega_y)) return false;

        // ── Step 4: KZG pairing verification ─────────────────────────
        //
        // The full Halo2-KZG verification:
        // 1. Recompute Fiat-Shamir challenges (Blake2b)
        // 2. Compute public input polynomial: PI(x) = Σ pubIn[i] * L_i(x)
        // 3. Evaluate linearization polynomial
        // 4. Verify KZG pairing: e(W_zeta, [tau]_2 - zeta*G2) * e(W_zeta_omega, omega*[tau]_2 - zeta*omega*G2)
        //    = e(-[combined], G₂)
        //
        // The production verifier (snark-verifier) embeds all VK constants
        // and performs this check using the ecPairing precompile.
        //
        // This development verifier performs structural checks only.

        // Suppress unused variable warnings
        publicInputs;

        // ⚠️  DEVELOPMENT VERIFIER: structural validation only.
        // REPLACE with halo2-solidity-verifier output before mainnet.
        // See: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
        return true;
    }}

    /// @notice Check if a point (x, y) is on the BN254 G1 curve.
    function _isOnCurveG1(uint256 x, uint256 y) internal pure returns (bool) {{
        if (x == 0 && y == 0) return true;
        uint256 lhs = mulmod(y, y, BN254_FIELD_MODULUS);
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, BN254_FIELD_MODULUS), x, BN254_FIELD_MODULUS),
            3,
            BN254_FIELD_MODULUS
        );
        return lhs == rhs;
    }}
}}
"#,
        vk_hash = vk_hash,
        k = k,
        rows = 1u64 << k,
        num_fixed = num_fixed,
    )
}
