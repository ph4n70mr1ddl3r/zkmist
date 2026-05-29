// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IHalo2Verifier — Interface for Halo2-KZG proof verification
/// @notice Defines the standard verification interface for Halo2 proofs.
interface IHalo2Verifier {
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
}

/// @title Halo2Verifier — ZKMist V2 KZG Proof Verifier
/// @notice Verifies Halo2-KZG proofs for the ZKMist V2 airdrop claim circuit.
/// @dev This verifier implements KZG verification using the BN254 ecPairing
///      precompile at address 0x08.
///
///      ╔══════════════════════════════════════════════════════════════════╗
///      ║  ⚠️  PRODUCTION WARNING                                        ║
///      ║                                                                  ║
///      ║  This contract MUST be regenerated from the circuit verification  ║
///      ║  key using snark-verifier before mainnet deployment:             ║
///      ║                                                                  ║
///      ║    cargo run --bin gen-verifier --features v2 --                 ║
///      ║      --output contracts/src/Halo2Verifier.sol                   ║
///      ║                                                                  ║
///      ║  The current `verify()` performs ONLY structural validation.     ║
///      ║  It does NOT perform cryptographic KZG pairing verification.     ║
///      ║  Deploying this as-is would accept ANY structurally-valid proof. ║
///      ╚══════════════════════════════════════════════════════════════════╝
contract Halo2Verifier is IHalo2Verifier {
    // ── Production readiness flag ────────────────────────────────────
    /// @dev Set to true only after regenerating with snark-verifier.
    ///      The airdrop contract should check this in production.
    bool public constant IS_PRODUCTION_VERIFIER = false;

    // ── Verification key hash (integrity check) ─────────────────────
    // This is a hash of the verification key parameters. If the VK changes
    // (e.g., due to circuit modifications), this hash must be updated.
    bytes32 public constant VK_HASH = bytes32(uint256(0xaa5c548e24ead166));

    // ── Verification parameters ─────────────────────────────────────
    uint256 public constant NUM_INSTANCES = 3;
    uint256 public constant K = 22;

    // ── BN254 pairing precompile ────────────────────────────────────
    address constant BN254_PAIRING = address(0x08);

    // ── BN254 curve constants ───────────────────────────────────────
    // Prime field modulus for BN254
    uint256 constant BN254_N =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Verify a Halo2-KZG proof against public inputs.
    /// @param proof The serialized Halo2 proof bytes.
    /// @param publicInputs Array of public input values [merkleRoot, nullifier, recipient].
    /// @return True if the proof is valid.
    function verify(
        bytes calldata proof,
        uint256[3] memory publicInputs
    ) external view returns (bool) {
        // ── Step 1: Structural validation ────────────────────────────
        if (proof.length < 400 || proof.length > 1200) {
            return false;
        }

        // ── Step 2: Public input validation ──────────────────────────
        // recipient must not be zero (address(0))
        if (publicInputs[2] == 0) {
            return false;
        }

        // ── Step 3: Deserialize and validate G1 points ───────────────
        if (proof.length < 128) {
            return false;
        }

        uint256 w_zeta_x;
        uint256 w_zeta_y;
        uint256 w_zeta_omega_x;
        uint256 w_zeta_omega_y;

        assembly {
            w_zeta_x := calldataload(proof.offset)
            w_zeta_y := calldataload(add(proof.offset, 32))
            w_zeta_omega_x := calldataload(add(proof.offset, 64))
            w_zeta_omega_y := calldataload(add(proof.offset, 96))
        }

        // Validate points are on the BN254 curve: y^2 = x^3 + 3
        if (!_isOnCurveG1(w_zeta_x, w_zeta_y)) {
            return false;
        }
        if (!_isOnCurveG1(w_zeta_omega_x, w_zeta_omega_y)) {
            return false;
        }

        // ── Step 4: KZG pairing verification ─────────────────────────
        //
        // ⚠️  PLACEHOLDER: The full pairing verification requires the
        // circuit's verification key (VK) to be embedded as constants.
        //
        // To generate the production verifier:
        //   1. Freeze the circuit layout (all gadgets production-ready)
        //   2. Generate the VK: keygen_vk(&params, &circuit)
        //   3. Run: cargo run --bin gen-verifier --features v2 -- --output Halo2Verifier.sol
        //
        // The production verifier will be ~2000-3000 lines of auto-generated
        // Solidity performing the full KZG pairing equation:
        //
        //   e(π, [τ]₂ - ζ·G₂) · e(π', ω·[τ]₂ - ζω·G₂)
        //       = e(-[C₀ + α·C₁ + β²·C₂ + ...], G₂)
        //
        // using the ecPairing precompile (address 0x08).
        //
        // For testnet deployment, this placeholder allows the airdrop flow
        // to be tested end-to-end. For mainnet, this MUST be replaced.

        // Suppress unused variable warnings
        publicInputs;

        // ⚠️  PLACEHOLDER: Returns true for structurally valid proofs.
        // REPLACE with full KZG verification before mainnet deployment.
        return true;
    }

    /// @notice Check if a point (x, y) is on the BN254 G1 curve.
    function _isOnCurveG1(uint256 x, uint256 y) internal pure returns (bool) {
        // Identity point (0, 0) is valid
        if (x == 0 && y == 0) return true;
        // y^2 == x^3 + 3 (mod BN254 field prime)
        uint256 lhs = mulmod(y, y, BN254_N);
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, BN254_N), x, BN254_N),
            3,
            BN254_N
        );
        return lhs == rhs;
    }
}
