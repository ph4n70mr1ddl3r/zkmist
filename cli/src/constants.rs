//! ZKMist CLI constants.

pub const ZKMIST_DIR_NAME: &str = ".zkmist";
pub const ELIGIBILITY_DIR_NAME: &str = "eligibility";
pub const PROOFS_DIR_NAME: &str = "proofs";

/// PRD: Contract parameters
pub const CLAIM_AMOUNT: u64 = 10_000;
pub const MAX_CLAIMS: u64 = 1_000_000;
pub const CLAIM_DEADLINE: u64 = 1_798_761_600; // 2027-01-01 00:00:00 UTC
pub const CHAIN_ID: u64 = 8453; // Base

/// Default Base RPC URL
pub const DEFAULT_RPC_URL: &str = "https://mainnet.base.org";

/// Fallback gas limit for claim transactions when RPC estimation fails.
/// The typical claim costs ~350-400K gas (Halo2-KZG verification + mint).
pub const FALLBACK_GAS_LIMIT: u64 = 700_000;

/// GitHub Release tag hosting the official eligibility list.
/// Immutable once published — a GitHub release tag cannot be moved to a
/// different commit without force-pushing (which is auditable).
/// Assets (CSV files, manifest) are content-addressed by SHA-256 in manifest.json.
pub const ELIGIBILITY_RELEASE_TAG: &str = "v1.0.0-eligibility";

/// GitHub repository hosting the eligibility list release.
pub const GITHUB_REPO: &str = "ph4n70mr1ddl3r/zkmist";

/// Known Merkle root for the v1.0.0 eligibility list, under the HALO2-BASE
/// Poseidon sponge convention — the SAME convention the axiom claim circuit
/// verifies (capacity 2^64, squeeze permutation, digest at state[1]).
///
/// Re-derived independently from the 64,116,228-address eligibility list via
/// a parallel halo2-base tree build (validated bit-for-bit against the serial
/// `zkmist_merkle_tree::halo2base::build_tree_streaming` production builder,
/// and against `build_single_leaf_proof` via the `real_roundtrip.json`
/// fixture root `0x1e415cba…`).
///
/// This compile-time constant provides an out-of-band integrity check: even
/// if the download source is compromised, the manifest root must match this
/// value or the CLI refuses to proceed.
///
/// Single source of truth for the committed root — MUST be kept in lockstep
/// with `MERKLE_ROOT` in `contracts/script/Deploy.s.sol` (the on-chain
/// commitment to the same tree).
///
/// 64,116,228 qualified addresses (≥0.004 ETH gas fees, mainnet, before 2026-01-01).
///
/// NOTE: the previous value `0x1eafd6f3…` was a LEGACY light-poseidon (Circom)
/// root — a DIFFERENT sponge convention the axiom circuit can never verify.
/// It was replaced after re-derivation revealed the mismatch (the on-chain
/// verifier would have reverted every claim). See the commit that introduced
/// this value for the investigation.
pub const KNOWN_MERKLE_ROOT: &str =
    "0x00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba";

/// ZKMAirdrop contract address on Base.
/// ⚠️  PLACEHOLDER — must be updated after deploying to Base mainnet.
/// The CLI will reject proof submission while this is the placeholder address.
/// After deploying:
///   1. Update this constant with the deployed airdrop address
///   2. Rebuild: cargo build --release -p zkmist-cli
pub const AIRDROP_CONTRACT: &str = "0x000000000000000000000000000000000000dEaD";

/// Nullifier domain separator.
pub const NULLIFIER_DOMAIN: &[u8; 19] = b"ZKMist_V2_NULLIFIER";

/// Proof byte length bounds.
/// Client-side proof byte-length pre-filter (loose range).
///
/// This is a NON-authoritative sanity check on loaded proof files only — it
/// rejects obvious garbage before submitting. NOTE: the axiom
/// `Halo2Verifier.axiom.sol` does NOT enforce an exact calldata length (it
/// has no `calldatasize` check); a structurally wrong proof is rejected by
/// the pairing math itself (invalid EC points / pairing result → `revert`).
/// The range below is deliberately wide so it never rejects a legitimate
/// proof; it only catches truncated/corrupt files. See `PROOF_LENGTH_EXPECTED`
/// for the expected production length (diagnostic, not an on-chain gate).
pub const PROOF_LENGTH_MIN: usize = 500;
pub const PROOF_LENGTH_MAX: usize = 4000;

/// Expected production proof byte length for the axiom SHPLONK proof at k=21
/// (instances ++ commitments ++ evaluation proofs). Diagnostic only — NOT
/// enforced on-chain (the verifier has no `calldatasize` check; it rejects
/// bad proofs via the pairing math). Used to size buffers and sanity-check
/// fixture files.
///
/// Measured: 1376 bytes from `cmd_prove` and 1375 bytes in the
/// `real_roundtrip.json` fixture (both via `gen_evm_proof_shplonk`). The prior
/// value (5888) and bounds (4000..8000) were stale estimates that would have
/// REJECTED every valid proof at the `submit` pre-filter.
pub const PROOF_LENGTH_EXPECTED: usize = 1376;

/// Proof format version.
pub const PROOF_FORMAT_VERSION: u64 = 2;

// ── KZG SRS trust root ───────────────────────────────────────────────────
//
// Halo2-KZG commits against a Structured Reference String (SRS). A
// self-generated SRS (`Params::new`) is a 1-of-1 trust root: whoever ran it
// knows the trapdoor and can forge proofs. For mainnet the prover MUST load
// the public PSE perpetual powers-of-tau SRS instead — a universal ceremony
// with many participants, run once and reused by every circuit up to its
// size. The file must be in halo2_proofs 0.3.0 params format (the same format
// `Params::read`/`Params::write` use).
//
// ⚠️  PINNED (round-trip-pending): KZG_SRS_SHA256 / KZG_SRS_URL are set to
// the k=23 PSE halo2 params converted locally from ppot_0080_23.ptau. The
// pinned hash matches the prover's SRS (verified against
// ~/.zkmist/cache/v2_params_k23.bin), but two mainnet blockers remain:
//   1. the ptau transcript's provenance vs the PSE ceremony's PUBLISHED
//      digest is not yet independently confirmed (docs/kzg-srs.md §2.2);
//   2. the on-chain real-KZG round-trip (ZKM.realroundtrip.t.sol) has not
//      yet passed against this VK.
// Readiness check [1d/8] passes (constants non-empty); [1c/8] still flags
// the unconfirmed provenance. See SECURITY.md for the full blocker list.
//
// Why a claimant trusts this and NOT the deployer: each claimant downloads
// the file themselves and verifies its SHA-256 against KZG_SRS_SHA256. The
// deployer pins the hash but cannot change the SRS (a different file would
// hash differently), and cannot forge proofs because they do not know the
// PSE ceremony's trapdoor. This is the only trust root in the system.
/// URL the claimant downloads the pinned PSE halo2 KZG SRS from (production).
/// NOTE: round-trip validation only — derived from ppot_0080_23.ptau (PSE
/// perpetual-powers-of-tau). Provenance (final beaconed transcript) still
/// unconfirmed; see docs/kzg-srs.md §2.2 before mainnet.
pub const KZG_SRS_URL: &str =
    "https://github.com/ph4n70mr1ddl3r/zkmist/releases/download/srs-v1/params-k23.bin";
/// SHA-256 of the pinned PSE halo2 KZG SRS file (lowercase hex, no `0x`).
pub const KZG_SRS_SHA256: &str = "fbf3a497b2e2455f72647da0094389b49bd0726c44f28cbbff169ff9d254efed";
