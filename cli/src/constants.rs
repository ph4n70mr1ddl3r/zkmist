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

/// Known Merkle root for the v1.0.0 eligibility list.
/// Sourced from the GitHub Release manifest and the `compute-root` tool output. This compile-time constant provides an
/// out-of-band integrity check: even if the download source is compromised,
/// the manifest root must match this value or the CLI refuses to proceed.
///
/// 64,116,228 qualified addresses (≥0.004 ETH gas fees, mainnet, before 2026-01-01).
pub const KNOWN_MERKLE_ROOT: &str =
    "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844";

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
/// rejects obvious garbage before submitting. The authoritative check is the
/// EXACT length `eq(0x1600, ...)` (= 5632 bytes) hardcoded in
/// `Halo2Verifier.sol`, which rejects any proof whose length differs. The
/// range below is deliberately wide so it never rejects a legitimate proof;
/// it only catches truncated/corrupt files. See `PROOF_LENGTH_EXPECTED` for
/// the real production length.
pub const PROOF_LENGTH_MIN: usize = 4000;
pub const PROOF_LENGTH_MAX: usize = 8000;

/// Exact proof byte length enforced by `Halo2Verifier.sol` (`0x1600`).
/// Single source of truth — keep in lockstep with the contract's
/// `PROOF_LENGTH` constant and the generated verifier's hardcoded check.
pub const PROOF_LENGTH_EXPECTED: usize = 5632;

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
// ⚠️  PLACEHOLDER — the deployer MUST set these to a verified PSE halo2
// params file BEFORE mainnet. See docs/kzg-srs.md for how to obtain,
// independently verify, and publish the file. The readiness checker fails
// (check [1d/8]) until KZG_SRS_SHA256 is non-empty.
//
// Why a claimant trusts this and NOT the deployer: each claimant downloads
// the file themselves and verifies its SHA-256 against KZG_SRS_SHA256. The
// deployer pins the hash but cannot change the SRS (a different file would
// hash differently), and cannot forge proofs because they do not know the
// PSE ceremony's trapdoor. This is the only trust root in the system.
/// URL the claimant downloads the pinned PSE halo2 KZG SRS from (production).
pub const KZG_SRS_URL: &str = "";
/// SHA-256 of the pinned PSE halo2 KZG SRS file (lowercase hex, no `0x`).
pub const KZG_SRS_SHA256: &str = "";
