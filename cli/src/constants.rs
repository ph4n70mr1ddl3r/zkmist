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
/// TODO: Update after deployment.
pub const AIRDROP_CONTRACT: &str = "0x000000000000000000000000000000000000dEaD";

/// Nullifier domain separator.
pub const NULLIFIER_DOMAIN: &[u8; 19] = b"ZKMist_V2_NULLIFIER";

/// Proof format version.
pub const PROOF_FORMAT_VERSION: u64 = 2;
