//! ZKMist CLI constants.

pub const ZKMIST_DIR_NAME: &str = ".zkmist";
pub const ELIGIBILITY_DIR_NAME: &str = "eligibility";
pub const PROOFS_DIR_NAME: &str = "proofs";
pub const GUEST_HASH_FILE: &str = "guest.sha256";

/// PRD §11: Contract parameters
pub const CLAIM_AMOUNT: u64 = 10_000;
pub const MAX_CLAIMS: u64 = 1_000_000;
pub const CLAIM_DEADLINE: u64 = 1_798_761_600; // 2027-01-01 00:00:00 UTC
pub const CHAIN_ID: u64 = 8453; // Base

/// Default Base RPC URL
pub const DEFAULT_RPC_URL: &str = "https://mainnet.base.org";

/// GitHub Release tag hosting the official eligibility list.
/// Immutable once published — a GitHub release tag cannot be moved to a
/// different commit without force-pushing (which is auditable).
/// Assets (CSV files, manifest) are content-addressed by SHA-256 in manifest.json.
pub const ELIGIBILITY_RELEASE_TAG: &str = "v1.0.0-eligibility";

/// GitHub repository hosting the eligibility list release.
pub const GITHUB_REPO: &str = "ph4n70mr1ddl3r/zkmist";

/// IPFS gateway for fallback downloads.
pub const IPFS_GATEWAY: &str = "https://gateway.pinata.cloud/ipfs";

/// Published IPFS CID for the eligibility list.
pub const FALLBACK_IPFS_CID: &str = "QmTTit9vDbzRjCffeKsd3LV3YFvdX4Kobm3uZwNd5zDUZb";

/// Known Merkle root for the v1.0.0 eligibility list.
/// Sourced from the GitHub Release manifest, the IPFS manifest, and the
/// `compute-root` tool output. This compile-time constant provides an
/// out-of-band integrity check: even if the download source is compromised,
/// the manifest root must match this value or the CLI refuses to proceed.
///
/// 64,116,228 qualified addresses (≥0.004 ETH gas fees, mainnet, before 2026-01-01).
pub const KNOWN_MERKLE_ROOT: &str =
    "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844";

/// Known guest program image ID.
/// Sourced from the DeployAll.s.sol deployment script and the compute-image-id tool.
/// This should be updated after the final production guest binary is built with:
///   cargo run --release -p zkmist-tools --bin compute-image-id
///
/// The image ID is a SHA-256 commitment to the guest program binary.
/// The on-chain airdrop contract's `imageId` immutable must match this value
/// for proofs to be accepted.
///
/// ⚠️  This changes with every guest program modification. Update after:
///     1. Any change to guest/src/main.rs or guest/Cargo.toml dependencies
///     2. RISC Zero toolchain upgrades (different compiler → different binary)
pub const KNOWN_IMAGE_ID: &str =
    "0x05ef31c9fea9a30ee1902fc49a7aae3e48fce139ffc9b728858dee5b36423277";

/// ZKMAirdrop contract address on Base.
/// Set after deployment.
pub const AIRDROP_CONTRACT: &str = "0x000000000000000000000000000000000000dEaD"; // placeholder
