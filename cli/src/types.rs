//! ZKMist CLI data types.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofFile {
    /// Schema version (2 = Halo2-KZG).
    pub version: u64,
    /// Proof file format version (independent of `version` which is the
    /// overall schema version).
    #[serde(default = "default_proof_format_version")]
    pub proof_format_version: u64,
    /// Hex-encoded Halo2-KZG proof bytes.
    pub proof: String,
    /// Unused for V2 (kept for schema compatibility).
    #[serde(default)]
    pub journal: String,
    /// Hex-encoded 32 bytes nullifier.
    pub nullifier: String,
    /// Hex-encoded 20 bytes recipient address.
    pub recipient: String,
    /// Claim amount in wei.
    pub claim_amount: String,
    /// Airdrop contract address.
    pub contract_address: String,
    /// Chain ID (8453 = Base).
    pub chain_id: u64,
    /// Not used in V2 (kept for schema compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hex: Option<String>,
}

use crate::PROOF_FORMAT_VERSION;

fn default_proof_format_version() -> u64 {
    PROOF_FORMAT_VERSION
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: u64,
    pub cutoff_timestamp: String,
    pub fee_threshold_eth: String,
    pub total_qualified: u64,
    pub merkle_root: String,
    pub merkle_tree_depth: usize,
    /// Claim amount in wei (e.g., "10000000000000000000000" = 10,000 ZKM).
    #[serde(default)]
    pub claim_amount_wei: Option<String>,
    /// Maximum number of claimants (1,000,000).
    #[serde(default)]
    pub max_claimants: Option<u64>,
    /// Claim deadline as ISO 8601 timestamp ("2027-01-01T00:00:00Z").
    #[serde(default)]
    pub claim_deadline: Option<String>,
    #[serde(default)]
    pub files: Vec<ManifestFile>,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestFile {
    pub file: String,
    pub sha256: String,
}
