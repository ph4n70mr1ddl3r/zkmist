//! Download functions for the ZKMist eligibility list.
//!
//! Downloads the official eligibility list with per-file SHA-256 integrity
//! verification. Tries GitHub Releases first, then IPFS as a fallback.
//!
//! Download sources (in priority order):
//!   1. GitHub Releases (primary — fast, content-addressed via SHA-256 in manifest)
//!   2. IPFS gateway (fallback — decentralized, content-addressed by CID)

use sha2::{Digest as Sha2Digest, Sha256};

use crate::constants::*;
use crate::helpers::*;
use crate::types::Manifest;

/// IPFS gateway for fallback downloads.
/// Uses the public ipfs.io gateway — content-addressed, so the gateway
/// operator cannot tamper with files (hash mismatch would be detected).
const IPFS_GATEWAY: &str = "https://ipfs.io/ipfs";

/// IPFS CID (Content Identifier) for the eligibility list directory.
/// This is set when the eligibility list is pinned to IPFS.
/// The CID is immutable — it references a specific directory of files.
///
/// ⚠️ Update this after publishing the eligibility list to IPFS.
///     Publish with: ipfs add -r eligibility/
const IPFS_CID: &str = "QmPENDING_PUBLISH_TO_IPFS_FIRST";

/// Whether the IPFS CID has been configured (not a placeholder).
fn ipfs_configured() -> bool {
    !IPFS_CID.starts_with("PENDING")
}

/// Fetch and validate the manifest from GitHub Releases, falling back to IPFS.
pub fn fetch_manifest(rt: &tokio::runtime::Runtime) -> Result<Manifest, String> {
    eprintln!("[1/3] Fetching manifest...");

    // Try GitHub first (primary source)
    let github_url = format!(
        "https://github.com/{}/releases/download/{}/manifest.json",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
    );
    eprintln!("      Source: GitHub Releases ({}/{})", GITHUB_REPO, ELIGIBILITY_RELEASE_TAG);

    match rt.block_on(fetch_json::<Manifest>(&github_url)) {
        Ok(manifest) => {
            eprintln!("      ✓ Manifest fetched from GitHub");
            return Ok(manifest);
        }
        Err(github_err) => {
            eprintln!("      ⚠ GitHub fetch failed: {}", github_err);
        }
    }

    // Try IPFS fallback
    if ipfs_configured() {
        let ipfs_url = format!("{}/{}/manifest.json", IPFS_GATEWAY, IPFS_CID);
        eprintln!("      Fallback: IPFS (CID: {})", IPFS_CID);

        match rt.block_on(fetch_json::<Manifest>(&ipfs_url)) {
            Ok(manifest) => {
                eprintln!("      ✓ Manifest fetched from IPFS");
                return Ok(manifest);
            }
            Err(ipfs_err) => {
                eprintln!("      ⚠ IPFS fetch failed: {}", ipfs_err);
            }
        }
    } else {
        eprintln!("      ℹ️  IPFS fallback not configured (CID is placeholder)");
        eprintln!("         To enable: pin the eligibility list to IPFS and update IPFS_CID in download.rs");
    }

    Err(format!(
        "Failed to fetch manifest from all sources.\n\
         \n\
         Manual alternatives:\n\
         1. Download from: https://github.com/{}/releases/tag/{}\n\
         2. Place CSV files manually in: {}\n\
         3. (Future) Pin the eligibility list to IPFS and configure IPFS_CID in cli/src/download.rs",
        GITHUB_REPO,
        ELIGIBILITY_RELEASE_TAG,
        eligibility_dir().display(),
    ))
}

/// Fetch and deserialize JSON from a URL.
pub async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {}", resp.status(), url));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Try downloading a single file from GitHub Releases, falling back to IPFS.
/// Returns Ok(true) if downloaded successfully, Ok(false) if all sources failed.
pub fn try_download_file(
    rt: &tokio::runtime::Runtime,
    filename: &str,
    dest: &std::path::Path,
    expected_hash: &str,
) -> Result<bool, String> {
    // Try GitHub first
    let github_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG, filename
    );

    match rt.block_on(download_and_verify(&github_url, expected_hash)) {
        Ok(data) => {
            std::fs::write(dest, &data)
                .map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;
            return Ok(true);
        }
        Err(e) => {
            eprintln!("      ⚠ GitHub download of {} failed: {}", filename, e);
        }
    }

    // Try IPFS fallback
    if ipfs_configured() {
        let ipfs_url = format!("{}/{}/{}", IPFS_GATEWAY, IPFS_CID, filename);
        eprintln!("      IPFS fallback for {}...", filename);

        match rt.block_on(download_and_verify(&ipfs_url, expected_hash)) {
            Ok(data) => {
                std::fs::write(dest, &data)
                    .map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;
                eprintln!("      ✓ Downloaded {} from IPFS", filename);
                return Ok(true);
            }
            Err(e) => {
                eprintln!("      ⚠ IPFS download of {} also failed: {}", filename, e);
            }
        }
    }

    Ok(false)
}

/// Download a file from a URL and verify its SHA-256 hash.
async fn download_and_verify(url: &str, expected_hash: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120)) // large files need generous timeout
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let data = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());
    if hash != expected_hash {
        return Err(format!(
            "SHA-256 mismatch: expected {}, got {}",
            expected_hash, hash
        ));
    }

    Ok(data.to_vec())
}
