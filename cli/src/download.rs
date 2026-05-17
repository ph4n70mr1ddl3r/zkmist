//! Download functions for the ZKMist eligibility list.
//!
//! Supports GitHub Releases (primary) and IPFS (fallback) download sources
//! with per-file SHA-256 integrity verification.

use sha2::{Digest as Sha2Digest, Sha256};

use crate::constants::*;
use crate::helpers::*;
use crate::types::{DownloadSource, Manifest};

/// Fetch and validate the manifest from the appropriate source(s).
pub fn fetch_manifest(
    rt: &tokio::runtime::Runtime,
    source: DownloadSource,
    ipfs_cid: &str,
) -> Result<Manifest, String> {
    let sources = match source {
        DownloadSource::Auto => &["github", "ipfs"] as &[&str],
        DownloadSource::Github => &["github"] as &[&str],
        DownloadSource::Ipfs => &["ipfs"] as &[&str],
    };

    eprintln!("[1/3] Fetching manifest...");

    let mut last_error = String::new();
    for &src in sources {
        let url = match src {
            "github" => {
                eprintln!(
                    "      Source: GitHub Releases ({}/{})",
                    GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
                );
                format!(
                    "https://github.com/{}/releases/download/{}/manifest.json",
                    GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
                )
            }
            "ipfs" => {
                eprintln!("      Source: IPFS (CID: {})", ipfs_cid);
                format!("{}/{}/manifest.json", IPFS_GATEWAY, ipfs_cid)
            }
            _ => unreachable!(),
        };

        match rt.block_on(fetch_json::<Manifest>(&url)) {
            Ok(manifest) => {
                eprintln!("      ✓ Manifest fetched from {}", src);
                return Ok(manifest);
            }
            Err(e) => {
                last_error = e.clone();
                eprintln!("      ✗ {} failed: {}", src, e);
                if sources.len() > 1 {
                    eprintln!("      Trying next source...");
                }
            }
        }
    }

    Err(format!(
        "All download sources failed. Last error: {}\n\
         \n\
         Manual alternatives:\n\
         1. Download from: https://github.com/{}/releases/tag/{}\n\
         2. IPFS direct: {}/{}/manifest.json\n\
         3. Place CSV files manually in: {}",
        last_error,
        GITHUB_REPO,
        ELIGIBILITY_RELEASE_TAG,
        IPFS_GATEWAY,
        ipfs_cid,
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

/// Try downloading a single file from the available sources.
/// Returns Ok(true) if downloaded successfully, Ok(false) if all sources failed.
pub fn try_download_file(
    rt: &tokio::runtime::Runtime,
    filename: &str,
    dest: &std::path::Path,
    expected_hash: &str,
    source: DownloadSource,
    ipfs_cid: &str,
) -> Result<bool, String> {
    let sources = match source {
        DownloadSource::Auto => &["github", "ipfs"] as &[&str],
        DownloadSource::Github => &["github"] as &[&str],
        DownloadSource::Ipfs => &["ipfs"] as &[&str],
    };

    for &src in sources {
        let url = match src {
            "github" => format!(
                "https://github.com/{}/releases/download/{}/{}",
                GITHUB_REPO, ELIGIBILITY_RELEASE_TAG, filename
            ),
            "ipfs" => format!("{}/{}/{}", IPFS_GATEWAY, ipfs_cid, filename),
            _ => unreachable!(),
        };

        match rt.block_on(download_and_verify(&url, expected_hash)) {
            Ok(data) => {
                std::fs::write(dest, &data)
                    .map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;
                return Ok(true);
            }
            Err(e) => {
                eprintln!("      ⚠ {} download of {} failed: {}", src, filename, e);
                continue;
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
