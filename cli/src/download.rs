//! Download functions for the ZKMist eligibility list.
//!
//! Downloads the official eligibility list from GitHub Releases
//! with per-file SHA-256 integrity verification.

use sha2::{Digest as Sha2Digest, Sha256};

use crate::constants::*;
use crate::helpers::*;
use crate::types::Manifest;

/// Fetch and validate the manifest from GitHub Releases.
pub fn fetch_manifest(rt: &tokio::runtime::Runtime) -> Result<Manifest, String> {
    eprintln!("[1/3] Fetching manifest...");
    eprintln!(
        "      Source: GitHub Releases ({}/{})",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
    );
    let url = format!(
        "https://github.com/{}/releases/download/{}/manifest.json",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
    );

    match rt.block_on(fetch_json::<Manifest>(&url)) {
        Ok(manifest) => {
            eprintln!("      ✓ Manifest fetched from GitHub");
            Ok(manifest)
        }
        Err(e) => Err(format!(
            "Failed to fetch manifest from GitHub. Last error: {}\n\
             \n\
             Manual alternatives:\n\
             1. Download from: https://github.com/{}/releases/tag/{}\n\
             2. Place CSV files manually in: {}",
            e,
            GITHUB_REPO,
            ELIGIBILITY_RELEASE_TAG,
            eligibility_dir().display(),
        )),
    }
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

/// Try downloading a single file from GitHub Releases.
/// Returns Ok(true) if downloaded successfully, Ok(false) if the download failed.
pub fn try_download_file(
    rt: &tokio::runtime::Runtime,
    filename: &str,
    dest: &std::path::Path,
    expected_hash: &str,
) -> Result<bool, String> {
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG, filename
    );

    match rt.block_on(download_and_verify(&url, expected_hash)) {
        Ok(data) => {
            std::fs::write(dest, &data)
                .map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;
            Ok(true)
        }
        Err(e) => {
            eprintln!("      ⚠ GitHub download of {} failed: {}", filename, e);
            Ok(false)
        }
    }
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
