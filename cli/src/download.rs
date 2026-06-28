//! Download functions for the ZKMist eligibility list.
//!
//! Downloads the official eligibility list from GitHub Releases with per-file
//! SHA-256 integrity verification.

use sha2::{Digest as Sha2Digest, Sha256};

use crate::constants::*;
use crate::helpers::*;
use crate::types::Manifest;

/// Fetch and validate the manifest from GitHub Releases.
pub fn fetch_manifest(rt: &tokio::runtime::Runtime) -> Result<Manifest, String> {
    eprintln!("[1/3] Fetching manifest...");

    let github_url = format!(
        "https://github.com/{}/releases/download/{}/manifest.json",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
    );
    eprintln!(
        "      Source: GitHub Releases ({}/{})",
        GITHUB_REPO, ELIGIBILITY_RELEASE_TAG
    );

    match rt.block_on(fetch_json::<Manifest>(&github_url)) {
        Ok(manifest) => {
            eprintln!("      ✓ Manifest fetched from GitHub");
            return Ok(manifest);
        }
        Err(github_err) => {
            eprintln!("      ⚠ GitHub fetch failed: {}", github_err);
        }
    }

    Err(format!(
        "Failed to fetch manifest from GitHub Releases.\n\
         \n\
         Manual alternatives:\n\
         1. Download from: https://github.com/{}/releases/tag/{}\n\
         2. Place CSV files manually in: {}",
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

/// Try downloading a single file from GitHub Releases.
/// Returns Ok(true) if downloaded successfully, Ok(false) if download failed.
pub fn try_download_file(
    rt: &tokio::runtime::Runtime,
    filename: &str,
    dest: &std::path::Path,
    expected_hash: &str,
) -> Result<bool, String> {
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

/// Run a future to completion on a dedicated current-thread runtime.
///
/// Proving is only ever called from the sync `cmd_*` entry points, so we are
/// never already inside a tokio runtime here and a fresh runtime is safe.
/// (A future caller that proves from within an async context would need a
/// worker-thread bridge instead.) Keeping it to a single-thread runtime also
/// avoids any `Send` requirement on the future — important because
/// `indicatif::ProgressBar` is held across `.await` points and is `!Send`.
fn block_on_download<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    rt.block_on(fut)
}

/// Stream a (potentially large — hundreds of MB) file from `url` to `dest`,
/// verifying its SHA-256 against `expected_hash` atomically.
///
/// The file is written to `dest.with_extension("part")` and renamed onto
/// `dest` only after the hash matches, so a partial/bad download never leaves
/// a usable-but-wrong file at `dest`. The body is streamed in chunks and never
/// buffered in memory — used for the KZG SRS transcript, which is far too
/// large to hold in RAM. `expected_hash` is compared case-insensitively as
/// lowercase hex.
///
/// Returns the number of bytes written.
pub fn download_and_verify_to_file(
    url: &str,
    expected_hash: &str,
    dest: &std::path::Path,
) -> Result<u64, String> {
    block_on_download(download_and_verify_to_file_async(
        url,
        expected_hash,
        dest.to_path_buf(),
    ))
}

async fn download_and_verify_to_file_async(
    url: &str,
    expected_hash: &str,
    dest: std::path::PathBuf,
) -> Result<u64, String> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let client = reqwest::Client::builder()
        // Allow generous time for a large, slow download (claimant bandwidth).
        .timeout(std::time::Duration::from_secs(3600))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {}", resp.status(), url));
    }

    let total = resp.content_length();
    let pb = match total {
        Some(n) => indicatif::ProgressBar::new(n),
        None => indicatif::ProgressBar::new_spinner(),
    };
    if let Some(n) = total {
        let _ = n; // length already passed to the bar
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
            )
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar()),
        );
    }
    pb.set_message("KZG SRS");

    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create cache dir: {e}"))?;
    }
    let tmp = dest.with_extension("part");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    let mut written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("stream read failed: {e}"))?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        written += chunk.len() as u64;
        pb.inc(chunk.len() as u64);
    }
    file.flush()
        .await
        .map_err(|e| format!("flush failed: {e}"))?;
    drop(file);
    pb.finish_with_message("KZG SRS downloaded");

    let got = hex::encode(hasher.finalize());
    if got != expected_hash.trim().to_lowercase() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(format!(
            "SHA-256 mismatch: expected {}, got {}",
            expected_hash, got
        ));
    }

    tokio::fs::rename(&tmp, &dest)
        .await
        .map_err(|e| format!("rename to {}: {e}", dest.display()))?;
    Ok(written)
}

/// Verify an existing file's SHA-256 against `expected_hash` (lowercase hex).
///
/// Used to re-check a cached KZG SRS against the pinned trust root before
/// loading it, so a tampered cache file is rejected. Reads in 64 KiB chunks
/// (never loads the whole file into memory). Returns `Ok(false)` on mismatch.
pub fn verify_file_sha256(path: &std::path::Path, expected_hash: &str) -> Result<bool, String> {
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = hex::encode(hasher.finalize());
    Ok(got == expected_hash.trim().to_lowercase())
}
