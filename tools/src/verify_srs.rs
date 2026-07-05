//! Deployer-side KZG SRS verification tool.
//!
//! Answers: "I downloaded a params file (or extracted one from the PSE
//! perpetual-powers-of-tau ceremony) — is it genuine, is it k=23, and what do
//! I paste into `cli/src/constants.rs`?"
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin verify-srs -- \
//!       path/to/params-A.bin [path/to/params-B.bin ...]
//!
//! For each file it prints: file size, SHA-256, the embedded `k`, `n = 2^k`,
//! and the G1 power count. It asserts `k == CIRCUIT_K` (23). When given two or
//! more files, it asserts they are BYTE-IDENTICAL (same digest AND same k) —
//! that is the strongest cross-check available without re-running phase2
//! extraction yourself (which is the gold standard — see docs/kzg-srs.md §2).
//!
//! This is the deployer-side complement to the claimant-side `download.rs`
//! (which verifies a *pinned* hash). Here there is no pinned hash yet — this
//! tool COMPUTES the hash you will pin.
//!
//! The file is read via the EXACT same `ParamsKZG::<Bn256>::read` the prover
//! uses (`cli/src/halo2_prover.rs`), so anything this tool accepts, the prover
//! accepts, and vice versa. It does NOT generate or trust any hash from
//! anywhere — every digest it prints is computed from the bytes you give it.

use std::io::BufReader;
use std::path::PathBuf;

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use sha2::{Digest, Sha256};

#[path = "srs_guard.rs"]
mod srs_guard;

/// Production circuit k. MUST match `CIRCUIT_K` in `cli/src/halo2_prover.rs`.
const EXPECTED_K: u32 = 23;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut expect_k: u32 = EXPECTED_K;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--params-file" => {
                if i + 1 >= args.len() {
                    eprintln!("--params-file requires a path");
                    std::process::exit(1);
                }
                files.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--expect-k" => {
                if i + 1 >= args.len() {
                    eprintln!("--expect-k requires a value (e.g. --expect-k 23)");
                    std::process::exit(1);
                }
                expect_k = match args[i + 1].parse() {
                    Ok(k) => k,
                    Err(_) => {
                        eprintln!(
                            "invalid --expect-k value '{}' (expected a u32)",
                            args[i + 1]
                        );
                        std::process::exit(1);
                    }
                };
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: verify-srs [--params-file] <file.bin> [<file2.bin> ...] [--expect-k N]"
                );
                eprintln!();
                eprintln!("  Verifies halo2 KZG params file(s): prints SHA-256, k, n=2^k, G1");
                eprintln!(
                    "  count; asserts k == {} (CIRCUIT_K). With 2+ files, asserts they",
                    EXPECTED_K
                );
                eprintln!(
                    "  are byte-identical (the cross-check). Prints the constants.rs snippet."
                );
                return;
            }
            other if other.starts_with("--") => {
                eprintln!("Unknown: {}", other);
                std::process::exit(1);
            }
            // Bare positional args are also accepted as file paths.
            _ => {
                files.push(PathBuf::from(&args[i]));
                i += 1;
            }
        }
    }

    if files.is_empty() {
        eprintln!("No params file given.");
        eprintln!("Usage: verify-srs <file.bin> [<file2.bin> ...]");
        eprintln!();
        eprintln!("This tool verifies a downloaded/extracted KZG SRS file. See the procedure");
        eprintln!("in docs/kzg-srs.md §2 for how to OBTAIN the file first (PSE perpetual");
        eprintln!(
            "powers-of-tau phase2 extraction at k={}, or a reputable pre-built file).",
            EXPECTED_K
        );
        std::process::exit(1);
    }

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist KZG SRS Verifier (deployer-side)                   ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    let mut digests: Vec<(PathBuf, String, u32)> = Vec::new();
    let mut any_k_mismatch = false;

    for path in &files {
        eprintln!(
            "── {} ──────────────────────────────────────────",
            path.display()
        );

        // 1. Read raw bytes + SHA-256 (over the EXACT bytes the prover will read).
        // 1. Read raw bytes + SHA-256 (over the EXACT bytes the prover will read).
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ❌ cannot read file: {}", e);
                std::process::exit(1);
            }
        };
        let size_mb = bytes.len() as f64 / (1024.0 * 1024.0);
        let digest_hex: String = {
            let mut h = Sha256::new();
            h.update(&bytes);
            h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
        };
        eprintln!("  file size:    {:.1} MiB ({} bytes)", size_mb, bytes.len());
        eprintln!("  SHA-256:      {}", digest_hex);

        // 2. Pre-flight: peek the header `k` and reject a value that would
        //    make `ParamsKZG::read` allocate hundreds of GiB (or panic on a
        //    32-bit `1<<k` shift) BEFORE we hand the file to halo2. This tool
        //    exists to report an untrusted file's `k`; OOMing on a corrupted /
        //    planted header (disk rot, a partial write, a tampered file, or the
        //    far more common truncated download) instead of printing it would
        //    defeat its purpose. Same bug class as the prover's
        //    `reject_untrusted_cache_oversized_k`; see `srs_guard.rs`.
        // 3. Parse as halo2 params via the SAME path the prover uses. This both
        //    confirms the file is a genuine halo2 params file AND surfaces the
        //    embedded k (which the prover allocates against — see ensure_params_k).
        let params = {
            let label = path.display().to_string();
            if let Err(e) = srs_guard::peek_and_bound_params_k(&bytes, &label) {
                eprintln!("  ❌ {}", e);
                eprintln!(
                    "     (refused before ParamsKZG::read — it would have allocated huge memory)"
                );
                any_k_mismatch = true;
                eprintln!();
                continue;
            }
            let mut reader = BufReader::new(&bytes[..]);
            ParamsKZG::<halo2curves::bn256::Bn256>::read(&mut reader).map_err(|e| e.to_string())
        };
        let params = match params {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  ❌ not a valid halo2 KZG params file: {}", e);
                eprintln!("     (ParamsKZG::<Bn256>::read rejected it — the prover would too)");
                any_k_mismatch = true;
                eprintln!();
                continue;
            }
        };

        use halo2_proofs::poly::commitment::{Params as _, ParamsProver as _};

        // 3. Sanity: a genuine halo2 params file has exactly 2^k G1 points.
        // (We do not separately verify that `read` consumed the whole file:
        // recomputing the consumed length would require re-reading, and halo2
        // reads a fixed structure — header + g1 vector + g2 + s — so the g1
        // count check below is the effective trailing-garbage guard.)

        let k = params.k();
        let n: u64 = 1u64 << k;
        let g1_count = params.get_g().len();
        eprintln!("  k:            {}  (n = 2^k = {} rows)", k, n);
        eprintln!("  G1 points:    {}  (expected = {} = 2^k)", g1_count, n);

        if k == expect_k {
            eprintln!("  k check:      ✅ k={} matches CIRCUIT_K", k);
        } else {
            eprintln!(
                "  k check:      ❌ k={} does NOT match CIRCUIT_K={}",
                k, expect_k
            );
            eprintln!(
                "     A {} file would allocate {}× more memory than k={} during proving",
                k,
                1u64 << k.saturating_sub(expect_k),
                expect_k
            );
            eprintln!(
                "     and produce proofs the on-chain verifier (pinned to k={}) rejects.",
                expect_k
            );
            any_k_mismatch = true;
        }

        // Sanity: a genuine halo2 params file has exactly 2^k G1 points.
        if g1_count != n as usize {
            eprintln!(
                "  ⚠️  G1 count {} != 2^k = {} — file is malformed or truncated",
                g1_count, n
            );
            any_k_mismatch = true;
        }

        eprintln!();
        digests.push((path.clone(), digest_hex, k));
    }

    if digests.is_empty() {
        eprintln!("❌ No file parsed successfully as a halo2 params file.");
        eprintln!("   The prover reads the file with ParamsKZG::<Bn256>::read (PSE git fork");
        eprintln!("   KZG format). See docs/kzg-srs.md §2.");
        std::process::exit(2);
    }

    // ── Cross-check: if 2+ files, assert byte-identical (same digest + same k). ──
    if digests.len() >= 2 {
        eprintln!(
            "── Cross-check ({} files) ──────────────────────────────",
            digests.len()
        );
        let (_, ref_digest, ref_k) = &digests[0];
        let mut all_match = true;
        for (path, digest, k) in digests.iter().skip(1) {
            let same = digest == ref_digest && *k == *ref_k;
            eprintln!(
                "  {} {} (digest {}, k={})",
                if same {
                    "✅ identical to first"
                } else {
                    "❌ DIFFERS from first"
                },
                path.display(),
                &digest[..16],
                k
            );
            if !same {
                all_match = false;
            }
        }
        if all_match {
            eprintln!("  All files are BYTE-IDENTICAL (same SHA-256 + same k).");
            eprintln!("  This is the practical cross-check: two independent");
            eprintln!("  downloads/extractions agree. The gold standard is");
            eprintln!("  independent phase2 extraction — see docs/kzg-srs.md §2.1.");
        } else {
            eprintln!();
            eprintln!("  ❌ Files differ. Do NOT pin any of them yet. Re-download or");
            eprintln!("     re-extract; a mismatch means at least one source is wrong.");
            std::process::exit(2);
        }
        eprintln!();
    }

    if any_k_mismatch {
        eprintln!("❌ One or more files failed verification. Fix before pinning.");
        std::process::exit(2);
    }
    let (ref_path, ref_digest, ref_k) = &digests[0];
    if *ref_k != expect_k {
        eprintln!(
            "❌ Primary file k={} does not match CIRCUIT_K={}",
            ref_k, expect_k
        );
        std::process::exit(2);
    }

    // ── Ready-to-paste constants.rs snippet (only printed on full success). ──
    eprintln!(
        "── constants.rs snippet (from {}) ────────────────────",
        ref_path.display()
    );
    eprintln!();
    println!("// cli/src/constants.rs — KZG SRS trust root");
    println!(
        "pub const KZG_SRS_URL: &str = \"https://<YOUR-HOST>/params-k{}.bin\";",
        ref_k
    );
    println!("pub const KZG_SRS_SHA256: &str = \"{}\";", ref_digest);
    eprintln!();
    eprintln!("  Replace <YOUR-HOST> with the URL you publish the file at");
    eprintln!("  (GitHub Release asset or IPFS — see docs/kzg-srs.md §2.3).");
    eprintln!("  Then rebuild + run the readiness checker:");
    eprintln!("    cargo build --release -p zkmist-cli");
    eprintln!("    cargo run -p zkmist-tools --bin readiness   # [1d/8] -> ✅");
    eprintln!();
    eprintln!("✅ SRS verified. Paste the snippet above into cli/src/constants.rs.");
}
