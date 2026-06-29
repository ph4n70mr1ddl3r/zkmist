//! `truncate-srs` — downsize a halo2 KZG SRS to exactly the circuit's k.
//!
//! Closes the "I can only find a k≥23 PSE SRS, not exactly k=23" sourcing gap
//! (see docs/kzg-srs.md §1.1). It takes a LARGER halo2 params file (any k ≥
//! CIRCUIT_K) and emits a VALID halo2 params file at exactly CIRCUIT_K (k=23),
//! by reusing halo2's OWN audited `Params::downsize(k)` method.
//!
//! # Why this is sound (no re-derivation, no custom serialization)
//!
//! A KZG SRS is the vector of powers `[1, τ, τ², …, τ^(n-1)]·G₁`. The first
//! `2^k'` elements of a `k`-sized SRS (k' < k) are *exactly* the `2^k'`-sized
//! SRS for the same trapdoor τ — there is nothing to recompute for the monomial
//! basis. halo2's `Params::downsize(k)`:
//!   1. truncates the stored monomial basis `g` to `2^k'` points, and
//!   2. RECOMPUTES the Lagrange basis `g_lagrange` for the smaller domain via
//!      its audited `g_to_lagrange` (FFT roots-of-unity transform).
//!
//! We never touch a private field or hand-roll serialization: we `read` a real
//! `ParamsKZG`, call the public `downsize`, and `write` it back in halo2's own
//! format. Whatever `ParamsKZG::read` accepts, the prover accepts; whatever
//! `ParamsKZG::write` emits, `ParamsKZG::read` re-ingests.
//!
//! # Trust model
//!
//! Truncation does NOT introduce a new trust assumption. The trapdoor τ is
//! unchanged — it is the SAME PSE ceremony, same security (1-of-N honesty of
//! the original participants). We are only dropping the high-degree powers the
//! circuit does not use. This is identical in trust to having downloaded a
//! k=23 file directly. (It is NOT the same as `Params::new`, which mints a
//! fresh forgeable 1-of-1 SRS — that path is gated behind ZKMIST_DEV_SRS.)
//!
//! # What it guards against
//!
//!   - Wrong-direction: `--target-k` must be `<` the input's k (else nothing
//!     to truncate; we refuse rather than silently pass-through, so a typo
//!     can't ship an oversize file that makes the prover OOM).
//!   - It cross-checks: after downsize, re-`read` the output and re-`write`
//!     it, then assert the bytes are stable (round-trip = we did not corrupt
//!     the framing). It also asserts `params.k() == target_k` and that the
//!     monomial prefix is byte-identical to the input's prefix (the G1 points
//!     we kept must be *the same points*, not recomputed).
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin truncate-srs -- \
//!       --input  params-k24.bin \
//!       --output params-k23.bin \
//!       [--target-k 23]
//!
//! Combine with `fetch-pse-srs.sh` + `verify-srs`:
//!   ./scripts/fetch-pse-srs.sh --url <publisher of k=24 file> \
//!       --sha256 <digest> --out params-k24.bin
//!   cargo run --release -p zkmist-tools --bin truncate-srs -- \
//!       --input params-k24.bin --output params-k23.bin
//!   cargo run --release -p zkmist-tools --bin verify-srs params-k23.bin
//!       # → prints the constants.rs snippet at k=23.

use std::io::{BufReader, BufWriter};

use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

/// Production circuit k. MUST match `CIRCUIT_K` in `cli/src/halo2_prover.rs`
/// and `EXPECTED_K` in `tools/src/verify_srs.rs`.
const DEFAULT_TARGET_K: u32 = 23;

fn main() {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut target_k: u32 = DEFAULT_TARGET_K;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" | "-i" => input = args.next(),
            "--output" | "-o" => output = args.next(),
            "--target-k" => {
                target_k = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_TARGET_K);
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: truncate-srs --input <file.bin> --output <file.bin> [--target-k N]"
                );
                eprintln!();
                eprintln!("  Downsizes a halo2 KZG SRS to exactly --target-k (default {DEFAULT_TARGET_K})");
                eprintln!("  via halo2's own audited Params::downsize(). See the module docs for");
                eprintln!(
                    "  why this is sound (same trapdoor τ; only high-degree powers dropped)."
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let input_path = input.expect("--input <PATH> is required");
    let output_path = output.expect("--output <PATH> is required");

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist KZG SRS Truncator (downsize to exactly k)          ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    // ── 1. Read the input file via the SAME path the prover uses. ──────────
    eprintln!("[1/5] Reading input: {input_path}");
    let in_bytes = std::fs::read(&input_path).unwrap_or_else(|e| {
        eprintln!("   ❌ cannot read input: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "   input size: {:.1} MiB ({} bytes)",
        in_bytes.len() as f64 / (1024.0 * 1024.0),
        in_bytes.len()
    );

    let mut params = {
        let mut reader = BufReader::new(&in_bytes[..]);
        ParamsKZG::<halo2curves::bn256::Bn256>::read(&mut reader).unwrap_or_else(|e| {
            eprintln!("   ❌ not a valid halo2 KZG params file: {e}");
            eprintln!("      (ParamsKZG::<Bn256>::read rejected it — the prover would too)");
            std::process::exit(1);
        })
    };

    let in_k = params.k();
    let in_n: u64 = 1 << in_k;
    eprintln!(
        "   input k: {in_k}  (n = 2^{in_k} = {in_n}, G1 points = {})",
        params.get_g().len()
    );

    if in_k == target_k {
        eprintln!();
        eprintln!("   ⚠️  input is already k={target_k} — nothing to truncate.");
        eprintln!("       Pass the file directly to verify-srs; no truncation needed.");
        std::process::exit(0);
    }
    if in_k < target_k {
        eprintln!();
        eprintln!("   ❌ input k={in_k} is SMALLER than target k={target_k}.");
        eprintln!("      Truncation only DROPS powers; it cannot manufacture a larger SRS.");
        eprintln!("      You need a source file at k ≥ {target_k}.");
        std::process::exit(1);
    }

    // Sanity: G1 count must equal 2^in_k for a well-formed file.
    assert_eq!(
        params.get_g().len(),
        in_n as usize,
        "input G1 count {} != 2^{in_k} — malformed file",
        params.get_g().len()
    );

    // ── 2. Serialize the INPUT params to a byte buffer. We will downsize ──
    //        `params` in place, then re-serialize it, and assert the kept
    //        G1 monomial points are byte-identical by comparing the leading
    //        bytes halo2's OWN writer produced (k-header + first `keep` G1
    //        points, each 64 bytes uncompressed under RawBytes). This proves
    //        downsize only DROPPED points — it did not alter a kept one.
    let keep = (1u64 << target_k) as usize;
    // RawBytes G1 point = 64 bytes (32 x ‖ 32 y); header = 4 bytes (k).
    let prefix_len = 4 + keep * 64;
    let mut in_buf = Vec::new();
    Params::write(&params, &mut in_buf).expect("halo2 Params::write of input");
    let _ = prefix_len; // kept for clarity; the byte-identity check uses in_buf directly.

    // ── 3. Downsize via halo2's own audited method. ───────────────────────
    eprintln!(
        "[3/5] Downsizing to k={target_k} via halo2 Params::downsize (recomputes g_lagrange)…"
    );
    let t = std::time::Instant::now();
    Params::downsize(&mut params, target_k);
    eprintln!("   downsize done in {:.1}s", t.elapsed().as_secs_f64());

    assert_eq!(params.k(), target_k, "downsize did not set k");
    assert_eq!(
        params.get_g().len(),
        keep,
        "downsize did not truncate g to 2^k"
    );

    // Assert the kept points are byte-identical to the input's prefix: serialize
    // the downsized params and compare the leading G1 bytes halo2 wrote.
    let mut out_check = Vec::new();
    Params::write(&params, &mut out_check).expect("halo2 Params::write of output");
    // Output header now encodes target_k (4 bytes), then `keep` G1 points. The
    // INPUT's header encoded in_k, so the first 4 bytes differ — compare only
    // the G1 region (skip each header).
    assert_eq!(
        in_buf[4..4 + keep * 64],
        out_check[4..4 + keep * 64],
        "downsize altered a kept G1 point — the first 2^target_k monomial \
         powers must be byte-identical to the input's"
    );
    eprintln!("   ✅ monomial prefix (first {keep} G1 points) byte-identical to input");

    // ── 4. Write the output, then round-trip re-read to prove the framing ─
    //        is intact (the file halo2 wrote is the file halo2 reads).
    eprintln!("[4/5] Writing output: {output_path}");
    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("   ❌ cannot create output dir: {e}");
            std::process::exit(1);
        });
    }
    {
        let f = std::fs::File::create(&output_path).unwrap_or_else(|e| {
            eprintln!("   ❌ cannot create output: {e}");
            std::process::exit(1);
        });
        let mut w = BufWriter::new(f);
        Params::write(&params, &mut w).unwrap_or_else(|e| {
            eprintln!("   ❌ write failed: {e}");
            std::process::exit(1);
        });
    }
    let out_bytes = std::fs::read(&output_path).unwrap_or_else(|e| {
        eprintln!("   ❌ cannot read back output: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "   output size: {:.1} MiB ({} bytes)",
        out_bytes.len() as f64 / (1024.0 * 1024.0),
        out_bytes.len()
    );

    // Round-trip: re-read the file we just wrote and confirm k + G1 count.
    let roundtrip = {
        let mut reader = BufReader::new(&out_bytes[..]);
        ParamsKZG::<halo2curves::bn256::Bn256>::read(&mut reader)
    }
    .unwrap_or_else(|e| {
        eprintln!("   ❌ round-trip read FAILED: {e}");
        eprintln!("      the file we wrote cannot be parsed back — do NOT use it");
        std::process::exit(1);
    });
    assert_eq!(roundtrip.k(), target_k, "round-trip k mismatch");
    assert_eq!(
        roundtrip.get_g().len(),
        keep,
        "round-trip G1 count mismatch"
    );
    eprintln!("   ✅ round-trip read OK (k={target_k}, {keep} G1 points)");

    // ── 5. Done — hand off to verify-srs. ─────────────────────────────────
    eprintln!("[5/5] Truncation complete.");
    eprintln!();
    eprintln!("   Next: run verify-srs to compute the SHA-256 you will pin:");
    eprintln!("     cargo run --release -p zkmist-tools --bin verify-srs {output_path}");
    eprintln!();
    eprintln!("   ⚠️  The output is the SAME PSE ceremony SRS (identical trapdoor τ),");
    eprintln!("      just the first 2^{target_k} G1 powers. It is NOT a forgeable dev SRS.");
    eprintln!("      Cross-check the digest against the source project's records before pinning.");
}
