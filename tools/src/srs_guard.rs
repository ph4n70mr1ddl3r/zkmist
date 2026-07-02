//! OOM guard for untrusted halo2 `ParamsKZG::<Bn256>` reads.
//!
//! Shared by the deployer-side SRS tools (`verify-srs`, `truncate-srs`,
//! `gen-verifier`). It is the direct analog of the prover's
//! `reject_untrusted_cache_oversized_k` in `cli/src/halo2_prover.rs`, applied
//! to the tools whose entire job is to inspect an operator-supplied
//! (downloaded / extracted / otherwise not-yet-trusted) SRS file.
//!
//! # The bug
//!
//! halo2 serializes params as `k.to_le_bytes()` (4 B) followed by the `g` and
//! `g_lagrange` G1 vectors, then `g2` + `s_g2` (RawBytes — see
//! `halo2_proofs::SerdeFormat::RawBytes`). On `read`, `ParamsKZG::read` →
//! `read_custom` parses those FIRST 4 bytes as `k`, computes `n = 1<<k`, and
//! allocates BOTH G1 vectors (`2·n` Bn256 G1 points) BEFORE control returns to
//! the caller — so the caller's own `assert_eq!(params.k(), ...)` cannot fire
//! in time. A corrupted or planted header claiming a large `k` (disk rot on
//! the first sector, a partial write from a crash mid-`Params::write`, or a
//! tampered file) therefore makes halo2 `malloc` ≈ `128 · 2^k` bytes (64 B per
//! G1 point × 2 vectors) and abort:
//!
//!   - `k = 28`  → ~32 GiB  (likely OOM on a laptop)
//!   - `k = 31`  → ~256 GiB (instant OOM-kill / allocator abort everywhere)
//!   - `k >= 32` → `1<<k` is a 32-bit shift: debug-panic, release-masks to a
//!     garbage `n` (Rust masks the shift amount to 5 bits).
//!
//! This matters most for `verify-srs`, whose REASON FOR EXISTING is to report
//! an untrusted file's `k` and SHA-256 — OOMing on a corrupted header (instead
//! of printing "k=31, file truncated") defeats the tool.
//!
//! # The guard
//!
//! Peek the header `k` and reject — BEFORE `ParamsKZG::read` — when either
//! holds:
//!
//!   1. `k >= 32` — shift-safety. No PSE perpetual-powers-of-tau SRS reaches
//!      k=32 (a k=32 file is ≥ 16 GiB of G1 alone; proving at k=32 needs ~2
//!      TiB RAM), so rejecting loses nothing real.
//!   2. `file_size < 128 · (1<<k)` — the file cannot contain the points its
//!      header claims. A real Bn256 RawBytes SRS holds `2·2^k` G1 points at
//!      64 B each = `128·2^k` bytes of G1 data (plus a 4 B header + two 128 B
//!      G2 points), so any legit file is ≥ this bound. A file below it is
//!      unambiguously corrupted or truncated. This also catches the far more
//!      common truncated-download case (header `k` intact, body short) with a
//!      clearer message than halo2's generic EOF error.
//!
//! The guard is conservative in the SAFE direction: it never rejects a legit
//! file (which is always ≥ the bound), only corrupted / oversized-k / truncated
//! ones. It does NOT replace `ParamsKZG::read`'s own validation — a file that
//! passes the guard can still fail to parse (e.g. a well-sized file of random
//! bytes) — it only prevents the allocator-driving case.

/// Minimum on-disk size, in bytes, of the G1 data in a halo2 `ParamsKZG::<Bn256>`
/// params file at circuit size `k`: two G1 vectors (`g` + `g_lagrange`) of
/// `2^k` points each, every point 64 B raw (`x ‖ y`, two 256-bit Bn256 `Fq`s —
/// see `halo2curves` `derive/curve.rs` `Affine::to_raw_bytes` → `2 * base_size`
/// with `base = Fq`, 32 B). The full file adds a 4 B `k` header + two 128 B G2
/// points on top of this, so a legit file is always strictly larger.
const G1_RAW_POINT_BYTES: usize = 64;

/// Core invariant checks for a halo2 `ParamsKZG::<Bn256>` header `k` against a
/// known file size — the allocator-driving value BEFORE the caller hands the
/// file to `ParamsKZG::read`.
///
/// Split out of [`peek_and_bound_params_k`] so the STREAMED read path (open
/// `File`, `read_exact` 4 bytes for the header, `metadata().len()` for the
/// size, then hand the seeked-back `File` straight to `ParamsKZG::read`) can
/// guard itself WITHOUT buffering the whole (potentially ~1 GiB) file into a
/// `Vec` — matching what `gen-verifier` / `gen-production-verifier` did before
/// the guard, so the fix adds no extra peak-RAM cost on top of `ParamsKZG::read`'s
/// own `2·2^k`-point allocation.
///
/// Returns `Ok(())` on success. See the module docs for the threat model and
/// the exact guard invariants.
///
/// *This module is `#[path]`-shared across `verify-srs`, `truncate-srs`, and
/// `gen-verifier`; each bin uses a different subset of its entry points, so the
/// function unused in a given bin would otherwise trip `-D warnings` under the
/// repo's CI lint gate. The `allow(dead_code)` is intentional and scoped.*
#[allow(dead_code)]
pub fn check_params_k(k: u32, file_size: u64, file_label: &str) -> Result<(), String> {
    // Guard 1: shift-safety. halo2 computes `n = 1 << k` as a 32-bit shift;
    // `k >= 32` debug-panics and release-masks to a garbage `n`. No PSE
    // ceremony SRS reaches k=32 in any case.
    if k >= 32 {
        return Err(format!(
            "{file_label}: header claims k={k} (>= 32). halo2's `1<<k` is a 32-bit \
             shift (debug-panic / release-mask) and a k=32 SRS would be >= 16 GiB of \
             G1 data alone. The file is corrupted or tampered; refusing to hand this \
             k to ParamsKZG::read."
        ));
    }

    // Guard 2: the file must be large enough to hold the two `2^k`-point G1
    // vectors its header claims. `128 · 2^k` is the G1 footprint (64 B/point ×
    // 2 vectors); a legit file is always >= this. k < 32 ⇒ `1<<k <= 2^31`, so
    // `128 · (1<<k) <= 2^38` fits comfortably in usize on a 64-bit target.
    let min_g1_bytes = (2 * G1_RAW_POINT_BYTES)
        .checked_mul(1usize << k)
        .expect("k < 32 ⇒ 2·64·2^k <= 2^38, no usize overflow on 64-bit");
    if (file_size as usize) < min_g1_bytes {
        let claimed_g1_points = 2u64 << k; // 2 · 2^k
        return Err(format!(
            "{file_label}: header claims k={k} ({g1_pts} G1 points across the g + \
             g_lagrange vectors = {min} bytes of G1 data at 64 B/point), but the file \
             is only {actual} bytes. It is corrupted or truncated (e.g. an interrupted \
             download, disk rot, or a tampered/planted header). Refusing to hand k={k} \
             to ParamsKZG::read — it would allocate ~{min} bytes before erroring on EOF.",
            g1_pts = claimed_g1_points,
            min = min_g1_bytes,
            actual = file_size,
        ));
    }
    Ok(())
}

/// Peek a halo2 `ParamsKZG::<Bn256>` params file's `k` header from its
/// in-memory bytes and reject a value that would make `ParamsKZG::read`
/// allocate hundreds of GiB (or panic) before the caller can inspect it.
///
/// Returns the validated `k` on success so the caller can surface it. The
/// `file_label` is included in error messages to identify which file failed
/// (these tools accept multiple / named files).
///
/// Call this on the SAME byte buffer you are about to hand to
/// `ParamsKZG::<Bn256>::read(&mut BufReader::new(&bytes[..]))`, e.g. right
/// after `std::fs::read(path)` — for the tools that ALREADY buffer the whole
/// file (`verify-srs` buffers it for SHA-256, `truncate-srs` buffers the
/// input). For tools that STREAM the file, call [`check_params_k`] directly
/// after a 4-byte header peek + `metadata().len()`.
#[allow(dead_code)]
pub fn peek_and_bound_params_k(bytes: &[u8], file_label: &str) -> Result<u32, String> {
    if bytes.len() < 4 {
        return Err(format!(
            "{file_label}: smaller than the 4-byte halo2 `k` header ({len} bytes) — \
             not a halo2 params file",
            len = bytes.len()
        ));
    }
    let k = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    check_params_k(k, bytes.len() as u64, file_label)?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(k: u32) -> [u8; 4] {
        k.to_le_bytes()
    }

    /// A legit-sized file at exactly the production circuit k (k=23) passes the
    /// guard. The minimum legit file size is `4 + 128·2^k + 256` (header + G1
    /// data + two G2 points); we synthesize that so the test is independent of
    /// any real (huge) SRS file on disk.
    #[test]
    fn accepts_legit_k23_file() {
        let k = 23u32;
        let legit_len = 4 + 128 * (1usize << k) + 256;
        let mut buf = vec![0u8; legit_len];
        buf[..4].copy_from_slice(&header(k));
        assert_eq!(peek_and_bound_params_k(&buf, "k23.bin").unwrap(), k);
    }

    /// Smaller legit k values (k=0 … 4) also pass — the guard must never reject
    /// a real file at the low end either.
    #[test]
    fn accepts_small_legit_k() {
        for k in 0..=4u32 {
            let legit_len = 4 + 128 * (1usize << k) + 256;
            let mut buf = vec![0u8; legit_len];
            buf[..4].copy_from_slice(&header(k));
            assert_eq!(
                peek_and_bound_params_k(&buf, &format!("k{k}.bin")).unwrap(),
                k,
                "legit k={k} file must pass"
            );
        }
    }

    /// A header claiming k=31 on a tiny file (the classic disk-rot / planted-
    /// header OOM attempt) is rejected WITHOUT the caller ever calling
    /// `ParamsKZG::read` (which would `malloc ~256 GiB`).
    #[test]
    fn rejects_huge_k_on_small_file_without_oom() {
        let mut buf = vec![0u8; 1024]; // 1 KiB
        buf[..4].copy_from_slice(&header(31));
        let err = peek_and_bound_params_k(&buf, "tampered.bin").expect_err("k=31 must reject");
        assert!(err.contains("k=31"), "error must name the bogus k: {err}");
        assert!(
            err.contains("tampered.bin"),
            "error must name the file: {err}"
        );
        assert!(
            err.contains("corrupted") || err.contains("truncated") || err.contains("tampered"),
            "error must explain it is corruption: {err}"
        );
    }

    /// `k >= 32` is rejected by the shift-safety guard specifically (halo2's
    /// `1<<k` is a 32-bit shift), regardless of file size — a huge `k` would
    /// mask to a garbage `n` in release or panic in debug.
    #[test]
    fn rejects_k_ge_32_for_shift_safety() {
        // k=32: even with a generously-sized (fake) body, rejected for shift safety.
        let mut buf = vec![0u8; 1 << 20]; // 1 MiB
        buf[..4].copy_from_slice(&header(32));
        let err = peek_and_bound_params_k(&buf, "k32.bin").expect_err("k>=32 must reject");
        assert!(err.contains("k=32"), "{err}");
        assert!(err.contains("32-bit"), "{err}");

        // k=255 (u32 near max): same shift-safety rejection.
        buf[..4].copy_from_slice(&header(255));
        let err = peek_and_bound_params_k(&buf, "k255.bin").expect_err("k>=32 must reject");
        assert!(err.contains("k=255"), "{err}");
    }

    /// The common truncated-download case: header `k` is intact (a legit k=23),
    /// but the body is far shorter than `128·2^k` bytes. Rejected as
    /// corrupted/truncated with a message that points at the real cause (an
    /// interrupted download), instead of halo2's generic EOF parse error.
    #[test]
    fn rejects_truncated_download() {
        let k = 23u32;
        let mut buf = vec![0u8; 1 << 20]; // 1 MiB — way short of the ~1 GiB G1 footprint
        buf[..4].copy_from_slice(&header(k));
        let err = peek_and_bound_params_k(&buf, "partial.bin").expect_err("truncated must reject");
        assert!(err.contains("k=23"), "{err}");
        assert!(
            err.contains("truncated") || err.contains("corrupted"),
            "error must name truncation/corruption: {err}"
        );
    }

    /// Boundary: a file at EXACTLY `128·2^k` bytes (the G1 footprint, no header
    /// slack, no G2) still passes — the guard is a strict lower bound, and a
    /// real file (which adds the header + G2) is always larger.
    #[test]
    fn boundary_min_g1_footprint_passes() {
        let k = 10u32;
        let min_g1 = 128 * (1usize << k);
        let mut buf = vec![0u8; min_g1];
        buf[..4].copy_from_slice(&header(k));
        assert_eq!(peek_and_bound_params_k(&buf, "k10.bin").unwrap(), k);

        // One byte short of the G1 footprint → rejected (boundary is strict).
        let mut short = vec![0u8; min_g1 - 1];
        short[..4].copy_from_slice(&header(k));
        assert!(
            peek_and_bound_params_k(&short, "k10-short.bin").is_err(),
            "one byte below the G1 footprint must reject"
        );
    }

    /// A file too small to even contain the 4-byte header is rejected cleanly
    /// (not via a slice panic).
    #[test]
    fn rejects_subheader_file() {
        let buf = [0u8; 2];
        let err = peek_and_bound_params_k(&buf, "tiny.bin").expect_err("sub-header must reject");
        assert!(err.contains("4-byte"), "{err}");
    }

    /// The streamed-path entry point (`check_params_k`) enforces the SAME
    /// invariants as the buffered-path entry point — it is what `gen-verifier`
    /// / `gen-production-verifier` call after a 4-byte header peek +
    /// `metadata().len()`, so they need not buffer the whole file. Cover it
    /// directly so a future edit to one path can't silently desync the other.
    #[test]
    fn check_params_k_matches_buffered_guard() {
        // k=23 legit size passes both paths.
        let k = 23u32;
        let legit_len = (4 + 128 * (1usize << k) + 256) as u64;
        assert!(check_params_k(k, legit_len, "k23.bin").is_ok());
        // k=31 on a 1 KiB file: rejected by the size guard (not the shift guard).
        let err = check_params_k(31, 1024, "tampered.bin").expect_err("must reject");
        assert!(err.contains("k=31") && err.contains("truncated"), "{err}");
        // k=32 rejected by the shift guard regardless of size.
        let err = check_params_k(32, u64::MAX, "k32.bin").expect_err("must reject");
        assert!(err.contains("k=32") && err.contains("32-bit"), "{err}");
    }
}
