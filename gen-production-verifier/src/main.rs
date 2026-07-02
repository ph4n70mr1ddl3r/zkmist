//! Production Solidity verifier generator for ZKMist.
//!
//! Generates `Halo2Verifier.sol` + `Halo2VerifyingKey.sol` from the REAL
//! `zkmist_circuits::ZKMistV2Claim` circuit via `keygen_vk`, then renders them
//! with the vendored `halo2-solidity-verifier`.
//!
//! # Why this crate is a separate workspace
//!
//! `halo2-solidity-verifier` is implemented against the **PSE git fork** of
//! halo2 (`v0.3.0`), whose `ConstraintSystem` / prover API is incompatible with
//! the crates.io `halo2_proofs` 0.3.x that the main zkmist workspace (CLI
//! prover, k=23 MockProver tests) is validated against. The two forks are
//! distinct crates to Cargo and their types do not unify, so a circuit compiled
//! under one cannot be passed to `keygen_vk` under the other.
//!
//! This crate is therefore its OWN workspace (`[workspace]` in Cargo.toml) on
//! the git fork, and forces `zkmist-circuits` onto the git fork too via
//! `cargo update --precise` + `[patch.crates-io]`-equivalent resolution, so
//! `keygen_vk` here accepts the same `ZKMistV2Claim` the prover uses. A tiny
//! cfg-gated compat shim in `zkmist-circuits` (`git-fork-api` feature) handles
//! the two forks' call-site differences (`query_fixed` arity, named `lookup`);
//! it is provably digest-preserving (guarded by `EXPECTED_CS_DIGEST` on both
//! sides). The main zkmist workspace is completely unaffected.
//!
//! # What this replaces
//!
//! Previously this file carried a hand-maintained duplicate of `configure()`
//! plus a STUB `synthesize()` (loading only the range8 table), guarded by
//! `SYNTHESIZE_IS_STUB` so it refused to emit. The stub's VK had identity
//! permutation commitments and missing fixed commitments, so it could never
//! match the prover. That duplicate is now DELETED: this crate imports
//! `ZKMistV2Claim` directly and runs its REAL `synthesize`, so the emitted VK
//! is derived from the true circuit.
//!
//! # Validation status — READ BEFORE EMITTING
//!
//! Compiling + `keygen_vk` succeeding proves the synthesize port is
//! STRUCTURALLY correct (the circuit synthesizes; fixed/permutation columns
//! are populated). It does NOT prove the emitted VK matches the prover's VK:
//! the VK commitments depend on the KZG SRS, which must be the SAME pinned PSE
//! perpetual-powers-of-tau file the prover loads (`KZG_SRS_SHA256` in
//! `cli/src/constants.rs`). Until that match is confirmed, this tool REFUSES
//! to write the `.sol` files (see the `--emit` flag below). The validation
//! procedure is DEPLOYMENT.md Phase 3:
//!   1. obtain + pin the PSE SRS (Phase 2);
//!   2. run this tool AND `tools/gen_verifier` against the SAME `--params-file`;
//!   3. confirm both print the SAME VK `transcript_repr` / pinned SHA-256;
//!   4. only then pass `--emit` to write the Solidity;
//!   5. finish with a real proof → Solidity verifier round-trip (Phase 4).

use std::path::PathBuf;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem},
    poly::kzg::commitment::ParamsKZG,
};
use halo2_solidity_verifier::{BatchOpenScheme, SolidityGenerator};

// The REAL circuit + parity-guard constants, imported directly (no duplicate).
use zkmist_circuits::{constraint_system_digest, ZKMistV2Claim, EXPECTED_CS_DIGEST};

/// Production circuit `k`. MUST match `CIRCUIT_K` in `cli/src/halo2_prover.rs`
/// (k=23 after the secp256k1 `point_add_mixed` optimization halved the witness).
const EXPECTED_K: u32 = 23;

/// OOM guard for an untrusted halo2 `ParamsKZG::<Bn256>` read.
///
/// Inline copy of `tools/src/srs_guard.rs::check_params_k` (this is a separate
/// workspace, so the module is not shared). halo2 parses the file's first 4
/// bytes as `k` and allocates `2·2^k` G1 points (64 B each) from it BEFORE the
/// caller's `k`-check can fire — so a corrupted / planted header (disk rot,
/// partial write, tampering) or a truncated download would OOM-abort. Reject,
/// before `ParamsKZG::read`, when:
///   - `k >= 32` (halo2's `1<<k` is a 32-bit shift: debug-panic / release-mask), or
///   - the file is smaller than `128·2^k` bytes (the G1 footprint it claims).
///
/// A legit Bn256 RawBytes file is always >= `128·2^k` (header + 2·2^k G1 points
/// + 2 G2 points), so this never rejects a real file.
fn check_params_k(k: u32, file_size: u64, file_label: &str) -> Result<(), String> {
    if k >= 32 {
        return Err(format!(
            "{file_label}: header claims k={k} (>= 32). halo2's `1<<k` is a 32-bit \
             shift (debug-panic / release-mask) and a k=32 SRS would be >= 16 GiB of \
             G1 data alone. The file is corrupted or tampered; refusing to hand this \
             k to ParamsKZG::read."
        ));
    }
    // k < 32 ⇒ 128·2^k <= 2^38, no usize overflow on 64-bit.
    let min_g1_bytes = 128usize * (1usize << k);
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

/// Peek a halo2 `ParamsKZG::<Bn256>` file's 4-byte `k` header + on-disk size
/// and run [`check_params_k`] against them, WITHOUT buffering the file body.
///
/// `ParamsKZG::read` parses the first 4 bytes as `k` and allocates the `g` +
/// `g_lagrange` G1 vectors (`2·2^k` points, 64 B each) from that `k` BEFORE
/// the caller can inspect it — so a corrupted / planted header (disk rot, a
/// partial write from a crash mid-`Params::write`, or a tampered file) or a
/// truncated download makes halo2 `malloc` a huge region and OOM-aborts the
/// process. This guard reads ONLY the 4-byte header + `metadata().len()` (zero
/// peak-RAM on top of `ParamsKZG::read`'s own allocation) and returns
/// `Ok(())` if the file's claimed `k` is safe to hand to `ParamsKZG::read`,
/// or an `Err(message)` describing why not. Shared by the `--params-file`
/// path (hard error → panic) and the dev-cache path (soft → delete +
/// regenerate).
fn peek_params_k_guard(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;
    let label = path.display().to_string();
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {label}: {e}"))?;
    let mut hdr = [0u8; 4];
    f.read_exact(&mut hdr)
        .map_err(|e| format!("read k header from {label}: {e}"))?;
    let file_size = f
        .metadata()
        .map(|m| m.len())
        .map_err(|e| format!("stat {label}: {e}"))?;
    check_params_k(u32::from_le_bytes(hdr), file_size, &label)
}

/// Load the KZG params (SRS) for `keygen_vk`.
///
/// Precedence:
///   1. `--params-file <PATH>` — load a pinned PSE transcript (production).
///      This MUST be derived from the same PSE perpetual powers-of-tau
///      ceremony the prover's `KZG_SRS_SHA256`-pinned file comes from, so the
///      VK's commitments match the proofs the prover generates.
///   2. `ZKMIST_DEV_SRS=1` — generate a RANDOM `ParamsKZG` via `setup` and
///      cache it under `~/.zkmist/cache/`, reusing it on later runs. Dev/test
///      ONLY: a VK emitted against this SRS is NOT consistent with the prover
///      (which loads the pinned PSE SRS) and proofs would be forgeable / would
///      not verify. Used to confirm `keygen_vk` runs end-to-end on the real
///      circuit without the large download.
///   3. Otherwise — error. Generating a random SRS unconditionally would emit
///      a VK that silently mismatches the prover (a soundness footgun).
fn load_or_gen_params(
    k: u32,
    params_file: Option<&std::path::Path>,
) -> ParamsKZG<halo2curves::bn256::Bn256> {
    use halo2_proofs::poly::commitment::Params;
    use std::io::{BufReader, BufWriter};

    // 1. Pinned transcript file (production).
    if let Some(path) = params_file {
        eprintln!("      Loading pinned KZG SRS from {}...", path.display());
        // Pre-flight the header `k` before `ParamsKZG::read`: halo2 parses the
        // file's first 4 bytes as `k` and allocates `2·2^k` G1 points from it
        // BEFORE our `assert_eq!(params.k(), k)` below can fire, so a corrupted /
        // planted header (disk rot, a partial write, tampering) or a truncated
        // download would OOM-abort this tool instead of producing the clean
        // "read params file" panic. Same bug class as the prover's
        // `reject_untrusted_cache_oversized_k`; see `check_params_k` /
        // `peek_params_k_guard`.
        if let Err(e) = peek_params_k_guard(path) {
            panic!("{e}");
        }
        let f = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("open params file {}: {}", path.display(), e));
        let params = ParamsKZG::<halo2curves::bn256::Bn256>::read(&mut BufReader::new(f))
            .unwrap_or_else(|e| panic!("parse params file {}: {}", path.display(), e));
        assert_eq!(params.k(), k, "pinned SRS k ({}) != --k {}", params.k(), k);
        eprintln!("      ✓ loaded pinned SRS (k={})", params.k());
        return params;
    }

    // 2. Dev fallback (RANDOM SRS), cached.
    if std::env::var("ZKMIST_DEV_SRS").is_ok() {
        let cache = dirs::home_dir().map(|h| {
            h.join(".zkmist")
                .join("cache")
                .join(format!("dev_paramskzg_k{}.bin", k))
        });
        if let Some(ref p) = cache {
            if p.exists() {
                eprintln!(
                    "      Loading cached dev ParamsKZG (k={}) from {}...",
                    k,
                    p.display()
                );
                // Pre-flight the header `k` BEFORE `ParamsKZG::read`: this
                // cache file is written by THIS tool via `params.write`, so a
                // crash mid-write (exactly the "partial write from a crash
                // mid-Params::write" the other SRS guards cite), disk rot, or a
                // tampered file can leave a header whose `k` is larger than the
                // cache key implies — and `ParamsKZG::read` would allocate
                // `2·2^k` G1 points from that header BEFORE any mismatch could
                // be caught, OOM-killing this tool. Same bug class as the
                // `--params-file` path above, the prover's
                // `reject_untrusted_cache_oversized_k`, and the merkle-tree
                // cache depth bound. On rejection, drop the corrupt cache and
                // fall through to regeneration below (the cache is optional
                // convenience, not a hard dependency).
                let guard_ok = match peek_params_k_guard(p) {
                    Ok(()) => true,
                    Err(e) => {
                        eprintln!("      ⚠️  {e}");
                        false
                    }
                };
                if guard_ok {
                    if let Ok(f) = std::fs::File::open(p) {
                        if let Ok(params) =
                            ParamsKZG::<halo2curves::bn256::Bn256>::read(&mut BufReader::new(f))
                        {
                            eprintln!("      ✓ cached dev SRS loaded");
                            return params;
                        }
                    }
                }
                // Guard rejected OR halo2's own read failed: the cache is
                // unusable. Remove it so the next run isn't poisoned, then
                // regenerate below.
                let _ = std::fs::remove_file(p);
                eprintln!("      ⚠️  cached dev SRS unreadable; regenerating");
            }
        }
        eprintln!("      ⚠️  ZKMIST_DEV_SRS=1 — generating a RANDOM ParamsKZG (dev/test ONLY)");
        eprintln!("         Do NOT emit a VK from this SRS — its commitments are against a");
        eprintln!("         self-generated SRS and will NOT match the prover's pinned SRS.");
        let params = ParamsKZG::<halo2curves::bn256::Bn256>::setup(k, &mut rand::thread_rng());
        if let Some(ref p) = cache {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(f) = std::fs::File::create(p) {
                let _ = params.write(&mut BufWriter::new(f));
                eprintln!(
                    "      ✓ cached dev SRS to {} (reused on subsequent runs)",
                    p.display()
                );
            }
        }
        return params;
    }

    // 3. No SRS source — refuse (would emit an inconsistent VK).
    eprintln!("❌ No KZG SRS source configured.");
    eprintln!("   Production: pass --params-file <PATH> with a PSE halo2 params file derived");
    eprintln!("   from the SAME perpetual powers-of-tau ceremony pinned in");
    eprintln!("   cli/src/constants.rs (KZG_SRS_SHA256), so the VK matches the prover.");
    eprintln!("   Dev/test: set ZKMIST_DEV_SRS=1 to generate a random cached SRS.");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let default_output_dir = PathBuf::from("../contracts/src");
    let mut output_dir = default_output_dir.clone();
    // True only when --output was explicitly passed on the CLI. Required by the
    // --allow-dev-emit guard below: a dev VK must NEVER silently overwrite the
    // default contracts/src/ (it is forgeable — deploying it would brick the
    // airdrop). Tracking the flag (rather than comparing path strings) is robust
    // to `../contracts/src` vs `contracts/src` vs absolute-path spellings.
    let mut output_set = false;
    let mut k: u32 = EXPECTED_K;
    let mut params_file: Option<PathBuf> = None;
    let mut emit = false;
    // Escape hatch for toolchain validation only: allows --emit against a RANDOM
    // dev SRS, but ONLY to a non-default --output dir (never contracts/src/).
    // The emitted VK is forgeable and stamped DEV-ONLY. Use to validate the
    // emit → forge build → on-chain round-trip path without a real PSE SRS;
    // NEVER deploy or commit a dev-emit VK. See scripts/regenerate-vk.sh.
    let mut allow_dev_emit = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                output_dir = PathBuf::from(&args[i + 1]);
                output_set = true;
                i += 2;
            }
            "--params-file" => {
                params_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--k" => {
                k = args[i + 1].parse().unwrap_or(EXPECTED_K);
                i += 2;
            }
            // ⚠️ Only pass --emit AFTER confirming the printed VK repr / pinned
            // SHA-256 matches `tools/gen_verifier`'s output against the SAME
            // pinned SRS (DEPLOYMENT.md Phase 3). Writes Halo2Verifier.sol +
            // Halo2VerifyingKey.sol, overwriting the current placeholder VK.
            "--emit" => {
                emit = true;
                i += 1;
            }
            "--allow-dev-emit" => {
                allow_dev_emit = true;
                i += 1;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: gen-production-verifier [--output DIR] [--k N] \
                     [--params-file PATH] [--emit] [--allow-dev-emit]"
                );
                eprintln!(
                    "  Default (no --emit): runs keygen_vk on the real circuit and prints the"
                );
                eprintln!(
                    "    VK fingerprint for cross-checking, but does NOT write the .sol files."
                );
                eprintln!("  --emit: also write Halo2Verifier.sol + Halo2VerifyingKey.sol.");
                eprintln!(
                    "  --allow-dev-emit: permit --emit against a dev SRS ONLY to a non-default"
                );
                eprintln!(
                    "    --output dir (toolchain validation; output is forgeable, DEV-ONLY)."
                );
                return;
            }
            _ => {
                eprintln!("Unknown: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist Production Verifier Generator                      ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    if k != EXPECTED_K {
        eprintln!(
            "⚠️  WARNING: k={} does not match expected CIRCUIT_K={}",
            k, EXPECTED_K
        );
        eprintln!("   The generated verifier will reject proofs created with a different k.");
        eprintln!(
            "   Proceeding anyway. Use --k {} for the production value.",
            EXPECTED_K
        );
    }

    eprintln!(
        "[1/4] Creating circuit (k={}) from zkmist_circuits::ZKMistV2Claim...",
        k
    );
    let circuit = ZKMistV2Claim::default();

    // Parity guard: the git-fork configure() digest must equal the crates.io
    // side's EXPECTED_CS_DIGEST. The compat shim is digest-preserving, so this
    // should always hold; if it fires, the circuit's `configure()` changed and
    // EXPECTED_CS_DIGEST must be regenerated on BOTH sides (run
    // `cargo test -p zkmist-circuits test_circuit_constraint_system_digest`).
    {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = <ZKMistV2Claim as Circuit<Fr>>::configure(&mut cs);
        let digest = constraint_system_digest(&cs);
        if digest != EXPECTED_CS_DIGEST {
            eprintln!("❌ Constraint-system digest mismatch (git-fork vs crates.io)!");
            eprintln!("   git-fork    : {}", digest);
            eprintln!("   EXPECTED    : {}", EXPECTED_CS_DIGEST);
            eprintln!("   The compat shim should be digest-preserving. If the circuit's");
            eprintln!("   configure() changed intentionally, regenerate EXPECTED_CS_DIGEST");
            eprintln!("   (cargo test -p zkmist-circuits test_circuit_constraint_system_digest).");
            std::process::exit(1);
        }
        eprintln!(
            "   ✓ constraint-system digest matches the crates.io circuit ({})",
            digest
        );
    }

    eprintln!("[2/4] Loading KZG SRS (params)...");
    let start = std::time::Instant::now();
    let params = load_or_gen_params(k, params_file.as_deref());
    eprintln!("      ✓ ({:.1}s)", start.elapsed().as_secs_f64());

    eprintln!("[3/4] Generating VK via keygen_vk on the REAL circuit synthesize...");
    let t = std::time::Instant::now();
    let vk = halo2_proofs::plonk::keygen_vk(&params, &circuit).expect("keygen_vk failed");
    eprintln!("      ✓ ({:.1}s)", t.elapsed().as_secs_f64());
    eprintln!("      VK repr: {:?}", vk.transcript_repr());
    eprintln!(
        "      fixed_commitments:       {}",
        vk.fixed_commitments().len()
    );
    eprintln!(
        "      permutation_commitments: {}",
        vk.permutation().commitments().len()
    );

    // Structural sanity: a real synthesize populates fixed + permutation
    // commitments. The old stub produced zero fixed and identity permutation
    // commitments. If these counts are implausibly low, the import is not the
    // real circuit — do not trust the VK.
    let n_fixed = vk.fixed_commitments().len();
    let n_perm = vk.permutation().commitments().len();
    if n_fixed == 0 {
        eprintln!("❌ ABORT: VK has ZERO fixed commitments — synthesize did not load any");
        eprintln!("   fixed/lookup tables. The imported ZKMistV2Claim is not the real circuit.");
        std::process::exit(2);
    }
    eprintln!(
        "   ✓ non-zero fixed commitments ({}); synthesize ran the real circuit",
        n_fixed
    );
    let _ = n_perm; // reported above

    // VK fingerprint for cross-checking against tools/gen_verifier under the
    // SAME pinned SRS. When both match byte-for-byte, the git-fork VK and the
    // prover-side VK agree → emitted Solidity will accept honest proofs.
    let pinned_sha256 = {
        use sha2::{Digest as Sha2Digest, Sha256};
        let pinned_debug = format!("{:?}", vk.pinned());
        let mut hasher = Sha256::new();
        hasher.update(pinned_debug.as_bytes());
        hasher.finalize()
    };
    eprintln!(
        "      pinned SHA-256: 0x{}",
        pinned_sha256
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    eprintln!();
    eprintln!(
        "   ⚠️  This VK was derived with {} SRS.",
        if params_file.is_some() {
            "a PINNED"
        } else {
            "a RANDOM dev"
        }
    );
    if params_file.is_none() {
        eprintln!("   It will NOT match the prover. Re-run with --params-file <pinned PSE SRS>.");
    }

    if !emit {
        eprintln!();
        eprintln!("[4/4] SKIPPED writing .sol files (no --emit).");
        eprintln!("   To deploy, you MUST first confirm the VK fingerprint above matches");
        eprintln!("   `cargo run -p zkmist-tools --bin gen-verifier --features v2 -- \\");
        eprintln!("       --params-file <SAME pinned PSE SRS>`");
        eprintln!("   printed VK repr / pinned SHA-256, byte-for-byte. Only then re-run with");
        eprintln!("   --emit. See DEPLOYMENT.md Phase 3-4.");
        return;
    }

    if params_file.is_none() {
        // Dev SRS. The default guard (no --allow-dev-emit) always refuses, so a
        // dev VK can never silently overwrite contracts/src/. --allow-dev-emit is
        // explicit opt-in for toolchain validation: the emitted VK is stamped
        // DEV-ONLY + FORGEABLE in its banner so it cannot be mistaken for, or
        // accidentally committed as, a production VK. See scripts/regenerate-vk.sh.
        if !allow_dev_emit {
            eprintln!();
            eprintln!("❌ REFUSING --emit with a RANDOM dev SRS.");
            eprintln!(
                "   --emit requires --params-file <pinned PSE SRS> so the emitted VK matches"
            );
            eprintln!("   the prover. Emitting against a dev SRS would brick the airdrop (every");
            eprintln!("   honest proof rejected on-chain).");
            eprintln!("   For TOOLCHAIN VALIDATION ONLY (forgeable, never deploy/commit): pass");
            eprintln!("   --allow-dev-emit AND a non-default --output DIR, e.g.");
            eprintln!("     --allow-dev-emit --output /tmp/dev-vk");
            std::process::exit(2);
        }
        // Enforce the promise in the --allow-dev-emit docstring: a dev VK must
        // NEVER land in the default contracts/src/ — only an explicit,
        // non-default --output dir. Without this, `--emit --allow-dev-emit`
        // (no --output) silently overwrites the production-bound verifier
        // stubs with a forgeable dev VK, which is exactly how the placeholder
        // can get clobbered by accident.
        if !output_set || output_dir == default_output_dir {
            eprintln!();
            eprintln!(
                "❌ REFUSING dev-emit to the DEFAULT output dir ({}).",
                output_dir.display()
            );
            eprintln!("   --allow-dev-emit requires an explicit, non-default --output DIR so a");
            eprintln!("   forgeable dev VK can never overwrite contracts/src/. Re-run with");
            eprintln!("   e.g. --allow-dev-emit --output /tmp/dev-vk");
            std::process::exit(2);
        }
        eprintln!();
        eprintln!("⚠️⚠️⚠️  --allow-dev-emit: emitting a DEV VK.");
        eprintln!("   This VK is FORGEABLE (random dev SRS). Toolchain validation ONLY.");
        eprintln!(
            "   Do NOT deploy, do NOT commit. Output dir: {}",
            output_dir.display()
        );
    }

    eprintln!("[4/4] Generating Solidity verifier (--emit)...");
    let gen = SolidityGenerator::new(&params, &vk, BatchOpenScheme::Bdfg21, 3);
    let (verifier, vk_sol) = gen.render_separately().expect("render failed");

    let is_dev = params_file.is_none();
    let banner = if is_dev {
        "// ⚠️⚠️⚠️ DEV-ONLY (toolchain validation) — emitted with --allow-dev-emit against\n\
                  // a RANDOM dev KZG SRS. This VK is FORGEABLE: proofs against it verify\n\
                  // but prove NOTHING. Do NOT deploy. Do NOT commit. Regenerate with a\n\
                  // pinned PSE SRS (--params-file) for production.\n\
                  // Auto-generated from zkmist_circuits::ZKMistV2Claim.\n\n"
    } else {
        "// ⚠️ AUTO-GENERATED by `gen-production-verifier --emit` from the REAL\n\
                  // zkmist_circuits::ZKMistV2Claim circuit. Do not edit by hand.\n\
                  // VK validity is gated on the pinned PSE KZG SRS (KZG_SRS_SHA256 in\n\
                  // cli/src/constants.rs); confirm via DEPLOYMENT.md Phase 3-4 before\n\
                  // deploying.\n\n"
    };

    std::fs::create_dir_all(&output_dir).ok();
    std::fs::write(
        output_dir.join("Halo2Verifier.sol"),
        format!("{}{}", banner, verifier),
    )
    .unwrap();
    std::fs::write(
        output_dir.join("Halo2VerifyingKey.sol"),
        format!("{}{}", banner, vk_sol),
    )
    .unwrap();

    let has_pairing = verifier.contains("ecPairing") || verifier.contains("0x08");
    eprintln!("      ✓ Halo2Verifier.sol ({} bytes)", verifier.len());
    eprintln!("      ✓ Halo2VerifyingKey.sol ({} bytes)", vk_sol.len());
    eprintln!("      Pairing: {}", if has_pairing { "✅" } else { "❌" });
    eprintln!();
    eprintln!("✅ Emitted. Next: cd contracts && forge build && forge test -vvv");
    eprintln!("   Then DEPLOYMENT.md Phase 4: real proof → Solidity verifier round-trip");
    eprintln!("   on a local anvil fork BEFORE any testnet/mainnet deploy.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::poly::commitment::Params;

    /// A unique scratch path so parallel `cargo test` invocations don't
    /// collide on the same filename. Cleaned up by each test on success AND
    /// failure (best-effort `let _ = remove_file`).
    fn scratch(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zkmist-gpv-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        p
    }

    /// A legit small halo2 params file is accepted by the guard (the happy
    /// path every dev-cache hit takes). Uses k=8 (256 rows, ~32 KiB file) so
    /// the test is instant and allocates nothing meaningful.
    #[test]
    fn peek_guard_accepts_legit_params_file() {
        let path = scratch("legit.bin");
        let params = ParamsKZG::<halo2curves::bn256::Bn256>::setup(8, &mut rand::rngs::OsRng);
        {
            use std::io::BufWriter;
            let f = std::fs::File::create(&path).unwrap();
            params.write(&mut BufWriter::new(f)).unwrap();
        }
        peek_params_k_guard(&path).expect("a legit halo2 params file must pass the guard");
        let _ = std::fs::remove_file(&path);
    }

    /// Regression for the dev-cache OOM: a corrupted header claiming k=31 on a
    /// 1 KiB body must be rejected WITHOUT ever handing that `k` to
    /// `ParamsKZG::read` (which would `malloc ~256 GiB` for the two G1
    /// vectors). This is the exact failure mode the prover's
    /// `reject_untrusted_cache_oversized_k` and the tools' `srs_guard` close;
    /// before this fix the dev-cache read in `load_or_gen_params` skipped the
    /// peek entirely.
    #[test]
    fn peek_guard_rejects_huge_k_header_without_oom() {
        let path = scratch("hugek.bin");
        let mut buf = (31u32).to_le_bytes().to_vec(); // header claims k=31
        buf.resize(1024, 0); // ...on a 1 KiB body (nowhere near 128·2^31)
        std::fs::write(&path, &buf).unwrap();
        let err = peek_params_k_guard(&path)
            .expect_err("a huge-k header on a tiny body must be rejected");
        assert!(
            err.contains("only") || err.contains("truncated") || err.contains("corrupted"),
            "guard must explain the rejection: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `k >= 32` is rejected for shift-safety (halo2's `1<<k` is a 32-bit
    /// shift: debug-panic / release-mask), and the `k >= 32` branch fires
    /// BEFORE the `1usize << k` min-size computation — so even a k=100 header
    /// (which would overflow the shift) is rejected cleanly.
    #[test]
    fn peek_guard_rejects_shift_overflow_k() {
        for k in [32u32, 33, 100] {
            let path = scratch(&format!("k{k}.bin"));
            let mut buf = k.to_le_bytes().to_vec();
            buf.resize(1 << 20, 0); // 1 MiB body — irrelevant; k>=32 alone rejects
            std::fs::write(&path, &buf).unwrap();
            let err =
                peek_params_k_guard(&path).expect_err("k>=32 must be rejected for shift safety");
            assert!(err.contains(">= 32"), "guard must cite shift-safety: {err}");
            let _ = std::fs::remove_file(&path);
        }
    }

    /// A truncated download — header `k` intact but the body far short of
    /// `128·2^k` — is rejected. This is the far more common real-world
    /// corruption (partial write / interrupted download) and the original
    /// motivation for the size bound.
    #[test]
    fn peek_guard_rejects_truncated_body() {
        let path = scratch("trunc.bin");
        // Header claims k=20 (min 128·2^20 ≈ 128 MiB) but only 1 MiB present.
        let mut buf = (20u32).to_le_bytes().to_vec();
        buf.resize(1 << 20, 0);
        std::fs::write(&path, &buf).unwrap();
        let err = peek_params_k_guard(&path).expect_err("a truncated body must be rejected");
        assert!(
            err.contains("truncated") || err.contains("only"),
            "guard must explain the truncation: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
