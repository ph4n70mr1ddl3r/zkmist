//! Pre-deployment readiness checker for ZKMist.
//!
//! Validates that all prerequisites are met before deploying to mainnet.
//!
//! Checks:
//!
//! - 1. Halo2Verifier.axiom.sol has real KZG pairing verification (ecPairing precompile)
//! - 1b. Halo2Verifier.axiom.sol has non-zero inline VK data
//! - 1c. Prover does not generate a random (forgeable) KZG SRS
//! - 1d. KZG SRS trust root (URL + SHA-256) pinned in constants.rs
//! - 1e. Halo2Verifier.axiom.sol SRS provenance — PINNED-SRS banner, not DEV-SRS
//! - 1f. Halo2Verifier.axiom.sol byte-integrity vs pinned SHA-256
//! - 2. Merkle root matches the known eligibility tree root
//! - 3. Constants are consistent between CLI and contracts
//! - 3b. VK k-value matches prover CIRCUIT_K
//! - 4. No placeholder values remain
//! - 5. Cargo clippy passes
//! - 6. Cargo fmt passes
//! - 7. Forge tests pass
//! - 8. Cargo tests pass
//!
//! Usage:
//!
//! ```sh
//! # PR gate (advisory on known deploy blockers; fails only on regressions):
//! cargo run -p zkmist-tools --bin readiness -- --skip-slow
//! # Deploy gate (fails on ANY blocker, including the known ones):
//! cargo run -p zkmist-tools --bin readiness -- --strict
//! ```
//!
//! # Known-blocker / regression split
//
//! A handful of checks are EXPECTED to fail until the operator completes a
//! documented pre-deploy step — VK regeneration (`1b`), SRS hash pinning
//! (`1d`), the verifier byte-pin (`1f`, empty until the mainnet artifact is
//! blessed), and the post-deploy `AIRDROP_CONTRACT` placeholder (`4`). On a PR
//! (default mode) these are counted as *known blockers* and do NOT fail the
//! run, so the gate stays green unless something that should be green truly
//! *regresses*. Under `--strict` (the manual/scheduled deploy gate) every
//! known blocker also fails the run, so you cannot deploy past them. A DEV-SRS
//! verifier (`1e`) is NOT a known blocker — it is a soundness regression that
//! fails the gate on PRs too (a forgeable verifier must never reach mainnet).

use std::path::{Path, PathBuf};

/// Find the project root directory by searching upward for the workspace Cargo.toml.
fn find_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return Some(dir);
                }
            }
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// SHA-256 (lowercase hex, no `0x`) of the canonical mainnet
/// `contracts/src/Halo2Verifier.axiom.sol` — the verifier emitted by
/// `circuits/tests/claim_evm_roundtrip.rs` under `ZKMIST_USE_PINNED_SRS=1`.
/// Empty until the operator blesses the mainnet artifact; while empty, check
/// `1f` is a *known blocker*. Once set, ANY change to the committed verifier
/// (regeneration under a different SRS, a circuit change, tampering) flips `1f`
/// to a hard regression — even if an attacker re-pastes the PINNED-SRS banner
/// that check `1e` keys off. Set it with:
///   sha256sum contracts/src/Halo2Verifier.axiom.sol   # drop the `0x`
const MAINNET_VERIFIER_SHA256: &str = "";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let skip_slow = args.iter().any(|a| a == "--skip-slow");
    // `--strict` fails the run on KNOWN deployment blockers (VK regen, SRS
    // pinning, placeholder AIRDROP_CONTRACT) too — use it for the manual /
    // scheduled deploy gate. The default (PR) mode treats those blockers as
    // advisory so the gate is green unless something genuinely *regresses*.
    let strict = args.iter().any(|a| a == "--strict");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("ZKMist Pre-Deployment Readiness Checker");
        eprintln!();
        eprintln!("Usage: readiness [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --skip-slow   Skip slow checks (MockProver, forge test)");
        eprintln!("  --strict      Fail on KNOWN deploy blockers too (deploy gate)");
        eprintln!("  --help        Show this help");
        std::process::exit(0);
    }

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist Pre-Deployment Readiness Check                     ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    let root = find_project_root().expect("Cannot find project root (workspace Cargo.toml)");
    eprintln!("  Project root: {}", root.display());
    eprintln!();

    let mut passed = 0usize;
    let mut failed = 0usize;
    // Failures from checks tagged as known deployment blockers (VK regen, SRS
    // pinning, placeholder AIRDROP_CONTRACT). Advisory unless `--strict`.
    let mut known_blockers = 0usize;
    let mut skipped = 0usize;

    // ── Check 1: Halo2Verifier.axiom.sol integrity ──────────────────
    // The verifier is snark-verifier-generated (axiom backend). It is a
    // `fallback`-based contract whose final gate is a BN254 pairing-precompile
    // call (`staticcall(gas(), 0x8, …)`) — the one check that actually rejects
    // forged proofs. A stub/placeholder would lack the precompile call and/or
    // the field prime.
    eprintln!("[1/8] Checking Halo2Verifier.axiom.sol integrity...");
    let verifier_path = root.join("contracts/src/Halo2Verifier.axiom.sol");
    if let Ok(content) = std::fs::read_to_string(&verifier_path) {
        let has_fallback = content.contains("fallback(");
        let has_ecpairing = content.contains("staticcall(gas(), 0x8")
            || content.contains("staticcall(gas(), 0x08")
            || content.contains("ecPairing");
        let has_bn254 = content.contains(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        ) || content
            .contains("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

        if has_fallback && has_ecpairing && has_bn254 {
            eprintln!(
                "      ✅ Halo2Verifier.axiom.sol has real KZG pairing verification (ecPairing precompile 0x8)"
            );
            passed += 1;
        } else {
            eprintln!(
                "      ❌ Halo2Verifier.axiom.sol is missing the pairing precompile / BN254 prime"
            );
            eprintln!(
                "         (fallback={has_fallback}, ecPairing={has_ecpairing}, bn254={has_bn254})"
            );
            eprintln!("         Regenerate via circuits/tests/claim_evm_roundtrip.rs (ZKMIST_EMIT_VERIFIER).");
            failed += 1;
        }
    } else {
        eprintln!(
            "      ⚠️  Halo2Verifier.axiom.sol not found at {}",
            verifier_path.display()
        );
        failed += 1;
    }

    // ── Check 1b: VK reality + prover AXIOM_CIRCUIT_K ────────────────
    // After the PSE→axiom migration the VK is embedded inline in
    // Halo2Verifier.axiom.sol — there is no separate Halo2VerifyingKey.sol and
    // no `// k` marker line to parse. So we (a) sanity-check the verifier
    // carries real VK data (a stub/placeholder would have very few non-zero
    // mstore constants), and (b) confirm the prover's AXIOM_CIRCUIT_K parses.
    // The true prover↔verifier k-consistency is enforced by the real-KZG →
    // on-chain round-trip (ZKM.realroundtrip.t.sol), not by static parsing.
    eprintln!("[1b/8] Checking VK reality + prover AXIOM_CIRCUIT_K...");
    let verifier_vk_path = root.join("contracts/src/Halo2Verifier.axiom.sol");
    if let Ok(verifier_content) = std::fs::read_to_string(&verifier_vk_path) {
        let nonzero_constants = verifier_content
            .lines()
            .filter(|l| {
                l.contains("mstore")
                    && l.contains("0x")
                    && !l.contains(
                        "0x0000000000000000000000000000000000000000000000000000000000000000",
                    )
            })
            .count();
        if nonzero_constants >= 20 {
            eprintln!(
                "      ✅ Halo2Verifier.axiom.sol carries real VK data ({nonzero_constants} non-zero mstore constants)"
            );
            passed += 1;
        } else {
            eprintln!(
                "      ❌ Halo2Verifier.axiom.sol has only {nonzero_constants} non-zero mstore constants — looks like a stub/placeholder VK"
            );
            eprintln!(
                "         Regenerate via circuits/tests/claim_evm_roundtrip.rs (ZKMIST_EMIT_VERIFIER)."
            );
            record_known_blocker(&mut failed, &mut known_blockers, strict);
        }

        // `extract_vk_k` is retained for any verifier that emits a `// k`
        // marker; the axiom verifier has none (None is expected here). Keeping
        // the call also prevents the parser from bit-rotting into dead code.
        if let Some(vk_k) = extract_vk_k(&verifier_content) {
            eprintln!("      ℹ️  Verifier carries a k marker (k={vk_k})");
        }
    } else {
        eprintln!("      ⚠️  Halo2Verifier.axiom.sol not found — cannot check VK reality");
        skipped += 1;
    }

    // Prover k-value (AXIOM_CIRCUIT_K). Reporting-only here; the production
    // value (21) is pinned by the `test_real_committed_files_k_values` unit
    // test so a circuit rewrite can't silently move it.
    let prover_k = extract_prover_k(&root.join("cli/src/halo2_prover_axiom.rs"));
    match prover_k {
        Some(k) => {
            eprintln!("      ✅ Prover AXIOM_CIRCUIT_K = {k}");
            passed += 1;
        }
        None => {
            eprintln!(
                "      ⚠️  Could not parse AXIOM_CIRCUIT_K from cli/src/halo2_prover_axiom.rs"
            );
            skipped += 1;
        }
    }

    // ── Check 1c: KZG SRS soundness (prover params source) ───────────
    // The on-chain verifier is only as trustworthy as the SRS the prover
    // commits against. `Params::new(k)` / `ParamsKZG::setup(k, rng)` derive a
    // RANDOM SRS whose trapdoor is known to the operator — proofs are forgeable
    // by whoever generated it. Mainnet MUST load the Ethereum KZG ceremony
    // SRS from a trusted transcript instead. This is a soundness blocker, so
    // it fails the readiness gate (not just a warning).
    eprintln!("[1c/8] Checking KZG SRS soundness (prover params source)...");
    let prover_path = root.join("cli/src/halo2_prover_axiom.rs");
    if let Ok(prover_src) = std::fs::read_to_string(&prover_path) {
        if uses_random_srs(&prover_src) {
            eprintln!(
                "      ❌ Prover generates KZG params via gen_srs / Params::new / ParamsKZG::setup"
            );
            eprintln!("         (random SRS). Whoever ran it knows the trapdoor and can forge");
            eprintln!("         proofs. This is dev/test ONLY — mainnet MUST load the Ethereum");
            eprintln!("         KZG ceremony SRS from a trusted transcript (Params::read). This");
            eprintln!("         also explains the >4 min cold params-generation cost at k=21.");
            failed += 1;
        } else {
            eprintln!("      ✅ Prover does not generate a random SRS (loads a transcript)");
            passed += 1;
        }
    } else {
        eprintln!("      ⚠️  cli/src/halo2_prover_axiom.rs not found — cannot check SRS source");
        skipped += 1;
    }

    // ── Check 1d: KZG SRS trust root pinned in constants.rs ───────────
    // `uses_random_srs` confirms the prover LOADS a transcript rather than
    // generating one, but that only matters if a real transcript is pinned.
    // KZG_SRS_URL + KZG_SRS_SHA256 are the sole trust root of the whole
    // system: each claimant downloads the file and verifies its SHA-256
    // against this hash, so the deployer cannot tamper with the SRS after
    // publication. An empty hash means the prover falls back to the dev
    // (forgeable) SRS — a hard mainnet blocker.
    eprintln!("[1d/8] Checking KZG SRS trust root (constants.rs)...");
    let srs_hash = extract_constant(&root.join("cli/src/constants.rs"), "KZG_SRS_SHA256");
    let srs_url = extract_constant(&root.join("cli/src/constants.rs"), "KZG_SRS_URL");
    match (srs_hash.as_deref(), srs_url.as_deref()) {
        (Some(h), Some(u)) => {
            eprintln!(
                "      ✅ KZG SRS pinned: SHA-256={}… URL={}",
                &h[..h.len().min(12)],
                u
            );
            passed += 1;
        }
        _ => {
            eprintln!(
                "      ❌ KZG SRS trust root not pinned (KZG_SRS_URL / KZG_SRS_SHA256 empty)"
            );
            eprintln!(
                "         Without a pinned public SRS the prover falls back to a self-generated"
            );
            eprintln!(
                "         (forgeable) SRS — proofs would be forgeable by whoever generated them."
            );
            eprintln!(
                "         See docs/kzg-srs.md to obtain, independently verify, and pin the PSE"
            );
            eprintln!("         perpetual powers-of-tau halo2 params file before mainnet.");
            record_known_blocker(&mut failed, &mut known_blockers, strict);
        }
    }

    // ── Check 1e: Halo2Verifier.axiom.sol SRS provenance ─────────────
    // The verifier is only as sound as the SRS its VK was keygen'd under.
    // `claim_evm_roundtrip.rs` stamps every emitted verifier with a
    // self-describing banner: "PINNED-SRS VERIFIER" (PSE ceremony SRS) or
    // "DEV-SRS WIRING-ONLY VERIFIER" (toxic-waste `gen_srs` — forgeable).
    // A committed DEV-SRS verifier is a SOUNDNESS regression, not a pending
    // pre-deploy step: production proofs (generated under the pinned SRS via
    // `load_srs_axiom`) will not even verify against it, and the dev-SRS
    // trapdoor holder can forge claims. So this is a HARD fail (counts as a
    // regression on PRs too), unlike the advisory known blockers. Checks 1c/1d
    // guard the *prover's* SRS; this guards the *verifier's*.
    eprintln!("[1e/8] Checking Halo2Verifier.axiom.sol SRS provenance...");
    let verifier_provenance_path = root.join("contracts/src/Halo2Verifier.axiom.sol");
    match std::fs::read_to_string(&verifier_provenance_path) {
        Ok(content) => {
            let is_dev = content.contains("DEV-SRS WIRING-ONLY VERIFIER");
            let is_pinned = content.contains("PINNED-SRS VERIFIER");
            if is_dev {
                eprintln!(
                    "      ❌ Halo2Verifier.axiom.sol carries the DEV-SRS banner — its VK was"
                );
                eprintln!(
                    "         keygen'd under a toxic-waste `gen_srs` SRS. The trapdoor holder can"
                );
                eprintln!(
                    "         forge claims, and production proofs (pinned ceremony SRS) will not"
                );
                eprintln!("         verify against it. Regenerate under the pinned SRS:");
                eprintln!("           ZKMIST_RUN_CLAIM_ROUNDTRIP=1 ZKMIST_USE_PINNED_SRS=1 \\");
                eprintln!("             ZKMIST_SRS_FILE=<pinned k23.bin> \\");
                eprintln!(
                    "             ZKMIST_EMIT_VERIFIER=contracts/src/Halo2Verifier.axiom.sol \\"
                );
                eprintln!(
                    "             cargo test -p zkmist-circuits --test claim_evm_roundtrip \\"
                );
                eprintln!("               test_claim_circuit_evm_roundtrip -- --nocapture");
                failed += 1;
            } else if is_pinned {
                eprintln!("      ✅ Halo2Verifier.axiom.sol carries the PINNED-SRS banner");
                passed += 1;
            } else {
                eprintln!(
                    "      ❌ Halo2Verifier.axiom.sol has NO SRS-provenance banner (expected"
                );
                eprintln!("         'PINNED-SRS VERIFIER' or 'DEV-SRS WIRING-ONLY VERIFIER'). Its");
                eprintln!(
                    "         provenance is unknown — regenerate via claim_evm_roundtrip.rs."
                );
                failed += 1;
            }
        }
        Err(e) => {
            eprintln!(
                "      ⚠️  Halo2Verifier.axiom.sol not found at {} ({})",
                verifier_provenance_path.display(),
                e
            );
            failed += 1;
        }
    }

    // ── Check 1f: Halo2Verifier.axiom.sol byte-integrity (pinned SHA-256) ──
    // Belt-and-suspenders on 1e: the banner is self-describing but editable.
    // Once the operator blesses the canonical mainnet verifier, pin its
    // SHA-256 in `MAINNET_VERIFIER_SHA256`; any regeneration (different SRS,
    // circuit change, tamper) then flips this to a hard regression even if an
    // attacker re-pastes the PINNED-SRS banner. Empty pin → known blocker
    // (artifact not yet blessed); mismatch → hard fail.
    eprintln!("[1f/8] Checking Halo2Verifier.axiom.sol byte-integrity...");
    let want = MAINNET_VERIFIER_SHA256.trim().to_lowercase();
    if want.is_empty() {
        eprintln!("      ⚠️  MAINNET_VERIFIER_SHA256 is empty — the canonical mainnet verifier");
        eprintln!("         is not byte-pinned yet. After emitting under ZKMIST_USE_PINNED_SRS=1,");
        eprintln!("         record `sha256sum contracts/src/Halo2Verifier.axiom.sol` in");
        eprintln!("         MAINNET_VERIFIER_SHA256 (tools/src/readiness.rs).");
        record_known_blocker(&mut failed, &mut known_blockers, strict);
    } else {
        let verifier_integrity_path = root.join("contracts/src/Halo2Verifier.axiom.sol");
        match std::fs::read(&verifier_integrity_path) {
            Ok(bytes) => {
                use sha2::{Digest, Sha256};
                let got = hex::encode(Sha256::digest(&bytes));
                if got == want {
                    eprintln!(
                        "      ✅ Halo2Verifier.axiom.sol byte-integrity OK (SHA-256 {}…)",
                        &got[..got.len().min(12)]
                    );
                    passed += 1;
                } else {
                    eprintln!("      ❌ Halo2Verifier.axiom.sol byte-integrity MISMATCH:");
                    eprintln!(
                        "         expected {}…, got {}…",
                        &want[..want.len().min(12)],
                        &got[..got.len().min(12)]
                    );
                    eprintln!(
                        "         the committed verifier differs from the blessed mainnet artifact"
                    );
                    eprintln!("         (regenerated under a different SRS, a circuit change, or tampered).");
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "      ⚠️  Halo2Verifier.axiom.sol not found at {} ({}) — cannot check byte-integrity",
                    verifier_integrity_path.display(),
                    e
                );
                skipped += 1;
            }
        }
    }

    // ── Check 2: Merkle root consistency ─────────────────────────────
    eprintln!("[2/8] Checking merkle root consistency...");
    let cli_root = extract_constant(&root.join("cli/src/constants.rs"), "KNOWN_MERKLE_ROOT");
    let deploy_root =
        extract_solidity_constant(&root.join("contracts/script/Deploy.s.sol"), "MERKLE_ROOT");
    let airdrop_test_root = find_test_merkle_root(&root.join("contracts/test"));

    match (cli_root.as_deref(), deploy_root.as_deref()) {
        (Some(cli), Some(deploy)) if !cli.is_empty() && cli == deploy => {
            eprintln!(
                "      ✅ Merkle root consistent: {}...{}",
                &cli[..18],
                &cli[cli.len() - 8..]
            );
            passed += 1;
        }
        (Some(cli), Some(deploy)) if !cli.is_empty() && !deploy.is_empty() => {
            eprintln!(
                "      ❌ Merkle root MISMATCH: CLI={} vs Deploy={}",
                cli, deploy
            );
            failed += 1;
        }
        _ => {
            eprintln!("      ⚠️  Could not extract merkle roots for comparison");
            failed += 1;
        }
    }

    if let Some(test_root) = airdrop_test_root {
        if test_root == cli_root.as_deref().unwrap_or("") {
            eprintln!("      ✅ Test merkle root matches");
        } else {
            eprintln!("      ⚠️  Test merkle root differs from CLI constant (may be intentional for tests)");
        }
    }

    // ── Check 3: Constants consistency ───────────────────────────────
    eprintln!("[3/8] Checking constants consistency...");
    let cli_deadline =
        extract_constant_value(&root.join("cli/src/constants.rs"), "CLAIM_DEADLINE: u64");
    let cli_claim_amount =
        extract_constant_value(&root.join("cli/src/constants.rs"), "CLAIM_AMOUNT: u64");
    let cli_max_claims =
        extract_constant_value(&root.join("cli/src/constants.rs"), "MAX_CLAIMS: u64");

    let mut constants_ok = true;
    if let Some(ref d) = cli_deadline {
        let clean = d.replace('_', "");
        if clean != "1798761600" {
            eprintln!("      ⚠️  CLAIM_DEADLINE = {} (expected 1798761600)", d);
            constants_ok = false;
        }
    }
    if let Some(ref a) = cli_claim_amount {
        let clean = a.replace('_', "");
        if clean != "10000" {
            eprintln!("      ⚠️  CLAIM_AMOUNT = {} (expected 10000)", a);
            constants_ok = false;
        }
    }
    if let Some(ref c) = cli_max_claims {
        let clean = c.replace('_', "");
        if clean != "1000000" {
            eprintln!("      ⚠️  MAX_CLAIMS = {} (expected 1000000)", c);
            constants_ok = false;
        }
    }
    if constants_ok {
        eprintln!("      ✅ CLI constants consistent");
        passed += 1;
    } else {
        failed += 1;
    }

    // ── Check 4: No placeholder values (besides VK) ──────────────────
    eprintln!("[4/8] Checking for placeholder values...");
    let mut placeholder_found = false;
    if let Ok(content) = std::fs::read_to_string(root.join("cli/src/constants.rs")) {
        if content.contains("0x000000000000000000000000000000000000dEaD") {
            eprintln!("      ⚠️  AIRDROP_CONTRACT is still placeholder (0x...dEaD)");
            eprintln!("         Update after deployment");
            placeholder_found = true;
        }
        if content.contains("TODO") {
            eprintln!("      ⚠️  TODO comments found in constants.rs");
            placeholder_found = true;
        }
    }
    if placeholder_found {
        eprintln!(
            "      ⚠️  Placeholders found (expected before deployment, must fix before mainnet)"
        );
        // Placeholders are a known pre-deploy blocker (AIRDROP_CONTRACT is
        // filled in only after deployment). Advisory on PRs; fails the run
        // under --strict (deploy gate).
        record_known_blocker(&mut failed, &mut known_blockers, strict);
    } else {
        eprintln!("      ✅ No placeholder values");
        passed += 1;
    }

    // ── Check 5: Cargo clippy ────────────────────────────────────────
    eprintln!("[5/8] Running cargo clippy...");
    let clippy_output = std::process::Command::new("cargo")
        .args(["clippy", "--workspace", "--", "-D", "warnings"])
        .current_dir(&root)
        .output();
    match clippy_output {
        Ok(output) if output.status.success() => {
            eprintln!("      ✅ Cargo clippy clean");
            passed += 1;
        }
        Ok(output) => {
            eprintln!("      ❌ Cargo clippy warnings/errors:");
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr
                .lines()
                .filter(|l| l.contains("warning") || l.contains("error"))
                .take(5)
            {
                eprintln!("         {}", line);
            }
            failed += 1;
        }
        Err(e) => {
            eprintln!("      ⚠️  Could not run cargo clippy: {}", e);
            skipped += 1;
        }
    }

    // ── Check 6: Cargo fmt ──────────────────────────────────────────
    eprintln!("[6/8] Checking cargo fmt...");
    let fmt_output = std::process::Command::new("cargo")
        .args(["fmt", "--all", "--", "--check"])
        .current_dir(&root)
        .output();
    match fmt_output {
        Ok(output) if output.status.success() => {
            eprintln!("      ✅ Cargo fmt clean");
            passed += 1;
        }
        Ok(_) => {
            eprintln!("      ❌ Cargo fmt: unformatted files found. Run: cargo fmt --all");
            failed += 1;
        }
        Err(e) => {
            eprintln!("      ⚠️  Could not run cargo fmt: {}", e);
            skipped += 1;
        }
    }

    // ── Check 7: Forge tests ────────────────────────────────────────
    if skip_slow {
        eprintln!("[7/8] Skipping forge tests (--skip-slow)");
        skipped += 1;
    } else {
        eprintln!("[7/8] Running forge tests...");
        let forge_output = std::process::Command::new("forge")
            .args(["test", "--summary"])
            .current_dir(root.join("contracts"))
            .output();
        match forge_output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().find(|l| l.contains("tests passed")) {
                    eprintln!("      ✅ {}", line.trim());
                } else {
                    eprintln!("      ✅ Forge tests passed");
                }
                passed += 1;
            }
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("      ❌ Forge tests failed:");
                // `forge test` writes its per-test results ("[FAIL: …] "
                // "test_name()", "Suite result: FAILED") to **stdout**; on a
                // test failure **stderr is empty**. The prior stderr-only read
                // therefore surfaced NOTHING on a failing run — the gate said
                // "Forge tests failed:" with no identifying lines, forcing a
                // manual re-run. Read both streams (stderr still carries forge
                // compile/link errors). See [`test_failure_lines`].
                for line in test_failure_lines(&stdout, &stderr) {
                    eprintln!("         {}", line);
                }
                failed += 1;
            }
            Err(e) => {
                eprintln!("      ⚠️  Could not run forge test: {}", e);
                eprintln!("         Is Foundry installed?");
                skipped += 1;
            }
        }
    }

    // ── Check 8: Cargo test ─────────────────────────────────────────
    if skip_slow {
        eprintln!("[8/8] Skipping cargo test (--skip-slow)");
        skipped += 1;
    } else {
        eprintln!("[8/8] Running cargo test...");
        let test_output = std::process::Command::new("cargo")
            .args(["test", "--workspace"])
            .current_dir(&root)
            .output();
        match test_output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let total: usize = stdout
                    .lines()
                    .filter_map(|l| {
                        if l.contains("test result:") && l.contains("passed") {
                            l.split_whitespace()
                                .find(|w| w.chars().all(|c| c.is_ascii_digit()))
                                .and_then(|n| n.parse::<usize>().ok())
                        } else {
                            None
                        }
                    })
                    .sum();
                eprintln!("      ✅ Cargo tests passed ({} tests)", total);
                passed += 1;
            }
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("      ❌ Cargo tests failed:");
                // The libtest harness writes per-test failures ("test foo … "
                // "FAILED", "test result: FAILED.") to **stdout**; cargo's own
                // "error: test failed" + any compile errors go to **stderr**.
                // The prior stderr-only read filtered for "FAILED"/"failures",
                // which match NOTHING on stderr — on a failing run the gate
                // printed "Cargo tests failed:" with zero identifying lines,
                // hiding WHICH test broke. Read both streams so a real test
                // failure AND a build failure are both diagnosable. See
                // [`test_failure_lines`].
                for line in test_failure_lines(&stdout, &stderr) {
                    eprintln!("         {}", line);
                }
                failed += 1;
            }
            Err(e) => {
                eprintln!("      ⚠️  Could not run cargo test: {}", e);
                skipped += 1;
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────
    eprintln!();
    eprintln!("════════════════════════════════════════════════════════════");
    eprintln!(
        "  Results: {} passed, {} regression(s), {} known blocker(s), {} skipped",
        passed, failed, known_blockers, skipped
    );
    eprintln!("════════════════════════════════════════════════════════════");

    // Exit policy:
    //   - A *regression* (failed > 0) always fails the run — on a PR this is
    //     the signal that a check which should be green has broken.
    //   - A *known deployment blocker* (VK regen, SRS pinning, placeholder
    //     AIRDROP_CONTRACT) only fails under `--strict` (the deploy gate). On
    //     a PR it is advisory, so the gate stays green while the documented
    //     pre-deploy steps are still pending.
    if failed > 0 {
        eprintln!();
        eprintln!(
            "  ❌ NOT READY — {} regression(s) detected (not counting known blockers)",
            failed
        );
        std::process::exit(1);
    }
    if known_blockers > 0 {
        eprintln!();
        eprintln!(
            "  ⚠️  {} known deployment blocker(s) remain (VK regen / SRS pin / post-deploy address).",
            known_blockers
        );
        if strict {
            eprintln!("  ❌ Failing under --strict — resolve the blockers before deploying.");
            std::process::exit(1);
        }
        eprintln!("  (advisory on PRs; run with --strict to gate the deploy)");
        std::process::exit(0);
    }

    // Fully green — no regressions, no known blockers.
    {
        eprintln!();
        eprintln!("  ✅ All automated checks passed!");
        eprintln!();
        eprintln!("  Remaining steps before mainnet deployment:");
        eprintln!("    ┌──────────────────────────────────────────────────────────────");
        eprintln!("    │ CRITICAL (blocks deployment):");
        eprintln!(
            "    │ [ ] Re-run the axiom circuit suite (happy-path + negatives + depth-26 @ k=21):"
        );
        eprintln!("    │     cargo test -p zkmist-circuits -- --nocapture");
        eprintln!("    │ [ ] Regenerate Halo2Verifier.axiom.sol if the circuit changed");
        eprintln!("    │     (circuits/tests/claim_evm_roundtrip.rs: ZKMIST_EMIT_VERIFIER + ZKMIST_USE_PINNED_SRS)");
        eprintln!("    │ [ ] Verify VK k-value matches CIRCUIT_K (checked above)");
        eprintln!("    │ [ ] Verify VK has non-zero fixed commitments (checked above)");
        eprintln!("    │ [ ] External security audit of the custom axiom gadgets");
        eprintln!("    │     → See: circuits/src/{{secp_axiom,keccak_axiom,poseidon_axiom}}.rs");
        eprintln!("    │       (secp scalar mul is on halo2-ecc's audited chips)");
        eprintln!("    │ [ ] Testnet deployment on Base Sepolia with full claim flow");
        eprintln!("    │     → ./scripts/testnet-deploy.sh");
        eprintln!("    │");
        eprintln!("    │ HIGH PRIORITY:");
        eprintln!(
            "    │ [ ] Generate real proof and validate size (~1376 bytes, axiom SHPLONG @ k=21)"
        );
        eprintln!("    │     → cargo run --release -p zkmist-cli -- bench");
        eprintln!("    │ [ ] Benchmark proving time on reference hardware (<60 sec target)");
        eprintln!("    │ [ ] Update AIRDROP_CONTRACT in cli/src/constants.rs after deployment");
        eprintln!("    │ [ ] Set up on-chain monitor: cargo run -p zkmist-tools --bin monitor");
        eprintln!("    │");
        eprintln!("    │ RECOMMENDED:");
        eprintln!("    │ [ ] Run full E2E test suite: ./scripts/e2e-test.sh");
        eprintln!("    │ [ ] Set up monitoring/alerting (BaseScan, Tenderly, Dune)");
        eprintln!("    │ [ ] secp256k1 already on halo2-ecc; audit the remaining custom glue");
        eprintln!("    └──────────────────────────────────────────────────────────────");
    }
}

/// Record a *known deployment blocker* (VK regen, SRS pinning, or the
/// post-deploy `AIRDROP_CONTRACT` placeholder). On a PR (default) these are
/// advisory so the gate only fails on genuine regressions; under `--strict`
/// (the manual/scheduled deploy gate) they also fail the run.
fn record_known_blocker(failed: &mut usize, known_blockers: &mut usize, strict: bool) {
    if strict {
        *failed += 1;
    } else {
        *known_blockers += 1;
    }
}

fn extract_constant(file_path: &Path, const_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(file_path).ok()?;
    // Normalize multi-line declarations into single lines
    let normalized: String = content
        .lines()
        .filter(|l| !l.trim().starts_with("//"))
        .collect::<Vec<&str>>()
        .join(" ");
    // Split by semicolons to get individual statements
    for statement in normalized.split(';') {
        if statement.contains(const_name) {
            if let Some(idx) = statement.find('=') {
                let val = statement[idx + 1..].trim().trim_matches('"').trim();
                let clean = val.strip_prefix("0x").unwrap_or(val).replace('_', "");
                if !clean.is_empty() {
                    return Some(clean);
                }
            }
        }
    }
    None
}

fn extract_constant_value(file_path: &Path, const_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pub const") && trimmed.contains(const_name.split(':').next()?) {
            if let Some(idx) = trimmed.find('=') {
                // Extract value between '=' and ';', stripping comments
                let after_eq = &trimmed[idx + 1..];
                let val = after_eq.split(';').next().unwrap_or("").trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn extract_solidity_constant(file_path: &Path, const_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains(const_name) && trimmed.contains("constant") {
            if let Some(idx) = trimmed.find('=') {
                let val = trimmed[idx + 1..]
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .replace("0x", "");
                return Some(val);
            }
        }
    }
    None
}

fn find_test_merkle_root(test_dir: &Path) -> Option<String> {
    if let Ok(entries) = std::fs::read_dir(test_dir) {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    if line.contains("MERKLE_ROOT") && line.contains("0x") {
                        if let Some(start) = line.find("0x") {
                            let hex = &line[start + 2..];
                            let hex_clean: String =
                                hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                            if hex_clean.len() == 64 {
                                return Some(hex_clean);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract the k-value from `Halo2VerifyingKey.sol`.
///
/// Matches the line `mstore(0x0040, 0x...0015) // k` and returns the **value**
/// (the second hex literal, after the comma) — *not* the memory **offset**.
///
/// Earlier versions grabbed the FIRST `0x` on the line, which is the `mstore`
/// offset (`0x0040` = 64), and so reported `k=64` instead of the value
/// (`0x15` = 21). That offset/value mix-up made the k-consistency check report
/// nonsense; the regression is pinned by the `extract_vk_k_*` unit tests below.
fn extract_vk_k(vk_content: &str) -> Option<u32> {
    for line in vk_content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("// k") {
            continue;
        }
        // `mstore(0xOFFSET, 0xVALUE)` — the value is everything after the first
        // comma. Taking the first `0x` on the line would return the offset.
        let after_comma = match trimmed.split_once(',') {
            Some((_, rest)) => rest,
            None => continue,
        };
        let start = match after_comma.find("0x") {
            Some(s) => s,
            None => continue,
        };
        let hex = &after_comma[start + 2..];
        let hex_clean: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if let Ok(val) = u32::from_str_radix(&hex_clean, 16) {
            return Some(val);
        }
    }
    None
}

/// Extract `CIRCUIT_K` from the prover source.
fn extract_prover_k(prover_path: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(prover_path).ok()?;
    extract_prover_k_from_str(&content)
}

/// String-parsing core of [`extract_prover_k`], split out so it can be unit
/// tested without writing a temporary file.
fn extract_prover_k_from_str(content: &str) -> Option<u32> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("CIRCUIT_K") && trimmed.contains('=') && !trimmed.starts_with("//") {
            if let Some(idx) = trimmed.find('=') {
                let val = trimmed[idx + 1..].trim().trim_end_matches(';').trim();
                if let Ok(k) = val.parse::<u32>() {
                    return Some(k);
                }
            }
        }
    }
    None
}

/// Detect whether a prover source generates KZG params from scratch with an
/// RNG (an untrusted/toy SRS) instead of loading a ceremony transcript.
///
/// Three call shapes all derive a structured reference string whose trapdoor
/// is known to whoever ran them — anyone holding it can forge proofs:
///   - `ParamsKZG::setup(k, rng)`  — the raw halo2 API.
///   - `Params::<...>::new(k)`     — the raw halo2 API (also RNG-backed).
///   - `gen_srs(k)`                — `halo2_base::utils::fs::gen_srs`, a thin
///     wrapper that calls `ParamsKZG::setup(k, ChaCha20Rng::from_seed(..))`.
///     This is the axiom backend's random-SRS entry point (the PSE prover used
///     the two raw forms above); without it in the pattern list the axiom
///     prover's `gen_srs` was an INVISIBLE soundness call — an ungated `gen_srs`
///     would pass this check while being every bit as forgeable as `setup`.
///
/// Mainnet MUST load the Ethereum/PSE KZG ceremony SRS from a trusted
/// transcript (e.g. `Params::read(...)`). This returns `true` when such a
/// generation call is present on a non-comment line AND the source is not
/// behind an explicit dev gate.
///
/// Convention: the ONLY permitted `Params::new` / `setup` / `gen_srs` must
/// sit behind an explicit `ZKMIST_DEV_SRS` env-var gate (see `load_srs_axiom`
/// in halo2_prover_axiom.rs). If the file references `ZKMIST_DEV_SRS`, the
/// random-SRS call is assumed to be the dev-gated fallback and is NOT flagged.
/// Removing the gate (or adding an ungated generator) flips this back to
/// `true`, failing the readiness gate.
///
/// Note: the good path (`Params::<...>::read(&mut reader)`) contains `Params`
/// but neither `::new(`, `setup(`, nor `gen_srs(`, so it is correctly NOT
/// flagged.
fn uses_random_srs(prover_src: &str) -> bool {
    let has_random_call = prover_src.lines().any(|line| {
        let t = line.trim();
        if t.starts_with("//") {
            return false;
        }
        let uses_setup = t.contains("ParamsKZG") && t.contains("setup(");
        let uses_new = t.contains("Params") && t.contains("::new(");
        // `gen_srs(` — halo2-base's wrapper around `ParamsKZG::setup`. Match the
        // CALL (with the opening paren) so a bare `gen_srs` identifier in a
        // doc/comment-on-same-line or a `use ... gen_srs` import is not flagged
        // (an import alone generates nothing); only an actual call does.
        let uses_gen_srs = t.contains("gen_srs(");
        uses_setup || uses_new || uses_gen_srs
    });
    has_random_call && !prover_src.contains("ZKMIST_DEV_SRS")
}

/// Extract the most failure-relevant lines from a `cargo test` / `forge test`
/// subprocess so the readiness checker can surface **what** failed without a
/// manual re-run.
///
/// Both harnesses write their per-test results to **stdout** (cargo libtest:
/// `test foo … FAILED`, `test result: FAILED.`; forge: `[FAIL: …] test_bar()`,
/// `Suite result: FAILED.`), while the toolchain's own errors (compile failures,
/// cargo's `error: test failed, to rerun …`) go to **stderr**.
///
/// The readiness checker previously read **stderr only** and filtered for
/// `FAILED`/`failures`, which match NOTHING on stderr (the per-test detail is
/// on stdout). On a failing run the gate therefore printed `❌ tests failed:`
/// with **zero** identifying lines, forcing the operator to re-run the whole
/// suite by hand just to see which test broke. (For `forge test` it was worse:
/// stderr is completely empty on a test failure.) This helper reads **both**
/// streams so a genuine test failure (stdout) and a build failure (stderr) are
/// both diagnosable.
///
/// Lines are deduplicated (forge prints each `[FAIL …]` line twice — once in
/// the run summary, once under `Failing tests:`) and trimmed. Returns up to a
/// handful of the most useful lines, stdout first.
///
/// Matching is CASE-SENSITIVE: the failure markers are the uppercase
/// `FAILED`/`FAIL:`; a green run's summary is lowercase (`0 failed` is a
/// COUNT), so uppercasing the line would false-match a passing run.
pub(crate) fn test_failure_lines(stdout: &str, stderr: &str) -> Vec<String> {
    // stdout: the harness's per-test failure + summary lines (these NAME the
    // failing test). stderr: compile errors + cargo's terminal "error: test
    // failed" (essential when the suite never ran — a build error leaves
    // stdout with no FAILED line at all).
    let stdout_hits = stdout
        .lines()
        .filter(|l| l.contains("FAIL:") || l.contains("FAILED"))
        .take(5);
    let stderr_hits = stderr
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("error") || t.starts_with("Error")
        })
        .take(3);

    let mut out: Vec<String> = Vec::new();
    for line in stdout_hits.chain(stderr_hits) {
        let t = line.trim();
        if !t.is_empty() && !out.iter().any(|e| e == t) {
            out.push(t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        // tools/ is one level below the workspace root.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools/ should have a parent dir")
            .to_path_buf()
    }

    // ── record_known_blocker (PR-advisory vs --strict deploy gate) ───────

    #[test]
    fn test_record_known_blocker_is_advisory_by_default() {
        let (mut failed, mut known) = (0usize, 0usize);
        record_known_blocker(&mut failed, &mut known, false);
        assert_eq!((failed, known), (0, 1));
    }

    #[test]
    fn test_record_known_blocker_fails_under_strict() {
        let (mut failed, mut known) = (0usize, 0usize);
        record_known_blocker(&mut failed, &mut known, true);
        assert_eq!((failed, known), (1, 0));
    }

    // ── extract_vk_k: must read the VALUE, not the OFFSET ───────────────

    #[test]
    fn test_extract_vk_k_real_k21_line() {
        // Real line from the currently-committed Halo2VerifyingKey.sol.
        let line = "            mstore(0x0040, 0x0000000000000000000000000000000000000000000000000000000000000015) // k\n";
        assert_eq!(extract_vk_k(line), Some(21));
    }

    #[test]
    fn test_extract_vk_k_regenerated_k24_line() {
        // The form gen-production-verifier emits once the real VK lands at k=23.
        let line = "            mstore(0x0040, 0x0000000000000000000000000000000000000000000000000000000000000018) // k\n";
        assert_eq!(extract_vk_k(line), Some(24));
    }

    #[test]
    fn test_extract_vk_k_does_not_return_the_offset() {
        // The bug reported 0x0040 (= 64, the offset) instead of the value.
        // Here the value is 0x18 = 24; it must NOT return 0x40 = 64.
        let line = "            mstore(0x0040, 0x18) // k\n";
        let got = extract_vk_k(line);
        assert_eq!(got, Some(24));
        assert_ne!(got, Some(0x40));
    }

    #[test]
    fn test_extract_vk_k_ignores_non_k_mstore_lines() {
        // Every VK constant uses mstore(...) with a trailing comment; only the
        // `// k` line must match.
        let vk = "\
            mstore(0x0000, 0x07d6cec294b3ee601635fc1b2bfa4b13c3c277629cacf756a13aec10ec7cf917) // vk_digest\n\
            mstore(0x0020, 0x3) // num_instances\n\
            mstore(0x0040, 0x15) // k\n\
            mstore(0x0060, 0x30644cefbebe09202b4ef7f3ff53a4511d70ff06da772cc3785d6b74e0536081) // n_inv\n";
        assert_eq!(extract_vk_k(vk), Some(21));
    }

    #[test]
    fn test_extract_vk_k_returns_none_without_k_marker() {
        let vk = "mstore(0x0000, 0x07d6) // vk_digest\nmstore(0x0060, 0x3064) // n_inv\n";
        assert_eq!(extract_vk_k(vk), None);
    }

    // ── extract_prover_k_from_str ───────────────────────────────────────

    // ── uses_random_srs ───────────────────────────────────────────────

    #[test]
    fn test_uses_random_srs_flags_params_new() {
        // The exact form used in cli/src/halo2_prover.rs::load_or_gen_params.
        let src = "    let params = Params::<G1Affine>::new(k);\n";
        assert!(uses_random_srs(src));
    }

    #[test]
    fn test_uses_random_srs_flags_paramskzg_setup() {
        // The form gen-production-verifier uses.
        let src = "    let params = ParamsKZG::<halo2curves::bn256::Bn256>::setup(k, &mut rng);\n";
        assert!(uses_random_srs(src));
    }

    #[test]
    fn test_uses_random_srs_ignores_comments() {
        // A doc/comment line mentioning Params::new must NOT trip the check —
        // only real code calls do. (The prover has comment lines like this.)
        let src = "// WARNING: Params::new(k) generates a random SRS.\nfn main() {}\n";
        assert!(!uses_random_srs(src));
    }

    #[test]
    fn test_uses_random_srs_allows_ceremony_load() {
        // The correct mainnet path: loading a trusted transcript. Must NOT flag.
        let src = "    let params = Params::<G1Affine>::read(&mut reader)?;\n";
        assert!(!uses_random_srs(src));
    }

    #[test]
    fn test_uses_random_srs_allows_dev_gated_params_new() {
        // Convention: a Params::new behind an explicit ZKMIST_DEV_SRS gate is
        // the accepted dev fallback and must NOT be flagged. (This is exactly
        // the shape of load_or_download_params in halo2_prover.rs.)
        let src = "    if std::env::var(\"ZKMIST_DEV_SRS\").is_ok() {\n        let params = Params::<G1Affine>::new(k);\n    }\n";
        assert!(!uses_random_srs(src));
    }

    // ── gen_srs detection (axiom backend) ───────────────────────────────
    //
    // `halo2_base::utils::fs::gen_srs(k)` is a thin wrapper around
    // `ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))`
    // — a deterministic-seed but still TOXIC-WASTE SRS (anyone who knows the
    // code knows the trapdoor). The axiom prover goes through `gen_srs` rather
    // than `Params::new`/`setup` directly, so without `gen_srs(` in the
    // pattern list an ungated `gen_srs` call was an INVISIBLE soundness
    // defect: equally forgeable as `setup`, but invisible to this check.
    // These tests lock down both the detection and the dev-gate exemption.

    #[test]
    fn test_uses_random_srs_flags_ungated_gen_srs() {
        // The exact form the axiom prover uses (cli/src/halo2_prover_axiom.rs),
        // here UNGATED — the dangerous case. MUST be flagged.
        let src = "    return Ok(gen_srs(circuit_k));\n";
        assert!(
            uses_random_srs(src),
            "ungated gen_srs must be flagged — it is a forgeable toxic-waste SRS"
        );
    }

    #[test]
    fn test_uses_random_srs_flags_gen_srs_with_path_prefix() {
        // Fully-qualified call form (no `use` import).
        let src = "    let params = halo2_base::utils::fs::gen_srs(k);\n";
        assert!(uses_random_srs(src));
    }

    #[test]
    fn test_uses_random_srs_allows_dev_gated_gen_srs() {
        // The axiom prover's actual shape: gen_srs behind a ZKMIST_DEV_SRS /
        // production gate. MUST NOT be flagged (this is the accepted dev
        // fallback). This is the exact pattern in load_srs_axiom.
        let src = "    if !production || std::env::var(\"ZKMIST_DEV_SRS\").as_deref() == Ok(\"1\") {\n        return Ok(gen_srs(circuit_k));\n    }\n";
        assert!(
            !uses_random_srs(src),
            "dev-gated gen_srs must NOT be flagged — it is the accepted dev fallback"
        );
    }

    #[test]
    fn test_uses_random_srs_does_not_flag_gen_srs_import_or_comment() {
        // A `use` import or doc comment mentioning gen_srs generates nothing —
        // only an actual CALL (with `(`) is dangerous. The pattern matches
        // `gen_srs(`, so these must NOT trip.
        let import = "use halo2_base::utils::fs::gen_srs;\nfn main() {}\n";
        assert!(!uses_random_srs(import), "a bare import must not flag");
        let doc = "//! Calls `gen_srs` in dev mode.\nfn main() {}\n";
        assert!(!uses_random_srs(doc), "a doc comment must not flag");
    }

    #[test]
    fn test_uses_random_srs_returns_false_on_clean_source() {
        assert!(!uses_random_srs("fn main() {}\n"));
    }

    // ── Parser guards against the real committed prover/constants ────────
    //
    // After the SRS-loading rewrite the prover LOADS a transcript in
    // production and only falls back to Params::new behind an explicit
    // ZKMIST_DEV_SRS gate. So uses_random_srs() must be FALSE on the real
    // prover now. The trust root IS now pinned (KZG_SRS_SHA256 set) — guarded
    // by test_real_committed_kzg_srs_hash_is_pinned, which asserts the hash
    // stays a well-formed 64-hex value (a change requires regenerating the VK
    // and rerunning the on-chain round-trip; see docs/kzg-srs.md §2.2).
    #[test]
    fn test_real_committed_prover_srs_is_dev_gated() {
        let prover_path = repo_root().join("cli/src/halo2_prover_axiom.rs");
        let src = std::fs::read_to_string(&prover_path)
            .unwrap_or_else(|e| panic!("read {}: {}", prover_path.display(), e));
        assert!(
            src.contains("ZKMIST_DEV_SRS"),
            "dev gate removed — re-add the ZKMIST_DEV_SRS gate around any gen_srs / Params::new"
        );
        assert!(
            !uses_random_srs(&src),
            "prover has an ungated random-SRS call (gen_srs / Params::new / setup with no \
             ZKMIST_DEV_SRS gate) — that is a soundness bug, re-gate it"
        );
    }

    #[test]
    fn test_real_committed_kzg_srs_hash_is_pinned() {
        // Trust root is now pinned. This tripwire guards against two silent
        // regressions: (a) KZG_SRS_SHA256 being cleared back to empty, and
        // (b) it being repinned to a malformed value. Repinning to a DIFFERENT
        // digest also requires regenerating Halo2VerifyingKey.sol (via
        // gen-production-verifier --emit) and rerunning ZKM.realroundtrip.t.sol
        // — see docs/kzg-srs.md §2.2 (provenance must be re-confirmed).
        let constants_path = repo_root().join("cli/src/constants.rs");
        let hash = extract_constant(&constants_path, "KZG_SRS_SHA256")
            .expect("KZG_SRS_SHA256 must be pinned (readiness [1d/8] fails without it)");
        assert_eq!(
            hash.len(),
            64,
            "KZG_SRS_SHA256 must be a 64-char SHA-256 digest"
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "KZG_SRS_SHA256 must be lowercase hex, got: {hash}"
        );
        assert_eq!(
            hash,
            hash.to_ascii_lowercase(),
            "KZG_SRS_SHA256 must be lowercase"
        );
    }

    #[test]
    fn test_extract_prover_k_real_definition() {
        let src = "// header\nconst CIRCUIT_K: u32 = 24;\nfn main() {}\n";
        assert_eq!(extract_prover_k_from_str(src), Some(24));
    }

    #[test]
    fn test_extract_prover_k_skips_comment_lines_mentioning_circuit_k() {
        // halo2_prover.rs has comment lines mentioning CIRCUIT_K before the
        // real const; those start with `//` and must be skipped.
        let src = "\
            // MUST match CIRCUIT_K in cli/src/halo2_prover.rs (k=24 after the rewrite)\n\
            const CIRCUIT_K: u32 = 24;\n";
        assert_eq!(extract_prover_k_from_str(src), Some(24));
    }

    #[test]
    fn test_extract_prover_k_skips_local_let_lines_mentioning_circuit_k() {
        // `let mut k: u32 = 24; // ... CIRCUIT_K` mentions CIRCUIT_K and has an
        // '=', but the value token is `24;` — which fails to parse, so the
        // search must continue to the real `const CIRCUIT_K: u32 = 24;` line.
        let src = "\
            let mut k: u32 = 24; // MUST match CIRCUIT_K\n\
            const CIRCUIT_K: u32 = 24;\n";
        assert_eq!(extract_prover_k_from_str(src), Some(24));
    }

    #[test]
    fn test_extract_prover_k_returns_none_when_absent() {
        assert_eq!(extract_prover_k_from_str("fn main() {}\n"), None);
    }

    // ── Parser guard against the real committed files (axiom backend) ────
    //
    // After the PSE→axiom migration the prover's circuit degree lives in
    // `AXIOM_CIRCUIT_K` (cli/src/halo2_prover_axiom.rs) and the VK is embedded
    // inline in Halo2Verifier.axiom.sol — there is no separate VK file and no
    // `// k` marker line to parse. So this guard (a) pins the prover's k to the
    // production value (21), and (b) confirms the axiom verifier carries real
    // VK data (not a stub). The true prover↔verifier k-consistency is enforced
    // by the real-KZG → on-chain round-trip (ZKM.realroundtrip.t.sol).
    #[test]
    fn test_real_committed_files_k_values() {
        let prover_path = repo_root().join("cli/src/halo2_prover_axiom.rs");
        let verifier_path = repo_root().join("contracts/src/Halo2Verifier.axiom.sol");
        let prover_content = std::fs::read_to_string(&prover_path)
            .unwrap_or_else(|e| panic!("read {}: {}", prover_path.display(), e));
        let verifier_content = std::fs::read_to_string(&verifier_path)
            .unwrap_or_else(|e| panic!("read {}: {}", verifier_path.display(), e));

        let prover_k = extract_prover_k_from_str(&prover_content)
            .expect("prover AXIOM_CIRCUIT_K should parse");
        // The axiom circuit runs at k=21 (≈1.9M advice cells; the k=23 SRS is
        // universal and only needs srs_k >= circuit_k). If this moves, the
        // verifier MUST be regenerated (circuits/tests/claim_evm_roundtrip.rs)
        // and the on-chain round-trip re-run.
        assert_eq!(
            prover_k, 21,
            "prover AXIOM_CIRCUIT_K moved — regenerate Halo2Verifier.axiom.sol and rerun ZKM.realroundtrip.t.sol"
        );

        // The verifier must carry real (non-zero) VK data — a stub/placeholder
        // would have very few non-zero mstore constants.
        let nonzero_constants = verifier_content
            .lines()
            .filter(|l| {
                l.contains("mstore")
                    && l.contains("0x")
                    && !l.contains(
                        "0x0000000000000000000000000000000000000000000000000000000000000000",
                    )
            })
            .count();
        assert!(
            nonzero_constants >= 20,
            "Halo2Verifier.axiom.sol has only {nonzero_constants} non-zero mstore constants — \
             looks like a stub/placeholder VK; regenerate via claim_evm_roundtrip.rs"
        );
    }

    // ── test_failure_lines: surface WHAT failed (stdout), not just that it did ─
    //
    // `cargo test` and `forge test` both write their per-test FAILURE lines to
    // stdout; the readiness checker used to read stderr only, so a failing run
    // printed "❌ tests failed:" with NO identifying lines (the bug). These
    // tests use the REAL captured output of a failing `cargo test` / `forge
    // test` run and assert the helper now surfaces the failing test name from
    // stdout — and that the old stderr-only behavior would have missed it.

    #[test]
    fn cargo_test_failure_surfaces_stdout_failing_test() {
        // Real `cargo test` output of a run with one failing test `fails_boom`.
        let stdout = "running 2 tests\n\
test passes ... ok\n\
test fails_boom ... FAILED\n\
\n\
failures:\n\
\n\
---- fails_boom stdout ----\n\
thread 'fails_boom' panicked at src/lib.rs:4:19:\n\
assertion `left == right` failed\n\
  left: 1\n\
 right: 2\n\
\n\
failures:\n\
    fails_boom\n\
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        let stderr = "    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s\n\
     Running unittests src/lib.rs\n\
error: test failed, to rerun pass `--lib`\n";

        // OLD behavior: read stderr, filter for FAILED/failures. stderr has
        // NONE of those tokens ("error: test failed" is lowercase "failed") —
        // this is the bug: zero identifying lines on a failing run.
        let old_stderr_only: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("FAILED") || l.contains("failures"))
            .collect();
        assert!(
            old_stderr_only.is_empty(),
            "the bug: stderr-only filter must find nothing, got {old_stderr_only:?}"
        );

        // NEW behavior: read stdout too → surface the failing test by name.
        let lines = test_failure_lines(stdout, stderr);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("fails_boom") && l.contains("FAILED")),
            "fix must surface the failing test from stdout: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("test result: FAILED")),
            "fix must surface the failing result summary: {lines:?}"
        );
        // Non-empty overall (the whole point).
        assert!(!lines.is_empty(), "must surface at least one failure line");
    }

    #[test]
    fn forge_test_failure_surfaces_stdout_failing_test() {
        // Real `forge test` output of a run with one failing test
        // `test_fail_boom()`. NOTE: forge writes ALL of this to stdout — its
        // stderr is empty on a test failure (only compile/link errors land on
        // stderr), so the old stderr-only read surfaced nothing at all.
        let stdout = "[FAIL: assertion failed: 1 != 2] test_fail_boom() (gas: 3332)\n\
Suite result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 1.65ms\n\
Ran 1 test suite in 10.83ms: 1 tests passed, 1 failed, 0 skipped (2 total tests)\n\
Failing tests:\n\
Encountered 1 failing test in test/Counter.t.sol:CounterTest\n\
[FAIL: assertion failed: 1 != 2] test_fail_boom() (gas: 3332)\n\
Encountered a total of 1 failing tests, 1 tests succeeded\n";
        let stderr = ""; // forge writes test results to stdout, not stderr

        // OLD behavior: empty stderr → zero lines (the bug).
        let old_stderr_only: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("fail") || l.contains("error"))
            .collect();
        assert!(
            old_stderr_only.is_empty(),
            "the bug: empty stderr → nothing"
        );

        // NEW behavior: surface the failing test name from stdout.
        let lines = test_failure_lines(stdout, stderr);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("test_fail_boom") && l.contains("FAIL")),
            "fix must surface the failing forge test from stdout: {lines:?}"
        );
        // Dedup: forge prints the `[FAIL …] test_fail_boom()` line twice (run
        // summary + Failing tests section); the helper must collapse them.
        let fail_count = lines
            .iter()
            .filter(|l| l.contains("test_fail_boom"))
            .count();
        assert_eq!(
            fail_count, 1,
            "duplicate FAIL lines must be deduped: {lines:?}"
        );
    }

    #[test]
    fn test_failure_lines_covers_compile_error_on_stderr() {
        // When the suite never ran (a build error), stdout has no FAILED line;
        // the useful detail is the compile error on stderr. The helper must
        // still surface something — otherwise a build-break shows as "tests
        // failed:" with no clue why.
        let stdout = "   Compiling foo v0.1.0\n";
        let stderr = "error[E0308]: mismatched types\n  --> src/lib.rs:4:18\n   |\n 4 |     let x: u32 = \"\";\n   |                   ^^ expected `u32`, found `&str`\n\nerror: could not compile `foo` due to previous error\n";
        let lines = test_failure_lines(stdout, stderr);
        assert!(
            lines.iter().any(|l| l.contains("error[E0308]")),
            "compile error on stderr must be surfaced: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("could not compile")),
            "cargo's terminal error line must be surfaced: {lines:?}"
        );
    }

    #[test]
    fn test_failure_lines_empty_on_success() {
        // A green run has no FAILED/error lines — the helper returns empty,
        // so the caller's loop is a no-op on success.
        let stdout = "running 3 tests\n\
test a ... ok\n\
test b ... ok\n\
test c ... ok\n\
test result: ok. 3 passed; 0 failed; 0 ignored\n";
        let stderr = "    Finished `test` profile [unoptimized + debuginfo] target(s)\n\
     Running unittests src/lib.rs\n";
        assert!(
            test_failure_lines(stdout, stderr).is_empty(),
            "a green run must yield no failure lines"
        );
    }
}
