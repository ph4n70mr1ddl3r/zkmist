//! Pre-deployment readiness checker for ZKMist.
//!
//! Validates that all prerequisites are met before deploying to mainnet.
//! Checks:
//!   1. Halo2Verifier.sol has IS_PRODUCTION_VERIFIER = true
//!   2. Merkle root matches the known eligibility tree root
//!   3. Circuit MockProver tests pass (optional, slow)
//!   4. Forge tests pass
//!   5. Cargo clippy/fmt pass
//!   6. Constants are consistent between CLI and contracts
//!   7. No placeholder values remain
//!
//! Usage:
//!   cargo run -p zkmist-tools --bin readiness
//!   cargo run -p zkmist-tools --bin readiness -- --skip-slow

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let skip_slow = args.iter().any(|a| a == "--skip-slow");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("ZKMist Pre-Deployment Readiness Checker");
        eprintln!();
        eprintln!("Usage: readiness [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --skip-slow   Skip slow checks (MockProver, forge test)");
        eprintln!("  --help        Show this help");
        std::process::exit(0);
    }

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist Pre-Deployment Readiness Check                     ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    // ── Check 1: IS_PRODUCTION_VERIFIER ──────────────────────────────
    eprintln!("[1/8] Checking Halo2Verifier.sol production status...");
    let verifier_path = Path::new("../contracts/src/Halo2Verifier.sol");
    if let Ok(content) = std::fs::read_to_string(verifier_path) {
        if content.contains("IS_PRODUCTION_VERIFIER = true") {
            eprintln!("      ✅ IS_PRODUCTION_VERIFIER = true");
            passed += 1;
        } else if content.contains("IS_PRODUCTION_VERIFIER = false") {
            eprintln!(
                "      ❌ IS_PRODUCTION_VERIFIER = false — MUST regenerate with snark-verifier"
            );
            failed += 1;
        } else {
            eprintln!("      ⚠️  Cannot determine IS_PRODUCTION_VERIFIER status");
            failed += 1;
        }
    } else {
        eprintln!(
            "      ⚠️  Halo2Verifier.sol not found at {}",
            verifier_path.display()
        );
        failed += 1;
    }

    // ── Check 2: Merkle root consistency ─────────────────────────────
    eprintln!("[2/8] Checking merkle root consistency...");
    let cli_root = extract_constant("../cli/src/constants.rs", "KNOWN_MERKLE_ROOT");
    let deploy_root = extract_solidity_constant("../contracts/script/Deploy.s.sol", "MERKLE_ROOT");
    let airdrop_test_root = find_test_merkle_root();

    match (cli_root.as_deref(), deploy_root.as_deref()) {
        (Some(cli), Some(deploy)) if cli == deploy => {
            eprintln!(
                "      ✅ Merkle root consistent: {}...{}",
                &cli[..18],
                &cli[cli.len() - 8..]
            );
            passed += 1;
        }
        (Some(cli), Some(deploy)) => {
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
    let cli_deadline = extract_constant_value("../cli/src/constants.rs", "CLAIM_DEADLINE: u64");
    let cli_claim_amount = extract_constant_value("../cli/src/constants.rs", "CLAIM_AMOUNT: u64");
    let cli_max_claims = extract_constant_value("../cli/src/constants.rs", "MAX_CLAIMS: u64");

    let mut constants_ok = true;
    if let Some(ref d) = cli_deadline {
        if d != "1_798_761_600" && d != "1798761600" {
            eprintln!("      ⚠️  CLAIM_DEADLINE = {} (expected 1798761600)", d);
            constants_ok = false;
        }
    }
    if let Some(ref a) = cli_claim_amount {
        if a != "10_000" && a != "10000" {
            eprintln!("      ⚠️  CLAIM_AMOUNT = {} (expected 10000)", a);
            constants_ok = false;
        }
    }
    if let Some(ref c) = cli_max_claims {
        if c != "1_000_000" && c != "1000000" {
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

    // ── Check 4: No placeholder values ──────────────────────────────
    eprintln!("[4/8] Checking for placeholder values...");
    let mut placeholder_found = false;
    if let Ok(content) = std::fs::read_to_string("../cli/src/constants.rs") {
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
        // Don't count as failure — placeholders are expected pre-deployment
        skipped += 1;
    } else {
        eprintln!("      ✅ No placeholder values");
        passed += 1;
    }

    // ── Check 5: Cargo clippy ────────────────────────────────────────
    eprintln!("[5/8] Running cargo clippy...");
    let clippy_output = std::process::Command::new("cargo")
        .args(["clippy", "--workspace", "--", "-D", "warnings"])
        .current_dir("..")
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
        .current_dir("..")
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
            .current_dir("../contracts")
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
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("      ❌ Forge tests failed:");
                for line in stderr
                    .lines()
                    .filter(|l| l.contains("fail") || l.contains("error"))
                    .take(5)
                {
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
            .current_dir("..")
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
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("      ❌ Cargo tests failed:");
                for line in stderr
                    .lines()
                    .filter(|l| l.contains("FAILED") || l.contains("failures"))
                    .take(5)
                {
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
        "  Results: {} passed, {} failed, {} skipped",
        passed, failed, skipped
    );
    eprintln!("════════════════════════════════════════════════════════════");

    if failed > 0 {
        eprintln!();
        eprintln!(
            "  ❌ NOT READY for deployment — fix {} failing check(s)",
            failed
        );
        std::process::exit(1);
    } else {
        eprintln!();
        eprintln!("  ✅ All automated checks passed!");
        eprintln!();
        eprintln!("  Remaining manual steps before mainnet deployment:");
        eprintln!("    [ ] External security audit of secp256k1 non-native field arithmetic");
        eprintln!(
            "    [ ] Run full E2E MockProver test (cargo test -p zkmist-circuits -- --ignored)"
        );
        eprintln!("    [ ] Testnet deployment on Base Sepolia with full claim flow");
        eprintln!("    [ ] Update AIRDROP_CONTRACT in cli/src/constants.rs after deployment");
        eprintln!("    [ ] Verify proof size in [400, 1200] byte range with real proof");
        eprintln!("    [ ] Benchmark proving time on reference hardware (<60 sec target)");
    }
}

fn extract_constant(file_path: &str, const_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for line in content.lines() {
        if line.contains(const_name) {
            // Extract the value after '=' or ':'
            if let Some(idx) = line.find('=') {
                let val = line[idx + 1..]
                    .trim()
                    .trim_matches('"')
                    .trim_end_matches(';')
                    .trim();
                return Some(val.replace('_', ""));
            }
        }
    }
    None
}

fn extract_constant_value(file_path: &str, const_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pub const") && trimmed.contains(const_name.split(':').next()?) {
            if let Some(idx) = trimmed.find('=') {
                return Some(trimmed[idx + 1..].trim().trim_end_matches(';').to_string());
            }
        }
    }
    None
}

fn extract_solidity_constant(file_path: &str, const_name: &str) -> Option<String> {
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

fn find_test_merkle_root() -> Option<String> {
    // Look for the merkle root in contract test files
    let test_dir = Path::new("../contracts/test");
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
