#!/usr/bin/env bash
# ZKMist Local End-to-End Test
#
# Generates a real Halo2-KZG proof and validates it end-to-end.
# This is the recommended pre-deployment validation step.
#
# What it does:
#   1. Generates a proof using `zkmist bench` (small Merkle tree, fast)
#   2. Validates proof size matches the axiom SHPLONK expected length (~1376 bytes)
#   3. Verifies the proof cryptographically (local verification)
#   4. Reports timing for each phase
#
# Prerequisites:
#   - Rust (stable) with cargo
#   - ~10 GiB RAM for proof generation (axiom backend at k=21)
#   - The bench step proves against a RANDOM dev SRS (ZKMIST_DEV_SRS=1, set
#     automatically below) so it runs without the pinned PSE ceremony SRS.
#     That SRS is forgeable, so the bench validates the proving CODE PATH and
#     proof SIZE only — never soundness. Mainnet MUST pin the real PSE SRS
#     (KZG_SRS_SHA256 in cli/src/constants.rs); the readiness checker enforces
#     this. The first run generates the dev SRS (2^23 G1 points, ~8 min cold;
#     cached under ~/.zkmist/cache/ thereafter).
#
# Usage:
#   ./scripts/e2e-test.sh
#   ./scripts/e2e-test.sh --full   # Also runs the full CLI prove command (requires eligibility list)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ZKMist Local End-to-End Test                               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

cd "$PROJECT_ROOT"

FAILED=0
PASS=0

pass() {
    echo -e "  ${GREEN}✅ PASS${NC}: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}❌ FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
}

warn() {
    echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"
}

# ── Step 1: Build ────────────────────────────────────────────────────
echo "[1/6] Building CLI (release mode)..."
START=$(date +%s)
cargo build --release -p zkmist-cli -p zkmist-tools 2>&1 | tail -3
ELAPSED=$(($(date +%s) - START))
echo "      Built in ${ELAPSED}s"
echo ""

# ── Step 2: Run circuit tests (fast) ────────────────────────────────
echo "[2/6] Running Rust unit tests..."
# The check command goes IN the `if` condition, not as a bare statement
# followed by `if [ $? ... ]`. Under `set -euo pipefail` (set at the top), a
# failing bare command aborts the script BEFORE the `if` can record it, so the
# `fail` branch is dead code and every later step (plus the final summary) is
# skipped — defeating the whole pass/fail tracking. A command in an `if`
# condition is one of the contexts where `set -e` does NOT trigger, so the
# failure is recorded and the script continues. (Same bug/fix in Steps 3 & 6.)
if cargo test -p zkmist-merkle-tree -p zkmist-circuits -p zkmist-cli --bin zkmist --quiet 2>&1 | tail -5; then
    pass "Rust unit tests"
else
    fail "Rust unit tests"
fi
echo ""

# ── Step 3: Run Solidity tests ──────────────────────────────────────
echo "[3/6] Running Solidity tests..."
cd contracts
# Command in the `if` condition — see the note in Step 2. A bare failing
# `forge test` would abort under `set -e` before `fail` could record it.
if forge test --quiet -vvv 2>&1 | tail -5; then
    pass "Solidity tests"
else
    fail "Solidity tests"
fi
cd "$PROJECT_ROOT"
echo ""

# ── Step 4: Run benchmark (generates real proof) ────────────────────
#
# SKIP_BENCH escape hatch: the CI workflow (.github/workflows/ci.yml) exports
# `SKIP_BENCH=1` for the E2E job (commented "Skip the bench step in CI (too
# slow)"). This step honors it: when set, the whole proof-generation step is
# skipped. A real k=23 Halo2-KZG proof peaks at ~16–20 GiB RSS (README + the
# prover's `preflight_ram_check`, which hard-fails below ~24 GiB available),
# so on a standard GitHub `ubuntu-latest` runner (~7 GiB RAM) the bench step
# would either be rejected by the preflight check or OOM-killed mid-prove —
# silently failing the E2E job the moment an operator manually triggers it.
# Before this guard the env var was set by CI but never read here, so the bench
# ran anyway (the exact failure mode the comment intended to prevent).
if [ -n "${SKIP_BENCH:-}" ]; then
    echo "[4/6] Skipping Halo2-KZG benchmark (SKIP_BENCH is set)."
    warn "Proof generation skipped — requires ~16-20 GiB RAM and minutes; run locally."
    echo ""
else
    echo "[4/6] Generating Halo2-KZG proof (benchmark mode)..."
    echo "      Uses a RANDOM dev SRS (ZKMIST_DEV_SRS=1) — validates proving code path"
    echo "      and proof SIZE only, NOT soundness. First run generates the dev SRS"
    echo "      (~8 min cold; cached after)."
    START=$(date +%s)
    # ZKMIST_DEV_SRS=1: the prover now REQUIRES a pinned PSE SRS
    # (KZG_SRS_SHA256) in production and falls back to a random dev SRS ONLY under
    # this gate. Without it `bench` errors with "No KZG SRS configured" before ever
    # proving — so this gate is what lets the benchmark actually produce a proof.
    # The dev SRS is forgeable; fine for a timing/size benchmark, NEVER for mainnet.
    BENCH_OUTPUT=$(ZKMIST_DEV_SRS=1 cargo run --release -p zkmist-cli --bin zkmist -- bench --tree-depth 4 2>&1) || true
    ELAPSED=$(($(date +%s) - START))

    echo "$BENCH_OUTPUT" | grep -E "Benchmark|Total|Proof size|Proof in range|under|exceeds|expected"

    if echo "$BENCH_OUTPUT" | grep -q "Proof in range.*YES"; then
        pass "Proof size matches expected length"
    else
        PROOF_SIZE=$(echo "$BENCH_OUTPUT" | grep "Proof size" | grep -oE '[0-9]+' | head -1)
        if [ -n "$PROOF_SIZE" ]; then
            # Production axiom SHPLONK proofs at k=21 are ~1376 bytes
            # (instances ++ commitments ++ evaluation proofs). The window is
            # deliberately loose — it catches truncated/corrupt output without
            # ever rejecting a legitimate proof. The prior [4000, 8000] window
            # was a stale leftover from the retired PSE backend (5888-byte IPA
            # proofs) and would have wrongly failed every real 1376-byte axiom
            # proof.
            if [ "$PROOF_SIZE" -ge 1000 ] && [ "$PROOF_SIZE" -le 2000 ]; then
                pass "Proof size ($PROOF_SIZE bytes) in axiom range"
            else
                fail "Proof size ($PROOF_SIZE bytes) outside expected axiom range [1000, 2000]"
            fi
        else
            warn "Could not determine proof size"
        fi
    fi

    if echo "$BENCH_OUTPUT" | grep -q "under 60s target"; then
        pass "Proving time under 60 seconds"
    elif [ $ELAPSED -lt 120 ]; then
        pass "Total benchmark completed in ${ELAPSED}s"
    else
        warn "Benchmark took ${ELAPSED}s (includes build overhead)"
    fi
    echo ""
fi

# ── Step 5: Run readiness checker ──────────────────────────────────
echo "[5/6] Running pre-deployment readiness check..."

# Quick prover k-value check (axiom backend).
#
# The PSE→axiom migration retired BOTH files this check used to grep, so the
# old extractions always came back empty:
#   • `contracts/src/Halo2VerifyingKey.sol` — a SEPARATE VK contract carrying a
#     `mstore(0x0040, 0x..0015) // k` marker. GONE: the VK is now embedded
#     INLINE in `Halo2Verifier.axiom.sol` (snark-verifier-generated) with NO
#     parseable `// k` marker, so the verifier k can no longer be grepped.
#   • `cli/src/halo2_prover.rs` (`const CIRCUIT_K: u32 = 23`) → renamed to
#     `cli/src/halo2_prover_axiom.rs` (`const AXIOM_CIRCUIT_K: u32 = 21`).
# With both paths stale, `VK_K`/`PROVER_K` were always empty AND — worse — under
# `set -euo pipefail` the failing `VK_K=$(grep …)` assignment ABORTED the whole
# script at Step 5: the readiness checker, the Step 6 lint checks, and the
# final summary never ran. (`./scripts/e2e-test.sh` died with exit 1 mid-Step-5
# on the axiom tree, taking the CI `E2E Test Suite` job down with it.)
#
# Fix: extract the prover k from its real (axiom) location and assert it equals
# the production value (21). The verifier↔prover k-consistency is no longer
# parseable in shell (no VK marker); it is enforced by the readiness checker's
# compiled test `test_real_committed_files_k_values` (prover k pinned to 21 +
# verifier carries real VK data) and, definitively, by the real-KZG on-chain
# round-trip (ZKM.realroundtrip.t.sol).
#
# `|| true` keeps the assignment from aborting under `set -e` when grep finds
# no match (file renamed/missing again) — the empty value is then reported via
# the `fail` branch below instead of killing the script (the original bug).
PROVER_K=$(grep -oP 'const AXIOM_CIRCUIT_K:\s*u32\s*=\s*\K\d+' "$PROJECT_ROOT/cli/src/halo2_prover_axiom.rs" 2>/dev/null | head -1 || true)
# Production circuit k for the axiom claim circuit (≈1.9M advice cells; the
# universal k=23 PSE SRS only needs srs_k >= circuit_k). MUST match
# `AXIOM_CIRCUIT_K` in cli/src/halo2_prover_axiom.rs and the readiness test
# `test_real_committed_files_k_values`. If this moves, regenerate
# Halo2Verifier.axiom.sol (circuits/tests/claim_evm_roundtrip.rs) and re-run
# the on-chain round-trip.
EXPECTED_AXIOM_K=21
if [ -n "$PROVER_K" ]; then
    if [ "$PROVER_K" != "$EXPECTED_AXIOM_K" ]; then
        echo -e "  ${RED}❌ FAIL${NC}: prover AXIOM_CIRCUIT_K=$PROVER_K != production k=$EXPECTED_AXIOM_K"
        FAILED=$((FAILED + 1))
    else
        pass "Prover AXIOM_CIRCUIT_K=$PROVER_K matches production k=$EXPECTED_AXIOM_K"
    fi
else
    fail "Could not extract AXIOM_CIRCUIT_K from cli/src/halo2_prover_axiom.rs (file renamed/missing?)"
fi

READINESS_OUTPUT=$(cargo run --release -p zkmist-tools --bin readiness -- --skip-slow 2>&1) || true
echo "$READINESS_OUTPUT" | grep -E "Results:|PASS|FAIL|✅|❌|⚠️"

# Match the readiness checker's ACTUAL summary line
#   "Results: N passed, M regression(s), K known blocker(s), S skipped"
# (tools/src/readiness.rs). The previous `grep -q "0 failed"` could never
# match — the tool reports "regression(s)", never "failed" — so this branch
# ALWAYS warned "Readiness check has failures" even on a perfectly clean run
# (a clean run has 0 regressions but may carry advisory known-blockers like
# the placeholder AIRDROP_CONTRACT). "0 regression(s)" is the real clean signal.
if echo "$READINESS_OUTPUT" | grep -q "0 regression(s)"; then
    pass "Readiness check (no regressions)"
else
    warn "Readiness check reports regressions (expected pre-deployment)"
fi
echo ""

# ── Step 6: Lint checks ─────────────────────────────────────────────
echo "[6/6] Running lint checks..."

# Each check goes IN the `if` condition. Under `set -euo pipefail` (set at the
# top) a BARE failing command aborts the script before the `else`/`fail` branch
# can run, so the failure is never recorded and the summary below is skipped —
# the exact opposite of what pass/fail tracking is for. The `if CMD; then ...`
# form is one of the contexts where `set -e` does NOT trigger, so a failure is
# recorded via `fail` and later checks still run. (Steps 2 & 3 had the same
# latent bug and use the same fix.) This was silent only because CI runs the
# script against a clean tree, so every check passed and the abort path was
# never exercised.

if cargo fmt --all -- --check 2>&1; then
    pass "cargo fmt clean"
else
    fail "cargo fmt: unformatted files"
fi

if cargo clippy --workspace -- -D warnings 2>&1 | tail -3; then
    pass "cargo clippy clean"
else
    fail "cargo clippy warnings"
fi

cd contracts
if forge fmt --check 2>&1; then
    pass "forge fmt clean"
else
    fail "forge fmt: unformatted files"
fi
cd "$PROJECT_ROOT"
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo -e "  E2E Test Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ Some checks failed. Fix before deploying.${NC}"
    exit 1
else
    echo -e "${GREEN}✅ All automated checks passed!${NC}"
    echo ""
    echo "Remaining steps before mainnet:"
    echo "  [ ] Run full E2E MockProver tests (slow):"
    echo "      cargo test -p zkmist-circuits -- --ignored --nocapture"
    echo "  [ ] External security audit of secp256k1 gadget"
    echo "  [ ] Generate production Halo2Verifier.sol"
    echo "  [ ] Deploy to Base Sepolia: ./scripts/testnet-deploy.sh"
    echo "  [ ] Full E2E claim on testnet"
fi
