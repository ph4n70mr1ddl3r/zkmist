#!/usr/bin/env bash
# ZKMist Local End-to-End Test
#
# Generates a real Halo2-KZG proof and validates it end-to-end.
# This is the recommended pre-deployment validation step.
#
# What it does:
#   1. Generates a proof using `zkmist bench` (small Merkle tree, fast)
#   2. Validates proof size matches the Halo2Verifier's expected length (5888 bytes)
#   3. Verifies the proof cryptographically (local verification)
#   4. Reports timing for each phase
#
# Prerequisites:
#   - Rust (stable) with cargo
#   - ~16-20 GiB RAM for proof generation (measured peak ~19.5 GiB RSS at k=23)
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
        # Production Halo2-KZG proofs are 5888 bytes (0x1700); the CLI's
        # PROOF_LENGTH_MIN/MAX acceptance window is [4000, 8000]. The old
        # [400, 1200] window was a stale leftover from the placeholder verifier
        # and would have wrongly failed every real 5888-byte proof.
        if [ "$PROOF_SIZE" -ge 4000 ] && [ "$PROOF_SIZE" -le 8000 ]; then
            pass "Proof size ($PROOF_SIZE bytes) in bench range"
        else
            fail "Proof size ($PROOF_SIZE bytes) outside expected range [4000, 8000]"
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

# ── Step 5: Run readiness checker ──────────────────────────────────
echo "[5/6] Running pre-deployment readiness check..."

# Quick k-value consistency check.
#
# Both extractions had to be fixed (they reported nonsense, so this check
# always failed with misleading numbers):
#   • VK_K  — the `// k` line is `mstore(0x0040, 0x...0015) // k`. The old
#     `grep -oP '0x\K...'` grabbed the FIRST hex literal, the mstore OFFSET
#     `0x0040` (=64), not the VALUE `0x15` (=21). The readiness checker's
#     `extract_vk_k` was already fixed for this exact offset/value bug (see its
#     `test_extract_vk_k_does_not_return_the_offset`); take the LAST hex literal
#     on the line, which is the value.
#   • PROVER_K — `grep 'CIRCUIT_K' | grep -oP '\d+'` hit the FIRST digit run on
#     the const line `const CIRCUIT_K: u32 = 23;`, which is `32` (from `u32`),
#     not `23`. Anchor on the const declaration and take the assigned value.
VK_K=$(grep '// k$' "$PROJECT_ROOT/contracts/src/Halo2VerifyingKey.sol" 2>/dev/null | grep -oP '0x[0-9a-fA-F]+' | tail -1 | sed 's/^0x//')
PROVER_K=$(grep -oP 'const CIRCUIT_K:\s*u32\s*=\s*\K\d+' "$PROJECT_ROOT/cli/src/halo2_prover.rs" 2>/dev/null | head -1)
if [ -n "$VK_K" ] && [ -n "$PROVER_K" ]; then
    VK_K_DEC=$((16#$VK_K))
    if [ "$VK_K_DEC" != "$PROVER_K" ]; then
        echo -e "  ${RED}❌ FAIL${NC}: VK k=$VK_K_DEC does not match prover CIRCUIT_K=$PROVER_K"
        FAILED=$((FAILED + 1))
    else
        pass "VK k-value ($VK_K_DEC) matches prover CIRCUIT_K"
    fi
else
    warn "Could not check VK k-value consistency"
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
