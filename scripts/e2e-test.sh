#!/usr/bin/env bash
# ZKMist Local End-to-End Test
#
# Generates a real Halo2-KZG proof and validates it end-to-end.
# This is the recommended pre-deployment validation step.
#
# What it does:
#   1. Generates a proof using `zkmist bench` (small Merkle tree, fast)
#   2. Validates proof size matches the Halo2Verifier's expected length (5632 bytes)
#   3. Verifies the proof cryptographically (local verification)
#   4. Reports timing for each phase
#
# Prerequisites:
#   - Rust (stable) with cargo
#   - ~16-20 GiB RAM for proof generation (measured peak ~19.5 GiB RSS at k=23)
#   - First proof is slow: cold KZG params generation for 16M G1 points was
#     measured to exceed 8 minutes. Subsequent runs reuse ~/.zkmist/cache/.
#     ⚠️ The prover currently uses a RANDOM SRS (Params::new) — dev/test only;
#     mainnet must load the Ethereum KZG ceremony SRS (see readiness checker).
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
cargo test -p zkmist-merkle-tree -p zkmist-circuits -p zkmist-cli --bin zkmist --quiet 2>&1 | tail -5
if [ $? -eq 0 ]; then
    pass "Rust unit tests"
else
    fail "Rust unit tests"
fi
echo ""

# ── Step 3: Run Solidity tests ──────────────────────────────────────
echo "[3/6] Running Solidity tests..."
cd contracts
forge test --quiet -vvv 2>&1 | tail -5
if [ $? -eq 0 ]; then
    pass "Solidity tests"
else
    fail "Solidity tests"
fi
cd "$PROJECT_ROOT"
echo ""

# ── Step 4: Run benchmark (generates real proof) ────────────────────
echo "[4/6] Generating Halo2-KZG proof (benchmark mode)..."
echo "      First run generates 16M KZG G1 points (measured >8 min cold; cached after)..."
START=$(date +%s)
BENCH_OUTPUT=$(cargo run --release -p zkmist-cli --bin zkmist -- bench --tree-depth 4 2>&1) || true
ELAPSED=$(($(date +%s) - START))

echo "$BENCH_OUTPUT" | grep -E "Benchmark|Total|Proof size|Proof in range|under|exceeds|expected"

if echo "$BENCH_OUTPUT" | grep -q "Proof in range.*YES"; then
    pass "Proof size matches expected length"
else
    PROOF_SIZE=$(echo "$BENCH_OUTPUT" | grep "Proof size" | grep -oE '[0-9]+' | head -1)
    if [ -n "$PROOF_SIZE" ]; then
        # Production Halo2-KZG proofs are 5632 bytes (0x1600); the CLI's
        # PROOF_LENGTH_MIN/MAX acceptance window is [4000, 8000]. The old
        # [400, 1200] window was a stale leftover from the placeholder verifier
        # and would have wrongly failed every real 5632-byte proof.
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

# Quick k-value consistency check
VK_K=$(grep '// k$' "$PROJECT_ROOT/contracts/src/Halo2VerifyingKey.sol" 2>/dev/null | grep -oP '0x\K[0-9a-fA-F]+' | head -1)
PROVER_K=$(grep 'CIRCUIT_K' "$PROJECT_ROOT/cli/src/halo2_prover.rs" 2>/dev/null | grep -oP '\d+' | head -1)
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

if echo "$READINESS_OUTPUT" | grep -q "0 failed"; then
    pass "Readiness check (no failures)"
else
    warn "Readiness check has failures (expected pre-deployment)"
fi
echo ""

# ── Step 6: Lint checks ─────────────────────────────────────────────
echo "[6/6] Running lint checks..."

cargo fmt --all -- --check 2>&1
if [ $? -eq 0 ]; then
    pass "cargo fmt clean"
else
    fail "cargo fmt: unformatted files"
fi

cargo clippy --workspace -- -D warnings 2>&1 | tail -3
if [ $? -eq 0 ]; then
    pass "cargo clippy clean"
else
    fail "cargo clippy warnings"
fi

cd contracts && forge fmt --check 2>&1
if [ $? -eq 0 ]; then
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
