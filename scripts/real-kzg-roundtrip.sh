#!/usr/bin/env bash
# ZKMist Real-KZG → On-chain Round-Trip Test
#
# Closes the documented deployment blocker: "the real-KZG → on-chain verifier
# loop has never been exercised" (SECURITY.md). It generates a REAL Halo2-KZG
# proof with the CLI prover and submits it through the PRODUCTION Halo2Verifier
# (real BN254 ecPairing) in the EVM, asserting the Claimed event + mint.
#
# Once this script goes green, it is the first ever honest on-chain verification.
#
# Prerequisites (it refuses to proceed silently if a hard blocker remains):
#   1. Halo2Verifier.axiom.sol regenerated with real VK data (NOT a
#      stub/placeholder). The VK is embedded inline in the verifier contract
#      (axiom backend, k=21); a stub would make every proof revert with
#      "Invalid proof". Regenerate via the axiom circuit's verifier emitter:
#        ZKMIST_EMIT_VERIFIER=1 ZKMIST_USE_PINNED_SRS=1 \
#          cargo test -p zkmist-circuits --test claim_evm_roundtrip -- --nocapture
#   2. A KZG SRS:
#        - mainnet-grade: pin KZG_SRS_URL + KZG_SRS_SHA256 in
#          cli/src/constants.rs (see docs/kzg-srs.md), OR
#        - dev/test only: export ZKMIST_DEV_SRS=1 (forgeable SRS; still
#          validates the verifier code path, NOT proof soundness).
#
# Usage:
#   ZKMIST_DEV_SRS=1 ./scripts/real-kzg-roundtrip.sh
#   ./scripts/real-kzg-roundtrip.sh --fork https://mainnet.base.org   # fork mode
#
# Exit codes: 0 = round-trip verified on-chain; 1 = blocked / failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
say() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARN:${NC} $*"; }
die() { echo -e "${RED}[$(date +%H:%M:%S)] FAIL:${NC} $*" >&2; exit 1; }

FORK_URL=""
if [[ "${1:-}" == "--fork" ]]; then
    FORK_URL="${2:-}"
    [[ -z "$FORK_URL" ]] && die "--fork requires an RPC URL"
fi

# ── Pre-flight ────────────────────────────────────────────────────────────
command -v cargo >/dev/null || die "cargo not found (install Rust)."
command -v forge >/dev/null || die "forge not found (install Foundry)."

# ── Hard blocker: the on-chain VK must be regenerated, not the placeholder ─
# The axiom backend embeds the VK INLINE in Halo2Verifier.axiom.sol (there is no
# separate Halo2VerifyingKey contract). The readiness checker's [1b] reports the
# VK state: it prints "looks like a stub/placeholder VK" when the verifier has
# too few non-zero mstore constants. (The strings this used to grep for —
# "VK k-value MISMATCH" / "ALL fixed commitments are zero" — were PSE-era and
# are NEVER emitted by the current readiness tool, so the old grep was dead code
# that could never detect a placeholder VK.)
say "Checking on-chain Halo2Verifier.axiom.sol is regenerated (not placeholder)..."
READINESS_OUT="$(cargo run -q -p zkmist-tools --bin readiness -- --skip-slow 2>&1 || true)"
if echo "$READINESS_OUT" | grep -q "stub/placeholder VK"; then
    die "Halo2Verifier.axiom.sol looks like a stub/placeholder VK (too few non-zero
     mstore constants). Regenerate it first via the axiom circuit's verifier
     emitter:
       ZKMIST_EMIT_VERIFIER=1 ZKMIST_USE_PINNED_SRS=1 \
         cargo test -p zkmist-circuits --test claim_evm_roundtrip -- --nocapture"
fi
say "VK looks regenerated."

# ── SRS availability ──────────────────────────────────────────────────────
if [[ -n "${ZKMIST_DEV_SRS:-}" ]]; then
    warn "ZKMIST_DEV_SRS is set — using a forgeable dev SRS. This validates the
       verifier code path but NOT proof soundness. Do not treat a green run
       here as mainnet-grade."
else
    SRS_HASH="$(grep -oP 'pub const KZG_SRS_SHA256:\s*&str\s*=\s*"\K[^"]*' cli/src/constants.rs 2>/dev/null || true)"
    [[ -z "$SRS_HASH" ]] && die "No pinned KZG SRS (KZG_SRS_SHA256 empty in cli/src/constants.rs)
     and ZKMIST_DEV_SRS is not set. Either pin the PSE SRS (see docs/kzg-srs.md)
     or set ZKMIST_DEV_SRS=1 for a forgeable dev SRS."
    say "Pinned PSE KZG SRS detected (sha256=${SRS_HASH:0:12}…)."
fi

# ── 1. Build the CLI (release; proof generation is slow in debug) ─────────
say "Building zkmist-cli (release)..."
cargo build --release -p zkmist-cli

# ── 2. Generate the real-KZG proof fixture ────────────────────────────────
FIXTURE="contracts/fixtures/real_roundtrip.json"
say "Generating real-KZG proof fixture → $FIXTURE (heavy ~3 min / ~20 GiB at k=23)..."
cargo run --release -p zkmist-cli -- gen-roundtrip-fixture --out "$FIXTURE"
[[ -f "$FIXTURE" ]] || die "fixture was not written"

# Proof length in bytes = hex chars / 2 (strip the leading 0x captured away
# by the \K lookbehind). ${#PROOF_HEX} counts chars with no trailing newline,
# so this is exact (the prior `wc -c)/2 - 1` was off-by-one: wc adds a newline).
PROOF_HEX="$(grep -oP '"proof":\s*"0x\K[0-9a-f]+' "$FIXTURE" | head -1)"
PROOF_BYTES=$(( ${#PROOF_HEX} / 2 ))
say "Fixture ready (proof = ${PROOF_BYTES} bytes; axiom SHPLONK at k=21 is ~1376)."

# ── 3. Run the on-chain round-trip in the EVM ─────────────────────────────
say "Running RealRoundtrip Forge test (RUN_REAL_ROUNDTRIP=1)..."
cd contracts
export RUN_REAL_ROUNDTRIP=1
export ROUNDTRIP_FIXTURE="fixtures/real_roundtrip.json"

if [[ -n "$FORK_URL" ]]; then
    forge test --match-contract RealRoundtrip --fork-url "$FORK_URL" -vvv
else
    forge test --match-contract RealRoundtrip -vvv
fi

cd "$PROJECT_ROOT"
say "✅ Real-KZG proof verified on-chain (Claimed event + mint confirmed)."
say "This was the first honest real-KZG → on-chain verifier round-trip."
