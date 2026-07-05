#!/usr/bin/env bash
# fetch-pse-srs.sh — obtain + rigorously verify a k=23 PSE halo2 KZG SRS
#
# This is the deployer-side "obtain" step from docs/kzg-srs.md §2.1/§2.2.
# It FETCHES a candidate file and VERIFIES it, reusing the existing
# `tools/src/verify_srs.rs` for the cryptographic checks (parse via the same
# ParamsKZG::<Bn256>::read the prover uses, assert k == 23, G1 count == 2^23,
# cross-check byte-identity across sources, emit the constants.rs snippet).
#
# ── What this script does NOT do ─────────────────────────────────────────
# It does NOT pick the trust source for you. Supplying --url is a deployer
# trust decision. A KZG SRS is the single trust root of the whole system, so
# the URL must be one you chose deliberately — not one this script silently
# defaulted to. See "Candidate publishers" below.
#
# ── Candidate publishers (RESEARCH + CONFIRM before trusting) ────────────
# These projects publish BN254 halo2 KZG SRS files. YOU must:
#   (a) confirm the URL currently serves a halo2 params file (not, say, raw
#       ceremony transcript bytes) at EXACTLY k=23, and
#   (b) obtain its digest INDEPENDENTLY of the download (project README, audit
#       report, official announcement, on-chain registry, …), and
#   (c) ideally cross-check two independent publishers by passing two --url
#       flags plus --sha256 — the script asserts all downloads are
#       byte-identical AND match the pinned digest.
#     • PSE halo2-setup:      https://github.com/privacy-scaling-explorations/halo2-setup
#     • PSE perpetual-pow-τ:  https://github.com/privacy-scaling-explorations/perpetualpowersoftau
#     • Scroll prover SRS:    https://github.com/scroll-tech  (search their repos for "srs"/"kzg")
#     • Taiko prover SRS:     https://github.com/taikoxyz     (search their repos for "srs"/"setup")
# If no reputable publisher serves EXACTLY k=23, the gold-standard path is to
# run PSE phase2 extraction at k=23 yourself (deterministic → cross-checkable).
# Truncating a larger file is NOT supported by the halo2 0.3.x public API —
# see docs/kzg-srs.md §1.1 before considering it.
#
# ── Usage ────────────────────────────────────────────────────────────────
#   # Real fetch (one source + its independently-obtained digest):
#   ./scripts/fetch-pse-srs.sh \
#       --url https://example.org/params-k23.bin \
#       --sha256 <64-hex-char-digest> \
#       --out ~/.zkmist/cache/v2_params_k23.bin
#
#   # Strongest: two independent sources, cross-checked:
#   ./scripts/fetch-pse-srs.sh \
#       --url https://publisher-A/params-k23.bin \
#       --url https://publisher-B/params-k23.bin \
#       --sha256 <digest> \
#       --out params-k23.bin
#
#   # If you can only find a LARGER k (e.g. k=24) from a reputable source:
#   #   downsize to exactly k=23 via halo2's own audited Params::downsize
#   #   (same trapdoor τ; only the unused high-degree powers are dropped).
#   ./scripts/fetch-pse-srs.sh \
#       --truncate-from params-k24.bin \
#       --out params-k23.bin
#
#   # Plumbing self-test (NO download): generates a small forgeable DEV file
#   # and exercises verify + cross-check + truncate end-to-end. Output is NOT
#   # a real SRS.
#   ./scripts/fetch-pse-srs.sh --self-test
#
# Exit codes: 0 = file verified + installed; 1 = usage / verification failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
say() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARN:${NC} $*"; }
die() { echo -e "${RED}[$(date +%H:%M:%S)] FAIL:${NC} $*" >&2; cleanup; exit 1; }

# ── Arg parsing ──────────────────────────────────────────────────────────
URLS=()
SHA256=""
OUT=""
EXPECT_K=23
SELF_TEST=0
TRUNCATE_INPUT=""   # if set, downsize this larger-k file to EXPECT_K instead of downloading

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)            URLS+=("$2"); shift 2 ;;
        --sha256)         SHA256="${2,,}"; shift 2 ;;   # lowercase
        --out)            OUT="$2"; shift 2 ;;
        --expect-k)       EXPECT_K="$2"; shift 2 ;;
        --self-test)      SELF_TEST=1; shift ;;
        --truncate-from)  TRUNCATE_INPUT="$2"; shift 2 ;;
        --help|-h)
            sed -n '3,68p' "$0"; exit 0 ;;
        *) die "unknown arg: $1 (try --help)" ;;
    esac
done

# ── Temp-file hygiene ────────────────────────────────────────────────────
TMPDIR_WORK="$(mktemp -d)"
TEMPS=()
cleanup() {
    for f in "${TEMPS[@]:-}"; do [[ -n "$f" && -f "$f" ]] && rm -f "$f"; done
    rm -rf "$TMPDIR_WORK" 2>/dev/null || true
}
trap cleanup EXIT

# Portable SHA-256 of a file (sha256sum on Linux, shasum -a 256 on macOS/BSD).
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "neither sha256sum nor shasum is installed"
    fi
}

# ── Ensure the verify-srs / truncate-srs binaries exist (build once, reuse) ─
VERIFY_BIN="$PROJECT_ROOT/target/release/verify-srs"
TRUNCATE_BIN="$PROJECT_ROOT/target/release/truncate-srs"
build_verify_srs() {
    if [[ -x "$VERIFY_BIN" && -x "$TRUNCATE_BIN" ]]; then return 0; fi
    say "Building verify-srs + truncate-srs (one-time)…"
    cargo build --release -p zkmist-tools --bin verify-srs --bin truncate-srs \
        || die "failed to build verify-srs/truncate-srs"
}

# ─────────────────────────────────────────────────────────────────────────
# SELF-TEST MODE — prove the plumbing without a real ceremony file
# ─────────────────────────────────────────────────────────────────────────
if [[ "$SELF_TEST" -eq 1 ]]; then
    say "SELF-TEST: generating a small FORGEABLE dev file to exercise the pipeline."
    say "           The output is NOT a real ceremony SRS — do not use on mainnet."
    # k=10 is small enough to generate in seconds; the real run asserts k=23.
    DEV_K=10
    cargo run --release -q -p zkmist-tools --example prime_dev_srs -- "$DEV_K" \
        >/dev/null 2>&1 || die "prime_dev_srs $DEV_K failed"
    DEV_FILE="$HOME/.zkmist/cache/v2_params_k${DEV_K}.bin"
    [[ -f "$DEV_FILE" ]] || die "dev file not found at $DEV_FILE"

    build_verify_srs
    # Simulate TWO independent downloads by copying the dev file to two temps.
    T1="$TMPDIR_WORK/source_a.bin"; T2="$TMPDIR_WORK/source_b.bin"
    cp "$DEV_FILE" "$T1"; cp "$DEV_FILE" "$T2"; TEMPS+=("$T1" "$T2")
    say "Running verify-srs --expect-k $DEV_K on both (cross-check)…"
    "$VERIFY_BIN" "$T1" "$T2" --expect-k "$DEV_K" || die "self-test verification failed"
    # Exercise the truncation path too: truncate the k=10 dev file to k=8 and
    # confirm truncate-srs produces a valid k=8 file (independent of a real SRS).
    T3="$TMPDIR_WORK/truncated_k8.bin"; TEMPS+=("$T3")
    "$TRUNCATE_BIN" --input "$DEV_FILE" --output "$T3" --target-k 8 >/dev/null 2>&1 \
        || die "truncate-srs self-test failed"
    "$VERIFY_BIN" "$T3" --expect-k 8 >/dev/null 2>&1 \
        || die "truncated k=8 file rejected by verify-srs"
    say "✅ truncate-srs self-test: k=10 → k=8 produced a valid halo2 params file."
    say "✅ SELF-TEST PASSED — fetch/verify/cross-check plumbing works."
    say "   Now run for real with --url <publisher> --sha256 <digest> --out <path>."
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────
# TRUNCATE-FROM MODE — downsize a larger-k SRS to EXPECT_K
# ─────────────────────────────────────────────────────────────────────────
# Unlocks the common case: a reputable publisher serves a k>EXPECT_K file
# (e.g. k=24/25) but not exactly EXPECT_K. truncate-srs uses halo2's OWN
# audited Params::downsize to drop the high-degree powers — same trapdoor τ,
# same ceremony security, just fewer points. See the header of
# tools/src/truncate_srs.rs for the soundness argument.
# ─────────────────────────────────────────────────────────────────────────
if [[ -n "$TRUNCATE_INPUT" ]]; then
    [[ -n "$OUT" ]] || die "--out <path> is required with --truncate-from"
    [[ -f "$TRUNCATE_INPUT" ]] || die "--truncate-from file not found: $TRUNCATE_INPUT"
    build_verify_srs
    say "Verifying INPUT (the larger-k source) parses as a halo2 params file…"
    # verify-srs always defaults to expecting k=23, so a larger-k input will exit
    # nonzero on the k-check — that is EXPECTED here. We only care that it PARSED
    # (no "not a valid halo2 KZG params file" line). truncate-srs re-parses and
    # aborts on a bad input regardless, so this is belt-and-suspenders.
    INPUT_VK_OUT="$("$VERIFY_BIN" "$TRUNCATE_INPUT" 2>&1 || true)"
    if echo "$INPUT_VK_OUT" | grep -q "not a valid halo2 KZG params file"; then
        die "verify-srs could not parse the input as a halo2 params file: $TRUNCATE_INPUT"
    fi
    INPUT_K="$(echo "$INPUT_VK_OUT" | grep -oE 'k:\s+[0-9]+' | head -1 | grep -oE '[0-9]+')"
    say "   input parsed OK (k=$INPUT_K); truncating to k=$EXPECT_K"
    say "Truncating $TRUNCATE_INPUT → k=$EXPECT_K (halo2 Params::downsize; recomputes g_lagrange)…"
    "$TRUNCATE_BIN" --input "$TRUNCATE_INPUT" --output "$OUT" --target-k "$EXPECT_K" \
        || die "truncate-srs failed"
    say "Verifying the truncated output at k=$EXPECT_K…"
    "$VERIFY_BIN" "$OUT" --expect-k "$EXPECT_K" \
        || die "verify-srs rejected the truncated output. Do NOT pin."
    say "✅ Truncated + verified → $OUT (k=$EXPECT_K)"
    say "   Next: publish, set KZG_SRS_URL/KZG_SRS_SHA256 (snippet above), run readiness."
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────
# REAL FETCH MODE
# ─────────────────────────────────────────────────────────────────────────
[[ ${#URLS[@]} -gt 0 ]] || die "no --url given. Either --url <publisher>, --truncate-from <larger-k file>, or --self-test (try --help)."
[[ -n "$OUT" ]]         || die "--out <path> is required"
command -v curl >/dev/null || die "curl is required"

build_verify_srs

say "Fetching ${#URLS[@]} source(s); asserting k=$EXPECT_K and (if given) SHA-256=$SHA256"
DOWNLOADS=()
for url in "${URLS[@]}"; do
    fname="$(basename "$url" | tr -c 'A-Za-z0-9._-' '_')"
    tmp="$TMPDIR_WORK/$fname"
    say "  ↓ $url"
    curl -fL --retry 3 --connect-timeout 30 -o "$tmp" "$url" \
        || die "download failed: $url"
    TEMPS+=("$tmp"); DOWNLOADS+=("$tmp")
    actual="$(sha256_file "$tmp")"
    [[ ${#actual} -eq 64 ]] \
        || die "downloaded file from $url produced a malformed digest (len=${#actual}, expected 64 hex chars)"
    say "    sha256=$actual"
    if [[ -n "$SHA256" ]]; then
        [[ "$actual" == "$SHA256" ]] \
            || die "SHA-256 mismatch for $url
       expected (pinned): $SHA256
       got:               $actual
       REFUSING to proceed — the file is not what you pinned. Do not lower this check."
    fi
done

# ── Rigorous verification + (if 2+) byte-identity cross-check ───────────
say "Running verify-srs (parse via ParamsKZG::read, k=$EXPECT_K, G1 count, cross-check)…"
"$VERIFY_BIN" "${DOWNLOADS[@]}" --expect-k "$EXPECT_K" \
    || die "verify-srs rejected the file(s). Do NOT pin."

# ── Install the verified file ───────────────────────────────────────────
mkdir -p "$(dirname "$OUT")"
cp "${DOWNLOADS[0]}" "$OUT"
say "✅ Installed verified SRS → $OUT"
say "   Next: publish $OUT at a stable URL, set KZG_SRS_URL/KZG_SRS_SHA256"
say "   in cli/src/constants.rs (snippet printed by verify-srs above), then:"
say "     cargo run -p zkmist-tools --bin readiness   # [1d/8] → ✅"
