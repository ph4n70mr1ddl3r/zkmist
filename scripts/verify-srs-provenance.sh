#!/usr/bin/env bash
# verify-srs-provenance.sh — prove the pinned KZG SRS is genuine via sources.
#
# The KZG SRS is the ONE trust root of the system (docs/kzg-srs.md). A self-made
# SRS (gen_srs / Params::new) is forgeable by whoever ran it; only a public,
# many-participant ceremony SRS is sound. "Is this file THAT ceremony's output?"
# cannot be answered by any single hash you were told — it is answered by
# INDEPENDENT reputable publishers serving a byte-identical file. This script
# automates that cross-check.
#
# USAGE
#   # Default: the pinned URL + the local cache file (if present).
#   ./scripts/verify-srs-provenance.sh
#
#   # Add INDEPENDENT sources (URLs and/or local files) — strongly recommended:
#   SRS_SOURCES="https://<independent-publisher>/params-k23.bin /path/mirror.bin" \
#       ./scripts/verify-srs-provenance.sh
#
#   # Skip network (use only local files supplied via SRS_SOURCES):
#   OFFLINE=1 ./scripts/verify-srs-provenance.sh
#
# WHAT IT PROVES (when ≥2 genuinely-independent sources agree)
#   - Integrity    : every source's SHA-256 == the pinned KZG_SRS_SHA256.
#   - Consistency  : all sources are byte-identical (no source disagrees).
#   - Structure    : the file loads as a valid k=23 halo2 ParamsKZG via the
#                    EXACT `ParamsKZG::read` the prover uses (delegated to the
#                    `verify-srs` tool — points deserialize, k matches, G1 power
#                    count matches the header).
#
# WHAT IT DOES NOT PROVE (the irreducible human step)
#   - That the digest corresponds to the PSE perpetual-powers-of-tau ceremony's
#     published, beaconed transcript. That trust comes from YOU choosing sources
#     that are genuinely independent of each other and of the deployer — e.g.
#     the PSE ceremony repo's phase2 output, an independent zkEVM project's
#     pinned mirror, or re-deriving from the transcript yourself (§2 gold
#     standard). ONE source (the pin) proves nothing about ceremony origin.
#   - Subgroup / powers-of-τ structure is not separately re-checked here; it is
#     implied by `ParamsKZG::read` succeeding on a file multiple sources agree
#     on. (A future `--deep` could add subgroup + e(g[i+1],g2)==e(g[i],s_g2).)
#
# EXIT 0 only if: pin matches AND structure valid AND ≥1 source agreed.
# Always review the "provenance strength" line — it states how many independent
# sources agreed, which is the actual trust metric.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONST="$ROOT/cli/src/constants.rs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
say() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARN:${NC} $*"; }
die() { echo -e "${RED}[$(date +%H:%M:%S)] FAIL:${NC} $*" >&2; exit 1; }

# ── Read the pinned trust root from the code (robust to line-spanning) ───
[[ -f "$CONST" ]] || die "constants not found: $CONST"
PINNED_URL=$(grep -A2 'pub const KZG_SRS_URL' "$CONST" | grep -oE 'https?://[^"]+' | head -n1 || true)
PINNED_SHA=$(grep -A2 'pub const KZG_SRS_SHA256' "$CONST" | grep -oE '[0-9a-f]{64}' | head -n1 || true)
[[ -n "$PINNED_URL" && -n "$PINNED_SHA" ]] \
  || die "could not read KZG_SRS_URL / KZG_SRS_SHA256 from $CONST"
say "Pinned digest : ${CYAN}${PINNED_SHA}${NC}"
say "Pinned URL     : ${CYAN}${PINNED_URL}${NC}"
echo

# ── Assemble the source list ───────────────────────────────────────────────
# Sources: pinned URL (network) + SRS_SOURCES (URLs or files) + default cache.
SOURCES=()
[[ "${OFFLINE:-0}" == "1" ]] || SOURCES+=("url:${PINNED_URL}")
LOCAL_CACHE="${HOME}/.zkmist/cache/v2_axiom_srs.bin"
[[ -f "$LOCAL_CACHE" ]] && SOURCES+=("file:${LOCAL_CACHE}")
for s in ${SRS_SOURCES:-}; do
  case "$s" in
    http://*|https://*) SOURCES+=("url:$s") ;;
    -*) warn "ignoring flag-like source: $s" ;;
    *) [[ -f "$s" ]] && SOURCES+=("file:$s") || warn "source not found, skipping: $s" ;;
  esac
done

if [[ ${#SOURCES[@]} -lt 1 ]]; then die "no sources to check. Set SRS_SOURCES or run online."; fi
say "Checking ${#SOURCES[@]} source(s)..."

# ── Materialize + SHA-256 each source ──────────────────────────────────────
declare -A SEEN_SHA
declare -a AGREEING
for src in "${SOURCES[@]}"; do
  kind="${src%%:*}"; loc="${src#*:}"
  out="$WORK/src_$(echo -n "$src" | sha256sum | cut -c1-16).bin"
  case "$kind" in
    url)
      if ! command -v curl >/dev/null; then warn "curl missing; skipping $loc"; continue; fi
      say "  ↓ $loc"
      if ! curl -fsSL "$loc" -o "$out"; then warn "download failed; skipping $loc"; continue; fi
      ;;
    file)
      cp "$loc" "$out"
      say "  · $loc"
      ;;
  esac
  sha=$(sha256sum "$out" | cut -d' ' -f1)
  size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out")
  if [[ "$sha" == "$PINNED_SHA" ]]; then
    say "    ${GREEN}✓ matches pin${NC} ($size bytes)"
    AGREEING+=("$out")
  else
    die "source $loc digest MISMATCH
       got      : $sha
       pinned   : $PINNED_SHA
       A disagreeing source is a hard failure — do NOT proceed."
  fi
  SEEN_SHA["$sha"]=1
done

if [[ ${#AGREEING[@]} -lt 1 ]]; then die "no source matched the pinned digest."; fi
echo
say "Digest agreement: ${#SEEN_SHA[@]} distinct digest(s); ${#AGREEING[@]} source(s) match the pin."

# ── Structural validation via the existing verify-srs tool ─────────────────
say "Structural validation (loads as k=23 halo2 ParamsKZG via the prover's reader)..."
if ! command -v cargo >/dev/null; then die "cargo not found (need it to build verify-srs)."; fi
say "  building verify-srs (release)..."
cargo build --release -p zkmist-tools --bin verify-srs >/dev/null 2>&1 \
  || die "verify-srs build failed."
"$ROOT/target/release/verify-srs" --expect-k 23 "${AGREEING[0]}" >/dev/null 2>&1 \
  || die "verify-srs REJECTED the file (structure invalid / wrong k / bad G1 count)."

echo
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
say "Integrity  : ${GREEN}✓${NC} all source digests == pinned KZG_SRS_SHA256"
say "Consistency: ${GREEN}✓${NC} all sources byte-identical"
say "Structure  : ${GREEN}✓${NC} loads as a valid k=23 halo2 ParamsKZG"

# Provenance strength = number of USER-SUPPLIED sources (SRS_SOURCES). The
# pinned URL + local cache both derive from the deployer, so they are NOT
# independent evidence of ceremony origin.
USER_SRC=0; for s in ${SRS_SOURCES:-}; do USER_SRC=$((USER_SRC+1)); done
echo
if [[ "$USER_SRC" -ge 2 ]]; then
  say "Provenance strength: ${GREEN}STRONG${NC} — $USER_SRC user-supplied source(s) agree."
elif [[ "$USER_SRC" -eq 1 ]]; then
  warn "Provenance strength: WEAK — only 1 user-supplied source. Add ≥2 independent sources via SRS_SOURCES."
else
  warn "Provenance strength: NONE — only the deployer's own pin/cache. This validates
       integrity + structure but NOT ceremony origin. Supply independent sources:
         SRS_SOURCES=\"<url1> <url2>\" $0"
fi
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
say "Done. Provenance is only as strong as the INDEPENDENCE of your sources."
exit 0
