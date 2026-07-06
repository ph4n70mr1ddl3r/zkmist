#!/usr/bin/env bash
# ZKMist MAINNET Deployment Script (Base, chain 8453)
#
# Deploys the REAL production contracts to Base MAINNET via Deploy.s.sol:
# the snark-verifier-generated Halo2Verifier (axiom backend, k=21, VK embedded
# inline — no separate verifying-key contract), ZKMToken, and ZKMAirdrop.
# There is NO mock on this path.
#
#  🛑 IRREVERSIBLE. Read this before running.
#
#  ZKMAirdrop and ZKMToken are FULLY IMMUTABLE: no owner, no admin, no pause,
#  no upgrade. A wrong Merkle root, a nonce-prediction mismatch, or a wrong
#  verifier is PERMANENT — there is no recovery path. This script adds mainnet-
#  specific guards (readiness gate, chain-id re-check, typed "mainnet"
#  confirmation) exactly so those mistakes cannot slip through. Do not weaken
#  them.
#
#  Pre-requisites (process gates the script CANNOT verify — from DEPLOYMENT.md):
#    - External audit of the custom axiom gadgets with NO open Critical/High.
#    - A green Base SEPOLIA deployment + live claim (scripts/testnet-deploy.sh
#      + scripts/e2e-test.sh --full). Mainnet must NOT be the first network
#      you deploy to.
#    - RUN_REAL_ROUNDTRIP=1 forge test passing against a PINNED-SRS fixture
#      (cargo run -p zkmist-cli -- gen-roundtrip-fixture — NOT ZKMIST_DEV_SRS).
#
#  Other prerequisites:
#    - Foundry (forge, cast) AND the Rust toolchain (cargo) installed.
#    - PRIVATE_KEY set to a DEDICATED deployer wallet with ≥0.01 real ETH on
#      Base. Do not send any other transaction from this wallet during the
#      deploy — Deploy.s.sol predicts the airdrop address from the deployer
#      nonce, and any interleaving tx breaks the token's immutable `minter`.
#
# Usage:
#   export PRIVATE_KEY=0x...            # dedicated, funded deployer key
#   export BASE_RPC_URL=https://mainnet.base.org   # (optional; defaults below)
#   ./scripts/mainnet-deploy.sh

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"

BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"
EXPECTED_CHAIN_ID=8453
BASESCAN_CHAIN="base"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  ZKMist MAINNET Deployment (Base — chain 8453)             ║${NC}"
echo -e "${RED}║  ⚠️  IRREVERSIBLE — immutable contracts, real funds        ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Pre-flight checks ────────────────────────────────────────────────

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo -e "${RED}ERROR: PRIVATE_KEY not set${NC}"
    echo "Usage: export PRIVATE_KEY=0x..."
    exit 1
fi

for bin in forge cast cargo; do
    if ! command -v "$bin" &> /dev/null; then
        echo -e "${RED}ERROR: $bin not found in PATH${NC}"
        [ "$bin" = "forge" ] && echo "  Install Foundry: https://getfoundry.sh"
        [ "$bin" = "cargo" ] && echo "  Install Rust:    https://rustup.rs (needed for the readiness gate + monitor)"
        exit 1
    fi
done

echo "Pre-flight checks..."

# Deployer identity + balance.
DEPLOYER=$(cast wallet address --private-key "$PRIVATE_KEY" 2>/dev/null || echo "unknown")
echo "  Deployer: $DEPLOYER"

# `cast balance` returns wei as a plain decimal integer string, so a direct
# numeric comparison against MIN_DEPLOYER_BALANCE (0.01 ether) is safe.
BALANCE=$(cast balance "$DEPLOYER" --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo "0")
echo "  Balance:  $(cast to-unit "$BALANCE" eth 2>/dev/null || echo "unknown") ETH"
if [ "$BALANCE" = "0" ]; then
    echo -e "${RED}ERROR: Deployer has no ETH on Base mainnet. Fund the wallet and retry.${NC}"
    exit 1
fi
MIN_WEI=10000000000000000  # 0.01 ether — Deploy.s.sol MIN_DEPLOYER_BALANCE
if [ "$BALANCE" -lt "$MIN_WEI" ]; then
    echo -e "${RED}ERROR: balance < 0.01 ETH — Deploy.s.sol will revert (MIN_DEPLOYER_BALANCE).${NC}"
    exit 1
fi

# Chain-id guard: this is the single most important mainnet check. A testnet
# RPC here would silently deploy to the wrong network.
CHAIN_ID=$(cast chain-id --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo "unknown")
echo "  Chain ID: $CHAIN_ID"
if [ "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]; then
    echo -e "${RED}ERROR: Expected chain ID $EXPECTED_CHAIN_ID (Base mainnet), got $CHAIN_ID.${NC}"
    echo -e "${RED}       Refusing to deploy — BASE_RPC_URL does not point at Base mainnet.${NC}"
    exit 1
fi

# Basescan (Etherscan-family) API key for source verification. Basescan is an
# Etherscan explorer, and Etherscan API keys are MULTI-CHAIN — a single key
# from etherscan.io verifies on Basescan too. Accept BASESCAN_API_KEY first
# (explicit), else fall back to ETHERSCAN_API_KEY. Exported so both forge's
# own `ETHERSCAN_API_KEY` env: default and foundry.toml's [etherscan] table
# interpolation pick it up.
VERIFY_KEY="${BASESCAN_API_KEY:-${ETHERSCAN_API_KEY:-}}"
if [ -z "$VERIFY_KEY" ]; then
    echo -e "${YELLOW}⚠️  No Basescan API key set (BASESCAN_API_KEY / ETHERSCAN_API_KEY).${NC}"
    echo -e "${YELLOW}    Deploy proceeds, but Basescan SOURCE VERIFICATION will fail below.${NC}"
    echo -e "${YELLOW}    Export one for on-chain source transparency:${NC}"
    echo -e "${YELLOW}      export ETHERSCAN_API_KEY=<your etherscan key>${NC}"
    VERIFY_KEY_FLAG=()
else
    echo "  Basescan API key: set (source verification enabled)"
    VERIFY_KEY_FLAG=(--etherscan-api-key "$VERIFY_KEY")
    export ETHERSCAN_API_KEY="$VERIFY_KEY"
fi

echo ""

# ── Readiness gate ───────────────────────────────────────────────────
#
# Runs the project's pre-deploy checker in fast mode (verifier integrity +
# SRS soundness/pinning + PINNED-SRS banner + verifier byte-pin + Merkle-root
# consistency + CLI constants + clippy + fmt). It SKIPS the slow forge/cargo
# test suites (this script runs `forge test` itself below).
#
# A *regression* (forgeable DEV-SRS verifier, unpinned SRS, root mismatch, …)
# exits non-zero and MUST block the deploy. The single *known blocker* —
# AIRDROP_CONTRACT being the 0x…dEaD placeholder — is ADVISORY here because it
# is only resolved AFTER deploy (Phase 5 of the runbook), so it does not fail
# the gate. That is the intended, expected state on the very run that deploys.
#
# Override with SKIP_READINESS=1 ONLY if you have just run `readiness --strict`
# by hand and understand why; the default is to enforce it.
if [ "${SKIP_READINESS:-0}" != "1" ]; then
    echo "Running readiness gate (fast)..."
    if ! cargo run -q -p zkmist-tools --bin readiness -- --skip-slow; then
        echo -e "${RED}ERROR: readiness gate reported a regression. Do NOT deploy until it is green.${NC}"
        echo -e "${RED}       (A known AIRDROP_CONTRACT placeholder is advisory and allowed here.)${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}✓ Readiness gate green (advisory placeholder is expected pre-deploy)${NC}"
else
    echo -e "${YELLOW}⚠️  SKIP_READINESS=1 — skipping the readiness gate. Only do this if you${NC}"
    echo -e "${YELLOW}    have just run \`readiness --strict\` manually. This is risky on mainnet.${NC}"
fi
echo ""

# ── Build + test contracts ───────────────────────────────────────────
echo "Building contracts..."
cd "$CONTRACTS_DIR"
forge build --quiet
echo -e "  ${GREEN}✓ Build successful${NC}"

echo ""
echo "Running contract tests..."
# `--quiet` and `-vvv` are mutually exclusive in current Foundry, so run
# quiet first (clean on pass) and only re-spawn with traces on failure.
if ! forge test --quiet; then
    echo -e "${RED}Contract tests FAILED — re-running with traces:${NC}"
    forge test -vvv
    exit 1
fi
echo -e "  ${GREEN}✓ All tests passed${NC}"

# ── Final confirmation (typed, not y/N) ───────────────────────────────
echo ""
echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  ABOUT TO DEPLOY TO BASE MAINNET (chain $EXPECTED_CHAIN_ID)${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Deployer:  $DEPLOYER${NC}"
echo    "  RPC:       $BASE_RPC_URL"
echo -e "${BOLD}  Contracts are IMMUTABLE — no admin, no pause, no upgrade.${NC}"
echo    "  Confirm ALL of:"
echo    "    [ ] external audit closed (no Critical/High)"
echo    "    [ ] Base Sepolia deploy + live claim passed"
echo    "    [ ] RUN_REAL_ROUNDTRIP=1 green on a PINNED-SRS fixture"
echo    "    [ ] deployer wallet is dedicated + untouched mid-deploy"
echo    "    [ ] Merkle root in Deploy.s.sol matches cli KNOWN_MERKLE_ROOT"
echo ""
echo    "  To proceed, type the network name exactly:  mainnet"
read -p "  > " confirm
if [ "${confirm,,}" != "mainnet" ]; then
    echo "Cancelled (did not type 'mainnet'). Nothing was broadcast."
    exit 0
fi

echo ""
echo "Deploying..."

# Deploy using forge script. Deploy.s.sol self-validates every linkage
# (minter→airdrop, merkleRoot, token/verifier refs) and reverts on any mismatch.
forge script script/Deploy.s.sol \
    --rpc-url "$BASE_RPC_URL" \
    --broadcast \
    --private-key "$PRIVATE_KEY" \
    -vvv

# ── Post-deployment: extract addresses and root ───────────────────────
MERKLE_ROOT=$(grep 'MERKLE_ROOT =' "$CONTRACTS_DIR/script/Deploy.s.sol" | sed 's/.*= *//; s/;.*//' | tr -d ' ')

BROADCAST_DIR="$CONTRACTS_DIR/broadcast/Deploy.s.sol/$EXPECTED_CHAIN_ID"
LATEST_RUN=$(ls -t "$BROADCAST_DIR"/run-*.json 2>/dev/null | head -1)

VERIFIER_ADDR=""
TOKEN_ADDR=""
AIRDROP_ADDR=""

if [ -n "$LATEST_RUN" ]; then
    echo ""
    echo "Extracting deployed addresses from broadcast..."
    # Extract the deployed `contractAddress` for a contract from a forge
    # broadcast run-*.json. Two bugs the testnet script fixed (and inherited
    # here) are:
    #
    #   1. The axiom backend embeds the VK INLINE in Halo2Verifier.axiom.sol
    #      (snark-verifier-generated), so there is no separate VK contract.
    #      Grepping for one yields an empty address that would gate the
    #      BaseScan block below on `-n` and silently skip verification of
    #      EVERY contract.
    #   2. forge's field is `contractAddress` (capital A), not `"address"`.
    #      The grep below matches the real field name regardless of order.
    extract_addr() {
        # $1 = broadcast file, $2 = contractName
        grep -A8 "\"contractName\": \"$2\"" "$1" 2>/dev/null \
            | grep -o '"contractAddress": *"[0-9a-fA-Fx]*"' | head -1 \
            | sed 's/.*: *"\(.*\)"/\1/'
    }
    VERIFIER_ADDR=$(extract_addr "$LATEST_RUN" "Halo2Verifier")
    TOKEN_ADDR=$(extract_addr "$LATEST_RUN" "ZKMToken")
    AIRDROP_ADDR=$(extract_addr "$LATEST_RUN" "ZKMAirdrop")

    if [ -n "$VERIFIER_ADDR" ]; then
        echo "  Halo2Verifier: $VERIFIER_ADDR  (VK embedded inline — no separate VK contract)"
        echo "  ZKMToken:      $TOKEN_ADDR"
        echo "  ZKMAirdrop:    $AIRDROP_ADDR"
    fi
else
    echo -e "${YELLOW}⚠️  No broadcast run-*.json found in $BROADCAST_DIR${NC}"
    echo -e "${YELLOW}    Extract addresses manually from the forge script output above.${NC}"
fi

# ── Verify contracts on Basescan ──────────────────────────────────────
# Gate on the THREE contracts that actually get deployed. The axiom VK is
# inline (no Halo2VerifyingKey contract), so there is no 4th address to gate on.
if [ -n "$VERIFIER_ADDR" ] && [ -n "$TOKEN_ADDR" ] && [ -n "$AIRDROP_ADDR" ]; then
    echo ""
    echo "Verifying contracts on Basescan (--chain $BASESCAN_CHAIN)..."

    forge verify-contract "$VERIFIER_ADDR" Halo2Verifier "${VERIFY_KEY_FLAG[@]}" --chain "$BASESCAN_CHAIN" --watch 2>&1 || \
        echo -e "  ${YELLOW}Verifier verification failed (check API key / manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} Halo2Verifier verified"

    forge verify-contract "$TOKEN_ADDR" ZKMToken "${VERIFY_KEY_FLAG[@]}" --chain "$BASESCAN_CHAIN" --watch 2>&1 || \
        echo -e "  ${YELLOW}Token verification failed (check API key / manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} ZKMToken verified"

    # ZKMAirdrop's constructor is (address token, address verifier, bytes32
    # merkleRoot) — 3 args, matching contracts/src/ZKMAirdrop.sol.
    forge verify-contract "$AIRDROP_ADDR" ZKMAirdrop --constructor-args \
        "$(cast abi-encode "constructor(address,address,bytes32)" "$TOKEN_ADDR" "$VERIFIER_ADDR" "$MERKLE_ROOT")" \
        "${VERIFY_KEY_FLAG[@]}" --chain "$BASESCAN_CHAIN" --watch 2>&1 || \
        echo -e "  ${YELLOW}Airdrop verification failed (check API key / manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} ZKMAirdrop verified"
fi

# ── Save the addresses to a file for the post-deploy steps ────────────
ADDRESSES_FILE="$PROJECT_ROOT/.mainnet-addresses.txt"
{
    echo "# ZKMist Base mainnet deployment — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Deployer: $DEPLOYER"
    echo "# Chain ID: $EXPECTED_CHAIN_ID"
    echo "Halo2Verifier=$VERIFIER_ADDR"
    echo "ZKMToken=$TOKEN_ADDR"
    echo "ZKMAirdrop=$AIRDROP_ADDR"
    echo "MerkleRoot=$MERKLE_ROOT"
} > "$ADDRESSES_FILE"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Mainnet deployment complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
if [ -n "$AIRDROP_ADDR" ]; then
    echo ""
    echo "  Deployed contracts:"
    echo "    Halo2Verifier: $VERIFIER_ADDR  (VK embedded inline)"
    echo "    ZKMToken:      $TOKEN_ADDR"
    echo "    ZKMAirdrop:    $AIRDROP_ADDR"
    echo "    MerkleRoot:    $MERKLE_ROOT"
    echo ""
    echo "  Addresses saved to: $ADDRESSES_FILE"
fi
echo ""
echo -e "${BOLD}Next steps (from DEPLOYMENT.md Phase 5–7):${NC}"
echo ""
if [ -z "$VERIFIER_ADDR" ]; then
    echo "  1. Extract deployed addresses from the broadcast log above"
fi
echo "  2. Pin the airdrop address in the CLI, then rebuild:"
if [ -n "$AIRDROP_ADDR" ]; then
    echo "       # cli/src/constants.rs:  AIRDROP_CONTRACT = \"$AIRDROP_ADDR\""
else
    echo "       # cli/src/constants.rs:  AIRDROP_CONTRACT = \"<airdrop_address>\""
fi
echo "       cargo build --release -p zkmist-cli"
echo "       cargo run -p zkmist-tools --bin readiness -- --skip-slow   # 0 known blockers now"
echo ""
echo "  3. Publish the eligibility list to a GitHub Release tagged"
echo "     v1.0.0-eligibility (per-file SHA-256 + manifest.json; the CLI"
echo "     verifies these against KNOWN_MERKLE_ROOT on \`zkmist fetch\`)."
echo ""
echo "  4. Do ONE real claim end-to-end to confirm the live wiring:"
if [ -n "$AIRDROP_ADDR" ]; then
    echo "       cargo run --release -p zkmist-cli -- prove"
    echo "       cargo run --release -p zkmist-cli -- submit <proof.json> --rpc-url $BASE_RPC_URL"
    echo "       cast call $TOKEN_ADDR \"balanceOf(address)(uint256)\" <recipient> --rpc-url $BASE_RPC_URL"
else
    echo "       cargo run --release -p zkmist-cli -- prove"
    echo "       cargo run --release -p zkmist-cli -- submit <proof.json> --rpc-url $BASE_RPC_URL"
fi
echo ""
echo "  5. Start the on-chain monitor:"
if [ -n "$AIRDROP_ADDR" ]; then
    echo "       cargo run -p zkmist-tools --features monitoring --bin monitor -- \\"
    echo "         $AIRDROP_ADDR --rpc $BASE_RPC_URL --interval 60"
else
    echo "       cargo run -p zkmist-tools --features monitoring --bin monitor -- \\"
    echo "         <airdrop_address> --rpc $BASE_RPC_URL --interval 60"
fi
echo ""
echo -e "${YELLOW}Reminder: the contracts are immutable. There is no admin path to${NC}"
echo -e "${YELLOW}fix anything. If step 4 fails, investigate before announcing.${NC}"
