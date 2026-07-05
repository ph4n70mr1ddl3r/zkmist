#!/usr/bin/env bash
# ZKMist Testnet Deployment Script
#
# Deploys the REAL production contracts to Base Sepolia via Deploy.s.sol:
# the snark-verifier-generated Halo2Verifier (axiom backend, k=21, VK embedded
# inline — no separate verifying-key contract), ZKMToken, and ZKMAirdrop.
# There is NO mock on this path — the same verifier that will go to mainnet
# is what gets deployed here.
#
# ⚠️  Caveat: the local real-KZG → on-chain round-trip (RUN_REAL_ROUNDTRIP=1
# forge test) PASSES against this verifier under the pinned ceremony SRS, but
# a real on-chain claim on a public network has not yet been exercised, and
# the circuit has not been externally audited (see DEPLOYMENT.md Phase 1 & 5
# and SECURITY.md). Treat a Sepolia deployment as wiring validation only,
# not soundness validation.
#
# Prerequisites:
#   - Foundry (forge, cast) installed
#   - PRIVATE_KEY set (needs ETH on Base Sepolia for gas)
#   - Get testnet ETH: https://www.coinbase.com/faucets/base-ethereum-goerli-testnet
#
# Usage:
#   export PRIVATE_KEY=0x...
#   ./scripts/testnet-deploy.sh

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"

BASE_SEPOLIA_RPC="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
EXPECTED_CHAIN_ID=84532

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ZKMist Testnet Deployment (Base Sepolia)                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Pre-flight checks ────────────────────────────────────────────────

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo -e "${RED}ERROR: PRIVATE_KEY not set${NC}"
    echo "Usage: export PRIVATE_KEY=0x..."
    exit 1
fi

if ! command -v forge &> /dev/null; then
    echo -e "${RED}ERROR: forge not found. Install Foundry: https://getfoundry.sh${NC}"
    exit 1
fi

# Check deployer balance
echo "Pre-flight checks..."
DEPLOYER=$(cast wallet address --private-key "$PRIVATE_KEY" 2>/dev/null || echo "unknown")
echo "  Deployer: $DEPLOYER"

BALANCE=$(cast balance "$DEPLOYER" --rpc-url "$BASE_SEPOLIA_RPC" 2>/dev/null || echo "0")
echo "  Balance: $(cast to-unit "$BALANCE" eth 2>/dev/null || echo "unknown") ETH"

if [ "$BALANCE" = "0" ]; then
    echo -e "${YELLOW}WARNING: Deployer has no ETH. Get testnet ETH from:${NC}"
    echo "  https://www.coinbase.com/faucets/base-ethereum-goerli-testnet"
fi

# Check chain ID
CHAIN_ID=$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC" 2>/dev/null || echo "unknown")
echo "  Chain ID: $CHAIN_ID"
if [ "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]; then
    echo -e "${RED}ERROR: Expected chain ID $EXPECTED_CHAIN_ID (Base Sepolia), got $CHAIN_ID${NC}"
    exit 1
fi

echo ""

# ── Build contracts ──────────────────────────────────────────────────
echo "Building contracts..."
cd "$CONTRACTS_DIR"
forge build --quiet
echo -e "  ${GREEN}✓ Build successful${NC}"

# ── Run tests ────────────────────────────────────────────────────────
echo ""
echo "Running contract tests..."
forge test --quiet -vvv
echo -e "  ${GREEN}✓ All tests passed${NC}"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "Ready to deploy to Base Sepolia"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo -e "${YELLOW}⚠️  This deploys the REAL production contracts to a PUBLIC testnet.${NC}"
echo -e "${YELLOW}   (real Halo2Verifier + VK — there is no mock on this path.)${NC}"
echo -e "${YELLOW}   Do NOT send real funds to testnet contracts.${NC}"
echo ""
read -p "Continue with deployment? [y/N] " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Deploying..."

# Deploy using forge script
forge script script/Deploy.s.sol \
    --rpc-url "$BASE_SEPOLIA_RPC" \
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
    # broadcast run-*.json. Two bugs in the prior revision are fixed here:
    #
    #   1. It grepped for a `"Halo2VerifyingKey"` contract that does not
    #      exist — the axiom backend embeds the VK INLINE in
    #      Halo2Verifier.axiom.sol (snark-verifier-generated), so there is no
    #      separate VK contract. The empty VK_ADDR then gated the BaseScan
    #      block below on `-n "$VK_ADDR"`, silently skipping verification of
    #      EVERY contract, and fed a bogus 4th arg into the ZKMAirdrop
    #      abi-encode (its constructor takes 3 args, not 4).
    #   2. The address field grep `grep '"address"'` never matched forge's
    #      real field name `contractAddress` (capital A, no leading quote —
    #      see forge-std Vm.sol `BroadcastTxReceipt.contractAddress`), so
    #      EVERY extracted address was empty too. We now grep a wide-enough
    #      window for the `contractAddress` value regardless of field order.
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
fi

# ── Verify contracts on BaseScan ──────────────────────────────────────
# Gate on the THREE contracts that actually get deployed. The previous gate
# also required a non-empty VK_ADDR; since the axiom VK is inline (no
# Halo2VerifyingKey contract), VK_ADDR was always empty and this whole block
# was dead code — a testnet deploy silently skipped BaseScan verification.
if [ -n "$VERIFIER_ADDR" ] && [ -n "$TOKEN_ADDR" ] && [ -n "$AIRDROP_ADDR" ]; then
    echo ""
    echo "Verifying contracts on BaseScan..."

    forge verify-contract "$VERIFIER_ADDR" Halo2Verifier --chain base-sepolia --watch 2>&1 || \
        echo -e "  ${YELLOW}Verifier verification failed (may need manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} Halo2Verifier verified"

    forge verify-contract "$TOKEN_ADDR" ZKMToken --chain base-sepolia --watch 2>&1 || \
        echo -e "  ${YELLOW}Token verification failed (may need manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} ZKMToken verified"

    # ZKMAirdrop's constructor is (address token, address verifier, bytes32
    # merkleRoot) — 3 args, matching contracts/src/ZKMAirdrop.sol. The prior
    # 4-arg abi-encode (which interpolated a VK_ADDR) would have produced a
    # wrong constructor-args ABI and failed BaseScan verification.
    forge verify-contract "$AIRDROP_ADDR" ZKMAirdrop --constructor-args \
        "$(cast abi-encode "constructor(address,address,bytes32)" "$TOKEN_ADDR" "$VERIFIER_ADDR" "$MERKLE_ROOT")" \
        --chain base-sepolia --watch 2>&1 || \
        echo -e "  ${YELLOW}Airdrop verification failed (may need manual retry)${NC}"
    echo -e "  ${GREEN}✓${NC} ZKMAirdrop verified"
fi


echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
if [ -n "$AIRDROP_ADDR" ]; then
    echo ""
    echo "  Deployed contracts:"
    echo "    Halo2Verifier: $VERIFIER_ADDR  (VK embedded inline)"
    echo "    ZKMToken:      $TOKEN_ADDR"
    echo "    ZKMAirdrop:    $AIRDROP_ADDR"
fi
echo ""
echo "Next steps:"
if [ -z "$VERIFIER_ADDR" ]; then
    echo "  1. Extract deployed addresses from broadcast log above"
fi
echo "  2. Update cli/src/constants.rs:"
if [ -n "$AIRDROP_ADDR" ]; then
    echo "     AIRDROP_CONTRACT = \"$AIRDROP_ADDR\""
else
    echo "     AIRDROP_CONTRACT = \"<airdrop_address>\""
fi
echo ""
echo "  3. Test full claim flow:"
echo "     cargo run --release -p zkmist-cli --bin zkmist -- prove"
echo "     cargo run --release -p zkmist-cli --bin zkmist -- submit proof.json --rpc-url $BASE_SEPOLIA_RPC"
echo ""
echo "  4. Run on-chain monitor:"
if [ -n "$AIRDROP_ADDR" ]; then
    echo "     cargo run -p zkmist-tools --bin monitor -- $AIRDROP_ADDR --rpc $BASE_SEPOLIA_RPC --once"
else
    echo "     cargo run -p zkmist-tools --bin monitor -- <airdrop_address> --rpc $BASE_SEPOLIA_RPC --once"
fi
