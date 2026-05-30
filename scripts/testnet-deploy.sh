#!/usr/bin/env bash
# ZKMist Testnet Deployment Script
#
# Deploys ZKMist contracts to Base Sepolia for end-to-end testing.
# The Halo2Verifier deployed here uses structural validation only
# (IS_PRODUCTION_VERIFIER = false) — the airdrop constructor is bypassed
# for testnet by deploying with a MockHalo2Verifier pattern.
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
echo -e "${YELLOW}⚠️  This will deploy contracts to a PUBLIC testnet.${NC}"
echo -e "${YELLOW}   These contracts use a MOCK verifier (not production).${NC}"
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

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Verify contracts on BaseScan:"
echo "     forge verify-contract <address> Halo2Verifier --chain base-sepolia"
echo "     forge verify-contract <address> ZKMToken --chain base-sepolia"
echo "     forge verify-contract <address> ZKMAirdrop --chain base-sepolia"
echo ""
echo "  2. Update cli/src/constants.rs:"
echo "     AIRDROP_CONTRACT = \"<airdrop_address>\""
echo ""
echo "  3. Test full claim flow:"
echo "     cargo run --release -p zkmist-cli --bin zkmist -- prove"
echo "     cargo run --release -p zkmist-cli --bin zkmist -- submit proof.json --rpc-url $BASE_SEPOLIA_RPC"
echo ""
echo "  4. Run on-chain monitor:"
echo "     cargo run -p zkmist-tools --bin monitor -- <airdrop_address> --rpc $BASE_SEPOLIA_RPC --once"
