#!/usr/bin/env bash
#
# ZKMist Deployment Script for Base Mainnet
#
# Deploys 3 contracts in one transaction:
#   1. RiscZeroGroth16Verifier (from risc0-ethereum)
#   2. ZKMToken (minter = predicted airdrop address)
#   3. ZKMAirdrop (references token, verifier, imageId, merkleRoot)
#
# Prerequisites:
#   - Foundry installed (forge, cast)
#   - Deployer private key with ETH on Base for gas (~$0.25)
#
# Usage:
#   export PRIVATE_KEY=0x...
#   ./deploy-base.sh check      # Verify prerequisites
#   ./deploy-base.sh dry-run    # Simulate deployment
#   ./deploy-base.sh deploy     # Deploy for real

set -euo pipefail

BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"

info()  { echo -e "\033[1;36m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }

check_prerequisites() {
    info "Checking prerequisites..."

    command -v forge &>/dev/null || error "forge not found. Install: https://getfoundry.sh"
    command -v cast &>/dev/null  || error "cast not found. Install: https://getfoundry.sh"

    if [ -z "${PRIVATE_KEY:-}" ]; then
        error "PRIVATE_KEY not set.\n  export PRIVATE_KEY=0x...\n\nUse a key with ETH on Base for gas."
    fi

    info "Testing RPC connection to Base..."
    local chain_id
    chain_id=$(cast chain-id --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo "failed")
    if [ "$chain_id" != "8453" ]; then
        error "RPC did not return Base chain ID (8453). Got: $chain_id\n  RPC URL: $BASE_RPC_URL"
    fi
    ok "Connected to Base (chain ID: 8453)"

    local address balance
    address=$(cast wallet address --private-key "$PRIVATE_KEY" 2>/dev/null)
    balance=$(cast balance "$address" --rpc-url "$BASE_RPC_URL" 2>/dev/null)
    local balance_eth
    balance_eth=$(cast from-wei "$balance" 2>/dev/null || echo "0")
    info "Deployer: $address"
    info "Balance:  $balance_eth ETH on Base"

    if [ "$(echo "$balance_eth < 0.001" | bc -l 2>/dev/null || echo 1)" = "1" ]; then
        warn "Low balance on Base. Bridge ETH: https://bridge.base.org"
    fi

    ok "All prerequisites met"
}

show_summary() {
    echo ""
    echo "=================================================="
    echo "  ZKMist Deployment Summary"
    echo "=================================================="
    echo "  Chain:             Base (8453)"
    echo "  RPC:               $BASE_RPC_URL"
    echo ""
    echo "  Contracts to deploy:"
    echo "    1. RiscZeroGroth16Verifier (risc0-ethereum)"
    echo "    2. ZKMToken (minter = predicted airdrop)"
    echo "    3. ZKMAirdrop (immutable, no admin)"
    echo ""
    echo "  Parameters:"
    echo "    Image ID:       0x05ef31c9...23277"
    echo "    Merkle Root:    0x1eafd6f3...97844"
    echo "    Claim Amount:   10,000 ZKM"
    echo "    Max Claims:     1,000,000"
    echo "    Claim Deadline: 2027-01-01 00:00:00 UTC"
    echo "    Max Supply:     10,000,000,000 ZKM"
    echo ""
    echo "  WARNING: CONTRACTS ARE IMMUTABLE AFTER DEPLOYMENT"
    echo "           No admin, no upgrade, no pause."
    echo "=================================================="
    echo ""
}

deploy_dry_run() {
    check_prerequisites
    show_summary

    info "Running DRY RUN (no broadcast)..."
    cd "$(dirname "$0")"

    forge script script/DeployAll.s.sol \
        --rpc-url "$BASE_RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        -vvv
}

deploy_contracts() {
    check_prerequisites
    show_summary

    read -p "  Deploy to Base mainnet? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Deployment cancelled."
        exit 0
    fi

    info "Deploying ZKMist contracts to Base..."
    cd "$(dirname "$0")"

    forge script script/DeployAll.s.sol \
        --rpc-url "$BASE_RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --broadcast \
        -vvv

    info "Deployment broadcast!"
    info "Check broadcast logs above for contract addresses."
    info ""
    info "Next steps:"
    info "  1. Save the deployed addresses"
    info "  2. Update AIRDROP_CONTRACT in cli/src/main.rs"
    info "  3. Verify contracts on BaseScan:"
    info "     forge verify-contract <TOKEN_ADDRESS> ZKMToken --chain 8453 --watch"
    info "     forge verify-contract <AIRDROP_ADDRESS> ZKMAirdrop --chain 8453 --watch --constructor-args '...'"
    info "     forge verify-contract <VERIFIER_ADDRESS> RiscZeroGroth16Verifier --chain 8453 --watch"
}

case "${1:-help}" in
    check)
        check_prerequisites
        show_summary
        ;;
    dry-run)
        deploy_dry_run
        ;;
    deploy)
        deploy_contracts
        ;;
    *)
        echo "Usage: $0 {check|dry-run|deploy}"
        echo ""
        echo "  1. export PRIVATE_KEY=0x..."
        echo "  2. $0 check       (verify prerequisites)"
        echo "  3. $0 dry-run     (simulate deployment)"
        echo "  4. $0 deploy      (deploy for real)"
        ;;
esac
