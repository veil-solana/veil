#!/bin/bash
# Nyx Protocol Deployment Script
#
# Usage:
#   ./scripts/deploy.sh localnet   # Deploy to local validator
#   ./scripts/deploy.sh devnet     # Deploy to devnet
#   ./scripts/deploy.sh mainnet    # Deploy to mainnet (requires confirmation)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROGRAM_DIR="$PROJECT_ROOT/solana-program"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v solana &> /dev/null; then
        log_error "Solana CLI not found. Install from https://docs.solana.com/cli/install-solana-cli-tools"
        exit 1
    fi

    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Install Rust from https://rustup.rs"
        exit 1
    fi

    log_info "Dependencies OK"
}

# Build the program
build_program() {
    log_info "Building Solana program..."
    cd "$PROJECT_ROOT"

    # Build with Solana BPF target
    cargo build-bpf --manifest-path solana-program/Cargo.toml

    log_info "Build complete"
}

# Deploy to localnet
deploy_localnet() {
    log_info "Deploying to localnet..."

    # Check if local validator is running
    if ! solana cluster-version --url localhost &> /dev/null; then
        log_error "Local validator not running. Start with: solana-test-validator"
        exit 1
    fi

    solana config set --url localhost

    # Airdrop SOL for deployment
    log_info "Requesting airdrop..."
    solana airdrop 10 || log_warn "Airdrop failed (may already have enough SOL)"

    # Deploy
    solana program deploy \
        --program-id "$PROJECT_ROOT/target/deploy/nyx_privacy_program-keypair.json" \
        "$PROJECT_ROOT/target/deploy/nyx_privacy_program.so"

    log_info "Deployed to localnet!"
}

# Deploy to devnet
deploy_devnet() {
    log_info "Deploying to devnet..."

    solana config set --url devnet

    # Check balance
    BALANCE=$(solana balance | awk '{print $1}')
    log_info "Current balance: $BALANCE SOL"

    if (( $(echo "$BALANCE < 2" | bc -l) )); then
        log_info "Requesting airdrop..."
        solana airdrop 2 || log_warn "Airdrop failed"
        sleep 5
    fi

    # Deploy
    solana program deploy \
        --program-id "$PROJECT_ROOT/target/deploy/nyx_privacy_program-keypair.json" \
        "$PROJECT_ROOT/target/deploy/nyx_privacy_program.so"

    log_info "Deployed to devnet!"
    log_info "Program ID: $(solana address -k $PROJECT_ROOT/target/deploy/nyx_privacy_program-keypair.json)"
}

# Deploy to mainnet
deploy_mainnet() {
    log_warn "MAINNET DEPLOYMENT"
    log_warn "This will deploy to Solana mainnet-beta."
    log_warn "Deployment costs approximately 2-5 SOL."
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        log_info "Deployment cancelled"
        exit 0
    fi

    solana config set --url mainnet-beta

    BALANCE=$(solana balance | awk '{print $1}')
    log_info "Current balance: $BALANCE SOL"

    if (( $(echo "$BALANCE < 5" | bc -l) )); then
        log_error "Insufficient balance for mainnet deployment (need ~5 SOL)"
        exit 1
    fi

    # Deploy with confirmation
    solana program deploy \
        --program-id "$PROJECT_ROOT/target/deploy/nyx_privacy_program-keypair.json" \
        "$PROJECT_ROOT/target/deploy/nyx_privacy_program.so" \
        --with-compute-unit-price 1

    log_info "Deployed to mainnet!"
    log_info "Program ID: $(solana address -k $PROJECT_ROOT/target/deploy/nyx_privacy_program-keypair.json)"
}

# Initialize the pool
init_pool() {
    local cluster=$1
    log_info "Initializing privacy pool on $cluster..."

    # This would call the initialize instruction
    # For now, just print instructions
    log_info "To initialize the pool, run:"
    echo "  python -c \"
from nyx_protocol import PrivacyClient
from solders.keypair import Keypair
import asyncio

async def main():
    client = PrivacyClient(rpc_url='$RPC_URL')
    keypair = Keypair()  # Or load your keypair
    tx = await client.initialize_pool_async(keypair)
    print(f'Pool initialized: {tx}')

asyncio.run(main())
\""
}

# Main
main() {
    local cluster=${1:-localnet}

    check_dependencies
    build_program

    case $cluster in
        localnet)
            deploy_localnet
            ;;
        devnet)
            deploy_devnet
            ;;
        mainnet|mainnet-beta)
            deploy_mainnet
            ;;
        *)
            log_error "Unknown cluster: $cluster"
            echo "Usage: $0 [localnet|devnet|mainnet]"
            exit 1
            ;;
    esac

    log_info "Deployment complete!"
}

main "$@"
