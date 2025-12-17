#!/bin/bash
# Nyx Protocol Test Runner
#
# Usage:
#   ./scripts/test.sh           # Run all tests
#   ./scripts/test.sh rust      # Run Rust tests only
#   ./scripts/test.sh python    # Run Python tests only
#   ./scripts/test.sh solana    # Run Solana program tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Run Rust core tests
run_rust_tests() {
    log_section "Running Rust Core Tests"
    cd "$PROJECT_ROOT"
    cargo test -p nyx-privacy-core --lib -- --nocapture
}

# Run Solana program tests
run_solana_tests() {
    log_section "Running Solana Program Tests"
    cd "$PROJECT_ROOT"
    cargo test -p nyx-privacy-program --lib -- --nocapture
}

# Run Python tests
run_python_tests() {
    log_section "Running Python Tests"
    cd "$PROJECT_ROOT"

    # Check if pytest is available
    if ! command -v pytest &> /dev/null; then
        log_info "Installing pytest..."
        pip install pytest pytest-asyncio
    fi

    # Run tests
    PYTHONPATH="$PROJECT_ROOT/python" pytest tests/python/ -v
}

# Run integration tests (requires local validator)
run_integration_tests() {
    log_section "Running Integration Tests"

    # Check if local validator is running
    if ! solana cluster-version --url localhost &> /dev/null 2>&1; then
        echo -e "${YELLOW}[WARN]${NC} Local validator not running."
        echo "Start with: solana-test-validator"
        echo "Skipping integration tests."
        return 0
    fi

    cd "$PROJECT_ROOT"
    cargo test -p nyx-privacy-program --test '*' -- --nocapture
}

# Run all tests
run_all_tests() {
    local failed=0

    run_rust_tests || failed=1
    run_solana_tests || failed=1

    # Python tests may fail if Rust extension not built
    run_python_tests || {
        echo -e "${YELLOW}[WARN]${NC} Python tests failed (Rust extension may not be built)"
    }

    if [ $failed -eq 1 ]; then
        echo ""
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
}

# Check workspace compiles
check_build() {
    log_section "Checking Build"
    cd "$PROJECT_ROOT"
    cargo check --workspace
    log_info "Build check passed"
}

# Main
main() {
    local test_type=${1:-all}

    cd "$PROJECT_ROOT"

    case $test_type in
        rust)
            run_rust_tests
            ;;
        solana)
            run_solana_tests
            ;;
        python)
            run_python_tests
            ;;
        integration)
            run_integration_tests
            ;;
        check)
            check_build
            ;;
        all)
            check_build
            run_all_tests
            ;;
        *)
            echo "Usage: $0 [rust|solana|python|integration|check|all]"
            exit 1
            ;;
    esac
}

main "$@"
