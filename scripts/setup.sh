#!/bin/bash
# Setup development environment for Nyx Protocol

set -e

echo "Setting up Nyx Protocol development environment..."

# Check prerequisites
echo ""
echo "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not installed."
    echo "Please install Python 3.12 or later."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  Python: $PYTHON_VERSION"

if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust is required but not installed."
    echo "Please install Rust from https://rustup.rs"
    exit 1
fi

RUST_VERSION=$(rustc --version | cut -d' ' -f2)
echo "  Rust: $RUST_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source .venv/bin/activate

# Install maturin
echo ""
echo "Installing maturin..."
pip install --upgrade pip
pip install maturin

# Build Rust components
echo ""
echo "Building Rust components..."
maturin develop --release

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -e ".[dev]"

# Run tests to verify installation
echo ""
echo "Running tests to verify installation..."
python -m pytest tests/ -v --tb=short

echo ""
echo "============================================"
echo "Setup complete!"
echo "============================================"
echo ""
echo "To activate the environment, run:"
echo "  source .venv/bin/activate"
echo ""
echo "To run tests:"
echo "  pytest tests/"
echo ""
echo "To try the examples:"
echo "  python examples/basic_usage.py"
echo ""
