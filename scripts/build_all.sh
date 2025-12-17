#!/bin/bash
# Build wheels for distribution

set -e

echo "Building Nyx Protocol wheels..."

# Check for maturin
if ! command -v maturin &> /dev/null; then
    echo "Installing maturin..."
    pip install maturin
fi

# Clean previous builds
echo ""
echo "Cleaning previous builds..."
rm -rf dist/ target/wheels/

# Build wheel for current platform
echo ""
echo "Building wheel for current platform..."
maturin build --release

# Show results
echo ""
echo "============================================"
echo "Build complete!"
echo "============================================"
echo ""
echo "Wheels are in: dist/"
ls -lh dist/

echo ""
echo "To install locally:"
echo "  pip install dist/*.whl"
echo ""
echo "To publish to PyPI:"
echo "  maturin publish"
echo ""
