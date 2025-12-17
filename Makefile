.PHONY: help build test test-rust test-python clean install-dev publish-test publish format lint version

# Default target
help:
	@echo "Veil SDK - Build and Publishing Commands"
	@echo ""
	@echo "Development:"
	@echo "  make install-dev    - Install package in development mode"
	@echo "  make test          - Run all tests"
	@echo "  make test-rust     - Run Rust tests only"
	@echo "  make test-python   - Run Python tests only"
	@echo "  make format        - Format code (Rust + Python)"
	@echo "  make lint          - Lint code"
	@echo ""
	@echo "Building:"
	@echo "  make build         - Build release wheel"
	@echo "  make build-dev     - Build debug wheel"
	@echo "  make clean         - Clean build artifacts"
	@echo ""
	@echo "Publishing:"
	@echo "  make publish-test  - Publish to TestPyPI"
	@echo "  make publish       - Publish to PyPI (production)"
	@echo "  make version       - Show current version"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci            - Run CI checks (test + lint)"

# Get version from pyproject.toml
VERSION := $(shell grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

version:
	@echo "Current version: $(VERSION)"

# Development installation
install-dev:
	@echo "Installing Veil in development mode..."
	maturin develop --release
	@echo "✓ Development installation complete"

# Build targets
build:
	@echo "Building Veil release wheel..."
	maturin build --release --interpreter python3.10 python3.11 python3.12
	@echo "✓ Wheel built in target/wheels/"

build-dev:
	@echo "Building Veil debug wheel..."
	maturin build
	@echo "✓ Debug wheel built in target/wheels/"

# Testing
test-rust:
	@echo "Running Rust tests..."
	cargo test --workspace --release
	@echo "✓ Rust tests passed"

test-python:
	@echo "Running Python tests..."
	@if [ -d "tests" ]; then \
		uv run python -m pytest tests/ -v; \
	else \
		echo "No Python tests found in tests/ directory"; \
	fi

test: test-rust test-python
	@echo "✓ All tests passed"

# Code quality
format:
	@echo "Formatting Rust code..."
	cargo fmt
	@echo "Formatting Python code..."
	@if command -v black >/dev/null 2>&1; then \
		black src/ tests/ examples/ --exclude src/veil/_rust_core; \
	else \
		echo "Warning: black not installed (pip install black)"; \
	fi
	@echo "✓ Code formatted"

lint:
	@echo "Linting Rust code..."
	cargo clippy --all-targets --all-features -- -D warnings
	@echo "Linting Python code..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check src/ tests/ examples/; \
	else \
		echo "Warning: ruff not installed (pip install ruff)"; \
	fi
	@echo "✓ Linting complete"

# Publishing
publish-test:
	@echo "Publishing to TestPyPI..."
	@echo "Version: $(VERSION)"
	maturin publish --repository testpypi --interpreter python3.10 python3.11 python3.12
	@echo "✓ Published to TestPyPI"
	@echo ""
	@echo "Test installation:"
	@echo "  pip install --index-url https://test.pypi.org/simple/ veil-solana"

publish:
	@echo "=========================================="
	@echo "Publishing Veil v$(VERSION) to PyPI"
	@echo "=========================================="
	@echo ""
	@echo "Pre-flight checklist:"
	@echo "  1. Version updated in pyproject.toml? ($(VERSION))"
	@echo "  2. CHANGELOG.md updated?"
	@echo "  3. All tests passing? (make test)"
	@echo "  4. Git tag created? (git tag -a v$(VERSION) -m 'Release v$(VERSION)')"
	@echo "  5. Tested with TestPyPI? (make publish-test)"
	@echo ""
	@read -p "Continue with publication to PyPI? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Building and publishing..."; \
		maturin publish --interpreter python3.10 python3.11 python3.12; \
		echo ""; \
		echo "✓ Published to PyPI!"; \
		echo ""; \
		echo "Next steps:"; \
		echo "  1. Create GitHub release: https://github.com/veil-solana/veil/releases/new"; \
		echo "  2. Push tags: git push --tags"; \
		echo "  3. Announce release"; \
		echo "  4. Verify: pip install veil-solana"; \
	else \
		echo "Publication cancelled"; \
	fi

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/wheels/
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info
	rm -rf src/veil/*.so
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Clean complete"

# CI target (for GitHub Actions)
ci: test lint
	@echo "✓ CI checks passed"

# Install all development tools
install-tools:
	@echo "Installing development tools..."
	pip install maturin black ruff pytest pytest-asyncio mypy
	rustup component add rustfmt clippy
	@echo "✓ Development tools installed"
