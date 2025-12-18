# Changelog

All notable changes to Veil will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-12-19

### Added

- **Full SPL Token Support** - Seamlessly shield, transfer, and unshield any SPL token
  - Automatic Associated Token Account (ATA) creation for users and pool vaults
  - Same intuitive API as SOL - just pass the token mint address
  - No manual token account setup required
  - Support for USDC, USDT, and any SPL token standard
- **Asset Registry** module for managing multi-asset privacy pools
  - Deterministic asset ID generation from mint addresses
  - Common token symbol shortcuts (USDC, USDT)
- **Token Utilities** module with ATA management helpers
- **SPL Token Example Script** (`examples/spl_privacy.py`)
- **Integration Tests** for SPL token privacy operations

### Changed

- Updated `SolanaClient.submit_shield_transaction()` to automatically handle SPL tokens
- Updated `SolanaClient.submit_unshield_transaction()` with optional `token` parameter
- Updated `PrivacyClient.unshield_assets_async()` to support SPL token parameter
- Enhanced README with SPL token examples and usage

### Removed

- `NotImplementedError` for SPL token shielding (now fully supported!)

### Technical Details

**New Files:**
- `src/veil/token_utils.py` - Token account management utilities
- `src/veil/assets.py` - Asset registry and ID management
- `examples/spl_privacy.py` - Complete SPL token privacy demo
- `tests/integration/test_spl_tokens.py` - SPL token test suite

**Modified Files:**
- `src/veil/solana_client.py` - SPL token integration with automatic ATA creation
- `src/veil/client.py` - Token parameter support in unshield operations
- `README.md` - SPL token examples and documentation

---

## [0.1.0] - 2025-12-16

**Veil's first release** - A privacy SDK for Solana with zkSNARK-powered transactions.

Package name: `veil-solana` (import as `veil`)

### Core Features

- **Python-first SDK** with intuitive API for privacy operations
- **Groth16 zkSNARK** proof system (~7,000 constraints)
- **Shield, Transfer, Unshield** operations for private transactions
- **Rust cryptographic backend** for high-performance proof generation
- **Solana on-chain program** for privacy pool management
- **Poseidon hash** function and Pedersen commitments
- **Merkle tree** for commitment tracking (depth 20, ~1M leaves)
- **Professional folder structure** following industry best practices

### Security Features

- Random blinding factors for privacy
- Unlinkable nullifiers
- Root history for front-running protection
- Nullifier-based double-spend prevention

### Documentation

- Comprehensive README with examples
- API reference and architecture documentation
- Security documentation and threat model
- Publishing guide for PyPI

### Coming Soon

- Relayer support (v0.2.0) for enhanced IP privacy

---

**Note**: This is the initial production-ready release of Veil privacy SDK.

For security issues, please email: security@veil.network

See [SECURITY.md](SECURITY.md) for full security documentation.
