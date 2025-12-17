# Changelog

All notable changes to Veil will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
