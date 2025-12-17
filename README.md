# Veil

[**veil-sdk.com**](https://veil-sdk.com)

> Privacy SDK infrastructure for Solana - Python interface with Rust cryptographic backbone

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-80%20passing-brightgreen)](.)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/veil-solana.svg)](https://pypi.org/project/veil-solana/)
[![Docs](https://img.shields.io/badge/docs-veil--sdk.com-informational)](https://veil-sdk.com)

Veil provides **production-ready privacy primitives** for Solana applications. Built with a **Python-first API** powered by **high-performance Rust cryptography**, Veil makes zero-knowledge proofs and private transactions accessible to Python developers without sacrificing performance.

Enable **private transactions** on Solana using **Groth16 zkSNARKs**. Shield your assets, transfer privately, and unshield without revealing amounts, senders, or recipients on-chain.

## Features

✨ **Python-First Design**
- Intuitive API for Python developers
- Comprehensive type hints and documentation
- Async/await support for Solana integration
- Zero Rust knowledge required

⚡ **Rust Performance**
- Cryptographic operations run at native speed
- Groth16 zkSNARK proofs on BN254 curve (~7,000 constraints)
- Poseidon hash (zkSNARK-friendly)
- PyO3 bindings for seamless Rust-Python integration

🔐 **Production-Ready Cryptography**
- Circuit-safe nullifier derivation
- Incremental Merkle tree (depth 20, ~1M leaves)
- Random blinding factors for privacy
- 80 passing tests

🛡️ **Complete Privacy**
- Shielded amounts, senders, and recipients
- ECDH note encryption for recipient recovery
- Unlinkable nullifiers prevent tracking
- Root history prevents front-running

🤝 **Relayer Support**
- Submit transactions without revealing IP
- Configurable fee markets (default: 0.3%)
- Multiple relayer selection
- Gas abstraction for users

## Quick Start

### Installation

```bash
# Install from PyPI
pip install veil-solana

# Or install from source
git clone https://github.com/veil-solana/veil
cd veil
pip install -e ".[dev]"
```

### Python Usage

#### 1. Shield Assets (Make Private)

```python
import asyncio
from veil import PrivacyClient, generate_secret
from solders.keypair import Keypair

# Initialize client
client = PrivacyClient(
    rpc_url="https://api.mainnet-beta.solana.com",
    program_id="Vei1111111111111111111111111111111111111111"  # Optional
)

# Generate your keypair (in real usage, load from file/env)
payer = Keypair()  # or Keypair.from_bytes(your_secret_key)

# Generate a secret for your commitment
secret = generate_secret()  # Securely store this!

# Shield assets - deposit into privacy pool (async, submits to blockchain)
async def main():
    tx = await client.shield_assets_async(
        amount=1_000_000_000,  # 1 SOL in lamports
        token="SOL",  # "SOL" for native SOL
        keypair=payer,
        secret=secret  # Optional: auto-generated if None
    )
    print(f"Shielded 1 SOL: {tx.signature}")
    print(f"Commitment: {tx.commitment[:16]}...")
    print(f"Secret (save this!): {tx.secret[:16]}...")

    await client.close()
    return tx

shield_tx = asyncio.run(main())
```

> **Offline mode**: For generating commitments without blockchain submission, use the sync version:
> ```python
> tx = client.shield_assets(amount=1_000_000_000, token="SOL", owner_secret=secret)
> # Returns commitment data without submitting transaction
> ```

**Note:** SPL token shielding currently requires manual token account setup. Use the Solana CLI or a wallet to create associated token accounts before shielding SPL tokens.

#### 2. Private Transfer

```python
# Private transfer to another address
async def main():
    recipient_address = "RecipientPublicKeyHere..."  # Recipient's Solana address

    transfer_tx = await client.private_transfer_async(
        recipient=recipient_address,
        amount=500_000_000,  # 0.5 SOL
        sender_keypair=payer,
        sender_secret=secret,  # Secret from shield operation
        sender_commitment=shield_tx.commitment
    )

    print(f"Private transfer: {transfer_tx.signature}")
    print(f"Nullifier: {transfer_tx.nullifier[:16]}...")
    print(f"New commitment: {transfer_tx.commitment[:16]}...")
    print(f"Recipient secret: {transfer_tx.recipient_secret[:16]}...")

    await client.close()
    return transfer_tx

transfer_tx = asyncio.run(main())
```

What happens in a private transfer:
- **Nullifier** prevents double-spending of your commitment
- **New commitment** is created for the recipient
- **Recipient secret** allows the recipient to spend the funds
- **On-chain**: Only nullifier, new commitment, and zkSNARK proof are visible
- **Private**: Amounts, sender, and recipient remain hidden

> **Offline mode**: `client.private_transfer(recipient, amount, sender_secret, sender_commitment)`

#### 3. Unshield (Make Public)

```python
# Unshield - withdraw to public Solana account
async def main():
    destination = str(payer.pubkey())  # Your public wallet address

    unshield_tx = await client.unshield_assets_async(
        amount=500_000_000,  # 0.5 SOL
        destination=destination,
        owner_keypair=payer,
        owner_secret=secret,
        commitment=shield_tx.commitment
    )

    print(f"Unshielded 0.5 SOL: {unshield_tx.signature}")
    print(f"Nullifier: {unshield_tx.nullifier[:16]}...")

    await client.close()
    return unshield_tx

unshield_tx = asyncio.run(main())
```

> **Offline mode**: `client.unshield_assets(amount, destination, owner_secret, commitment)`

#### 4. Using Relayers (Coming Soon)

The SDK will support anonymous transaction submission via relayers in v0.2.0:
- IP privacy protection through relayer network
- Fee market for relayer selection
- Automatic relayer discovery and failover

This feature is currently in development. Stay tuned for updates!

#### 5. Note Discovery

In v0.1.x, note discovery requires manual tracking of your commitments and secrets. Future versions will include automatic note scanning capabilities.

**For now, store your commitments and secrets securely:**
```python
# After shield: Save the commitment and secret
shield_tx = await client.shield_assets_async(...)
# Store: shield_tx.commitment, shield_tx.secret

# After private_transfer: Save the new commitment and recipient secret
transfer_tx = await client.private_transfer_async(...)
# Store: transfer_tx.commitment, transfer_tx.recipient_secret

# Use these to unshield or transfer again later
unshield_tx = await client.unshield_assets_async(
    commitment=shield_tx.commitment,  # The commitment you want to spend
    owner_secret=shield_tx.secret,     # The secret for that commitment
    ...
)
```

**Note**: Automatic note scanning will be added in a future release.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Python SDK (User-Facing)                  │
│  • Python-first API design                                  │
│  • High-level operations (shield/transfer/unshield)         │
│  • Note management and encryption                           │
│  • Relayer communication                                    │
│  • Async/await support for Solana                           │
└──────────────────────────┬──────────────────────────────────┘
                           │ PyO3 Bindings
┌──────────────────────────▼──────────────────────────────────┐
│                    Rust Core (veil-core)                     │
│                                                              │
│  Cryptography:                                              │
│  • Pedersen commitments (BN254 G1)                         │
│  • Poseidon hash (t=3, RF=8, RP=57)                        │
│  • ECDH note encryption (ChaCha20-Poly1305)                │
│  • Merkle trees (Poseidon-based, depth 20)                 │
│                                                              │
│  zkSNARKs:                                                  │
│  • Groth16 proof generation (arkworks)                     │
│  • Transfer circuit (~7,000 constraints)                    │
│  • R1CS constraint system                                   │
│  • Gadgets: Poseidon, Merkle path verification             │
│                                                              │
│  Utilities:                                                 │
│  • Relayer client (fee estimation, selection)              │
│  • Error handling and validation                            │
│  • Solana VK export (LE ↔ BE conversion)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ Solana RPC
┌──────────────────────────▼──────────────────────────────────┐
│              Solana On-Chain Program (Anchor)                │
│                                                              │
│  • Incremental Merkle tree (on-chain state)                │
│  • Nullifier set (PDA-based double-spend prevention)       │
│  • Root history (30 recent roots for concurrency)          │
│  • Groth16 verification (groth16-solana, ~200k CU)         │
│  • Auto-detection: MVP (96 bytes) vs Groth16 (256 bytes)   │
│  • Relayer fee accounting                                   │
└─────────────────────────────────────────────────────────────┘
```

## How It Works

### Privacy Model

1. **Shield**: Deposit assets + create Pedersen commitment
   - Commitment = `Commit(amount, blinding_factor) = amount*G + blinding*H`
   - Commitment stored in Merkle tree
   - Encrypted note published for recipient

2. **Transfer**: Spend commitment + create new commitment
   - Prove: "I know secret for input commitment in Merkle tree"
   - Nullifier = `Poseidon(SpendingKey, leaf_index)` prevents double-spend
   - New commitment created for recipient
   - zkSNARK proof ensures amount preservation

3. **Unshield**: Spend commitment + withdraw to public account
   - Same proof system as transfer
   - Output goes to specified Solana address

### zkSNARK Circuit

The transfer circuit proves:
```
Public Inputs:  merkle_root, nullifier, new_commitment
Private Inputs: secret, amount, blinding, merkle_path, ...

Constraints:
1. spending_key = Poseidon(secret)
2. input_commitment = Commit(amount, input_blinding)
3. MerkleVerify(merkle_root, input_commitment, merkle_path) = true
4. nullifier = Poseidon(spending_key, leaf_index)
5. new_commitment = Commit(amount, output_blinding)
```

Circuit size: **~7,000 R1CS constraints**

### Security Features

| Feature | Implementation |
|---------|----------------|
| **Double-spend prevention** | Nullifier PDAs (Anchor `init` constraint) |
| **Front-running protection** | 30-root history window |
| **Amount integrity** | zkSNARK proves `input_amount = output_amount` |
| **Membership proof** | Merkle path verification in circuit |
| **Unlinkability** | Poseidon-based nullifiers, random blinding |

## Development

### Prerequisites

- **Rust** 1.70+ (for core cryptography)
- **Python** 3.12+ (for SDK)
- **Solana CLI** 1.18+ (for on-chain program)
- **Anchor** 0.29+ (for Solana development)

### Build from Source

```bash
# Clone repository
git clone https://github.com/veil-solana/veil
cd veil

# Build Rust core
cargo build --release --workspace

# Run Rust tests (80 tests)
cargo test --workspace --release

# Build Python bindings
pip install maturin
maturin develop --release

# Run Python tests
uv run pytest tests/
```

### Project Structure

```
veil/
├── crates/                     # Rust workspace
│   ├── core/                  # Cryptography core (veil-core)
│   │   ├── src/
│   │   │   ├── crypto/       # Commitments, Poseidon, Merkle, encryption
│   │   │   ├── proof/        # Groth16 circuits and proof system
│   │   │   ├── relayer/      # Relayer client infrastructure
│   │   │   └── lib.rs        # PyO3 bindings
│   │   └── Cargo.toml
│   │
│   └── program/               # Solana on-chain program (Anchor)
│       ├── src/
│       │   ├── groth16.rs    # Groth16 verification
│       │   ├── state.rs      # Pool state, Merkle tree
│       │   └── lib.rs        # Instruction handlers
│       └── Cargo.toml
│
├── src/veil/                  # Python SDK (user-facing)
│   ├── __init__.py           # Public API exports
│   ├── client.py             # PrivacyClient class
│   ├── types.py              # Type definitions
│   ├── utils.py              # Utility functions
│   └── solana_client.py      # Solana RPC integration
│
├── tests/                     # Test suite
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── e2e/                  # End-to-end tests
│
├── examples/                  # Usage examples
│   ├── basic_usage.py
│   ├── benchmark.py
│   └── localnet_demo.py
│
├── pyproject.toml            # Python package config
├── Cargo.toml                # Rust workspace config
└── README.md
```

## Testing

```bash
# Run all tests
cargo test --workspace --release

# Run specific test suites
cargo test -p veil-core encryption     # Encryption tests
cargo test -p veil-core transfer_circuit  # Circuit tests
cargo test -p veil-program             # On-chain tests

# Test results: 80 tests passing
# - veil-core: 65 tests
# - veil-program: 15 tests
```

## Roadmap

- [x] Phase 1: Scaffold & stubs
- [x] Phase 2: MVP with signature-based proofs
- [x] Phase 3: Production Groth16 implementation
  - [x] 3A: Cryptographic foundations (Poseidon, random blinding)
  - [x] 3B: Groth16 circuit (7k constraints)
  - [x] 3C: On-chain verification (groth16-solana)
  - [x] 3D: Relayer infrastructure
  - [x] 3E: Note encryption (ECDH)
  - [x] 3F: SDK hardening
  - [x] 3G: Security preparation

### Future Enhancements

- [ ] Relayer support (v0.2.0)
- [ ] Multi-asset support
- [ ] Advanced features (compliance modules, shielded pools)

## Security

### Production-Ready Features

✅ **Mainnet Ready** - Production-grade privacy SDK

- ✅ Circuit implementation complete (~7,000 constraints)
- ✅ 80 tests passing
- ✅ Groth16 zkSNARK proof system
- ✅ Poseidon hash and Pedersen commitments
- ✅ ECDH note encryption

### Reporting Vulnerabilities

For responsible disclosure: `security@veil.network`

See [SECURITY.md](SECURITY.md) for full security documentation.

## Cryptographic Specifications

| Component | Specification |
|-----------|---------------|
| **Curve** | BN254 (alt_bn128) |
| **Proof System** | Groth16 |
| **Hash Function** | Poseidon (t=3, RF=8, RP=57) |
| **Commitment** | Pedersen on G1 |
| **Encryption** | ECDH + ChaCha20-Poly1305 |
| **Merkle Tree** | Poseidon-based, depth 20 |
| **Security Level** | ~128 bits |

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Proof generation | ~5-10s | Client-side (depends on CPU) |
| Proof verification | <1s | On-chain (~200k compute units) |
| Commitment creation | <1ms | Using arkworks |
| Merkle proof | <10ms | Depth 20 tree |
| Note encryption | <1ms | ECDH + ChaCha20 |

## Contributing

We welcome contributions! Areas of interest:

- Circuit optimizations (reduce constraint count)
- Additional asset support
- Relayer implementations
- Documentation improvements
- Security reviews

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with:
- [arkworks](https://github.com/arkworks-rs/algebra) - zkSNARK libraries (Groth16, BN254)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana) - On-chain verification
- [PyO3](https://pyo3.rs) - Rust ↔ Python bindings
- [Anchor](https://www.anchor-lang.com) - Solana framework
- [Solana](https://solana.com) - High-performance blockchain

Special thanks to:
- [Tornado Cash](https://tornado.cash) - Privacy protocol inspiration
- [Zcash](https://z.cash) - zkSNARK research
- [Light Protocol](https://lightprotocol.com) - Solana privacy research

---

**Veil** - Privacy by design 🔒

*"High-performance privacy primitives for Python developers"*
