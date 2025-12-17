"""
Veil - Privacy SDK infrastructure for Solana

Privacy-preserving transactions using zkSNARK proofs.
Python interface with Rust cryptographic backbone.
"""

__version__ = "0.1.0"

# Import Rust core
try:
    from . import _rust_core

    RUST_AVAILABLE = True
except ImportError as e:
    import warnings

    warnings.warn(
        f"Rust core module not available: {e}. "
        "Install with: pip install veil"
    )
    RUST_AVAILABLE = False
    _rust_core = None  # type: ignore

# Export main API
from .client import PrivacyClient
from .types import (
    CommitmentData,
    PrivateTransaction,
    ShieldRequest,
    TransactionStatus,
    TransferRequest,
    UnshieldRequest,
)
from .utils import commitment_to_hex, generate_secret

__all__ = [
    # Main client
    "PrivacyClient",
    # Types
    "ShieldRequest",
    "TransferRequest",
    "UnshieldRequest",
    "PrivateTransaction",
    "CommitmentData",
    "TransactionStatus",
    # Utilities
    "generate_secret",
    "commitment_to_hex",
    # Module info
    "__version__",
    "RUST_AVAILABLE",
]
