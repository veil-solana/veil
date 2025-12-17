"""Type definitions for Veil"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class TransactionStatus(Enum):
    """Transaction status"""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"


@dataclass
class ShieldRequest:
    """Request to shield assets"""

    amount: int
    token: str
    owner_secret: str

    def validate(self) -> None:
        """Validate shield request"""
        if self.amount <= 0:
            raise ValueError("Amount must be positive")
        if len(self.owner_secret) < 32:
            raise ValueError("Secret must be at least 32 characters")


@dataclass
class TransferRequest:
    """Request for private transfer"""

    recipient: str
    amount: int
    sender_secret: str
    sender_commitment: str

    def validate(self) -> None:
        """Validate transfer request"""
        if self.amount <= 0:
            raise ValueError("Amount must be positive")
        if len(self.sender_secret) < 32:
            raise ValueError("Secret must be at least 32 characters")


@dataclass
class UnshieldRequest:
    """Request to unshield assets"""

    amount: int
    destination: str
    owner_secret: str
    commitment: str

    def validate(self) -> None:
        """Validate unshield request"""
        if self.amount <= 0:
            raise ValueError("Amount must be positive")


@dataclass
class CommitmentData:
    """Commitment data structure"""

    commitment: bytes
    amount: int
    blinding_factor: Optional[bytes] = None

    def to_hex(self) -> str:
        """Convert commitment to hex string"""
        return self.commitment.hex()

    @classmethod
    def from_hex(cls, hex_str: str, amount: int) -> "CommitmentData":
        """Create from hex string"""
        return cls(commitment=bytes.fromhex(hex_str), amount=amount)


@dataclass
class PrivateTransaction:
    """Private transaction result"""

    signature: str
    status: TransactionStatus
    commitment: Optional[str] = None
    nullifier: Optional[str] = None
    proof: Optional[bytes] = None
    secret: Optional[str] = None  # Secret used for shield commitment
    recipient_secret: Optional[str] = None  # Secret for recipient (transfer)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "signature": self.signature,
            "status": self.status.value,
            "commitment": self.commitment,
            "nullifier": self.nullifier,
            "proof": self.proof.hex() if self.proof else None,
        }
        # Only include secrets in dict if present (security: usually shouldn't serialize)
        if self.secret:
            result["secret"] = self.secret
        if self.recipient_secret:
            result["recipient_secret"] = self.recipient_secret
        return result
