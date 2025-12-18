"""
Main Privacy Client for Veil

Provides high-level API for privacy-preserving transactions on Solana.
"""

import json
import secrets
from typing import Any, Optional

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from . import _rust_core
from .solana_client import SolanaClient
from .types import (
    CommitmentData,
    PrivateTransaction,
    ShieldRequest,
    TransactionStatus,
)
from .utils import hex_to_bytes, validate_solana_address


def generate_mvp_proof(
    nullifier: bytes,
    commitment: bytes,
    root: bytes,
    keypair: Keypair,
) -> bytes:
    """
    Generate MVP proof (Ed25519 signature)

    For MVP, we use signatures instead of zkSNARK proofs.
    This is NOT private - only for testing.

    Args:
        nullifier: Nullifier bytes (32 bytes)
        commitment: New commitment bytes (32 bytes)
        root: Merkle root bytes (32 bytes)
        keypair: Signing keypair

    Returns:
        96-byte proof: signature (64) + pubkey (32)
    """
    import hashlib

    # Build message to sign: keccak256(nullifier || commitment || root)
    message = nullifier + commitment + root
    message_hash = hashlib.sha3_256(message).digest()

    # Sign with Ed25519
    signature = keypair.sign_message(message_hash)

    # Return signature + pubkey
    return bytes(signature) + bytes(keypair.pubkey())


class PrivacyClient:
    """
    Main client for privacy-preserving transactions on Solana

    Example:
        ```python
        client = PrivacyClient(rpc_url="https://api.devnet.solana.com")

        # Shield assets (async)
        tx = await client.shield_assets_async(
            amount=1000000,  # 0.001 SOL in lamports
            token="SOL",
            keypair=my_keypair
        )

        # Private transfer
        tx = await client.private_transfer_async(
            recipient="recipient_address",
            amount=500000,
            sender_keypair=my_keypair,
            sender_secret="my_secret"
        )
        ```
    """

    def __init__(
        self,
        rpc_url: str = "https://api.devnet.solana.com",
        program_id: Optional[str] = None,
    ):
        """
        Initialize Privacy Client

        Args:
            rpc_url: Solana RPC endpoint
            program_id: Privacy program ID (optional, uses default)
        """
        self.rpc_url = rpc_url
        self.program_id = program_id
        self.solana = SolanaClient(rpc_url, program_id)
        self._rust = _rust_core

    # =========================================================================
    # Async Methods (with blockchain interaction)
    # =========================================================================

    async def initialize_pool_async(self, authority: Keypair) -> str:
        """
        Initialize the privacy pool on-chain

        Args:
            authority: Pool authority keypair

        Returns:
            Transaction signature
        """
        return await self.solana.initialize_pool(authority)

    async def shield_assets_async(
        self,
        amount: int,
        token: str,
        keypair: Keypair,
        secret: Optional[str] = None,
    ) -> PrivateTransaction:
        """
        Shield assets to make them private (submits to blockchain)

        Args:
            amount: Amount to shield (in lamports/smallest unit)
            token: Token address (use "SOL" for native SOL)
            keypair: Payer keypair
            secret: Secret for commitment (generates random if not provided)

        Returns:
            Private transaction with commitment
        """
        # Generate secret if not provided
        if secret is None:
            secret = secrets.token_hex(32)

        # Generate commitment using Rust
        commitment_bytes = self._rust.generate_commitment(
            amount=amount,
            secret=secret.encode(),
        )

        # Submit to blockchain
        signature = await self.solana.submit_shield_transaction(
            commitment=commitment_bytes,
            amount=amount,
            token=token,
            payer_keypair=bytes(keypair),
        )

        return PrivateTransaction(
            signature=signature,
            status=TransactionStatus.CONFIRMED,
            commitment=commitment_bytes.hex(),
            secret=secret,
        )

    async def private_transfer_async(
        self,
        recipient: str,
        amount: int,
        sender_keypair: Keypair,
        sender_secret: str,
        sender_commitment: Optional[str] = None,
    ) -> PrivateTransaction:
        """
        Transfer assets privately (submits to blockchain)

        Args:
            recipient: Recipient's address
            amount: Amount to transfer
            sender_keypair: Sender's keypair for signing
            sender_secret: Sender's secret key (for commitment)
            sender_commitment: Sender's commitment hex (optional)

        Returns:
            Private transaction with nullifier and proof
        """
        if not validate_solana_address(recipient):
            raise ValueError("Invalid Solana address")

        if amount <= 0:
            raise ValueError("Amount must be positive")

        # Generate sender commitment if not provided
        if sender_commitment is None:
            sender_commitment_bytes = self._rust.generate_commitment(
                amount=amount,
                secret=sender_secret.encode(),
            )
            sender_commitment = sender_commitment_bytes.hex()
        else:
            sender_commitment_bytes = hex_to_bytes(sender_commitment)

        # Generate nullifier
        nullifier_bytes = self._rust.generate_nullifier(
            commitment=sender_commitment_bytes,
            secret=sender_secret.encode(),
        )

        # Generate new commitment for recipient
        recipient_secret = secrets.token_hex(32)
        recipient_commitment_bytes = self._rust.generate_commitment(
            amount=amount,
            secret=recipient_secret.encode(),
        )

        # Get current Merkle root
        root = await self.solana.get_merkle_root()

        # Generate MVP proof (signature-based)
        proof = generate_mvp_proof(
            nullifier=nullifier_bytes,
            commitment=recipient_commitment_bytes,
            root=root,
            keypair=sender_keypair,
        )

        # Submit to blockchain
        signature = await self.solana.submit_transfer_transaction(
            nullifier=nullifier_bytes,
            new_commitment=recipient_commitment_bytes,
            proof=proof,
            payer_keypair=bytes(sender_keypair),
        )

        return PrivateTransaction(
            signature=signature,
            status=TransactionStatus.CONFIRMED,
            nullifier=nullifier_bytes.hex(),
            commitment=recipient_commitment_bytes.hex(),
            proof=proof,
            recipient_secret=recipient_secret,
        )

    async def unshield_assets_async(
        self,
        amount: int,
        destination: str,
        owner_keypair: Keypair,
        owner_secret: str,
        commitment: str,
        token: str = "SOL",
    ) -> PrivateTransaction:
        """
        Unshield assets to make them public (submits to blockchain)

        Args:
            amount: Amount to unshield
            destination: Destination public address
            owner_keypair: Owner's keypair for signing
            owner_secret: Owner's secret key
            commitment: Commitment hex to unshield
            token: Token mint address ("SOL" for native SOL)

        Returns:
            Transaction result
        """
        if not validate_solana_address(destination):
            raise ValueError("Invalid destination address")

        commitment_bytes = hex_to_bytes(commitment)

        # Generate nullifier
        nullifier_bytes = self._rust.generate_nullifier(
            commitment=commitment_bytes,
            secret=owner_secret.encode(),
        )

        # Get current Merkle root
        root = await self.solana.get_merkle_root()

        # Generate MVP proof (signature-based)
        # For unshield, we sign: keccak256(nullifier || recipient || amount || root)
        import hashlib
        message = (
            nullifier_bytes
            + bytes(Pubkey.from_string(destination))
            + amount.to_bytes(8, 'little')
            + root
        )
        message_hash = hashlib.sha3_256(message).digest()
        signature_bytes = owner_keypair.sign_message(message_hash)
        proof = bytes(signature_bytes) + bytes(owner_keypair.pubkey())

        # Submit to blockchain
        tx_signature = await self.solana.submit_unshield_transaction(
            nullifier=nullifier_bytes,
            destination=destination,
            amount=amount,
            proof=proof,
            payer_keypair=bytes(owner_keypair),
            token=token,
        )

        return PrivateTransaction(
            signature=tx_signature,
            status=TransactionStatus.CONFIRMED,
            nullifier=nullifier_bytes.hex(),
            proof=proof,
        )

    async def is_nullifier_spent(self, nullifier: bytes) -> bool:
        """Check if a nullifier has been spent on-chain"""
        return await self.solana.is_nullifier_spent(nullifier)

    async def get_merkle_root(self) -> bytes:
        """Get current Merkle root from on-chain state"""
        return await self.solana.get_merkle_root()

    # =========================================================================
    # Sync Methods (offline operations)
    # =========================================================================

    def shield_assets(
        self,
        amount: int,
        token: str,
        owner_secret: str,
    ) -> PrivateTransaction:
        """
        Generate shield commitment (offline, doesn't submit to blockchain)

        Args:
            amount: Amount to shield
            token: Token address
            owner_secret: Owner's secret key

        Returns:
            Private transaction with commitment (not yet on-chain)
        """
        request = ShieldRequest(
            amount=amount,
            token=token,
            owner_secret=owner_secret,
        )
        request.validate()

        commitment_bytes = self._rust.generate_commitment(
            amount=amount,
            secret=owner_secret.encode(),
        )

        commitment_data = CommitmentData(
            commitment=commitment_bytes,
            amount=amount,
        )

        return PrivateTransaction(
            signature="offline_" + secrets.token_hex(16),
            status=TransactionStatus.PENDING,
            commitment=commitment_data.to_hex(),
            secret=owner_secret,
        )

    def private_transfer(
        self,
        recipient: str,
        amount: int,
        sender_secret: str,
        sender_commitment: Optional[str] = None,
    ) -> PrivateTransaction:
        """
        Generate transfer transaction data (offline)

        Args:
            recipient: Recipient's address
            amount: Amount to transfer
            sender_secret: Sender's secret key
            sender_commitment: Sender's commitment

        Returns:
            Private transaction data (not yet on-chain)
        """
        if not validate_solana_address(recipient):
            raise ValueError("Invalid Solana address")

        if amount <= 0:
            raise ValueError("Amount must be positive")

        if sender_commitment is None:
            sender_commitment_bytes = self._rust.generate_commitment(
                amount=amount,
                secret=sender_secret.encode(),
            )
            sender_commitment = sender_commitment_bytes.hex()

        nullifier_bytes = self._rust.generate_nullifier(
            commitment=hex_to_bytes(sender_commitment),
            secret=sender_secret.encode(),
        )

        recipient_commitment_bytes = self._rust.generate_commitment(
            amount=amount,
            secret=recipient.encode(),
        )

        witness = {
            "sender_secret": sender_secret,
            "sender_commitment": sender_commitment,
            "recipient": recipient,
            "amount": amount,
            "nullifier": nullifier_bytes.hex(),
        }

        proof_bytes = self._rust.generate_proof(witness_json=json.dumps(witness))

        return PrivateTransaction(
            signature="offline_" + secrets.token_hex(16),
            status=TransactionStatus.PENDING,
            nullifier=nullifier_bytes.hex(),
            commitment=recipient_commitment_bytes.hex(),
            proof=proof_bytes,
        )

    def unshield_assets(
        self,
        amount: int,
        destination: str,
        owner_secret: str,
        commitment: str,
    ) -> PrivateTransaction:
        """
        Generate unshield transaction data (offline)

        Args:
            amount: Amount to unshield
            destination: Destination address
            owner_secret: Owner's secret key
            commitment: Commitment to unshield

        Returns:
            Private transaction data (not yet on-chain)
        """
        if not validate_solana_address(destination):
            raise ValueError("Invalid destination address")

        nullifier_bytes = self._rust.generate_nullifier(
            commitment=hex_to_bytes(commitment),
            secret=owner_secret.encode(),
        )

        witness = {
            "sender_secret": owner_secret,
            "sender_commitment": commitment,
            "recipient": destination,
            "amount": amount,
            "nullifier": nullifier_bytes.hex(),
        }

        proof_bytes = self._rust.generate_proof(witness_json=json.dumps(witness))

        return PrivateTransaction(
            signature="offline_" + secrets.token_hex(16),
            status=TransactionStatus.PENDING,
            nullifier=nullifier_bytes.hex(),
            proof=proof_bytes,
        )

    def verify_proof(
        self,
        proof: bytes,
        public_inputs: dict[str, Any],
    ) -> bool:
        """
        Verify a zkSNARK proof

        Args:
            proof: Proof bytes
            public_inputs: Public inputs dictionary

        Returns:
            True if proof is valid
        """
        return self._rust.verify_proof(
            proof=proof,
            public_inputs_json=json.dumps(public_inputs),
        )

    async def close(self) -> None:
        """Close RPC connection"""
        await self.solana.close()
