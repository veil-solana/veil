"""
Solana blockchain interaction for Veil privacy SDK

This module provides low-level Solana interaction functionality:
- Transaction building and signing
- Account management
- On-chain program interaction
"""

from typing import Optional, Tuple
import struct

from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.instruction import Instruction, AccountMeta
from solders.transaction import Transaction
from solders.message import Message
from solders.hash import Hash
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from spl.token.constants import TOKEN_PROGRAM_ID

from .token_utils import get_or_create_ata, get_associated_token_address

# Program ID - replace with actual deployed program ID
DEFAULT_PROGRAM_ID = "Nyx1111111111111111111111111111111111111111"

# Seeds for PDAs
POOL_SEED = b"privacy_pool"
VAULT_SEED = b"vault"
NULLIFIER_SEED = b"nullifier"


def find_pool_pda(program_id: Pubkey) -> Tuple[Pubkey, int]:
    """Derive the pool PDA address"""
    return Pubkey.find_program_address([POOL_SEED], program_id)


def find_vault_pda(program_id: Pubkey, pool: Pubkey) -> Tuple[Pubkey, int]:
    """Derive the vault PDA address"""
    return Pubkey.find_program_address([VAULT_SEED, bytes(pool)], program_id)


def find_nullifier_pda(
    program_id: Pubkey, pool: Pubkey, nullifier: bytes
) -> Tuple[Pubkey, int]:
    """Derive the nullifier marker PDA address"""
    return Pubkey.find_program_address(
        [NULLIFIER_SEED, bytes(pool), nullifier], program_id
    )


class InstructionBuilder:
    """Builds Veil privacy pool instructions"""

    # Instruction discriminators (first 8 bytes of sha256 hash of instruction name)
    INITIALIZE_DISC = bytes([175, 175, 109, 31, 13, 152, 155, 237])
    SHIELD_SOL_DISC = bytes([183, 4, 24, 123, 20, 45, 203, 91])
    SHIELD_DISC = bytes([112, 186, 93, 111, 79, 168, 36, 51])
    TRANSFER_DISC = bytes([163, 52, 200, 231, 140, 3, 69, 186])
    UNSHIELD_SOL_DISC = bytes([45, 127, 188, 9, 224, 78, 199, 57])
    UNSHIELD_DISC = bytes([126, 89, 240, 247, 56, 193, 126, 10])

    def __init__(self, program_id: Pubkey):
        """Initialize instruction builder.

        Args:
            program_id: The Veil program public key
        """
        self.program_id = program_id

    def initialize(self, authority: Pubkey) -> Instruction:
        """Build initialize instruction"""
        pool, _pool_bump = find_pool_pda(self.program_id)

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(authority, is_signer=True, is_writable=True),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        return Instruction(self.program_id, self.INITIALIZE_DISC, accounts)

    def shield_sol(
        self,
        depositor: Pubkey,
        commitment: bytes,
        amount: int,
    ) -> Instruction:
        """Build shield SOL instruction"""
        if len(commitment) != 32:
            raise ValueError("Commitment must be 32 bytes")

        pool, _pool_bump = find_pool_pda(self.program_id)
        vault, _vault_bump = find_vault_pda(self.program_id, pool)

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(vault, is_signer=False, is_writable=True),
            AccountMeta(depositor, is_signer=True, is_writable=True),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        # Instruction data: discriminator + commitment (32 bytes) + amount (u64)
        data = self.SHIELD_SOL_DISC + commitment + struct.pack("<Q", amount)

        return Instruction(self.program_id, data, accounts)

    def shield_spl(
        self,
        depositor: Pubkey,
        depositor_token_account: Pubkey,
        vault_token_account: Pubkey,
        commitment: bytes,
        amount: int,
    ) -> Instruction:
        """Build shield SPL token instruction"""
        if len(commitment) != 32:
            raise ValueError("Commitment must be 32 bytes")

        pool, _pool_bump = find_pool_pda(self.program_id)
        vault_authority, _vault_bump = find_vault_pda(self.program_id, pool)

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(vault_authority, is_signer=False, is_writable=False),
            AccountMeta(vault_token_account, is_signer=False, is_writable=True),
            AccountMeta(depositor_token_account, is_signer=False, is_writable=True),
            AccountMeta(depositor, is_signer=True, is_writable=True),
            AccountMeta(TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        # Instruction data: discriminator + commitment (32 bytes) + amount (u64)
        data = self.SHIELD_DISC + commitment + struct.pack("<Q", amount)

        return Instruction(self.program_id, data, accounts)

    def transfer(
        self,
        relayer: Pubkey,
        nullifier: bytes,
        new_commitment: bytes,
        proof: bytes,
    ) -> Instruction:
        """Build private transfer instruction"""
        if len(nullifier) != 32:
            raise ValueError("Nullifier must be 32 bytes")
        if len(new_commitment) != 32:
            raise ValueError("New commitment must be 32 bytes")

        pool, _pool_bump = find_pool_pda(self.program_id)
        nullifier_marker, _null_bump = find_nullifier_pda(
            self.program_id, pool, nullifier
        )

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(nullifier_marker, is_signer=False, is_writable=True),
            AccountMeta(relayer, is_signer=True, is_writable=True),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        # Instruction data: discriminator + nullifier + new_commitment + proof
        # Proof is variable length, preceded by 4-byte length
        data = (
            self.TRANSFER_DISC
            + nullifier
            + new_commitment
            + struct.pack("<I", len(proof))
            + proof
        )

        return Instruction(self.program_id, data, accounts)

    def unshield_sol(
        self,
        relayer: Pubkey,
        recipient: Pubkey,
        nullifier: bytes,
        amount: int,
        proof: bytes,
    ) -> Instruction:
        """Build unshield SOL instruction"""
        if len(nullifier) != 32:
            raise ValueError("Nullifier must be 32 bytes")

        pool, _pool_bump = find_pool_pda(self.program_id)
        vault, _vault_bump = find_vault_pda(self.program_id, pool)
        nullifier_marker, _null_bump = find_nullifier_pda(
            self.program_id, pool, nullifier
        )

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(nullifier_marker, is_signer=False, is_writable=True),
            AccountMeta(vault, is_signer=False, is_writable=True),
            AccountMeta(recipient, is_signer=False, is_writable=True),
            AccountMeta(relayer, is_signer=True, is_writable=True),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        # Instruction data: discriminator + nullifier + amount + proof
        data = (
            self.UNSHIELD_SOL_DISC
            + nullifier
            + struct.pack("<Q", amount)
            + struct.pack("<I", len(proof))
            + proof
        )

        return Instruction(self.program_id, data, accounts)

    def unshield_spl(
        self,
        relayer: Pubkey,
        recipient_token_account: Pubkey,
        vault_token_account: Pubkey,
        nullifier: bytes,
        amount: int,
        proof: bytes,
    ) -> Instruction:
        """Build unshield SPL token instruction"""
        if len(nullifier) != 32:
            raise ValueError("Nullifier must be 32 bytes")

        pool, _pool_bump = find_pool_pda(self.program_id)
        vault_authority, _vault_bump = find_vault_pda(self.program_id, pool)
        nullifier_marker, _null_bump = find_nullifier_pda(
            self.program_id, pool, nullifier
        )

        accounts = [
            AccountMeta(pool, is_signer=False, is_writable=True),
            AccountMeta(nullifier_marker, is_signer=False, is_writable=True),
            AccountMeta(vault_authority, is_signer=False, is_writable=False),
            AccountMeta(vault_token_account, is_signer=False, is_writable=True),
            AccountMeta(recipient_token_account, is_signer=False, is_writable=True),
            AccountMeta(relayer, is_signer=True, is_writable=True),
            AccountMeta(TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ]

        # Instruction data: discriminator + nullifier + amount + proof
        data = (
            self.UNSHIELD_DISC
            + nullifier
            + struct.pack("<Q", amount)
            + struct.pack("<I", len(proof))
            + proof
        )

        return Instruction(self.program_id, data, accounts)


class SolanaClient:
    """
    Low-level Solana client for privacy operations

    Handles direct blockchain interaction including:
    - Submitting transactions
    - Reading account state
    - Interacting with privacy program
    """

    def __init__(
        self,
        rpc_url: str = "https://api.devnet.solana.com",
        program_id: Optional[str] = None,
    ):
        """
        Initialize Solana client

        Args:
            rpc_url: Solana RPC endpoint
            program_id: Privacy program ID
        """
        self.rpc_url = rpc_url
        self.client = AsyncClient(rpc_url)
        self.program_id = Pubkey.from_string(program_id or DEFAULT_PROGRAM_ID)
        self.instruction_builder = InstructionBuilder(self.program_id)
        self.pool_pda, _ = find_pool_pda(self.program_id)

    async def get_recent_blockhash(self) -> Hash:
        """Get recent blockhash for transaction"""
        response = await self.client.get_latest_blockhash(commitment=Confirmed)
        return response.value.blockhash

    async def send_transaction(
        self, instruction: Instruction, payer: Keypair
    ) -> str:
        """Send a single instruction as a transaction"""
        blockhash = await self.get_recent_blockhash()

        message = Message.new_with_blockhash(
            [instruction], payer.pubkey(), blockhash
        )
        tx = Transaction.new_unsigned(message)
        tx.sign([payer], blockhash)

        response = await self.client.send_transaction(tx, commitment=Confirmed)
        return str(response.value)

    async def get_pool_state(self) -> Optional[dict]:
        """
        Get privacy pool state from blockchain

        Returns:
            Pool state dict if exists, None otherwise
        """
        response = await self.client.get_account_info(
            self.pool_pda, commitment=Confirmed
        )
        if response.value is None:
            return None

        data = bytes(response.value.data)
        if len(data) < 8:  # Account discriminator
            return None

        # Skip 8-byte discriminator
        data = data[8:]

        # Parse pool state (simplified)
        return {
            "authority": Pubkey.from_bytes(data[0:32]),
            "merkle_root": data[32 + 8 + 680 : 32 + 8 + 680 + 32],  # After tree
            "nullifier_count": struct.unpack("<Q", data[-9:-1])[0],
        }

    async def get_merkle_root(self) -> bytes:
        """
        Get current Merkle root from on-chain state

        Returns:
            Merkle root bytes (32 bytes)
        """
        state = await self.get_pool_state()
        if state is None:
            return bytes(32)
        return state.get("merkle_root", bytes(32))

    async def is_nullifier_spent(self, nullifier: bytes) -> bool:
        """
        Check if nullifier has been spent

        Args:
            nullifier: Nullifier bytes (32 bytes)

        Returns:
            True if spent (PDA exists)
        """
        nullifier_pda, _ = find_nullifier_pda(
            self.program_id, self.pool_pda, nullifier
        )
        response = await self.client.get_account_info(
            nullifier_pda, commitment=Confirmed
        )
        return response.value is not None

    async def initialize_pool(self, authority: Keypair) -> str:
        """
        Initialize the privacy pool

        Args:
            authority: Pool authority keypair

        Returns:
            Transaction signature
        """
        instruction = self.instruction_builder.initialize(authority.pubkey())
        return await self.send_transaction(instruction, authority)

    async def submit_shield_transaction(
        self,
        commitment: bytes,
        amount: int,
        token: str,
        payer_keypair: bytes,
    ) -> str:
        """
        Submit shield transaction to blockchain

        Args:
            commitment: Generated commitment (32 bytes)
            amount: Amount to shield (lamports or token units)
            token: Token mint address ("SOL" for native SOL)
            payer_keypair: Payer's keypair bytes (64 bytes)

        Returns:
            Transaction signature
        """
        payer = Keypair.from_bytes(payer_keypair)

        if token.upper() == "SOL":
            # Native SOL shielding
            instruction = self.instruction_builder.shield_sol(
                payer.pubkey(), commitment, amount
            )
        else:
            # SPL token shielding with automatic ATA management
            mint = Pubkey.from_string(token)

            # Get or create user's associated token account
            user_ata = await get_or_create_ata(
                self.client, payer.pubkey(), mint, payer
            )

            # Get vault authority PDA
            vault_authority, _ = find_vault_pda(self.program_id, self.pool_pda)

            # Get or create vault's associated token account
            vault_ata = await get_or_create_ata(
                self.client, vault_authority, mint, payer
            )

            instruction = self.instruction_builder.shield_spl(
                payer.pubkey(),
                user_ata,
                vault_ata,
                commitment,
                amount,
            )

        return await self.send_transaction(instruction, payer)

    async def submit_transfer_transaction(
        self,
        nullifier: bytes,
        new_commitment: bytes,
        proof: bytes,
        payer_keypair: bytes,
    ) -> str:
        """
        Submit private transfer transaction

        Args:
            nullifier: Nullifier to spend (32 bytes)
            new_commitment: New commitment for recipient (32 bytes)
            proof: Proof bytes (96 bytes for MVP)
            payer_keypair: Payer's keypair bytes (64 bytes)

        Returns:
            Transaction signature
        """
        payer = Keypair.from_bytes(payer_keypair)

        instruction = self.instruction_builder.transfer(
            payer.pubkey(), nullifier, new_commitment, proof
        )

        return await self.send_transaction(instruction, payer)

    async def submit_unshield_transaction(
        self,
        nullifier: bytes,
        destination: str,
        amount: int,
        proof: bytes,
        payer_keypair: bytes,
        token: str = "SOL",
    ) -> str:
        """
        Submit unshield transaction

        Args:
            nullifier: Nullifier to spend (32 bytes)
            destination: Destination address (base58 pubkey)
            amount: Amount to unshield
            proof: Proof bytes (96 bytes for MVP)
            payer_keypair: Payer's keypair bytes (64 bytes)
            token: Token mint address ("SOL" for native SOL)

        Returns:
            Transaction signature
        """
        payer = Keypair.from_bytes(payer_keypair)
        recipient = Pubkey.from_string(destination)

        if token.upper() == "SOL":
            # Native SOL unshielding
            instruction = self.instruction_builder.unshield_sol(
                payer.pubkey(), recipient, nullifier, amount, proof
            )
        else:
            # SPL token unshielding with automatic ATA management
            mint = Pubkey.from_string(token)

            # Get vault authority PDA
            vault_authority, _ = find_vault_pda(self.program_id, self.pool_pda)

            # Get vault's token account (should already exist from shield)
            vault_ata = await get_associated_token_address(vault_authority, mint)

            # Get or create recipient's token account
            recipient_ata = await get_or_create_ata(
                self.client, recipient, mint, payer
            )

            instruction = self.instruction_builder.unshield_spl(
                payer.pubkey(),
                recipient_ata,
                vault_ata,
                nullifier,
                amount,
                proof,
            )

        return await self.send_transaction(instruction, payer)

    async def close(self) -> None:
        """Close RPC connection"""
        await self.client.close()
