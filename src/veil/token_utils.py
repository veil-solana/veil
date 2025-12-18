"""
Token account utilities for SPL token support

This module provides helper functions for managing SPL token accounts:
- Associated Token Account (ATA) creation and lookup
- Pool vault token account management
- Token account validation
"""

from typing import Optional
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.instruction import Instruction
from solders.transaction import Transaction
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from spl.token.async_client import AsyncToken
from spl.token._layouts import ACCOUNT_LAYOUT
import spl.token.instructions as spl_token


async def get_associated_token_address(
    owner: Pubkey,
    mint: Pubkey,
) -> Pubkey:
    """
    Derive the associated token account address for an owner and mint.

    Args:
        owner: The owner's public key
        mint: The token mint public key

    Returns:
        The derived ATA public key
    """
    # Find PDA: [owner, token_program, mint]
    seeds = [
        bytes(owner),
        bytes(TOKEN_PROGRAM_ID),
        bytes(mint),
    ]
    ata, _ = Pubkey.find_program_address(seeds, ASSOCIATED_TOKEN_PROGRAM_ID)
    return ata


async def get_or_create_ata(
    client: AsyncClient,
    owner: Pubkey,
    mint: Pubkey,
    payer: Keypair,
    skip_confirmation: bool = False,
) -> Pubkey:
    """
    Get or create an associated token account for the owner.

    If the ATA already exists, returns its address.
    If it doesn't exist, creates it and returns the address.

    Args:
        client: Solana RPC client
        owner: The owner of the token account
        mint: The token mint
        payer: Keypair that will pay for account creation
        skip_confirmation: If True, don't wait for transaction confirmation

    Returns:
        The ATA public key
    """
    ata = await get_associated_token_address(owner, mint)

    # Check if account exists
    try:
        account_info = await client.get_account_info(ata, commitment=Confirmed)
        if account_info.value is not None:
            # Account exists
            return ata
    except Exception:
        # Account doesn't exist, need to create it
        pass

    # Create the associated token account
    create_ata_ix = spl_token.create_associated_token_account(
        payer=payer.pubkey(),
        owner=owner,
        mint=mint,
    )

    # Build and send transaction
    recent_blockhash = await client.get_latest_blockhash()
    transaction = Transaction.new_signed_with_payer(
        [create_ata_ix],
        payer.pubkey(),
        [payer],
        recent_blockhash.value.blockhash,
    )

    result = await client.send_transaction(transaction, payer)

    if not skip_confirmation:
        await client.confirm_transaction(
            result.value,
            commitment=Confirmed,
        )

    return ata


async def account_exists(client: AsyncClient, address: Pubkey) -> bool:
    """
    Check if an account exists on-chain.

    Args:
        client: Solana RPC client
        address: The account address to check

    Returns:
        True if account exists, False otherwise
    """
    try:
        account_info = await client.get_account_info(address, commitment=Confirmed)
        return account_info.value is not None
    except Exception:
        return False


async def get_token_account_balance(
    client: AsyncClient,
    token_account: Pubkey,
) -> Optional[int]:
    """
    Get the token balance of a token account.

    Args:
        client: Solana RPC client
        token_account: The token account address

    Returns:
        Token balance in base units, or None if account doesn't exist
    """
    try:
        response = await client.get_token_account_balance(token_account)
        if response.value:
            return int(response.value.amount)
        return None
    except Exception:
        return None


async def get_token_mint(
    client: AsyncClient,
    token_account: Pubkey,
) -> Optional[Pubkey]:
    """
    Get the mint address for a token account.

    Args:
        client: Solana RPC client
        token_account: The token account address

    Returns:
        The mint public key, or None if account doesn't exist
    """
    try:
        account_info = await client.get_account_info(token_account, commitment=Confirmed)
        if account_info.value is None:
            return None

        # Parse token account data
        data = account_info.value.data
        decoded = ACCOUNT_LAYOUT.parse(data)
        return Pubkey(decoded.mint)
    except Exception:
        return None
