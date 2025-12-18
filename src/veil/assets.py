"""
Asset registry for multi-asset privacy pools

This module provides utilities for managing different asset types
(SOL, SPL tokens) within the Veil privacy protocol.
"""

import hashlib
from typing import Union
from solders.pubkey import Pubkey


# Special asset ID for native SOL
SOL_ASSET_ID = 0


class AssetRegistry:
    """
    Registry for managing asset types in privacy pools.

    The asset registry converts token mint addresses to 8-byte asset IDs
    that are used in commitments and encrypted notes.
    """

    @staticmethod
    def get_asset_id(token: Union[str, Pubkey]) -> int:
        """
        Convert a token identifier to an 8-byte asset ID.

        Args:
            token: Either "SOL" string or a token mint address (Pubkey or string)

        Returns:
            8-byte asset ID as integer
        """
        if isinstance(token, str):
            if token.upper() == "SOL":
                return SOL_ASSET_ID

            # It's a mint address string
            mint_str = token
        elif isinstance(token, Pubkey):
            mint_str = str(token)
        else:
            raise ValueError(f"Invalid token type: {type(token)}")

        # Hash the mint address to get a deterministic 8-byte ID
        hash_bytes = hashlib.sha256(mint_str.encode()).digest()
        # Take first 8 bytes and convert to little-endian integer
        return int.from_bytes(hash_bytes[:8], 'little')

    @staticmethod
    def is_sol(asset_id: int) -> bool:
        """
        Check if an asset ID represents native SOL.

        Args:
            asset_id: The asset ID to check

        Returns:
            True if the asset is SOL, False otherwise
        """
        return asset_id == SOL_ASSET_ID

    @staticmethod
    def is_spl_token(asset_id: int) -> bool:
        """
        Check if an asset ID represents an SPL token.

        Args:
            asset_id: The asset ID to check

        Returns:
            True if the asset is an SPL token, False otherwise
        """
        return asset_id != SOL_ASSET_ID


# Common token mint addresses for convenience
COMMON_TOKENS = {
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    "SOL": "SOL",  # Native SOL
}


def get_token_mint(token_symbol: str) -> str:
    """
    Get the mint address for a common token symbol.

    Args:
        token_symbol: Token symbol (e.g., "USDC", "USDT", "SOL")

    Returns:
        Token mint address or "SOL" for native SOL

    Raises:
        ValueError: If token symbol is not recognized
    """
    symbol = token_symbol.upper()
    if symbol in COMMON_TOKENS:
        return COMMON_TOKENS[symbol]
    raise ValueError(
        f"Unknown token symbol: {token_symbol}. "
        f"Provide the full mint address or use one of: {list(COMMON_TOKENS.keys())}"
    )
