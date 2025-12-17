"""Utility functions"""

import secrets


def generate_secret(length: int = 32) -> str:
    """
    Generate a cryptographically secure secret

    Args:
        length: Length of secret in bytes

    Returns:
        Hex-encoded secret string
    """
    return secrets.token_hex(length)


def commitment_to_hex(commitment: bytes) -> str:
    """
    Convert commitment bytes to hex string

    Args:
        commitment: Commitment bytes

    Returns:
        Hex string
    """
    return commitment.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes

    Args:
        hex_str: Hex string (with or without 0x prefix)

    Returns:
        Bytes
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def validate_solana_address(address: str) -> bool:
    """
    Validate Solana address

    Args:
        address: Base58-encoded Solana address

    Returns:
        True if valid
    """
    try:
        import base58

        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False
