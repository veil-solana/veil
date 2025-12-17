"""Test commitment generation"""

import pytest

from veil import _rust_core
from veil.utils import generate_secret


def test_generate_commitment():
    """Test basic commitment generation"""
    secret = generate_secret(32)
    amount = 1000

    commitment = _rust_core.generate_commitment(
        amount=amount,
        secret=secret.encode(),
    )

    assert len(commitment) == 32
    assert isinstance(commitment, bytes)


def test_commitment_deterministic():
    """Test that commitments are deterministic"""
    secret = "my_test_secret_key_32_chars_min!"
    amount = 1000

    c1 = _rust_core.generate_commitment(amount=amount, secret=secret.encode())
    c2 = _rust_core.generate_commitment(amount=amount, secret=secret.encode())

    assert c1 == c2


def test_different_amounts_different_commitments():
    """Test that different amounts produce different commitments"""
    secret = "my_test_secret_key_32_chars_min!"

    c1 = _rust_core.generate_commitment(amount=1000, secret=secret.encode())
    c2 = _rust_core.generate_commitment(amount=2000, secret=secret.encode())

    assert c1 != c2


def test_different_secrets_different_commitments():
    """Test that different secrets produce different commitments"""
    secret1 = "my_test_secret_key_32_chars_min!"
    secret2 = "another_secret_key_32_chars_min!"
    amount = 1000

    c1 = _rust_core.generate_commitment(amount=amount, secret=secret1.encode())
    c2 = _rust_core.generate_commitment(amount=amount, secret=secret2.encode())

    assert c1 != c2


def test_invalid_secret_length():
    """Test that short secrets are rejected"""
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _rust_core.generate_commitment(amount=1000, secret=b"short")


def test_zero_amount_commitment():
    """Test commitment with zero amount"""
    secret = "my_test_secret_key_32_chars_min!"

    commitment = _rust_core.generate_commitment(amount=0, secret=secret.encode())

    assert len(commitment) == 32


def test_large_amount_commitment():
    """Test commitment with large amount"""
    secret = "my_test_secret_key_32_chars_min!"
    large_amount = 2**63 - 1  # Max u64

    commitment = _rust_core.generate_commitment(
        amount=large_amount, secret=secret.encode()
    )

    assert len(commitment) == 32
