"""Integration tests"""

import pytest

from veil import PrivacyClient
from veil.types import TransactionStatus
from veil.utils import generate_secret


@pytest.mark.asyncio
async def test_full_flow():
    """Test complete shield -> transfer -> unshield flow"""
    client = PrivacyClient()

    # Generate secrets
    alice_secret = generate_secret()
    bob_address = "11111111111111111111111111111111"  # Mock address (32 bytes base58)

    # 1. Alice shields 1000 tokens
    shield_tx = client.shield_assets(
        amount=1000,
        token="SOL",
        owner_secret=alice_secret,
    )

    assert shield_tx.status == TransactionStatus.CONFIRMED
    assert shield_tx.commitment is not None
    alice_commitment = shield_tx.commitment

    # 2. Alice transfers 500 to Bob privately
    transfer_tx = client.private_transfer(
        recipient=bob_address,
        amount=500,
        sender_secret=alice_secret,
        sender_commitment=alice_commitment,
    )

    assert transfer_tx.status == TransactionStatus.CONFIRMED
    assert transfer_tx.nullifier is not None
    assert transfer_tx.proof is not None
    assert len(transfer_tx.proof) == 64

    # 3. Verify proof
    valid = client.verify_proof(
        proof=transfer_tx.proof,
        public_inputs={
            "nullifier": transfer_tx.nullifier,
            "new_commitment": transfer_tx.commitment,
            "root": "mock_root",
        },
    )

    assert valid is True

    await client.close()


@pytest.mark.asyncio
async def test_multiple_transfers():
    """Test multiple sequential private transfers"""
    client = PrivacyClient()

    secret = generate_secret()
    recipient = "11111111111111111111111111111111"

    # Shield initial amount
    shield_tx = client.shield_assets(
        amount=1000,
        token="SOL",
        owner_secret=secret,
    )

    # Make multiple transfers
    nullifiers = set()
    for i in range(3):
        transfer_tx = client.private_transfer(
            recipient=recipient,
            amount=100,
            sender_secret=secret,
            sender_commitment=shield_tx.commitment,
        )

        assert transfer_tx.nullifier is not None
        # Each transfer should have same nullifier (same commitment + secret)
        nullifiers.add(transfer_tx.nullifier)

    # All nullifiers should be the same (deterministic)
    assert len(nullifiers) == 1

    await client.close()


@pytest.mark.asyncio
async def test_unshield_flow():
    """Test shield -> unshield flow"""
    client = PrivacyClient()

    secret = generate_secret()
    destination = "22222222222222222222222222222222"

    # Shield assets
    shield_tx = client.shield_assets(
        amount=1000,
        token="SOL",
        owner_secret=secret,
    )

    # Unshield assets
    unshield_tx = client.unshield_assets(
        amount=1000,
        destination=destination,
        owner_secret=secret,
        commitment=shield_tx.commitment,
    )

    assert unshield_tx.status == TransactionStatus.CONFIRMED
    assert unshield_tx.nullifier is not None
    assert unshield_tx.proof is not None

    await client.close()


def test_nullifier_generation():
    """Test that nullifiers are generated correctly"""
    from nyx_protocol import _rust_core
    from nyx_protocol.utils import hex_to_bytes

    secret = "my_test_secret_key_32_chars_min!"
    commitment_bytes = bytes(32)  # Zero commitment for testing

    nullifier = _rust_core.generate_nullifier(
        commitment=commitment_bytes,
        secret=secret.encode(),
    )

    assert len(nullifier) == 32
    assert isinstance(nullifier, bytes)


def test_nullifier_deterministic():
    """Test that nullifiers are deterministic"""
    from nyx_protocol import _rust_core

    secret = "my_test_secret_key_32_chars_min!"
    commitment_bytes = bytes(32)

    n1 = _rust_core.generate_nullifier(
        commitment=commitment_bytes,
        secret=secret.encode(),
    )
    n2 = _rust_core.generate_nullifier(
        commitment=commitment_bytes,
        secret=secret.encode(),
    )

    assert n1 == n2


def test_proof_generation():
    """Test proof generation"""
    from nyx_protocol import _rust_core
    import json

    witness = {
        "sender_secret": "my_test_secret_key_32_chars_min!",
        "sender_commitment": "abc123",
        "recipient": "recipient_address",
        "amount": 1000,
        "nullifier": "nullifier_hash",
    }

    proof = _rust_core.generate_proof(witness_json=json.dumps(witness))

    assert len(proof) == 64
    assert isinstance(proof, bytes)


def test_proof_verification():
    """Test proof verification"""
    from nyx_protocol import _rust_core
    import json

    # Generate a proof
    witness = {
        "sender_secret": "my_test_secret_key_32_chars_min!",
        "sender_commitment": "abc123",
        "recipient": "recipient_address",
        "amount": 1000,
        "nullifier": "nullifier_hash",
    }

    proof = _rust_core.generate_proof(witness_json=json.dumps(witness))

    # Verify it
    public_inputs = {
        "nullifier": "nullifier_hash",
        "new_commitment": "new_commitment_hash",
        "root": "merkle_root",
    }

    valid = _rust_core.verify_proof(
        proof=proof,
        public_inputs_json=json.dumps(public_inputs),
    )

    assert valid is True


def test_poseidon_hash():
    """Test Poseidon hash function"""
    from nyx_protocol import _rust_core

    inputs = [
        bytes([1] * 32),
        bytes([2] * 32),
    ]

    result = _rust_core.poseidon_hash(inputs)

    assert len(result) > 0
    assert isinstance(result, bytes)


def test_poseidon_hash_deterministic():
    """Test that Poseidon hash is deterministic"""
    from nyx_protocol import _rust_core

    inputs = [
        bytes([1] * 32),
        bytes([2] * 32),
    ]

    h1 = _rust_core.poseidon_hash(inputs)
    h2 = _rust_core.poseidon_hash(inputs)

    assert h1 == h2
