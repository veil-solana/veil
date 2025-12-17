"""
Integration tests for Nyx Protocol Python SDK

These tests verify the SDK functionality without requiring a live Solana network.
For full integration tests, run with a local validator.
"""

import pytest
import secrets
from unittest.mock import AsyncMock, MagicMock, patch

# Test imports
import sys
sys.path.insert(0, "src")

from veil.types import TransactionStatus, PrivateTransaction
from veil.utils import validate_solana_address


class TestUtils:
    """Test utility functions"""

    def test_validate_solana_address_valid(self):
        """Test valid Solana addresses"""
        # Standard base58 addresses (32 bytes = 43-44 chars in base58)
        valid_addresses = [
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "So11111111111111111111111111111111111111112",
        ]
        for addr in valid_addresses:
            assert validate_solana_address(addr), f"Should be valid: {addr}"

    def test_validate_solana_address_invalid(self):
        """Test invalid Solana addresses"""
        invalid_addresses = [
            "",
            "short",
            "0x1234567890123456789012345678901234567890",  # Ethereum format
            "not-a-valid-address!@#$",
        ]
        for addr in invalid_addresses:
            assert not validate_solana_address(addr), f"Should be invalid: {addr}"


class TestPrivateTransaction:
    """Test PrivateTransaction dataclass"""

    def test_to_dict_basic(self):
        """Test basic transaction serialization"""
        tx = PrivateTransaction(
            signature="test_sig_123",
            status=TransactionStatus.CONFIRMED,
            commitment="abcd1234",
        )
        result = tx.to_dict()

        assert result["signature"] == "test_sig_123"
        assert result["status"] == "confirmed"
        assert result["commitment"] == "abcd1234"
        assert result["nullifier"] is None
        assert result["proof"] is None

    def test_to_dict_with_proof(self):
        """Test transaction with proof"""
        proof = bytes([1, 2, 3, 4])
        tx = PrivateTransaction(
            signature="sig",
            status=TransactionStatus.PENDING,
            proof=proof,
        )
        result = tx.to_dict()

        assert result["proof"] == "01020304"
        assert result["status"] == "pending"

    def test_to_dict_with_secrets(self):
        """Test transaction with secrets included"""
        tx = PrivateTransaction(
            signature="sig",
            status=TransactionStatus.CONFIRMED,
            secret="my_secret",
            recipient_secret="recipient_secret",
        )
        result = tx.to_dict()

        assert result["secret"] == "my_secret"
        assert result["recipient_secret"] == "recipient_secret"


class TestInstructionBuilder:
    """Test instruction building"""

    def test_shield_sol_instruction_data(self):
        """Test shield SOL instruction data format"""
        from nyx_protocol.solana_client import InstructionBuilder
        from solders.pubkey import Pubkey

        program_id = Pubkey.from_string("Nyx1111111111111111111111111111111111111111")
        builder = InstructionBuilder(program_id)

        depositor = Pubkey.new_unique()
        commitment = bytes([42] * 32)
        amount = 1_000_000_000  # 1 SOL in lamports

        ix = builder.shield_sol(depositor, commitment, amount)

        # Check instruction data format
        assert len(ix.data) == 8 + 32 + 8  # discriminator + commitment + amount
        assert ix.data[8:40] == commitment
        assert int.from_bytes(ix.data[40:48], 'little') == amount

    def test_transfer_instruction_data(self):
        """Test transfer instruction data format"""
        from nyx_protocol.solana_client import InstructionBuilder
        from solders.pubkey import Pubkey

        program_id = Pubkey.from_string("Nyx1111111111111111111111111111111111111111")
        builder = InstructionBuilder(program_id)

        relayer = Pubkey.new_unique()
        nullifier = bytes([1] * 32)
        new_commitment = bytes([2] * 32)
        proof = bytes([3] * 96)

        ix = builder.transfer(relayer, nullifier, new_commitment, proof)

        # Check instruction data format
        # 8 (disc) + 32 (nullifier) + 32 (commitment) + 4 (len) + 96 (proof)
        assert len(ix.data) == 8 + 32 + 32 + 4 + 96
        assert ix.data[8:40] == nullifier
        assert ix.data[40:72] == new_commitment


class TestPDADerivation:
    """Test PDA derivation functions"""

    def test_find_pool_pda(self):
        """Test pool PDA derivation"""
        from nyx_protocol.solana_client import find_pool_pda
        from solders.pubkey import Pubkey

        program_id = Pubkey.from_string("Nyx1111111111111111111111111111111111111111")
        pda, bump = find_pool_pda(program_id)

        # Should return valid PDA
        assert isinstance(pda, Pubkey)
        assert 0 <= bump <= 255

        # Should be deterministic
        pda2, bump2 = find_pool_pda(program_id)
        assert pda == pda2
        assert bump == bump2

    def test_find_vault_pda(self):
        """Test vault PDA derivation"""
        from nyx_protocol.solana_client import find_pool_pda, find_vault_pda
        from solders.pubkey import Pubkey

        program_id = Pubkey.from_string("Nyx1111111111111111111111111111111111111111")
        pool, _ = find_pool_pda(program_id)
        vault, bump = find_vault_pda(program_id, pool)

        assert isinstance(vault, Pubkey)
        assert vault != pool  # Different PDAs

    def test_find_nullifier_pda(self):
        """Test nullifier PDA derivation"""
        from nyx_protocol.solana_client import find_pool_pda, find_nullifier_pda
        from solders.pubkey import Pubkey

        program_id = Pubkey.from_string("Nyx1111111111111111111111111111111111111111")
        pool, _ = find_pool_pda(program_id)

        nullifier1 = bytes([1] * 32)
        nullifier2 = bytes([2] * 32)

        pda1, _ = find_nullifier_pda(program_id, pool, nullifier1)
        pda2, _ = find_nullifier_pda(program_id, pool, nullifier2)

        # Different nullifiers should produce different PDAs
        assert pda1 != pda2


class TestMVPProof:
    """Test MVP proof generation"""

    def test_generate_mvp_proof(self):
        """Test MVP proof format"""
        from nyx_protocol.client import generate_mvp_proof
        from solders.keypair import Keypair

        keypair = Keypair()
        nullifier = bytes([1] * 32)
        commitment = bytes([2] * 32)
        root = bytes([3] * 32)

        proof = generate_mvp_proof(nullifier, commitment, root, keypair)

        # Proof should be 96 bytes (64 sig + 32 pubkey)
        assert len(proof) == 96

        # Last 32 bytes should be the pubkey
        assert proof[64:] == bytes(keypair.pubkey())

    def test_mvp_proof_deterministic(self):
        """Test that same inputs produce consistent proof format"""
        from nyx_protocol.client import generate_mvp_proof
        from solders.keypair import Keypair

        keypair = Keypair()
        nullifier = bytes([1] * 32)
        commitment = bytes([2] * 32)
        root = bytes([3] * 32)

        proof1 = generate_mvp_proof(nullifier, commitment, root, keypair)
        proof2 = generate_mvp_proof(nullifier, commitment, root, keypair)

        # Same inputs should produce same proof
        assert proof1 == proof2


class TestClientOffline:
    """Test client offline operations (no network required)"""

    @pytest.fixture
    def mock_rust_core(self):
        """Mock the Rust core module"""
        mock = MagicMock()
        mock.generate_commitment.return_value = bytes([1] * 32)
        mock.generate_nullifier.return_value = bytes([2] * 32)
        mock.generate_proof.return_value = bytes([3] * 64)
        mock.verify_proof.return_value = True
        return mock

    def test_shield_assets_offline(self, mock_rust_core):
        """Test offline shield operation"""
        with patch.dict('sys.modules', {'nyx_protocol._rust_core': mock_rust_core}):
            # Need to reimport to get mocked version
            from nyx_protocol.client import PrivacyClient

            client = PrivacyClient.__new__(PrivacyClient)
            client._rust = mock_rust_core
            client.rpc_url = "http://localhost:8899"
            client.program_id = None

            tx = client.shield_assets(
                amount=1000000,
                token="SOL",
                owner_secret="a" * 32,
            )

            assert tx.status == TransactionStatus.PENDING
            assert tx.signature.startswith("offline_")
            assert tx.commitment is not None
            mock_rust_core.generate_commitment.assert_called_once()

    def test_private_transfer_offline(self, mock_rust_core):
        """Test offline transfer operation"""
        with patch.dict('sys.modules', {'nyx_protocol._rust_core': mock_rust_core}):
            from nyx_protocol.client import PrivacyClient

            client = PrivacyClient.__new__(PrivacyClient)
            client._rust = mock_rust_core
            client.rpc_url = "http://localhost:8899"
            client.program_id = None

            tx = client.private_transfer(
                recipient="11111111111111111111111111111111",
                amount=500000,
                sender_secret="b" * 32,
            )

            assert tx.status == TransactionStatus.PENDING
            assert tx.nullifier is not None
            assert tx.proof is not None


class TestCommitmentData:
    """Test CommitmentData operations"""

    def test_commitment_hex_conversion(self):
        """Test hex string conversion"""
        from nyx_protocol.types import CommitmentData

        original = bytes([0xab, 0xcd, 0xef] + [0] * 29)
        data = CommitmentData(commitment=original, amount=1000)

        hex_str = data.to_hex()
        assert hex_str.startswith("abcdef")

        restored = CommitmentData.from_hex(hex_str, 1000)
        assert restored.commitment == original
        assert restored.amount == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
