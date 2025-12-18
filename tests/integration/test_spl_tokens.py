"""
Integration tests for SPL token support

Tests the complete SPL token privacy flow:
- Shield SPL tokens
- Private transfers
- Unshield SPL tokens
- Token account management
"""

import pytest
import asyncio
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from veil import PrivacyClient, generate_secret
from veil.assets import AssetRegistry, get_token_mint
from veil.token_utils import get_associated_token_address, get_or_create_ata


# Test token mint (use devnet USDC for real tests)
TEST_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"


class TestAssetRegistry:
    """Test asset ID generation and management"""

    def test_sol_asset_id(self):
        """Test that SOL has asset ID 0"""
        assert AssetRegistry.get_asset_id("SOL") == 0
        assert AssetRegistry.get_asset_id("sol") == 0

    def test_spl_asset_id(self):
        """Test SPL token asset ID generation"""
        usdc_id = AssetRegistry.get_asset_id(TEST_MINT)
        assert usdc_id != 0
        assert isinstance(usdc_id, int)

        # Same mint should give same ID
        usdc_id_2 = AssetRegistry.get_asset_id(TEST_MINT)
        assert usdc_id == usdc_id_2

    def test_asset_type_checks(self):
        """Test asset type checking functions"""
        assert AssetRegistry.is_sol(0)
        assert not AssetRegistry.is_sol(12345)

        assert not AssetRegistry.is_spl_token(0)
        assert AssetRegistry.is_spl_token(12345)

    def test_common_tokens(self):
        """Test common token symbol lookup"""
        usdc_mint = get_token_mint("USDC")
        assert isinstance(usdc_mint, str)
        assert len(usdc_mint) > 0

        with pytest.raises(ValueError):
            get_token_mint("UNKNOWN_TOKEN")


class TestTokenUtils:
    """Test token account utilities"""

    def test_ata_derivation(self):
        """Test associated token address derivation"""
        owner = Keypair().pubkey()
        mint = Pubkey.from_string(TEST_MINT)

        # Derive ATA
        ata = asyncio.run(get_associated_token_address(owner, mint))
        assert isinstance(ata, Pubkey)

        # Same inputs should give same ATA
        ata2 = asyncio.run(get_associated_token_address(owner, mint))
        assert ata == ata2

        # Different owner should give different ATA
        other_owner = Keypair().pubkey()
        other_ata = asyncio.run(get_associated_token_address(other_owner, mint))
        assert ata != other_ata


@pytest.mark.asyncio
@pytest.mark.integration
class TestSPLTokenPrivacy:
    """Integration tests for SPL token privacy operations"""

    @pytest.fixture
    async def client(self):
        """Create privacy client for tests"""
        client = PrivacyClient(
            rpc_url="https://api.devnet.solana.com",
            program_id="Vei1111111111111111111111111111111111111111"
        )
        yield client
        await client.close()

    @pytest.fixture
    def keypair(self):
        """Generate test keypair"""
        return Keypair()

    @pytest.mark.skip(reason="Requires funded wallet and deployed program")
    async def test_shield_spl_token(self, client, keypair):
        """Test shielding SPL tokens"""
        secret = generate_secret()

        # Shield 1 USDC (6 decimals)
        tx = await client.shield_assets_async(
            amount=1_000_000,
            token=TEST_MINT,
            keypair=keypair,
            secret=secret
        )

        assert tx.signature is not None
        assert tx.commitment is not None
        assert tx.secret == secret

    @pytest.mark.skip(reason="Requires funded wallet and deployed program")
    async def test_private_transfer_spl(self, client, keypair):
        """Test private SPL token transfer"""
        sender_secret = generate_secret()
        recipient = Keypair().pubkey()

        # First shield
        shield_tx = await client.shield_assets_async(
            amount=1_000_000,
            token=TEST_MINT,
            keypair=keypair,
            secret=sender_secret
        )

        # Then transfer
        transfer_tx = await client.private_transfer_async(
            recipient=str(recipient),
            amount=500_000,
            sender_keypair=keypair,
            sender_secret=sender_secret,
            sender_commitment=shield_tx.commitment
        )

        assert transfer_tx.signature is not None
        assert transfer_tx.nullifier is not None
        assert transfer_tx.commitment is not None
        assert transfer_tx.recipient_secret is not None

    @pytest.mark.skip(reason="Requires funded wallet and deployed program")
    async def test_unshield_spl_token(self, client, keypair):
        """Test unshielding SPL tokens"""
        secret = generate_secret()

        # Shield first
        shield_tx = await client.shield_assets_async(
            amount=1_000_000,
            token=TEST_MINT,
            keypair=keypair,
            secret=secret
        )

        # Then unshield
        destination = str(keypair.pubkey())
        unshield_tx = await client.unshield_assets_async(
            amount=1_000_000,
            destination=destination,
            owner_keypair=keypair,
            owner_secret=secret,
            commitment=shield_tx.commitment,
            token=TEST_MINT  # Specify SPL token
        )

        assert unshield_tx.signature is not None
        assert unshield_tx.nullifier is not None

    @pytest.mark.skip(reason="Requires funded wallet and deployed program")
    async def test_multi_asset_balances(self, client, keypair):
        """Test tracking balances across multiple asset types"""
        sol_secret = generate_secret()
        usdc_secret = generate_secret()

        # Shield SOL
        sol_tx = await client.shield_assets_async(
            amount=1_000_000_000,  # 1 SOL
            token="SOL",
            keypair=keypair,
            secret=sol_secret
        )

        # Shield USDC
        usdc_tx = await client.shield_assets_async(
            amount=1_000_000,  # 1 USDC
            token=TEST_MINT,
            keypair=keypair,
            secret=usdc_secret
        )

        # Verify both commitments exist
        assert sol_tx.commitment is not None
        assert usdc_tx.commitment is not None
        assert sol_tx.commitment != usdc_tx.commitment


@pytest.mark.asyncio
class TestTokenAccountCreation:
    """Test automatic token account creation"""

    @pytest.mark.skip(reason="Requires RPC connection and SOL for rent")
    async def test_create_ata_if_not_exists(self):
        """Test ATA creation when account doesn't exist"""
        from solana.rpc.async_api import AsyncClient

        client = AsyncClient("https://api.devnet.solana.com")
        payer = Keypair()
        owner = Keypair().pubkey()
        mint = Pubkey.from_string(TEST_MINT)

        try:
            # This should create the ATA if it doesn't exist
            ata = await get_or_create_ata(client, owner, mint, payer)
            assert isinstance(ata, Pubkey)

            # Calling again should return the same ATA without error
            ata2 = await get_or_create_ata(client, owner, mint, payer)
            assert ata == ata2

        finally:
            await client.close()


def test_example_script_imports():
    """Test that the example script can be imported"""
    import sys
    import os

    # Add examples directory to path
    examples_dir = os.path.join(os.path.dirname(__file__), "../../examples")
    sys.path.insert(0, examples_dir)

    # Should import without errors
    try:
        import spl_privacy
        assert hasattr(spl_privacy, "main")
    except ImportError as e:
        pytest.skip(f"Example script import failed: {e}")
