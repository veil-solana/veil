"""
SPL Token Privacy Example

This example demonstrates how to use Veil for private SPL token transactions.
It shows the complete flow: shield → private transfer → unshield

Requirements:
- Funded Solana wallet (for gas fees and SPL tokens)
- Devnet or testnet RPC access
- SPL tokens in your wallet (e.g., USDC)
"""

import asyncio
from solders.keypair import Keypair
from veil import PrivacyClient, generate_secret
from veil.assets import COMMON_TOKENS, get_token_mint

# USDC mint address on devnet
# For mainnet, use: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"


async def main():
    # Initialize Veil client (devnet)
    client = PrivacyClient(
        rpc_url="https://api.devnet.solana.com",
        program_id="Vei1111111111111111111111111111111111111111"  # Replace with actual program ID
    )

    # Load your wallet (NEVER commit real keys!)
    # In production, load from secure storage
    payer = Keypair()  # Generate new keypair for demo
    print(f"Wallet: {payer.pubkey()}")
    print("⚠️  Fund this wallet with devnet SOL and USDC before running!")
    print()

    # Generate secrets for privacy
    alice_secret = generate_secret()  # Your secret
    bob_secret = generate_secret()    # Recipient's secret
    bob_pubkey = Keypair().pubkey()   # Recipient's public address

    print("=" * 60)
    print("STEP 1: Shield SPL Tokens (USDC)")
    print("=" * 60)

    try:
        # Shield 1 USDC (6 decimals = 1,000,000 base units)
        shield_tx = await client.shield_assets_async(
            amount=1_000_000,  # 1 USDC
            token=USDC_DEVNET,  # SPL token mint address
            keypair=payer,
            secret=alice_secret
        )

        print(f"✅ Shielded 1 USDC")
        print(f"   Transaction: {shield_tx.signature}")
        print(f"   Commitment: {shield_tx.commitment[:16]}...")
        print(f"   Secret (save this!): {shield_tx.secret[:16]}...")
        print()

        # The SDK automatically:
        # 1. Found/created your USDC token account
        # 2. Found/created pool's USDC vault
        # 3. Transferred tokens to privacy pool
        # 4. Added commitment to Merkle tree

    except Exception as e:
        print(f"❌ Shield failed: {e}")
        await client.close()
        return

    print("=" * 60)
    print("STEP 2: Private Transfer")
    print("=" * 60)

    try:
        # Transfer 0.5 USDC privately to Bob
        transfer_tx = await client.private_transfer_async(
            recipient=str(bob_pubkey),
            amount=500_000,  # 0.5 USDC
            sender_keypair=payer,
            sender_secret=alice_secret,
            sender_commitment=shield_tx.commitment
        )

        print(f"✅ Transferred 0.5 USDC privately to Bob")
        print(f"   Transaction: {transfer_tx.signature}")
        print(f"   Nullifier: {transfer_tx.nullifier[:16]}...")
        print(f"   New commitment: {transfer_tx.commitment[:16]}...")
        print(f"   Bob's secret: {transfer_tx.recipient_secret[:16]}...")
        print()

        # On-chain observers can see:
        # - A nullifier was spent
        # - A new commitment was created
        # - A zkSNARK proof was verified
        #
        # They CANNOT see:
        # - Who sent (Alice)
        # - Who received (Bob)
        # - How much was transferred (0.5 USDC)

    except Exception as e:
        print(f"❌ Transfer failed: {e}")
        await client.close()
        return

    print("=" * 60)
    print("STEP 3: Unshield to Public Account")
    print("=" * 60)

    try:
        # Bob unshields his USDC back to a public account
        unshield_tx = await client.unshield_assets_async(
            amount=500_000,  # 0.5 USDC
            destination=str(bob_pubkey),
            owner_keypair=payer,  # In real usage, Bob would use his keypair
            owner_secret=transfer_tx.recipient_secret,  # Bob's secret from transfer
            commitment=transfer_tx.commitment,
            token=USDC_DEVNET  # Specify SPL token
        )

        print(f"✅ Unshielded 0.5 USDC to {str(bob_pubkey)[:8]}...")
        print(f"   Transaction: {unshield_tx.signature}")
        print(f"   Nullifier: {unshield_tx.nullifier[:16]}...")
        print()

        # The SDK automatically:
        # 1. Found/created Bob's USDC token account
        # 2. Transferred tokens from vault to Bob
        # 3. Marked nullifier as spent

    except Exception as e:
        print(f"❌ Unshield failed: {e}")
        await client.close()
        return

    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"✅ Complete privacy flow demonstrated!")
    print(f"   - Shielded 1 USDC")
    print(f"   - Transferred 0.5 USDC privately")
    print(f"   - Unshielded 0.5 USDC to public account")
    print()
    print("💡 Key Features:")
    print("   • Automatic token account creation")
    print("   • Private amounts, sender, and recipient")
    print("   • Works with any SPL token")
    print("   • Same API as SOL (just pass mint address)")

    await client.close()


async def demonstrate_common_tokens():
    """Show how to use common token symbols"""

    print("\n" + "=" * 60)
    print("Using Common Token Symbols")
    print("=" * 60)

    # You can use common token symbols
    try:
        usdc_mint = get_token_mint("USDC")
        print(f"USDC mint: {usdc_mint}")

        usdt_mint = get_token_mint("USDT")
        print(f"USDT mint: {usdt_mint}")
    except ValueError as e:
        print(f"Unknown token: {e}")

    # Or pass the mint address directly
    custom_token = "YourCustomTokenMintAddress..."
    print(f"Custom token: {custom_token}")


if __name__ == "__main__":
    print("🔐 Veil SPL Token Privacy Demo")
    print()
    print("This demo shows how to use Veil for private SPL token transactions.")
    print("Make sure you have devnet SOL and USDC in your wallet!")
    print()

    # Run the main demo
    asyncio.run(main())

    # Show common token usage
    asyncio.run(demonstrate_common_tokens())
