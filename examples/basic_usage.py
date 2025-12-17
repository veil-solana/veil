"""
Basic usage example for Veil Privacy SDK
"""

import asyncio
from veil import PrivacyClient, generate_secret
from solders.keypair import Keypair


async def main():
    # Initialize client
    client = PrivacyClient(rpc_url="https://api.devnet.solana.com")

    print("=== Veil Privacy SDK Demo ===\n")

    # Generate test keypair and secret
    alice = Keypair()
    my_secret = generate_secret()
    print(f"Generated secret: {my_secret[:16]}...")

    # 1. Shield (offline demo - doesn't submit to chain)
    print("\n1. Generating shield commitment (offline)...")
    shield_tx = client.shield_assets(
        amount=1_000_000_000,  # 1 SOL
        token="SOL",
        owner_secret=my_secret,
    )
    print(f"   Commitment: {shield_tx.commitment[:16]}...")

    # 2. Private transfer (offline)
    print("\n2. Generating transfer proof (offline)...")
    recipient = str(Keypair().pubkey())
    transfer_tx = client.private_transfer(
        recipient=recipient,
        amount=500_000_000,
        sender_secret=my_secret,
        sender_commitment=shield_tx.commitment,
    )
    print(f"   Nullifier: {transfer_tx.nullifier[:16]}...")
    print(f"   New commitment: {transfer_tx.commitment[:16]}...")
    print(f"   Proof size: {len(transfer_tx.proof)} bytes")

    # 3. Verify proof
    print("\n3. Verifying proof...")
    valid = client.verify_proof(
        proof=transfer_tx.proof,
        public_inputs={
            "nullifier": transfer_tx.nullifier,
            "new_commitment": transfer_tx.commitment,
            "root": "mock_merkle_root",
        },
    )
    print(f"   Proof is {'valid' if valid else 'invalid'}!")

    # 4. Unshield (offline)
    print("\n4. Generating unshield transaction (offline)...")
    my_wallet = str(alice.pubkey())
    unshield_tx = client.unshield_assets(
        amount=500_000_000,
        destination=my_wallet,
        owner_secret=my_secret,
        commitment=transfer_tx.commitment,
    )
    print(f"   Nullifier: {unshield_tx.nullifier[:16]}...")

    print("\n=== Demo Complete ===")
    print("\nNote: This demo uses offline methods.")
    print("For blockchain submission, use: shield_assets_async(), private_transfer_async(), unshield_assets_async()")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
