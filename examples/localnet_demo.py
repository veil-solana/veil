#!/usr/bin/env python3
"""
Veil Privacy SDK Localnet Demo

This script demonstrates the full privacy flow on a local Solana validator.

Prerequisites:
1. Start local validator: solana-test-validator
2. Build and deploy: ./scripts/deploy.sh localnet
3. Install SDK: pip install -e .

Usage:
    python examples/localnet_demo.py
"""

import asyncio

from solders.keypair import Keypair
from veil import PrivacyClient


async def main():
    print("=" * 60)
    print("Veil Privacy SDK - Privacy Demo on Localnet")
    print("=" * 60)
    print()

    # Configuration
    RPC_URL = "http://localhost:8899"
    PROGRAM_ID = "Vei1111111111111111111111111111111111111111"

    # Create client
    print("[1] Creating privacy client...")
    client = PrivacyClient(rpc_url=RPC_URL, program_id=PROGRAM_ID)

    # Generate test keypairs
    print("[2] Generating test keypairs...")
    alice = Keypair()
    bob = Keypair()
    print(f"    Alice: {alice.pubkey()}")
    print(f"    Bob:   {bob.pubkey()}")

    try:
        # Step 1: Initialize pool (first time only)
        print()
        print("[3] Initializing privacy pool...")
        try:
            tx = await client.initialize_pool_async(alice)
            print(f"    Pool initialized: {tx}")
        except Exception as e:
            if "already in use" in str(e).lower():
                print("    Pool already initialized (OK)")
            else:
                raise

        # Step 2: Shield SOL
        print()
        print("[4] Shielding 0.1 SOL...")
        shield_amount = 100_000_000  # 0.1 SOL in lamports

        shield_tx = await client.shield_assets_async(
            amount=shield_amount,
            token="SOL",
            keypair=alice,
        )
        print(f"    Transaction: {shield_tx.signature}")
        print(f"    Commitment:  {shield_tx.commitment[:32]}...")
        print(f"    Secret:      {shield_tx.secret[:16]}... (save this!)")

        # Step 3: Private transfer to Bob
        print()
        print("[5] Private transfer to Bob...")

        transfer_tx = await client.private_transfer_async(
            recipient=str(bob.pubkey()),
            amount=shield_amount,
            sender_keypair=alice,
            sender_secret=shield_tx.secret,
            sender_commitment=shield_tx.commitment,
        )
        print(f"    Transaction:       {transfer_tx.signature}")
        print(f"    Nullifier:         {transfer_tx.nullifier[:32]}...")
        print(f"    New Commitment:    {transfer_tx.commitment[:32]}...")
        print(f"    Recipient Secret:  {transfer_tx.recipient_secret[:16]}...")

        # Step 4: Check nullifier is spent
        print()
        print("[6] Verifying nullifier is spent...")
        nullifier_bytes = bytes.fromhex(transfer_tx.nullifier)
        is_spent = await client.is_nullifier_spent(nullifier_bytes)
        print(f"    Nullifier spent: {is_spent}")

        # Step 5: Bob unshields
        print()
        print("[7] Bob unshielding funds...")

        unshield_tx = await client.unshield_assets_async(
            amount=shield_amount,
            destination=str(bob.pubkey()),
            owner_keypair=bob,
            owner_secret=transfer_tx.recipient_secret,
            commitment=transfer_tx.commitment,
        )
        print(f"    Transaction: {unshield_tx.signature}")
        print(f"    Nullifier:   {unshield_tx.nullifier[:32]}...")

        print()
        print("=" * 60)
        print("Demo complete! Full privacy flow executed successfully.")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nTroubleshooting:")
        print("1. Ensure local validator is running: solana-test-validator")
        print("2. Ensure Veil program is deployed: ./scripts/deploy.sh localnet")
        print("3. Airdrop SOL to Alice: solana airdrop 10 <alice_pubkey>")
        raise

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
