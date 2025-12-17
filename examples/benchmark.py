"""
Benchmark example for Veil Privacy SDK

Measures performance of cryptographic operations.

Note: This benchmark uses internal _rust_core API for accurate performance measurement.
"""

import json
import time
from statistics import mean, stdev

from veil import _rust_core
from veil import generate_secret


def benchmark(name: str, func, iterations: int = 100):
    """Run benchmark and print results"""
    times = []

    # Warmup
    for _ in range(10):
        func()

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)

    avg = mean(times)
    std = stdev(times) if len(times) > 1 else 0
    min_t = min(times)
    max_t = max(times)

    print(f"{name}:")
    print(f"  Average: {avg:.3f} ms")
    print(f"  Std Dev: {std:.3f} ms")
    print(f"  Min/Max: {min_t:.3f} / {max_t:.3f} ms")
    print(f"  Ops/sec: {1000 / avg:.1f}")
    print()


def main():
    print("=== Veil Privacy SDK Benchmark ===\n")
    print("Running cryptographic operation benchmarks...\n")

    # Setup
    secret = generate_secret()
    secret_bytes = secret.encode()
    amount = 1000

    # Benchmark commitment generation
    benchmark(
        "Commitment Generation",
        lambda: _rust_core.generate_commitment(amount=amount, secret=secret_bytes),
    )

    # Generate a commitment for nullifier benchmark
    commitment = _rust_core.generate_commitment(amount=amount, secret=secret_bytes)

    # Benchmark nullifier generation
    benchmark(
        "Nullifier Generation",
        lambda: _rust_core.generate_nullifier(commitment=commitment, secret=secret_bytes),
    )

    # Setup for proof benchmark
    witness = {
        "sender_secret": secret,
        "sender_commitment": commitment.hex(),
        "recipient": "recipient_address",
        "amount": amount,
        "nullifier": "nullifier_hash",
    }
    witness_json = json.dumps(witness)

    # Benchmark proof generation (mock)
    benchmark(
        "Proof Generation (Mock)",
        lambda: _rust_core.generate_proof(witness_json=witness_json),
        iterations=100,
    )

    # Setup for verification benchmark
    proof = _rust_core.generate_proof(witness_json=witness_json)
    public_inputs = json.dumps({
        "nullifier": "nullifier_hash",
        "new_commitment": "new_commitment",
        "root": "merkle_root",
    })

    # Benchmark proof verification (mock)
    benchmark(
        "Proof Verification (Mock)",
        lambda: _rust_core.verify_proof(proof=proof, public_inputs_json=public_inputs),
    )

    # Benchmark Poseidon hash
    inputs = [bytes([1] * 32), bytes([2] * 32)]
    benchmark(
        "Poseidon Hash (2 inputs)",
        lambda: _rust_core.poseidon_hash(inputs),
    )

    print("=== Benchmark Complete ===")
    print("\nNote: Proof generation/verification use mock implementations.")
    print("Real zkSNARK proofs will be slower (2-5 seconds for generation).")


if __name__ == "__main__":
    main()
