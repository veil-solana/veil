//! Benchmarks for cryptographic operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nyx_privacy_core::crypto::Commitment;

fn bench_commitment_generation(c: &mut Criterion) {
    let secret = b"benchmark_secret_key_32_bytes!!!";
    let amount = 1000u64;

    c.bench_function("commitment_generation", |b| {
        b.iter(|| {
            let commitment = Commitment::new(black_box(amount), black_box(secret)).unwrap();
            black_box(commitment.to_bytes())
        })
    });
}

fn bench_commitment_serialization(c: &mut Criterion) {
    let secret = b"benchmark_secret_key_32_bytes!!!";
    let amount = 1000u64;
    let commitment = Commitment::new(amount, secret).unwrap();

    c.bench_function("commitment_serialization", |b| {
        b.iter(|| black_box(commitment.to_bytes()))
    });
}

criterion_group!(
    benches,
    bench_commitment_generation,
    bench_commitment_serialization
);
criterion_main!(benches);
