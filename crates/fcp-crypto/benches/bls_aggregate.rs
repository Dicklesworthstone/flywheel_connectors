//! Benchmarks for BLS12-381 threshold-aggregate quorum signatures
//! (br-angoc.17.4 numeric targets).
//!
//! Targets (release profile, p99):
//! - `bls_sign`: < 800 µs
//! - `bls_verify_aggregate_32`: < 3 ms (two pairings + 31 G1 additions)
//!
//! Pairing math is 10–50× slower in debug builds, so these targets are
//! asserted here (Criterion, release) rather than in unit tests.

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_crypto::bls::{
    AggregateSignature, BlsSecretKey, BlsSignature, PopRegistry, aggregate, verify_aggregate,
};
use std::hint::black_box;

const MESSAGE: &[u8] = b"zone admission: node-candidate-77 -> z:work (nonce 42)";

fn signer_fixture(n: usize) -> (Vec<(String, BlsSecretKey)>, PopRegistry) {
    let signers: Vec<(String, BlsSecretKey)> = (0..n)
        .map(|i| (format!("node-{i}"), BlsSecretKey::generate()))
        .collect();
    let mut registry = PopRegistry::new();
    for (id, sk) in &signers {
        registry
            .register(id.clone(), sk.public_key(), &sk.prove_possession())
            .expect("valid PoP registers");
    }
    (signers, registry)
}

fn aggregate_fixture(
    signers: &[(String, BlsSecretKey)],
    registry: &PopRegistry,
) -> AggregateSignature {
    let shares: Vec<(String, BlsSignature)> = signers
        .iter()
        .map(|(id, sk)| (id.clone(), sk.sign(MESSAGE)))
        .collect();
    aggregate(&shares, registry).expect("aggregation succeeds")
}

fn bench_bls_sign(c: &mut Criterion) {
    let sk = BlsSecretKey::generate();
    // Target: < 800 µs p99 (one G2 hash-to-curve + one G2 scalar mul).
    c.bench_function("bls_sign", |b| {
        b.iter(|| sk.sign(black_box(MESSAGE)));
    });
}

fn bench_bls_verify_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls_verify_aggregate");
    for n in [5usize, 32] {
        let (signers, registry) = signer_fixture(n);
        let agg = aggregate_fixture(&signers, &registry);
        // Target for n=32: < 3 ms p99 (two pairings dominate).
        group.bench_function(format!("{n}_signers"), |b| {
            b.iter(|| {
                verify_aggregate(black_box(&agg), black_box(MESSAGE), black_box(&registry))
                    .expect("aggregate verifies");
            });
        });
    }
    group.finish();
}

fn bench_bls_aggregate_only(c: &mut Criterion) {
    let (signers, registry) = signer_fixture(32);
    let shares: Vec<(String, BlsSignature)> = signers
        .iter()
        .map(|(id, sk)| (id.clone(), sk.sign(MESSAGE)))
        .collect();
    // Aggregation itself is pairing-free: 31 G2 additions + registry lookups.
    c.bench_function("bls_aggregate_32_shares", |b| {
        b.iter(|| aggregate(black_box(&shares), black_box(&registry)).expect("aggregates"));
    });
}

fn bench_pop_register(c: &mut Criterion) {
    let sk = BlsSecretKey::generate();
    let pk = sk.public_key();
    let pop = sk.prove_possession();
    // PoP verification is a two-pairing check, same shape as verify.
    c.bench_function("bls_pop_register", |b| {
        b.iter(|| {
            let mut registry = PopRegistry::new();
            registry
                .register("node-0", black_box(pk), black_box(&pop))
                .expect("valid PoP registers");
        });
    });
}

criterion_group!(
    benches,
    bench_bls_sign,
    bench_bls_verify_aggregate,
    bench_bls_aggregate_only,
    bench_pop_register
);
criterion_main!(benches);
