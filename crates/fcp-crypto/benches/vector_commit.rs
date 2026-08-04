//! Benchmarks for state-root vector commitments (br-angoc.17.1 numeric
//! targets).
//!
//! Targets (release profile, p99):
//! - `kzg_verify`: < 2 ms (two pairings, n-independent)
//! - `ipa_verify` at n=1024: < 12 ms (single MSM of ~2n ristretto points)
//!
//! Pairing / ristretto MSM arithmetic is 10–50× slower at opt-level 0, so
//! these targets are asserted here (Criterion, release) rather than in unit
//! tests.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_crypto::vector_commit::kzg::{KzgSrs, KzgVectorCommitment};
use fcp_crypto::vector_commit::{IpaVectorCommitment, VectorCommitmentScheme};

fn slots(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(i as u64).to_le_bytes());
            s
        })
        .collect()
}

fn bench_kzg(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg");
    for n in [1024usize, 4096] {
        let srs = Arc::new(KzgSrs::insecure_deterministic(n, b"bench-seed"));
        let vc = KzgVectorCommitment::new(srs, n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let index = n / 3;
        let proof = vc.open(&values, index).unwrap();

        group.bench_function(format!("commit_{n}"), |b| {
            b.iter(|| vc.commit(black_box(&values)).unwrap());
        });
        group.bench_function(format!("open_{n}"), |b| {
            b.iter(|| vc.open(black_box(&values), black_box(index)).unwrap());
        });
        // Target: < 2 ms p99, independent of n.
        group.bench_function(format!("verify_{n}"), |b| {
            b.iter(|| {
                vc.verify(
                    black_box(&commitment),
                    black_box(index),
                    black_box(&values[index]),
                    black_box(&proof),
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_ipa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipa");
    for n in [256usize, 1024] {
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let index = n / 3;
        let proof = vc.open(&values, index).unwrap();

        group.bench_function(format!("commit_{n}"), |b| {
            b.iter(|| vc.commit(black_box(&values)).unwrap());
        });
        group.bench_function(format!("open_{n}"), |b| {
            b.iter(|| vc.open(black_box(&values), black_box(index)).unwrap());
        });
        // Target: < 12 ms p99 at n=1024.
        group.bench_function(format!("verify_{n}"), |b| {
            b.iter(|| {
                vc.verify(
                    black_box(&commitment),
                    black_box(index),
                    black_box(&values[index]),
                    black_box(&proof),
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_kzg, bench_ipa);
criterion_main!(benches);
