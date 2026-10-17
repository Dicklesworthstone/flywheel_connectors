use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fcp_crypto_hw::{Blake3Hasher, Blake3Tier};

fn blake3_dispatch(c: &mut Criterion) {
    let payload = vec![0xA5_u8; 64 * 1024];
    let mut group = c.benchmark_group("blake3_64kib");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    for tier in [
        Blake3Tier::Portable,
        Blake3Tier::X86Avx2,
        Blake3Tier::X86Avx512,
    ] {
        let hasher = Blake3Hasher::with_tier(tier);
        group.bench_function(format!("blake3_hash_{}", tier.as_str()), |b| {
            b.iter(|| black_box(hasher.hash(black_box(&payload))));
        });
    }

    group.finish();
}

criterion_group!(benches, blake3_dispatch);
criterion_main!(benches);
