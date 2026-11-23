//! Benchmarks for symbol store operations.
//!
//! These benchmarks measure the performance of core symbol store operations
//! as required by the FCP2 store acceptance criteria.

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_async_core::runtime::Runtime;
use fcp_prelude::{ObjectId, ZoneId};
use fcp_store::{
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    StoredSymbol, SymbolMeta, SymbolStore,
};
use std::hint::black_box;

fn test_zone() -> ZoneId {
    "z:bench".parse().unwrap()
}

const fn test_object_id(n: u8) -> ObjectId {
    let mut bytes = [0_u8; 32];
    bytes[0] = n;
    ObjectId::from_bytes(bytes)
}

fn test_object_meta(object_id: ObjectId, source_symbols: u32) -> ObjectSymbolMeta {
    test_object_meta_with_symbol_size(object_id, source_symbols, 256)
}

fn test_object_meta_with_symbol_size(
    object_id: ObjectId,
    source_symbols: u32,
    symbol_size: usize,
) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id,
        zone_id: test_zone(),
        oti: ObjectTransmissionInfo {
            transfer_length: u64::from(source_symbols) * u64::try_from(symbol_size).unwrap(),
            symbol_size: u16::try_from(symbol_size).unwrap(),
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols,
        first_symbol_at: 1_000_000,
    }
}

fn test_symbol(object_id: ObjectId, esi: u32, size: usize) -> StoredSymbol {
    StoredSymbol {
        meta: SymbolMeta {
            object_id,
            esi,
            zone_id: test_zone(),
            source_node: Some(1),
            stored_at: 1_000_000,
        },
        data: Bytes::from(vec![0xAB_u8; size]),
    }
}

fn bench_put_symbol(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("put_symbol");

    for symbol_size in [64, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(symbol_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(symbol_size),
            &symbol_size,
            |b, &size| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                        let obj_id = test_object_id(1);
                        store
                            .put_object_meta(test_object_meta_with_symbol_size(obj_id, 100, size))
                            .await
                            .unwrap();

                        for esi in 0..100 {
                            store
                                .put_symbol(test_symbol(obj_id, esi, size))
                                .await
                                .unwrap();
                        }
                        black_box(store.symbol_count(&obj_id).await)
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_put_object_meta_sparse(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("put_object_meta_sparse");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(2));

    for source_symbols in [100_u32, 1_000, 10_000, 56_403] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(source_symbols),
            &source_symbols,
            |b, &source_symbols| {
                b.iter_batched(
                    || {
                        (
                            MemorySymbolStore::new(MemorySymbolStoreConfig::default()),
                            test_object_meta(test_object_id(1), source_symbols),
                        )
                    },
                    |(store, meta)| {
                        rt.block_on(async move {
                            store.put_object_meta(meta).await.unwrap();
                            black_box(store.storage_used().await)
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_get_symbol(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let obj_id = test_object_id(1);

    // Pre-populate the store
    rt.block_on(async {
        store
            .put_object_meta(test_object_meta(obj_id, 1000))
            .await
            .unwrap();
        for esi in 0..1000 {
            store
                .put_symbol(test_symbol(obj_id, esi, 256))
                .await
                .unwrap();
        }
    });

    let mut group = c.benchmark_group("get_symbol");
    group.throughput(Throughput::Elements(1));

    group.bench_function("single_lookup", |b| {
        let mut esi = 0_u32;
        b.iter(|| {
            rt.block_on(async {
                let result = store.get_symbol(&obj_id, esi % 1000).await.unwrap();
                esi = esi.wrapping_add(1);
                black_box(result)
            });
        });
    });

    group.bench_function("sequential_100", |b| {
        b.iter(|| {
            rt.block_on(async {
                for esi in 0..100 {
                    black_box(store.get_symbol(&obj_id, esi).await.unwrap());
                }
            });
        });
    });

    group.finish();
}

fn bench_get_all_symbols(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("get_all_symbols");

    for symbol_count in [10, 100, 500, 1000] {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let obj_id = test_object_id(1);

        rt.block_on(async {
            store
                .put_object_meta(test_object_meta(obj_id, symbol_count))
                .await
                .unwrap();
            for esi in 0..symbol_count {
                store
                    .put_symbol(test_symbol(obj_id, esi, 256))
                    .await
                    .unwrap();
            }
        });

        group.throughput(Throughput::Elements(u64::from(symbol_count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(symbol_count),
            &symbol_count,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async { black_box(store.get_all_symbols(&obj_id).await) });
                });
            },
        );
    }

    group.finish();
}

fn bench_can_reconstruct(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("can_reconstruct");

    // Test with varying symbol counts relative to source_symbols
    for (source_symbols, stored_symbols) in [(100, 50), (100, 100), (500, 500), (1000, 1000)] {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let obj_id = test_object_id(1);

        rt.block_on(async {
            store
                .put_object_meta(test_object_meta(obj_id, source_symbols))
                .await
                .unwrap();
            for esi in 0..stored_symbols {
                store
                    .put_symbol(test_symbol(obj_id, esi, 256))
                    .await
                    .unwrap();
            }
        });

        group.bench_with_input(
            BenchmarkId::new("symbols", format!("{source_symbols}_{stored_symbols}")),
            &(source_symbols, stored_symbols),
            |b, _| {
                b.iter(|| rt.block_on(async { black_box(store.can_reconstruct(&obj_id).await) }));
            },
        );
    }

    group.finish();
}

fn bench_get_distribution(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("get_distribution");

    for symbol_count in [10, 100, 500] {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let obj_id = test_object_id(1);

        rt.block_on(async {
            store
                .put_object_meta(test_object_meta(obj_id, symbol_count))
                .await
                .unwrap();
            for esi in 0..symbol_count {
                let mut symbol = test_symbol(obj_id, esi, 256);
                // Distribute across multiple nodes for realistic coverage
                symbol.meta.source_node = Some(u64::from(esi % 5));
                store.put_symbol(symbol).await.unwrap();
            }
        });

        group.throughput(Throughput::Elements(u64::from(symbol_count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(symbol_count),
            &symbol_count,
            |b, _| {
                b.iter(|| rt.block_on(async { black_box(store.get_distribution(&obj_id).await) }));
            },
        );
    }

    group.finish();
}

fn bench_list_zone(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("list_zone");

    for object_count in [10_u32, 100, 500] {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

        rt.block_on(async {
            for obj_idx in 0..object_count {
                #[allow(clippy::cast_possible_truncation)]
                let obj_id = test_object_id(obj_idx as u8);
                store
                    .put_object_meta(test_object_meta(obj_id, 100))
                    .await
                    .unwrap();
            }
        });

        group.throughput(Throughput::Elements(u64::from(object_count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(object_count),
            &object_count,
            |b, _| b.iter(|| rt.block_on(async { black_box(store.list_zone(&test_zone()).await) })),
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_put_symbol,
    bench_put_object_meta_sparse,
    bench_get_symbol,
    bench_get_all_symbols,
    bench_can_reconstruct,
    bench_get_distribution,
    bench_list_zone,
);
criterion_main!(benches);
