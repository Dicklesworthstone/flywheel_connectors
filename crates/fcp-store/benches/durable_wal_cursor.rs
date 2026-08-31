//! Criterion coverage for durable WAL append throughput and cursor walks.

use std::hint::black_box;
use std::time::Duration;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_async_core::runtime::Runtime;
use fcp_prelude::{
    ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_store::{
    DurableObjectStore, DurableObjectStoreConfig, DurableSymbolStore, DurableSymbolStoreConfig,
    GcRoots, ObjectStore, ObjectSymbolMeta, ObjectTransmissionInfo, StoredSymbol, SymbolMeta,
    SymbolStore, snapshot_zone_lifecycle,
};
use tempfile::TempDir;

struct DurableFixture {
    _dir: TempDir,
    store: DurableObjectStore,
}

struct DurableSymbolFixture {
    _dir: TempDir,
    store: DurableSymbolStore,
}

fn bench_zone() -> ZoneId {
    "z:bench:store".parse().unwrap()
}

fn bench_schema() -> fcp_cbor::SchemaId {
    fcp_cbor::SchemaId::new(
        "fcp.store.bench",
        "DurableObject",
        semver::Version::new(1, 0, 0),
    )
}

fn bench_object_id(index: u64) -> ObjectId {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&index.to_le_bytes());
    ObjectId::from_bytes(bytes)
}

fn bench_object(index: u64, body_len: usize, refs: Vec<ObjectId>) -> StoredObject {
    let zone_id = bench_zone();
    StoredObject {
        object_id: bench_object_id(index),
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: bench_schema(),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000_u64.saturating_add(index),
            provenance: Provenance::new(zone_id),
            refs,
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        body: vec![u8::try_from(index % 251).unwrap(); body_len],
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

fn durable_fixture() -> DurableFixture {
    let dir = TempDir::new().unwrap();
    let mut config = DurableObjectStoreConfig::new(dir.path());
    config.max_bytes = 512 * 1024 * 1024;
    config.checkpoint_after_ops = 0;
    let store = DurableObjectStore::open(config).unwrap();
    DurableFixture { _dir: dir, store }
}

fn durable_symbol_fixture() -> DurableSymbolFixture {
    let dir = TempDir::new().unwrap();
    let mut config = DurableSymbolStoreConfig::new(dir.path().join("symbols"));
    config.max_bytes = 512 * 1024 * 1024;
    config.checkpoint_after_ops = 0;
    let store = DurableSymbolStore::open(config).unwrap();
    DurableSymbolFixture { _dir: dir, store }
}

fn bench_symbol_oti(source_symbols: u32, symbol_size: usize) -> ObjectTransmissionInfo {
    ObjectTransmissionInfo {
        transfer_length: u64::from(source_symbols) * u64::try_from(symbol_size).unwrap(),
        symbol_size: u16::try_from(symbol_size).unwrap(),
        source_blocks: 1,
        sub_blocks: 1,
        alignment: 1,
        payload_hash: None,
    }
}

fn bench_symbol_meta(index: u64, source_symbols: u32, symbol_size: usize) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: bench_object_id(index),
        zone_id: bench_zone(),
        oti: bench_symbol_oti(source_symbols, symbol_size),
        source_symbols,
        first_symbol_at: 1_700_000_000_u64.saturating_add(index),
    }
}

fn bench_symbol(index: u64, esi: u32, symbol_size: usize) -> StoredSymbol {
    StoredSymbol {
        meta: SymbolMeta {
            object_id: bench_object_id(index),
            esi,
            zone_id: bench_zone(),
            source_node: Some(1),
            stored_at: 1_700_000_000_u64.saturating_add(index),
        },
        data: Bytes::from(vec![u8::try_from(esi % 251).unwrap(); symbol_size]),
    }
}

fn populated_fixture(rt: &Runtime, object_count: u64) -> DurableFixture {
    let fixture = durable_fixture();
    rt.block_on(async {
        for index in 0..object_count {
            let refs = if index + 1 < object_count {
                vec![bench_object_id(index + 1)]
            } else {
                Vec::new()
            };
            fixture
                .store
                .put(bench_object(index, 128, refs))
                .await
                .unwrap();
        }
    });
    fixture
}

fn bench_wal_append_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("durable_wal_append_throughput");

    for body_len in [256_usize, 4_096] {
        let fixture = durable_fixture();
        let mut sequence = 0_u64;

        group.throughput(Throughput::Bytes(body_len as u64));
        group.bench_with_input(
            BenchmarkId::new("body_bytes", body_len),
            &body_len,
            |b, &body_len| {
                b.iter(|| {
                    sequence = sequence.saturating_add(1);
                    let object = bench_object(sequence, body_len, Vec::new());
                    rt.block_on(async {
                        fixture.store.put(object).await.unwrap();
                    });
                    black_box(sequence);
                });
            },
        );
    }

    group.finish();
}

#[allow(clippy::significant_drop_tightening)]
fn bench_cursor_walk_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let zone_id = bench_zone();
    let mut list_group = c.benchmark_group("durable_cursor_walk_list_zone");

    for object_count in [128_u64, 1_024, 4_096] {
        let fixture = populated_fixture(&rt, object_count);

        list_group.throughput(Throughput::Elements(object_count));
        list_group.bench_with_input(
            BenchmarkId::from_parameter(object_count),
            &object_count,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async { black_box(fixture.store.list_zone(&zone_id).await) });
                });
            },
        );
    }

    list_group.finish();

    let mut lifecycle_group = c.benchmark_group("durable_cursor_walk_lifecycle_snapshot");
    for object_count in [128_u64, 1_024, 4_096] {
        let fixture = populated_fixture(&rt, object_count);
        let mut roots = GcRoots::new();
        roots.set_checkpoint(bench_object_id(0));

        lifecycle_group.throughput(Throughput::Elements(object_count));
        lifecycle_group.bench_with_input(
            BenchmarkId::from_parameter(object_count),
            &object_count,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(
                            snapshot_zone_lifecycle(
                                &zone_id,
                                &roots,
                                &fixture.store,
                                None,
                                1_800_000_000,
                            )
                            .await
                            .unwrap(),
                        );
                    });
                });
            },
        );
    }

    lifecycle_group.finish();
}

fn bench_durable_symbol_mutation_flow(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("durable_symbol_mutation_flow");

    for (source_symbols, symbol_size) in [(8_u32, 256_usize), (64, 1_024)] {
        let fixture = durable_symbol_fixture();
        let mut object_index = 0_u64;

        group.throughput(Throughput::Bytes(
            u64::from(source_symbols) * u64::try_from(symbol_size).unwrap(),
        ));
        group.bench_with_input(
            BenchmarkId::new(
                "put_meta_plus_symbols",
                format!("{source_symbols}x{symbol_size}"),
            ),
            &(source_symbols, symbol_size),
            |b, &(source_symbols, symbol_size)| {
                b.iter(|| {
                    object_index = object_index.saturating_add(1);
                    let meta = bench_symbol_meta(object_index, source_symbols, symbol_size);
                    rt.block_on(async {
                        fixture.store.put_object_meta(meta).await.unwrap();
                        for esi in 0..source_symbols {
                            fixture
                                .store
                                .put_symbol(bench_symbol(object_index, esi, symbol_size))
                                .await
                                .unwrap();
                        }
                    });
                    black_box(object_index);
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_wal_append_throughput, bench_cursor_walk_latency, bench_durable_symbol_mutation_flow
}
criterion_main!(benches);
