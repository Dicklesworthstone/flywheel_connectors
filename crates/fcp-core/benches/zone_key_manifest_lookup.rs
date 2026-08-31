//! `ZoneKeyManifest` recipient-lookup benchmark (br-d2oa0 + br-nw5zb).
//!
//! Measures the cost of `wrapped_key_for` / `wrapped_key_v4_for` /
//! `resolved_wrapped_key_for` at recipient counts N ∈ {8, 32, 128,
//! 256} for both:
//!
//! - **Linear scan** (the existing `ZoneKeyManifest::wrapped_key_for`
//!   implementation — `iter().find(|e| e.recipient == *node_id)`).
//! - **Indexed O(1)** (the new `IndexedZoneKeyManifest::wrapped_key_for`
//!   from br-d2oa0 — `HashMap` lookup).
//!
//! The d2oa0 fix is justified by the linear-scan cost at N=128/256;
//! the bench publishes the speedup for operators reasoning about
//! dispatcher cost growth as cohabitation manifests grow.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fcp_core::{
    IndexedZoneKeyManifest, NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance,
    TailscaleNodeId, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId,
    ZoneKeyManifest, wrap_zone_key,
};
use fcp_crypto::X25519SecretKey;

fn header(zone: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: fcp_cbor::SchemaId::new(
            "fcp.zone",
            "ZoneKeyManifest",
            semver::Version::new(1, 0, 0),
        ),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn make_manifest(n: usize) -> (ZoneKeyManifest, Vec<TailscaleNodeId>) {
    let zone = ZoneId::work();
    let zone_key = ZoneKey::from_bytes([0x42; 32]);
    let mut wrapped = Vec::with_capacity(n);
    let mut recipients = Vec::with_capacity(n);
    for i in 0..n {
        let sk = X25519SecretKey::generate();
        let recipient = TailscaleNodeId::new(format!("100.64.{}.{}", (i / 256) % 256, i % 256));
        let wrap = wrap_zone_key(
            &sk.public_key(),
            &zone,
            &recipient,
            1_700_000_000,
            &zone_key,
        )
        .expect("HPKE wrap");
        wrapped.push(wrap);
        recipients.push(recipient);
    }
    let manifest = ZoneKeyManifest {
        header: header(&zone),
        zone_id: zone,
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: 1_700_000_000,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: wrapped,
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: NodeSignature::new(NodeId::new("owner"), [0u8; 64], 1_700_000_000),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    };
    (manifest, recipients)
}

/// Hit-path lookup: pick a deterministic recipient near the END of
/// the list (worst case for linear scan, identical work for `HashMap`).
fn bench_v3_hit_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_key_manifest_v3_hit");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));
    group.throughput(Throughput::Elements(1));

    for &n in &[8usize, 32, 128, 256] {
        let (manifest, recipients) = make_manifest(n);
        // Pick recipient near the END so linear scan does the worst-
        // case ~N comparisons.
        let target = recipients[n - 1].clone();

        group.bench_function(format!("linear_scan/n={n}"), |b| {
            b.iter(|| {
                let r = black_box(manifest.wrapped_key_for(black_box(&target)));
                debug_assert!(r.is_some());
            });
        });

        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("benchmark fixtures have unique recipients");
        group.bench_function(format!("indexed_o1/n={n}"), |b| {
            b.iter(|| {
                let r = black_box(indexed.wrapped_key_for(black_box(&target)));
                debug_assert!(r.is_some());
            });
        });
    }

    group.finish();
}

/// Miss-path lookup: target a recipient that's NOT in the manifest.
/// Linear scan iterates the full list every time (worst case);
/// `HashMap` lookup is constant-time.
fn bench_v3_miss_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_key_manifest_v3_miss");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));
    group.throughput(Throughput::Elements(1));

    let missing = TailscaleNodeId::new("100.99.0.0".to_owned());

    for &n in &[8usize, 32, 128, 256] {
        let (manifest, _) = make_manifest(n);
        group.bench_function(format!("linear_scan/n={n}"), |b| {
            b.iter(|| {
                let r = black_box(manifest.wrapped_key_for(black_box(&missing)));
                debug_assert!(r.is_none());
            });
        });

        let indexed = IndexedZoneKeyManifest::new(manifest)
            .expect("benchmark fixtures have unique recipients");
        group.bench_function(format!("indexed_o1/n={n}"), |b| {
            b.iter(|| {
                let r = black_box(indexed.wrapped_key_for(black_box(&missing)));
                debug_assert!(r.is_none());
            });
        });
    }

    group.finish();
}

/// Index construction cost — the one-time price you pay for the
/// O(1) lookups. At N=256 this should still be sub-microsecond.
/// Operators sizing whether to wrap a manifest per-request vs
/// per-zone need this number.
fn bench_index_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_key_manifest_indexed_construction");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));
    group.throughput(Throughput::Elements(1));

    for &n in &[8usize, 32, 128, 256] {
        let (manifest, _) = make_manifest(n);
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                let idx = black_box(
                    IndexedZoneKeyManifest::new(black_box(manifest.clone()))
                        .expect("benchmark fixtures have unique recipients"),
                );
                drop(idx);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_v3_hit_lookup,
    bench_v3_miss_lookup,
    bench_index_construction,
);
criterion_main!(benches);
