use std::time::Instant;

use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectHeader, ObjectId, Provenance, QuotientFilter, RevocationObject, RevocationRegistry,
    RevocationScope, ZoneId,
};
use semver::Version;

fn object_id_from_counter(counter: u64) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-core-quotient-filter-test");
    hasher.update(&counter.to_le_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

fn revocation_for(object_id: ObjectId) -> RevocationObject {
    RevocationObject {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        revoked: vec![object_id],
        scope: RevocationScope::Capability,
        reason: "quotient-cache-test".into(),
        effective_at: 1_700_000_000,
        expires_at: None,
        signature: [0; 64],
    }
}

#[test]
fn test_no_false_negatives_after_delete() {
    let item_count = 1_000_000_u64;
    let mut filter = QuotientFilter::with_capacity(usize::try_from(item_count).unwrap_or(0));

    for counter in 0..item_count {
        filter.insert(&object_id_from_counter(counter));
    }

    for counter in (0..item_count).step_by(2) {
        assert!(filter.delete(&object_id_from_counter(counter)));
    }

    for counter in (1..item_count).step_by(2) {
        assert!(
            filter.may_contain(&object_id_from_counter(counter)),
            "remaining inserted item {counter} produced a false negative"
        );
    }
}

#[test]
fn test_fpr_bounded_at_2_pow_minus_16() {
    let insert_count = 100_000_u64;
    let probe_count = 1_000_000_u64;
    let mut filter = QuotientFilter::with_capacity(usize::try_from(insert_count).unwrap_or(0));

    for counter in 0..insert_count {
        filter.insert(&object_id_from_counter(counter));
    }

    let mut false_positives = 0_u64;
    for counter in insert_count..(insert_count + probe_count) {
        if filter.may_contain(&object_id_from_counter(counter)) {
            false_positives += 1;
        }
    }

    let max_false_positives = 16;
    assert!(
        false_positives <= max_false_positives,
        "observed {false_positives} false positives over {probe_count} probes"
    );
}

#[test]
fn test_memory_at_most_10_bytes_per_entry() {
    let insert_count = 100_000_usize;
    let mut filter = QuotientFilter::with_capacity(insert_count);

    for counter in 0..u64::try_from(insert_count).unwrap_or(0) {
        filter.insert(&object_id_from_counter(counter));
    }

    let bytes_used = std::mem::size_of_val(&filter) + filter.heap_size_bytes();
    assert!(
        bytes_used <= insert_count * 10,
        "filter used {bytes_used} bytes for {insert_count} entries"
    );
}

#[test]
fn test_cache_eviction_latency_100ms_p99() {
    let revoked_id = object_id_from_counter(42);
    let revocation = revocation_for(revoked_id);
    let mut peer_latencies = Vec::with_capacity(10);
    let mut peers = (0..10)
        .map(|_| RevocationRegistry::with_capacity(1))
        .collect::<Vec<_>>();

    for peer in &mut peers {
        let start = Instant::now();
        peer.add_revocation(&revocation);
        assert!(peer.quotient_cache.may_contain(&revoked_id));
        assert!(peer.is_revoked(&revoked_id));
        peer_latencies.push(start.elapsed());
    }

    peer_latencies.sort_unstable();
    let p99 = peer_latencies[peer_latencies.len() - 1];
    assert!(
        p99.as_millis() <= 100,
        "synthetic 10-peer cache eviction p99 was {p99:?}"
    );
}
