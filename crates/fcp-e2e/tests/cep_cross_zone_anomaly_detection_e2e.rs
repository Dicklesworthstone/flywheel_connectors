//! E2E test for Phase Q.D (`flywheel_connectors-angoc.11.9`):
//! Flink-style CEP audit pattern matching across zones (`EventPattern`) +
//! deterministic reservoir-sampling compaction (`ReservoirCompactor`).

use std::time::{Duration, Instant};

use fcp_audit::{
    AuditEntry, AuditEntryBuilder, CEP_ANOMALY_ALERT_SCHEMA_VERSION, EventPattern, EventPredicate,
    HybridLogicalClock, HybridLogicalTimestamp, ReservoirCompactor, Severity, compact_entries,
    event_types,
};
use serde_json::json;

fn make_entry(
    id: &str,
    event_type: &str,
    zone_id: &str,
    seq: u64,
    hlc: HybridLogicalTimestamp,
) -> AuditEntry {
    AuditEntryBuilder::new()
        .id(id)
        .event_type(event_type)
        .actor("agent:executor")
        .zone_id(zone_id)
        .seq(seq)
        .occurred_at(hlc.physical_ms / 1_000)
        .hlc(hlc)
        .build()
        .expect("valid audit entry")
}

#[test]
fn cep_cross_zone_anomaly_detection_surfaces_alert_under_one_second_e2e() {
    let pattern = EventPattern::new(
        "private-secret-to-public-egress",
        vec![
            EventPredicate::event_type_in_zone(event_types::SECRET_ACCESS, "z:private"),
            EventPredicate::event_type_in_zone(event_types::ZONE_TRANSITION, "z:work"),
            EventPredicate::event_type_in_zone(event_types::CAPABILITY_INVOKE, "z:public"),
        ],
        30_000,
    )
    .expect("valid cross-zone CEP pattern");

    let mut clock_priv = HybridLogicalClock::new("node-priv");
    let mut clock_work = HybridLogicalClock::new("node-work");
    let mut clock_pub = HybridLogicalClock::new("node-pub");

    let t_secret = clock_priv.tick(1_700_000_001_000);
    let t_transition = clock_work.merge(&t_secret, 1_700_000_005_000);
    let t_egress = clock_pub.merge(&t_transition, 1_700_000_012_000);

    // Feed out-of-order with 500 background entries to exercise HLC sorting + NFA matching.
    let mut stream = Vec::with_capacity(503);
    for idx in 0..500u64 {
        let hlc = HybridLogicalTimestamp::new(1_700_000_000_000 + idx * 50, 0, "node-bg");
        stream.push(make_entry(
            &format!("bg-{idx}"),
            event_types::CAPABILITY_INVOKE,
            "z:work",
            idx + 10,
            hlc,
        ));
    }
    stream.push(make_entry(
        "evt-public-egress",
        event_types::CAPABILITY_INVOKE,
        "z:public",
        3,
        t_egress,
    ));
    stream.push(make_entry(
        "evt-private-secret",
        event_types::SECRET_ACCESS,
        "z:private",
        1,
        t_secret,
    ));
    stream.push(make_entry(
        "evt-work-transition",
        event_types::ZONE_TRANSITION,
        "z:work",
        2,
        t_transition,
    ));

    let start = Instant::now();
    let matches = pattern.find_matches(&stream);
    assert_eq!(matches.len(), 1, "expected exactly 1 cross-zone anomaly match");

    let matched = &matches[0];
    let alert_entry = matched
        .to_anomaly_alert_entry(
            "fcp.audit.cep",
            "z:private",
            504,
            Some("evt-public-egress"),
        )
        .expect("anomaly alert materializes");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "CEP anomaly detection + alert materialization must complete in < 1s (took {elapsed:?})"
    );
    assert_eq!(alert_entry.event_type, event_types::CEP_ANOMALY_ALERT);
    assert_eq!(alert_entry.severity, Severity::Error);
    assert_eq!(
        alert_entry.metadata.get("schema_version"),
        Some(&json!(CEP_ANOMALY_ALERT_SCHEMA_VERSION))
    );
    assert_eq!(
        alert_entry.metadata.get("matched_entry_ids"),
        Some(&json!([
            "evt-private-secret",
            "evt-work-transition",
            "evt-public-egress"
        ]))
    );
    assert_eq!(
        alert_entry.metadata.get("matched_zones"),
        Some(&json!(["z:private", "z:work", "z:public"]))
    );
    assert_eq!(alert_entry.metadata.get("duration_ms"), Some(&json!(11_000)));
    assert_eq!(
        alert_entry.id,
        alert_entry.computed_id().expect("computed id valid")
    );
}

#[test]
fn cep_and_reservoir_compaction_pipeline_e2e() {
    let entries: Vec<AuditEntry> = (1..=2_000u64)
        .map(|seq| {
            let hlc = HybridLogicalTimestamp::new(1_700_000_000_000 + seq * 10, 0, "node-a");
            make_entry(
                &format!("entry-{seq}"),
                event_types::CAPABILITY_INVOKE,
                "z:work",
                seq,
                hlc,
            )
        })
        .collect();

    let compacted = compact_entries(entries.clone(), 128, 0xCAFE_BABE_1234_5678)
        .expect("reservoir compaction succeeds");
    assert_eq!(compacted.entries.len(), 128);
    assert_eq!(compacted.report.total_observed, 2_000);
    assert_eq!(compacted.report.retained_count, 128);
    assert_eq!(compacted.report.dropped_count, 1_872);
    assert_eq!(compacted.report.observed_seq_min, Some(1));
    assert_eq!(compacted.report.observed_seq_max, Some(2_000));
    assert!(!compacted.report.sample_digest.is_empty());

    // Retained entries must be strictly sorted by sequence number for deterministic replay.
    for pair in compacted.entries.windows(2) {
        assert!(pair[0].seq < pair[1].seq);
    }

    // Streaming push via ReservoirCompactor with the same seed produces identical digest.
    let mut streaming =
        ReservoirCompactor::new(128, 0xCAFE_BABE_1234_5678).expect("valid capacity");
    streaming.extend(entries);
    let streaming_result = streaming.finish();
    assert_eq!(
        streaming_result.report.sample_digest,
        compacted.report.sample_digest
    );
}
