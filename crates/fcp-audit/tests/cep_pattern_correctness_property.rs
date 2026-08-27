use fcp_audit::{
    AnomalyAlertError, AuditEntry, AuditEntryBuilder, EventPattern, EventPatternError,
    EventPredicate, HybridLogicalTimestamp, Severity, event_types,
};
use proptest::prelude::*;
use serde_json::json;

fn entry(id: &str, event_type: &str, zone_id: &str, seq: u64, physical_ms: u64) -> AuditEntry {
    AuditEntryBuilder::new()
        .id(id)
        .event_type(event_type)
        .actor("agent")
        .zone_id(zone_id)
        .seq(seq)
        .occurred_at(physical_ms / 1_000)
        .hlc(HybridLogicalTimestamp::new(physical_ms, 0, "node-a"))
        .build()
        .expect("test entry is valid")
}

fn cross_zone_pattern(max_window_ms: u64) -> EventPattern {
    EventPattern::new(
        "work-then-public-capability",
        vec![
            EventPredicate::event_type_in_zone("capability.invoke", "z:work"),
            EventPredicate::event_type_in_zone("capability.invoke", "z:public"),
        ],
        max_window_ms,
    )
    .expect("pattern is valid")
}

#[test]
fn cross_zone_sequence_matches_within_window() {
    let pattern = cross_zone_pattern(60_000);
    let entries = vec![
        entry("a", "capability.invoke", "z:work", 1, 1_000),
        entry("b", "capability.invoke", "z:public", 2, 30_000),
    ];

    let matches = pattern.find_matches(&entries);

    assert_eq!(matches.len(), 1);
    let evidence = &matches[0];
    assert_eq!(evidence.pattern_name, "work-then-public-capability");
    assert_eq!(evidence.entry_ids, ["a", "b"]);
    assert_eq!(evidence.zones, ["z:work", "z:public"]);
    assert_eq!(
        evidence.event_types,
        ["capability.invoke", "capability.invoke"]
    );
    assert_eq!(evidence.duration_ms, 29_000);
}

#[test]
fn cross_zone_sequence_does_not_match_outside_window() {
    let pattern = cross_zone_pattern(5_000);
    let entries = vec![
        entry("a", "capability.invoke", "z:work", 1, 1_000),
        entry("b", "capability.invoke", "z:public", 2, 10_001),
    ];

    assert_eq!(pattern.find_matches(&entries), [] as [fcp_audit::PatternMatch; 0]);
}

#[test]
fn matcher_sorts_by_hlc_before_matching() {
    let pattern = cross_zone_pattern(60_000);
    let entries = vec![
        entry("b", "capability.invoke", "z:public", 2, 30_000),
        entry("a", "capability.invoke", "z:work", 1, 1_000),
    ];

    let matches = pattern.find_matches(&entries);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].entry_ids, ["a", "b"]);
}

#[test]
fn pattern_match_materializes_anomaly_alert_entry() {
    let pattern = cross_zone_pattern(60_000);
    let entries = vec![
        entry("a", "capability.invoke", "z:work", 1, 1_000),
        entry("b", "capability.invoke", "z:public", 2, 30_000),
    ];
    let evidence = pattern
        .find_matches(&entries)
        .pop()
        .expect("pattern should match");

    let alert = evidence
        .to_anomaly_alert_entry("fcp.audit.cep", "z:work", 3, Some("prev-entry"))
        .expect("alert entry materializes");

    assert_eq!(alert.event_type, event_types::CEP_ANOMALY_ALERT);
    assert_eq!(alert.severity, Severity::Error);
    assert_eq!(alert.actor, "fcp.audit.cep");
    assert_eq!(alert.zone_id, "z:work");
    assert_eq!(alert.seq, 3);
    assert_eq!(alert.prev.as_deref(), Some("prev-entry"));
    assert_eq!(alert.occurred_at, 30);
    assert_eq!(alert.hlc, evidence.last_hlc);
    assert_eq!(
        alert.id,
        alert
            .computed_id()
            .expect("computed anomaly alert id is stable")
    );
    assert_eq!(
        alert.metadata.get("schema_version"),
        Some(&json!("fcp.audit.cep_anomaly_alert.v1"))
    );
    assert_eq!(
        alert.metadata.get("pattern_name"),
        Some(&json!("work-then-public-capability"))
    );
    assert_eq!(
        alert.metadata.get("matched_entry_ids"),
        Some(&json!(["a", "b"]))
    );
    assert_eq!(
        alert.metadata.get("matched_zones"),
        Some(&json!(["z:work", "z:public"]))
    );
    assert_eq!(
        alert.metadata.get("matched_event_types"),
        Some(&json!(["capability.invoke", "capability.invoke"]))
    );
    assert_eq!(alert.metadata.get("duration_ms"), Some(&json!(29_000)));
    assert_eq!(alert.metadata.get("match_count"), Some(&json!(2)));
}

#[test]
fn anomaly_alert_context_fails_closed() {
    let pattern = cross_zone_pattern(60_000);
    let entries = vec![
        entry("a", "capability.invoke", "z:work", 1, 1_000),
        entry("b", "capability.invoke", "z:public", 2, 30_000),
    ];
    let evidence = pattern
        .find_matches(&entries)
        .pop()
        .expect("pattern should match");

    assert!(matches!(
        evidence.to_anomaly_alert_entry("  ", "z:ops", 3, None),
        Err(AnomalyAlertError::EmptyActor)
    ));
    assert!(matches!(
        evidence.to_anomaly_alert_entry("fcp.audit.cep", "  ", 3, None),
        Err(AnomalyAlertError::EmptyZone)
    ));
}

#[test]
fn invalid_patterns_fail_closed() {
    assert_eq!(
        EventPattern::new("", vec![EventPredicate::event_type("x")], 1).unwrap_err(),
        EventPatternError::EmptyName
    );
    assert_eq!(
        EventPattern::new("empty", Vec::new(), 1).unwrap_err(),
        EventPatternError::EmptySequence
    );
    assert_eq!(
        EventPattern::new("zero", vec![EventPredicate::event_type("x")], 0).unwrap_err(),
        EventPatternError::ZeroWindow
    );
    assert_eq!(
        EventPattern::new(
            "wildcard",
            vec![EventPredicate {
                event_type: None,
                zone_id: None,
            }],
            1,
        )
        .unwrap_err(),
        EventPatternError::EmptyPredicate
    );
    assert_eq!(
        EventPattern::new("empty-event-type", vec![EventPredicate::event_type("")], 1).unwrap_err(),
        EventPatternError::EmptyPredicate
    );
    assert_eq!(
        EventPattern::new("blank-zone", vec![EventPredicate::zone("   ")], 1).unwrap_err(),
        EventPatternError::EmptyPredicate
    );
}

#[test]
fn deserialization_enforces_constructor_invariants() {
    // An empty `sequence` previously slipped past `new()` via serde and then
    // panicked `find_matches` at `sequence[0]`. Deserialization must now reject
    // it the same way the constructor does.
    let empty_sequence = r#"{"name":"x","sequence":[],"max_window_ms":5}"#;
    assert!(
        serde_json::from_str::<EventPattern>(empty_sequence).is_err(),
        "deserializing an empty-sequence pattern must fail, not build a panicking pattern"
    );

    // Other constructor invariants are enforced on the deserialize path too.
    assert!(
        serde_json::from_str::<EventPattern>(
            r#"{"name":"","sequence":[{"event_type":"x"}],"max_window_ms":5}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<EventPattern>(
            r#"{"name":"z","sequence":[{"event_type":"x"}],"max_window_ms":0}"#
        )
        .is_err()
    );

    // A valid pattern round-trips through serde and matches without panicking.
    let valid = cross_zone_pattern(60_000);
    let json = serde_json::to_string(&valid).expect("serialize");
    let restored: EventPattern = serde_json::from_str(&json).expect("valid pattern deserializes");
    assert_eq!(restored, valid);
    let entries = vec![
        entry("a", "capability.invoke", "z:work", 1, 1_000),
        entry("b", "capability.invoke", "z:public", 2, 30_000),
    ];
    assert_eq!(restored.find_matches(&entries).len(), 1);
}

proptest! {
    #[test]
    fn window_boundary_is_inclusive(offset in 0_u64..=60_000) {
        let pattern = cross_zone_pattern(60_000);
        let entries = vec![
            entry("a", "capability.invoke", "z:work", 1, 100_000),
            entry("b", "capability.invoke", "z:public", 2, 100_000 + offset),
        ];

        let matches = pattern.find_matches(&entries);

        prop_assert_eq!(matches.len(), 1);
        prop_assert_eq!(matches[0].duration_ms, offset);
    }
}
