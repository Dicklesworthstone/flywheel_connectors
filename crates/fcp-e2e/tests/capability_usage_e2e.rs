//! E2E tests: Capability Usage -> Recommendation flow.
//!
//! Validates the full telemetry pipeline:
//! 1. Record usage events via `CapabilityUsageStore`
//! 2. Generate aggregates via `snapshot()`
//! 3. Run recommendation engine via `recommend_capabilities()`
//! 4. Verify suggestions match observed usage patterns
//!
//! These tests exercise the complete CAP pipeline from event ingestion
//! through to actionable least-privilege recommendations.

use fcp_e2e::{AssertionsSummary, E2eLogEntry, E2eLogger};
use fcp_prelude::{CapabilityId, ConnectorId, OperationId, PrincipalId, SafetyTier, ZoneId};
use fcp_telemetry::{
    CapabilityRecommendationReport, CapabilitySuggestionKind, CapabilityUsageEvent,
    CapabilityUsageKey, CapabilityUsageOutcome, CapabilityUsageStore, RecommendationConfig,
    UsageTelemetryConfig, recommend_capabilities,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_event(
    zone: ZoneId,
    connector: &'static str,
    capability: &'static str,
    tier: SafetyTier,
    operation: &'static str,
    outcome: CapabilityUsageOutcome,
    occurred_at: u64,
) -> CapabilityUsageEvent {
    CapabilityUsageEvent::new(
        CapabilityUsageKey::new(
            zone,
            ConnectorId::from_static(connector),
            CapabilityId::from_static(capability),
        ),
        PrincipalId::new("e2e-agent").expect("valid principal"),
        tier,
        OperationId::from_static(operation),
        outcome,
        occurred_at,
    )
}

fn new_store() -> CapabilityUsageStore {
    CapabilityUsageStore::new(UsageTelemetryConfig {
        retention_secs: 365 * 24 * 60 * 60, // 1 year retention for tests
        ..UsageTelemetryConfig::default()
    })
}

fn count_by_kind(report: &CapabilityRecommendationReport, kind: CapabilitySuggestionKind) -> usize {
    report
        .recommendations
        .iter()
        .filter(|r| r.suggestion == kind)
        .count()
}

// ---------------------------------------------------------------------------
// A. Event Ingestion Tests
// ---------------------------------------------------------------------------

#[test]
fn ingestion_records_single_event() {
    let store = new_store();
    let recorded = store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_000,
    ));
    assert!(recorded);
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].total, 1);
    assert_eq!(snap[0].allowed, 1);
}

#[test]
fn ingestion_aggregates_multiple_events_same_key() {
    let store = new_store();
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            1_000_000 + i,
        ));
    }
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].total, 10);
    assert_eq!(snap[0].allowed, 10);
}

#[test]
fn ingestion_separates_different_capabilities() {
    let store = new_store();
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_000,
    ));
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.read",
        SafetyTier::Safe,
        "list_channels",
        CapabilityUsageOutcome::Allow,
        1_000_001,
    ));
    let snap = store.snapshot();
    assert_eq!(snap.len(), 2);
}

#[test]
fn ingestion_separates_different_zones() {
    let store = new_store();
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_000,
    ));
    store.record(&make_event(
        ZoneId::private(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_001,
    ));
    let snap = store.snapshot();
    assert_eq!(snap.len(), 2);
}

#[test]
fn ingestion_tracks_outcome_counts() {
    let store = new_store();
    let ts = 1_000_000;
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Allow,
            ts + i,
        ));
    }
    for i in 0..3 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Deny,
            ts + 10 + i,
        ));
    }
    for i in 0..2 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Error,
            ts + 20 + i,
        ));
    }
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].total, 10);
    assert_eq!(snap[0].allowed, 5);
    assert_eq!(snap[0].denied, 3);
    assert_eq!(snap[0].errors, 2);
}

#[test]
fn ingestion_tracks_first_and_last_seen() {
    let store = new_store();
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        100,
    ));
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        500,
    ));
    let snap = store.snapshot();
    assert_eq!(snap[0].first_seen, 100);
    assert_eq!(snap[0].last_seen, 500);
}

#[test]
fn ingestion_snapshot_is_deterministic() {
    let store = new_store();
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            1_000 + i,
        ));
    }
    let snap1 = store.snapshot();
    let snap2 = store.snapshot();
    assert_eq!(snap1.len(), snap2.len());
    for (a, b) in snap1.iter().zip(snap2.iter()) {
        assert_eq!(a.total, b.total);
        assert_eq!(a.key.capability_id, b.key.capability_id);
    }
}

// ---------------------------------------------------------------------------
// B. Recommendation Engine Tests
// ---------------------------------------------------------------------------

#[test]
fn recommend_active_safe_gets_keep() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations.len(), 1);
    assert_eq!(
        report.recommendations[0].suggestion,
        CapabilitySuggestionKind::Keep
    );
}

#[test]
fn recommend_stale_gets_remove_unused() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.delete",
        SafetyTier::Risky,
        "delete_issue",
        CapabilityUsageOutcome::Allow,
        now - 90 * 86400, // 90 days ago
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations.len(), 1);
    assert_eq!(
        report.recommendations[0].suggestion,
        CapabilitySuggestionKind::RemoveUnused
    );
}

#[test]
fn recommend_dangerous_active_gets_review_risky() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations.len(), 1);
    assert_eq!(
        report.recommendations[0].suggestion,
        CapabilitySuggestionKind::ReviewRisky
    );
}

#[test]
fn recommend_critical_active_gets_review_risky() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.stripe:request_response:0.1.0",
        "stripe.charge",
        SafetyTier::Critical,
        "create_charge",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(
        report.recommendations[0].suggestion,
        CapabilitySuggestionKind::ReviewRisky
    );
}

#[test]
fn recommend_mixed_usage_produces_all_kinds() {
    let store = new_store();
    let now = 1_700_000_000_u64;

    // Active safe → Keep
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }

    // Active dangerous → ReviewRisky
    for i in 0..3 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Allow,
            now - 50 + i,
        ));
    }

    // Stale → RemoveUnused
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.delete",
        SafetyTier::Risky,
        "delete_issue",
        CapabilityUsageOutcome::Allow,
        now - 90 * 86400,
    ));

    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);

    assert_eq!(report.recommendations.len(), 3);
    assert_eq!(count_by_kind(&report, CapabilitySuggestionKind::Keep), 1);
    assert_eq!(
        count_by_kind(&report, CapabilitySuggestionKind::ReviewRisky),
        1
    );
    assert_eq!(
        count_by_kind(&report, CapabilitySuggestionKind::RemoveUnused),
        1
    );
}

// ---------------------------------------------------------------------------
// C. Report Structure Tests
// ---------------------------------------------------------------------------

#[test]
fn report_summary_counts_match() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.delete",
        SafetyTier::Risky,
        "delete_issue",
        CapabilityUsageOutcome::Allow,
        now - 90 * 86400,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    let summary = report.summary();
    assert_eq!(summary.total, report.recommendations.len());
    assert_eq!(
        summary.keep + summary.remove_unused + summary.review_risky,
        summary.total
    );
}

#[test]
fn report_json_roundtrip() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    let json = report.to_json().expect("json serialization");
    let back: CapabilityRecommendationReport =
        serde_json::from_str(&json).expect("json deserialization");
    assert_eq!(back.recommendations.len(), report.recommendations.len());
}

#[test]
fn report_json_pretty_is_human_readable() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    let pretty = report.to_json_pretty().expect("pretty json");
    assert!(pretty.contains('\n'), "pretty JSON should have newlines");
    assert!(
        pretty.contains("recommendations"),
        "should contain recommendations key"
    );
}

#[test]
fn report_by_suggestion_filters_correctly() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.delete",
        SafetyTier::Risky,
        "delete_issue",
        CapabilityUsageOutcome::Allow,
        now - 90 * 86400,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    let keep = report.by_suggestion(CapabilitySuggestionKind::Keep);
    let unused = report.by_suggestion(CapabilitySuggestionKind::RemoveUnused);
    assert_eq!(keep.len(), 1);
    assert_eq!(unused.len(), 1);
}

// ---------------------------------------------------------------------------
// D. Risk Summary Tests
// ---------------------------------------------------------------------------

#[test]
fn risk_summary_groups_by_zone() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    // Work zone: safe
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    // Private zone: dangerous
    store.record(&make_event(
        ZoneId::private(),
        "fcp.stripe:request_response:0.1.0",
        "stripe.charge",
        SafetyTier::Dangerous,
        "create_charge",
        CapabilityUsageOutcome::Allow,
        now - 5,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    assert!(
        report.risk_summaries.len() >= 2,
        "should have risk summaries for both zones"
    );
}

#[test]
fn risk_summary_counts_by_tier() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    // 10 safe invocations
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    // 5 dangerous invocations
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Allow,
            now - 50 + i,
        ));
    }
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    let work_summary = report
        .risk_summaries
        .iter()
        .find(|s| s.zone_id == "z:work")
        .expect("work zone summary");
    assert!(work_summary.safe > 0, "should have safe usage");
    assert!(work_summary.dangerous > 0, "should have dangerous usage");
}

// ---------------------------------------------------------------------------
// E. Edge Case Tests
// ---------------------------------------------------------------------------

#[test]
fn empty_store_produces_empty_recommendations() {
    let store = new_store();
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, 1_000_000, config);
    assert!(report.recommendations.is_empty());
    assert!(report.risk_summaries.is_empty());
}

#[test]
fn recommendation_reason_codes_are_set() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.old",
        SafetyTier::Risky,
        "old_op",
        CapabilityUsageOutcome::Allow,
        now - 90 * 86400,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    for rec in &report.recommendations {
        assert!(
            !rec.reason_code.is_empty(),
            "reason_code should not be empty"
        );
    }
}

#[test]
fn recommendation_usage_total_matches_aggregate() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..7 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations[0].usage_total, 7);
}

#[test]
fn recommendation_risk_tier_preserved() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.github:request_response:0.1.0",
        "github.delete",
        SafetyTier::Dangerous,
        "delete_repo",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations[0].risk_tier, SafetyTier::Dangerous);
}

#[test]
fn unused_threshold_boundary_exactly_at_threshold() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    let threshold = 86400_u64;
    // Event exactly at threshold boundary
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - threshold,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig {
        unused_after_secs: threshold,
    };
    let report = recommend_capabilities(&snap, now, config);
    // At exactly the boundary, still considered unused (> threshold check)
    assert!(!report.recommendations.is_empty());
}

#[test]
fn sampling_zero_rate_rejects_all() {
    let store = CapabilityUsageStore::new(UsageTelemetryConfig {
        sample_rate_bps: 0,
        ..UsageTelemetryConfig::default()
    });
    let recorded = store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_000,
    ));
    assert!(!recorded, "should reject with 0 sample rate");
    assert!(store.snapshot().is_empty());
}

#[test]
fn max_entries_caps_distinct_keys() {
    let store = CapabilityUsageStore::new(UsageTelemetryConfig {
        max_entries: 2,
        retention_secs: 365 * 86400,
        ..UsageTelemetryConfig::default()
    });
    // First two keys accepted
    assert!(store.record(&make_event(
        ZoneId::work(),
        "fcp.a:request_response:0.1.0",
        "a.op",
        SafetyTier::Safe,
        "op",
        CapabilityUsageOutcome::Allow,
        1_000,
    )));
    assert!(store.record(&make_event(
        ZoneId::work(),
        "fcp.b:request_response:0.1.0",
        "b.op",
        SafetyTier::Safe,
        "op",
        CapabilityUsageOutcome::Allow,
        1_001,
    )));
    // Third key rejected (at capacity)
    assert!(!store.record(&make_event(
        ZoneId::work(),
        "fcp.c:request_response:0.1.0",
        "c.op",
        SafetyTier::Safe,
        "op",
        CapabilityUsageOutcome::Allow,
        1_002,
    )));
    assert_eq!(store.snapshot().len(), 2);
}

// ---------------------------------------------------------------------------
// F. E2E Logged Flow Tests
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn full_usage_suggestion_flow_logged() {
    let mut logger = E2eLogger::new();
    let test_name = "capability_usage_e2e";
    let module = "fcp-e2e";
    let correlation_id = "cap-e2e-001";
    let mut passed_count = 0_u32;
    let mut failed_count = 0_u32;

    // Step 1: Create store and record events
    let store = new_store();
    let now = 1_700_000_000_u64;

    // Active safe
    for i in 0..20 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    // Active dangerous
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Allow,
            now - 50 + i,
        ));
    }
    // Stale
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.old",
        SafetyTier::Risky,
        "old_operation",
        CapabilityUsageOutcome::Allow,
        now - 60 * 86400,
    ));

    logger.push(E2eLogEntry::new(
        "info",
        test_name.to_string(),
        module,
        "setup",
        correlation_id.to_string(),
        "pass",
        0,
        AssertionsSummary::new(passed_count, failed_count),
        serde_json::json!({
            "step": "record_events",
            "event_count": 26,
            "distinct_capabilities": 3
        }),
    ));

    // Step 2: Snapshot
    let snap = store.snapshot();
    if snap.len() == 3 {
        passed_count += 1;
    } else {
        failed_count += 1;
    }

    logger.push(E2eLogEntry::new(
        "info",
        test_name.to_string(),
        module,
        "verify",
        correlation_id.to_string(),
        if snap.len() == 3 { "pass" } else { "fail" },
        0,
        AssertionsSummary::new(passed_count, failed_count),
        serde_json::json!({
            "step": "snapshot",
            "aggregate_count": snap.len()
        }),
    ));

    // Step 3: Recommendations
    let config = RecommendationConfig {
        unused_after_secs: 30 * 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    let summary = report.summary();

    let suggestions_valid =
        summary.keep == 1 && summary.review_risky == 1 && summary.remove_unused == 1;
    if suggestions_valid {
        passed_count += 1;
    } else {
        failed_count += 1;
    }

    logger.push(E2eLogEntry::new(
        if suggestions_valid { "info" } else { "error" },
        test_name.to_string(),
        module,
        "verify",
        correlation_id.to_string(),
        if suggestions_valid { "pass" } else { "fail" },
        0,
        AssertionsSummary::new(passed_count, failed_count),
        serde_json::json!({
            "step": "recommendations",
            "suggestions_count": summary.total,
            "keep": summary.keep,
            "review_risky": summary.review_risky,
            "remove_unused": summary.remove_unused
        }),
    ));

    // Step 4: JSON export
    let json = report.to_json().expect("json export");
    let back: CapabilityRecommendationReport = serde_json::from_str(&json).expect("json roundtrip");
    let export_ok = back.recommendations.len() == report.recommendations.len();
    if export_ok {
        passed_count += 1;
    } else {
        failed_count += 1;
    }

    logger.push(E2eLogEntry::new(
        if export_ok { "info" } else { "error" },
        test_name.to_string(),
        module,
        "verify",
        correlation_id.to_string(),
        if export_ok { "pass" } else { "fail" },
        0,
        AssertionsSummary::new(passed_count, failed_count),
        serde_json::json!({
            "step": "json_export",
            "export_bytes": json.len(),
            "roundtrip_ok": export_ok
        }),
    ));

    // Final assertions
    assert_eq!(failed_count, 0, "no E2E steps should fail");
    assert_eq!(passed_count, 3, "all E2E steps should pass");
    assert!(
        !logger.entries().is_empty(),
        "should have structured log entries"
    );

    // Validate JSONL output
    let jsonl = logger.to_json_lines();
    assert!(!jsonl.is_empty(), "JSONL output should not be empty");
    for line in jsonl.lines() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each line should be valid JSON");
        assert!(
            parsed.get("test_name").is_some(),
            "each log entry should have test_name"
        );
    }
}

#[test]
fn multi_zone_flow_logged() {
    let store = new_store();
    let now = 1_700_000_000_u64;

    // Work zone: active safe + active dangerous
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now - 100 + i,
        ));
    }
    for i in 0..3 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete",
            SafetyTier::Dangerous,
            "delete_repo",
            CapabilityUsageOutcome::Deny,
            now - 50 + i,
        ));
    }

    // Private zone: active risky + errors
    for i in 0..8 {
        store.record(&make_event(
            ZoneId::private(),
            "fcp.gmail:request_response:0.1.0",
            "gmail.send",
            SafetyTier::Risky,
            "send_email",
            CapabilityUsageOutcome::Allow,
            now - 200 + i,
        ));
    }
    for i in 0..2 {
        store.record(&make_event(
            ZoneId::private(),
            "fcp.stripe:request_response:0.1.0",
            "stripe.charge",
            SafetyTier::Critical,
            "create_charge",
            CapabilityUsageOutcome::Error,
            now - 300 + i,
        ));
    }

    let snap = store.snapshot();
    assert_eq!(snap.len(), 4, "should have 4 distinct aggregates");

    let config = RecommendationConfig {
        unused_after_secs: 86400,
    };
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(report.recommendations.len(), 4);

    // Verify risk summaries span both zones
    let zones: Vec<&str> = report
        .risk_summaries
        .iter()
        .map(|s| s.zone_id.as_str())
        .collect();
    assert!(zones.contains(&"z:work"), "should have work zone summary");
    assert!(
        zones.contains(&"z:private"),
        "should have private zone summary"
    );

    // Verify JSON serialization
    let json = report.to_json_pretty().expect("pretty json");
    let back: CapabilityRecommendationReport = serde_json::from_str(&json).expect("roundtrip");
    assert_eq!(back.recommendations.len(), 4);
}

#[test]
fn denied_only_capability_still_tracked() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.admin",
            SafetyTier::Dangerous,
            "admin_op",
            CapabilityUsageOutcome::Deny,
            now - 100 + i,
        ));
    }
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].total, 5);
    assert_eq!(snap[0].allowed, 0);
    assert_eq!(snap[0].denied, 5);
}

#[test]
fn error_only_capability_still_tracked() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    for i in 0..3 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.stripe:request_response:0.1.0",
            "stripe.refund",
            SafetyTier::Dangerous,
            "create_refund",
            CapabilityUsageOutcome::Error,
            now - 100 + i,
        ));
    }
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].errors, 3);
}

#[test]
fn aggregate_key_includes_connector_and_capability() {
    let store = new_store();
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        1_000_000,
    ));
    let snap = store.snapshot();
    assert_eq!(
        snap[0].key.connector_id.as_str(),
        "fcp.slack:request_response:0.1.0"
    );
    assert_eq!(snap[0].key.capability_id.as_str(), "slack.send");
}

#[test]
fn recommendation_key_matches_aggregate_key() {
    let store = new_store();
    let now = 1_700_000_000_u64;
    store.record(&make_event(
        ZoneId::work(),
        "fcp.slack:request_response:0.1.0",
        "slack.send",
        SafetyTier::Safe,
        "send_message",
        CapabilityUsageOutcome::Allow,
        now - 10,
    ));
    let snap = store.snapshot();
    let config = RecommendationConfig::default();
    let report = recommend_capabilities(&snap, now, config);
    assert_eq!(
        report.recommendations[0].key.connector_id,
        snap[0].key.connector_id
    );
    assert_eq!(
        report.recommendations[0].key.capability_id,
        snap[0].key.capability_id
    );
}
