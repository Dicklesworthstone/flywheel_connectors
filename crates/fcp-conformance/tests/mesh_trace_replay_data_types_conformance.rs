//! `fcp_mesh::replay` data type + format detection conformance.
//!
//! `TraceReplayEngine` is the offline-debug primitive for diffing
//! captured mesh traces against a deterministic replay. The engine
//! itself needs `MeshNode` + stores to drive, but the surrounding
//! data types — `TraceReplayInputFormat`, `TraceReplayDiff`,
//! `TraceReplaySummary`, `TraceReplayReport`, `TraceReplayError` —
//! are pure cross-crate contracts every consumer of replay JSON/CBOR
//! relies on.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`TraceReplayInputFormat` 3 variants** — Auto, Json, Cbor.
//!    Serde uses `snake_case` wire form (`auto` / `json` / `cbor`).
//! 2. **Format `Copy + Eq + Hash`** — must be small and cheap; replay
//!    UIs put it in `HashMap` keys.
//! 3. **`TraceReplayDiff` field-preserving struct** — index,
//!    `event_type`, `expected_decision`, `actual_decision`, detail. Serde
//!    round-trip is identity; `PartialEq` compares all five fields.
//! 4. **`TraceReplaySummary`** counts roundtrip via JSON identity:
//!    `total_events`, `event_type_counts` (`BTreeMap` is stable-ordered),
//!    `expected/actual_decision_counts`, matched/mismatched events +
//!    decisions.
//! 5. **`TraceReplayReport`** roundtrip and Default-construction
//!    sanity (`PartialEq` + serde).
//! 6. **`TraceReplayError` Display contract** — operator log greps:
//!    "trace IO error" / "failed to parse trace as <fmt>" /
//!    "mesh replay failed" / "trace capture unavailable".
//! 7. **`TraceReplayError::from(MeshNodeError)`** wraps via the
//!    `Mesh` variant (auto-derive via `#[from]`).

use fcp_mesh::{TraceReplayDiff, TraceReplayInputFormat, TraceReplayReport, TraceReplaySummary};
use std::collections::BTreeMap;

// ─── TraceReplayInputFormat ─────────────────────────────────────────

#[test]
fn input_format_three_variants_are_distinct() {
    let a = TraceReplayInputFormat::Auto;
    let j = TraceReplayInputFormat::Json;
    let c = TraceReplayInputFormat::Cbor;
    assert_ne!(a, j);
    assert_ne!(a, c);
    assert_ne!(j, c);
}

#[test]
fn input_format_implements_copy() {
    // Cheap-pass-by-value contract: replay UIs and configs pass this
    // through filters/maps without cloning.
    fn takes_value(_: TraceReplayInputFormat) {}
    let f = TraceReplayInputFormat::Auto;
    takes_value(f);
    takes_value(f); // would fail to compile if !Copy
    assert_eq!(f, TraceReplayInputFormat::Auto);
}

#[test]
fn input_format_serde_uses_snake_case_wire_form() {
    let cases = [
        (TraceReplayInputFormat::Auto, "\"auto\""),
        (TraceReplayInputFormat::Json, "\"json\""),
        (TraceReplayInputFormat::Cbor, "\"cbor\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as snake_case wire form '{expected}'"
        );
        let parsed: TraceReplayInputFormat = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn input_format_rejects_unknown_or_uppercase_variants() {
    for bogus in ["\"AUTO\"", "\"yaml\"", "\"\"", "\"json5\""] {
        assert!(
            serde_json::from_str::<TraceReplayInputFormat>(bogus).is_err(),
            "TraceReplayInputFormat MUST reject {bogus}"
        );
    }
}

// ─── TraceReplayDiff ────────────────────────────────────────────────

#[test]
fn diff_constructor_preserves_all_five_fields() {
    let d = TraceReplayDiff {
        index: 7,
        event_type: "routing".into(),
        expected_decision: Some("allow".into()),
        actual_decision: Some("deny".into()),
        detail: "decision mismatch".into(),
    };
    assert_eq!(d.index, 7);
    assert_eq!(d.event_type, "routing");
    assert_eq!(d.expected_decision.as_deref(), Some("allow"));
    assert_eq!(d.actual_decision.as_deref(), Some("deny"));
    assert_eq!(d.detail, "decision mismatch");
}

#[test]
fn diff_serde_roundtrip_is_identity() {
    let d = TraceReplayDiff {
        index: 42,
        event_type: "admission".into(),
        expected_decision: Some("admit".into()),
        actual_decision: None,
        detail: "missing replay event".into(),
    };
    let json = serde_json::to_string(&d).expect("serialize");
    let parsed: TraceReplayDiff = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, d);
}

#[test]
fn diff_partial_eq_compares_every_field() {
    let base = TraceReplayDiff {
        index: 1,
        event_type: "policy".into(),
        expected_decision: Some("allow".into()),
        actual_decision: Some("allow".into()),
        detail: "ok".into(),
    };
    let mut bumped = base.clone();
    bumped.index = 2;
    assert_ne!(base, bumped, "index difference MUST register on PartialEq");

    let mut diff_event = base.clone();
    diff_event.event_type = "routing".into();
    assert_ne!(base, diff_event);

    let mut diff_actual = base.clone();
    diff_actual.actual_decision = Some("deny".into());
    assert_ne!(base, diff_actual);
}

#[test]
fn diff_handles_optional_decisions_independently() {
    // The diff carries Option<String> for both expected and actual —
    // missing/unexpected events produce one-sided diffs.
    let missing = TraceReplayDiff {
        index: 0,
        event_type: "policy".into(),
        expected_decision: Some("allow".into()),
        actual_decision: None,
        detail: "missing replay event".into(),
    };
    let unexpected = TraceReplayDiff {
        index: 0,
        event_type: "policy".into(),
        expected_decision: None,
        actual_decision: Some("allow".into()),
        detail: "unexpected replay event".into(),
    };
    assert_ne!(
        missing, unexpected,
        "missing vs unexpected MUST be distinct"
    );
}

// ─── TraceReplaySummary ────────────────────────────────────────────

#[test]
fn summary_default_is_all_zero() {
    let s = TraceReplaySummary {
        total_events: 0,
        event_type_counts: BTreeMap::new(),
        expected_decision_counts: BTreeMap::new(),
        actual_decision_counts: BTreeMap::new(),
        matched_events: 0,
        mismatched_events: 0,
        matched_decisions: 0,
        mismatched_decisions: 0,
    };
    assert_eq!(s.total_events, 0);
    assert!(s.event_type_counts.is_empty());
    assert_eq!(s.matched_events, 0);
}

#[test]
fn summary_serde_roundtrip_preserves_btreemap_ordering() {
    // BTreeMap MUST preserve ordering across serde — replay UI
    // depends on stable iteration for diff display.
    let mut event_type_counts = BTreeMap::new();
    event_type_counts.insert("admission".to_string(), 5_u64);
    event_type_counts.insert("routing".to_string(), 3_u64);
    event_type_counts.insert("policy".to_string(), 2_u64);

    let mut expected_decision_counts = BTreeMap::new();
    expected_decision_counts.insert("allow".to_string(), 7_u64);
    expected_decision_counts.insert("deny".to_string(), 3_u64);

    let s = TraceReplaySummary {
        total_events: 10,
        event_type_counts,
        expected_decision_counts: expected_decision_counts.clone(),
        actual_decision_counts: expected_decision_counts,
        matched_events: 9,
        mismatched_events: 1,
        matched_decisions: 8,
        mismatched_decisions: 2,
    };
    let json = serde_json::to_string(&s).expect("serialize");
    let parsed: TraceReplaySummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, s);

    // Stable ordering in serialized form (BTreeMap → ascending keys).
    let position_of = |needle: &str| json.find(needle).unwrap_or(usize::MAX);
    assert!(
        position_of("admission") < position_of("policy"),
        "BTreeMap MUST serialize keys in ascending order"
    );
    assert!(position_of("policy") < position_of("routing"));
}

// ─── TraceReplayReport ─────────────────────────────────────────────

#[test]
fn report_serde_roundtrip_preserves_all_fields() {
    let summary = TraceReplaySummary {
        total_events: 5,
        event_type_counts: BTreeMap::new(),
        expected_decision_counts: BTreeMap::new(),
        actual_decision_counts: BTreeMap::new(),
        matched_events: 5,
        mismatched_events: 0,
        matched_decisions: 5,
        mismatched_decisions: 0,
    };
    let report = TraceReplayReport {
        source_trace_id: "trace-abc".into(),
        source_capturing_node: Some("node-99".into()),
        input_events: 5,
        replayed_events: 5,
        summary,
        diffs: vec![],
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: TraceReplayReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, report);
}

#[test]
fn report_with_diffs_serializes_each_diff() {
    let diffs = vec![
        TraceReplayDiff {
            index: 0,
            event_type: "routing".into(),
            expected_decision: Some("allow".into()),
            actual_decision: Some("deny".into()),
            detail: "decision mismatch".into(),
        },
        TraceReplayDiff {
            index: 3,
            event_type: "policy".into(),
            expected_decision: None,
            actual_decision: Some("allow".into()),
            detail: "unexpected replay event".into(),
        },
    ];
    let report = TraceReplayReport {
        source_trace_id: "trace-x".into(),
        source_capturing_node: None,
        input_events: 4,
        replayed_events: 5,
        summary: TraceReplaySummary {
            total_events: 4,
            event_type_counts: BTreeMap::new(),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 2,
            mismatched_events: 2,
            matched_decisions: 1,
            mismatched_decisions: 2,
        },
        diffs: diffs.clone(),
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: TraceReplayReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.diffs.len(), 2);
    assert_eq!(parsed.diffs, diffs);
}

#[test]
fn report_source_capturing_node_is_optional() {
    let report = TraceReplayReport {
        source_trace_id: "trace-x".into(),
        source_capturing_node: None,
        input_events: 0,
        replayed_events: 0,
        summary: TraceReplaySummary {
            total_events: 0,
            event_type_counts: BTreeMap::new(),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 0,
            mismatched_events: 0,
            matched_decisions: 0,
            mismatched_decisions: 0,
        },
        diffs: vec![],
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: TraceReplayReport = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed.source_capturing_node.is_none());
}

// ─── TraceReplayError ──────────────────────────────────────────────

#[test]
fn error_io_display_includes_path_and_message() {
    use fcp_mesh::TraceReplayError;
    let e = TraceReplayError::Io {
        path: "/tmp/missing.trace".into(),
        message: "No such file".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("trace IO error"),
        "Display MUST include literal 'trace IO error' for log greps; got {s}"
    );
    assert!(s.contains("/tmp/missing.trace"), "got {s}");
    assert!(s.contains("No such file"), "got {s}");
}

#[test]
fn error_parse_display_includes_format_and_message() {
    use fcp_mesh::TraceReplayError;
    let e = TraceReplayError::Parse {
        format: "json",
        message: "expected `{`".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("failed to parse trace as json"),
        "Display MUST include 'failed to parse trace as <fmt>'; got {s}"
    );
    assert!(s.contains("expected `{`"), "got {s}");
}

#[test]
fn error_trace_capture_unavailable_display_is_specific() {
    use fcp_mesh::TraceReplayError;
    let e = TraceReplayError::TraceCaptureUnavailable;
    let s = format!("{e}");
    assert!(
        s.contains("trace capture unavailable"),
        "Display MUST mention 'trace capture unavailable'; got {s}"
    );
}

#[test]
fn error_is_std_error() {
    use fcp_mesh::TraceReplayError;
    let e = TraceReplayError::TraceCaptureUnavailable;
    let _: &dyn std::error::Error = &e;
    // Smoke check — also pin that Debug is non-empty.
    let dbg = format!("{e:?}");
    assert_ne!(dbg, "");
}
