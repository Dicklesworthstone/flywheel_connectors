//! `EventEnvelope` builder + canonical encoding + `OrderingPolicy`
//! serde conformance.
//!
//! `fcp_core::EventEnvelope` is the streaming-event wrapper used by
//! every connector that emits events. Two contracts that downstream
//! consumers (gateway router, replay engine, dedup tooling) all key
//! on:
//!
//! 1. **Schema `fcp.stream/EventEnvelope/v1.1.0` is wire format.**
//!    Drift is a silent break for any tool reading captured events.
//! 2. **`canonical_bytes` is deterministic.** Cursors and dedup
//!    rely on byte-identical CBOR for byte-identical envelopes.
//!
//! Plus the builder methods MUST be deterministic, optional fields
//! (`stream_key`, `ordering`) MUST be omitted when `None` for
//! forward compat with v1.0 readers, and `OrderingPolicy` serde
//! uses `snake_case` wire form (`gateway` / `per_key` / `unordered`).

use fcp_cbor::SchemaId;
use fcp_prelude::{
    ConnectorId, CorrelationId, EventData, EventEnvelope, InstanceId, OrderingPolicy, Principal,
    TrustLevel, ZoneId,
};
use semver::Version;

fn test_event_data() -> EventData {
    EventData::new(
        ConnectorId::from_static("test"),
        InstanceId::new(),
        ZoneId::work(),
        Principal {
            kind: "user".into(),
            id: "user:alice".into(),
            trust: TrustLevel::Paired,
            display: None,
        },
        serde_json::json!({"k": "v"}),
    )
}

#[test]
fn schema_is_fcp_stream_event_envelope_v_1_1_0() {
    let s = EventEnvelope::schema();
    assert_eq!(s.namespace, "fcp.stream");
    assert_eq!(s.name, "EventEnvelope");
    assert_eq!(
        s.version,
        Version::new(1, 1, 0),
        "EventEnvelope schema MUST be at version 1.1.0 — bumping is a deliberate \
         cross-release coordination step"
    );
}

#[test]
fn schema_namespace_matches_streaming_subsystem() {
    let s = EventEnvelope::schema();
    assert_eq!(
        s.namespace, "fcp.stream",
        "EventEnvelope MUST live under fcp.stream namespace (streaming subsystem)"
    );
}

#[test]
fn new_initializes_seq_to_zero_and_cursor_empty() {
    let env = EventEnvelope::new("topic", test_event_data());
    assert_eq!(env.seq, 0);
    assert_eq!(env.cursor, "");
    assert!(!env.requires_ack);
    assert!(env.stream_key.is_none());
    assert!(env.ordering.is_none());
}

#[test]
fn new_topic_is_preserved() {
    let env = EventEnvelope::new("test.topic.v1", test_event_data());
    assert_eq!(env.topic, "test.topic.v1");
}

#[test]
fn with_seq_sets_seq_field() {
    let env = EventEnvelope::new("t", test_event_data()).with_seq(42);
    assert_eq!(env.seq, 42);
}

#[test]
fn with_cursor_sets_cursor_field() {
    let env = EventEnvelope::new("t", test_event_data()).with_cursor("abc-123");
    assert_eq!(env.cursor, "abc-123");
}

#[test]
fn requiring_ack_sets_requires_ack_to_true() {
    let env = EventEnvelope::new("t", test_event_data()).requiring_ack();
    assert!(env.requires_ack);
}

#[test]
fn with_stream_key_sets_optional_key() {
    let env = EventEnvelope::new("t", test_event_data()).with_stream_key("channel-99");
    assert_eq!(env.stream_key.as_deref(), Some("channel-99"));
}

#[test]
fn with_ordering_sets_optional_policy() {
    let env = EventEnvelope::new("t", test_event_data()).with_ordering(OrderingPolicy::PerKey);
    assert_eq!(env.ordering, Some(OrderingPolicy::PerKey));
}

#[test]
fn with_cursor_seq_renders_decimal_string() {
    let env = EventEnvelope::new("t", test_event_data()).with_cursor_seq(12345);
    assert_eq!(
        env.cursor, "12345",
        "with_cursor_seq MUST render the seq as decimal string for downstream \
         cursor parsing"
    );
}

#[test]
fn builder_chains_are_deterministic() {
    // The same chain on two fresh envelopes (modulo timestamp)
    // MUST produce identical builder-set fields. Pin so a
    // refactor doesn't accidentally make a builder method
    // non-deterministic.
    let mk = || {
        EventEnvelope::new("t", test_event_data())
            .with_seq(7)
            .with_cursor("c-7")
            .with_stream_key("k-1")
            .with_ordering(OrderingPolicy::Gateway)
            .requiring_ack()
    };
    let a = mk();
    let b = mk();
    assert_eq!(a.seq, b.seq);
    assert_eq!(a.cursor, b.cursor);
    assert_eq!(a.stream_key, b.stream_key);
    assert_eq!(a.ordering, b.ordering);
    assert_eq!(a.requires_ack, b.requires_ack);
}

#[test]
fn json_serde_omits_stream_key_when_none() {
    let env = EventEnvelope::new("t", test_event_data());
    let json = serde_json::to_string(&env).expect("serialize");
    assert!(
        !json.contains("stream_key"),
        "stream_key=None MUST be omitted from JSON for forward compat with v1.0 readers; \
         got {json}"
    );
}

#[test]
fn json_serde_omits_ordering_when_none() {
    let env = EventEnvelope::new("t", test_event_data());
    let json = serde_json::to_string(&env).expect("serialize");
    assert!(
        !json.contains("\"ordering\""),
        "ordering=None MUST be omitted from JSON for forward compat with v1.0 readers; \
         got {json}"
    );
}

#[test]
fn json_serde_includes_stream_key_when_some() {
    let env = EventEnvelope::new("t", test_event_data()).with_stream_key("k-99");
    let json = serde_json::to_string(&env).expect("serialize");
    assert!(json.contains("\"stream_key\":\"k-99\""));
}

#[test]
fn ordering_policy_serde_uses_snake_case_wire_form() {
    assert_eq!(
        serde_json::to_string(&OrderingPolicy::Gateway).expect("serialize"),
        "\"gateway\"",
        "OrderingPolicy::Gateway MUST serialize as 'gateway'"
    );
    assert_eq!(
        serde_json::to_string(&OrderingPolicy::PerKey).expect("serialize"),
        "\"per_key\"",
        "OrderingPolicy::PerKey MUST serialize as 'per_key' (snake_case rename)"
    );
    assert_eq!(
        serde_json::to_string(&OrderingPolicy::Unordered).expect("serialize"),
        "\"unordered\""
    );
}

#[test]
fn ordering_policy_serde_roundtrip_for_all_variants() {
    for policy in [
        OrderingPolicy::Gateway,
        OrderingPolicy::PerKey,
        OrderingPolicy::Unordered,
    ] {
        let json = serde_json::to_string(&policy).expect("serialize");
        let parsed: OrderingPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, policy);
    }
}

#[test]
fn ordering_policy_rejects_unknown_variant_strings() {
    let bogus = ["\"global\"", "\"per_topic\"", "\"\"", "\"GATEWAY\""];
    for s in bogus {
        let result = serde_json::from_str::<OrderingPolicy>(s);
        assert!(
            result.is_err(),
            "OrderingPolicy MUST reject unknown variant '{s}'"
        );
    }
}

#[test]
fn canonical_bytes_is_deterministic_for_fixed_envelope() {
    // canonical_bytes drives cursor/dedup keys downstream. Two
    // envelopes that compare equal MUST produce identical bytes.
    let env = EventEnvelope::new("topic", test_event_data())
        .with_seq(7)
        .with_cursor("c-7")
        .with_ordering(OrderingPolicy::PerKey);
    let bytes_a = env.canonical_bytes().expect("canonical bytes");
    let bytes_b = env.canonical_bytes().expect("canonical bytes");
    assert_eq!(
        bytes_a, bytes_b,
        "canonical_bytes MUST be deterministic — cursor/dedup keys depend on this"
    );
}

#[test]
fn canonical_bytes_differs_when_seq_differs() {
    // Sanity: the encoded bytes MUST vary with a meaningful field
    // change. Otherwise dedup would alias distinct events.
    let mk = |seq: u64| {
        // Construct envelopes that share everything except seq.
        // Use a fixed timestamp via clone of one base envelope's
        // timestamp to remove that source of variation.
        let mut env = EventEnvelope::new("topic", test_event_data());
        env.seq = seq;
        env
    };
    let env_a = mk(1);
    let mut env_b = env_a.clone();
    env_b.seq = 2;
    let bytes_a = env_a.canonical_bytes().expect("a");
    let bytes_b = env_b.canonical_bytes().expect("b");
    assert_ne!(
        bytes_a, bytes_b,
        "canonical_bytes MUST differ when seq differs (otherwise dedup aliases events)"
    );
}

#[test]
fn json_serde_roundtrip_preserves_envelope_fields() {
    let mut env = EventEnvelope::new("topic", test_event_data())
        .with_seq(99)
        .with_cursor("c-99")
        .with_stream_key("k-99")
        .with_ordering(OrderingPolicy::Gateway)
        .requiring_ack();
    // Deterministic timestamp for the round-trip check.
    env.timestamp = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("parse timestamp")
        .with_timezone(&chrono::Utc);

    let json = serde_json::to_string(&env).expect("serialize");
    let parsed: EventEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.topic, env.topic);
    assert_eq!(parsed.seq, env.seq);
    assert_eq!(parsed.cursor, env.cursor);
    assert_eq!(parsed.requires_ack, env.requires_ack);
    assert_eq!(parsed.stream_key, env.stream_key);
    assert_eq!(parsed.ordering, env.ordering);
    assert_eq!(parsed.timestamp, env.timestamp);
}

#[test]
fn event_data_with_correlation_id_sets_optional_field() {
    let id = CorrelationId::new();
    let data = test_event_data().with_correlation_id(id);
    assert!(
        data.correlation_id.is_some(),
        "with_correlation_id MUST set the optional field"
    );
}

#[test]
fn event_data_default_correlation_id_is_none() {
    let data = test_event_data();
    assert!(
        data.correlation_id.is_none(),
        "default EventData MUST have no correlation_id"
    );
}

#[test]
fn event_data_default_resource_uris_is_empty() {
    let data = test_event_data();
    assert!(
        data.resource_uris.is_empty(),
        "default EventData MUST have empty resource_uris"
    );
}

#[test]
fn schema_id_construction_independent_of_envelope_state() {
    // EventEnvelope::schema is associated, not method — pin that
    // it's stable regardless of envelope construction state.
    let s1 = EventEnvelope::schema();
    let s2: SchemaId = EventEnvelope::schema();
    assert_eq!(s1, s2);
}
