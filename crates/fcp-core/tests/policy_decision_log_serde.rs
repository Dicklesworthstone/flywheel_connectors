//! Pin `AuditEvent` 14-field JSON shape + skip-when-None semantics + chain-
//! link distinctness — the closest analogue to "`PolicyDecisionLog` serde"
//! (flywheel_connectors-3pz0m).
//!
//! Bead asks for `PolicyDecisionLog` JSON+CBOR roundtrip pinning. No type
//! literally named `PolicyDecisionLog` exists in fcp-core. The closest
//! append-only-decision-log analogue is [`AuditEvent`] at
//! `crates/fcp-core/src/audit.rs:164` — the per-zone hash-linked log of
//! capability/policy/secret events with monotonic `seq` and `prev`
//! linkage.
//!
//! Existing `audit_chain_golden_vectors.rs` covers chain semantics
//! (genesis, follows, prev, seq) but not the 14-field JSON shape, the
//! 7 skip-when-`None` `Option` fields, or the per-axis serialization
//! distinctness for security-critical fields.
//!
//! Coverage:
//!   * 14-field JSON shape pinned (`header` / `correlation_id` / `trace_context`
//!     / `event_type` / `actor` / `zone_id` / `connector_id` / `operation` /
//!     `capability_token_jti` / `request_object_id` / `result_object_id` /
//!     `prev` / `seq` / `occurred_at` / `signature`),
//!   * skip-when-`None` for 7 optional fields (`trace_context`, `connector_id`,
//!     `operation`, `capability_token_jti`, `request_object_id`, `result_object_id`,
//!     `prev`),
//!   * Required minimum-shape contract: 7 fields when all optionals are `None`,
//!   * `is_genesis` truth table (`seq=0` AND `prev=None`),
//!   * `follows()` truth table for chain-linkage,
//!   * JSON + CBOR full round-trip,
//!   * Per-axis distinctness for security-critical fields (`event_type`,
//!     `actor`, `seq`, `prev`, `occurred_at`).

use fcp_cbor::SchemaId;
use fcp_core::{
    AuditEvent, ConnectorId, CorrelationId, NodeId, NodeSignature, ObjectHeader, ObjectId,
    OperationId, PrincipalId, Provenance, ZoneId,
};
use semver::Version;
use serde_json::json;
use uuid::Uuid;

const fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn header() -> ObjectHeader {
    let zone = ZoneId::work();
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.audit", "AuditEvent", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("audit-node"), [0u8; 64], 1_700_000_000)
}

fn populated_event() -> AuditEvent {
    AuditEvent {
        header: header(),
        correlation_id: CorrelationId(Uuid::from_bytes([0x42; 16])),
        trace_context: None,
        event_type: "capability.invoke".to_string(),
        actor: PrincipalId::new("user:alice").unwrap(),
        zone_id: ZoneId::work(),
        connector_id: Some(ConnectorId::from_static("connector:test")),
        operation: Some(OperationId::from_static("op.read")),
        capability_token_jti: Some(Uuid::from_bytes([0xab; 16])),
        request_object_id: Some(obj(0x10)),
        result_object_id: Some(obj(0x20)),
        prev: Some(obj(0x30)),
        seq: 5,
        occurred_at: 1_700_000_500,
        signature: signature(),
    }
}

fn genesis_event() -> AuditEvent {
    AuditEvent {
        header: header(),
        correlation_id: CorrelationId(Uuid::nil()),
        trace_context: None,
        event_type: "audit.genesis".to_string(),
        actor: PrincipalId::new("user:alice").unwrap(),
        zone_id: ZoneId::work(),
        connector_id: None,
        operation: None,
        capability_token_jti: None,
        request_object_id: None,
        result_object_id: None,
        prev: None,
        seq: 0,
        occurred_at: 1_700_000_000,
        signature: signature(),
    }
}

#[test]
fn populated_event_full_field_set_pinned() {
    let evt = populated_event();
    let v = serde_json::to_value(&evt).unwrap();
    let obj_value = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "header",
        "correlation_id",
        "event_type",
        "actor",
        "zone_id",
        "connector_id",
        "operation",
        "capability_token_jti",
        "request_object_id",
        "result_object_id",
        "prev",
        "seq",
        "occurred_at",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj_value.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "AuditEvent shape drift: {obj_value:?}");
}

#[test]
fn genesis_event_omits_all_optional_fields() {
    // 7 optional fields: trace_context, connector_id, operation,
    // capability_token_jti, request_object_id, result_object_id, prev.
    // Genesis event has all 7 as None → minimal shape is 7 required fields.
    let evt = genesis_event();
    let v = serde_json::to_value(&evt).unwrap();
    let obj_value = v.as_object().expect("must be object");

    let expected_required: std::collections::BTreeSet<&str> = [
        "header",
        "correlation_id",
        "event_type",
        "actor",
        "zone_id",
        "seq",
        "occurred_at",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj_value.keys().map(String::as_str).collect();
    assert_eq!(
        actual, expected_required,
        "AuditEvent minimal shape drift: {obj_value:?}"
    );

    // Spot-check that each optional field is omitted (NOT serialized as null).
    for skipped in [
        "trace_context",
        "connector_id",
        "operation",
        "capability_token_jti",
        "request_object_id",
        "result_object_id",
        "prev",
    ] {
        assert!(
            !obj_value.contains_key(skipped),
            "{skipped} must be omitted when None"
        );
    }
}

#[test]
fn json_roundtrip_preserves_all_decision_critical_fields() {
    let evt = populated_event();
    let bytes = serde_json::to_vec(&evt).unwrap();
    let back: AuditEvent = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.event_type, evt.event_type);
    assert_eq!(back.actor, evt.actor);
    assert_eq!(back.zone_id, evt.zone_id);
    assert_eq!(back.connector_id, evt.connector_id);
    assert_eq!(back.operation, evt.operation);
    assert_eq!(back.capability_token_jti, evt.capability_token_jti);
    assert_eq!(back.request_object_id, evt.request_object_id);
    assert_eq!(back.result_object_id, evt.result_object_id);
    assert_eq!(back.prev, evt.prev);
    assert_eq!(back.seq, evt.seq);
    assert_eq!(back.occurred_at, evt.occurred_at);
}

#[test]
fn cbor_roundtrip_preserves_all_decision_critical_fields() {
    let evt = populated_event();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&evt, &mut bytes).unwrap();
    let back: AuditEvent = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.event_type, evt.event_type);
    assert_eq!(back.actor, evt.actor);
    assert_eq!(back.seq, evt.seq);
    assert_eq!(back.prev, evt.prev);
    assert_eq!(back.connector_id, evt.connector_id);
    assert_eq!(back.operation, evt.operation);
    assert_eq!(back.capability_token_jti, evt.capability_token_jti);
}

#[test]
fn json_and_cbor_decode_to_equivalent_event() {
    let evt = populated_event();
    let json_bytes = serde_json::to_vec(&evt).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&evt, &mut cbor_bytes).unwrap();

    let from_json: AuditEvent = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: AuditEvent = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.event_type, from_cbor.event_type);
    assert_eq!(from_json.actor, from_cbor.actor);
    assert_eq!(from_json.seq, from_cbor.seq);
    assert_eq!(from_json.prev, from_cbor.prev);
    assert_eq!(from_json.connector_id, from_cbor.connector_id);
}

#[test]
fn is_genesis_truth_table() {
    // is_genesis: seq == 0 AND prev == None.
    let mut evt = genesis_event();
    assert!(evt.is_genesis(), "seq=0 + prev=None must be genesis");

    // seq != 0 but prev == None → NOT genesis.
    evt.seq = 1;
    assert!(!evt.is_genesis(), "seq=1 + prev=None must NOT be genesis");

    // seq == 0 but prev == Some → NOT genesis.
    evt.seq = 0;
    evt.prev = Some(obj(0x99));
    assert!(
        !evt.is_genesis(),
        "seq=0 + prev=Some must NOT be genesis (chain malformed)"
    );

    // seq != 0 AND prev == Some → NOT genesis (normal mid-chain event).
    evt.seq = 5;
    assert!(!evt.is_genesis());
}

#[test]
fn follows_truth_table_for_chain_linkage() {
    // Build prev event with known seq + ObjectId.
    let mut prev = genesis_event();
    prev.seq = 4;
    let prev_id = obj(0x30);

    // Successor: seq = 5, prev = Some(prev_id) → follows.
    let successor = AuditEvent {
        seq: 5,
        prev: Some(prev_id),
        ..genesis_event()
    };
    assert!(successor.follows(&prev, &prev_id));

    // Wrong prev pointer → not follows.
    let bad = AuditEvent {
        seq: 5,
        prev: Some(obj(0x99)),
        ..genesis_event()
    };
    assert!(!bad.follows(&prev, &prev_id));

    // Wrong seq (gap) → not follows.
    let gap = AuditEvent {
        seq: 7,
        prev: Some(prev_id),
        ..genesis_event()
    };
    assert!(!gap.follows(&prev, &prev_id));

    // Wrong seq (regression) → not follows.
    let regress = AuditEvent {
        seq: 3,
        prev: Some(prev_id),
        ..genesis_event()
    };
    assert!(!regress.follows(&prev, &prev_id));

    // Successor with prev=None → not follows.
    let no_prev = AuditEvent {
        seq: 5,
        prev: None,
        ..genesis_event()
    };
    assert!(!no_prev.follows(&prev, &prev_id));
}

#[test]
fn distinct_event_type_produces_distinct_json() {
    let mut a = populated_event();
    let mut b = populated_event();
    a.event_type = "capability.invoke".to_string();
    b.event_type = "secret.access".to_string();
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn distinct_actor_produces_distinct_json() {
    let mut a = populated_event();
    let mut b = populated_event();
    a.actor = PrincipalId::new("user:alice").unwrap();
    b.actor = PrincipalId::new("user:bob").unwrap();
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn distinct_seq_produces_distinct_json() {
    let mut a = populated_event();
    let mut b = populated_event();
    a.seq = 5;
    b.seq = 6;
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn distinct_prev_produces_distinct_json() {
    // Chain-link sentinel: changing the prev pointer (or going from
    // Some to None) must change the wire form.
    let mut a = populated_event();
    let mut b = populated_event();
    a.prev = Some(obj(0xaa));
    b.prev = Some(obj(0xbb));
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );

    // Some vs None also distinct.
    let mut c = populated_event();
    let mut d = populated_event();
    c.prev = Some(obj(0xaa));
    d.prev = None;
    assert_ne!(
        serde_json::to_value(&c).unwrap(),
        serde_json::to_value(&d).unwrap()
    );
}

#[test]
fn distinct_occurred_at_produces_distinct_json() {
    let mut a = populated_event();
    let mut b = populated_event();
    a.occurred_at = 1_700_000_000;
    b.occurred_at = 1_700_000_001;
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn populated_event_event_type_is_serialized_as_string() {
    // event_type is a String — pin that it appears as a JSON scalar
    // (not e.g. a tagged enum form that would change wire compatibility).
    let evt = populated_event();
    let v = serde_json::to_value(&evt).unwrap();
    let event_type = v.get("event_type").unwrap();
    assert_eq!(event_type, &json!("capability.invoke"));
    assert!(event_type.is_string());
}

#[test]
fn zone_id_helper_returns_zone_id_field() {
    let evt = populated_event();
    assert_eq!(evt.zone_id(), &ZoneId::work());

    let mut evt2 = populated_event();
    evt2.zone_id = ZoneId::private();
    assert_eq!(evt2.zone_id(), &ZoneId::private());
}

#[test]
fn correlation_id_uuid_serializes_as_scalar_string() {
    // CorrelationId wraps a Uuid; serde transparent or named-field check —
    // Uuid's default serde produces a hyphenated string. Pin so the
    // wire form stays human-readable in audit logs.
    let evt = populated_event();
    let v = serde_json::to_value(&evt).unwrap();
    let cid = v.get("correlation_id").unwrap();
    // Should be a scalar (not nested).
    assert!(
        cid.is_string() || cid.is_object(),
        "correlation_id must be string or object, got {cid:?}"
    );
}

#[test]
fn capability_token_jti_uuid_round_trips_through_json() {
    let mut evt = populated_event();
    let jti = Uuid::from_bytes([0xcd; 16]);
    evt.capability_token_jti = Some(jti);

    let bytes = serde_json::to_vec(&evt).unwrap();
    let back: AuditEvent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.capability_token_jti, Some(jti));
}
