//! Pin `OperationReceipt` JSON shape + skip-when-None semantics +
//! `signable_bytes` axis-distinctness — the closest analogue to
//! "`SignedReceipt` serde" (flywheel_connectors-v897d).
//!
//! Bead asks for `SignedReceipt` JSON+CBOR roundtrip pinning. No type
//! literally named `SignedReceipt` exists in fcp-core. The closest
//! signed-receipt analogue is [`OperationReceipt`] at
//! `crates/fcp-core/src/operation.rs:216` — the per-operation receipt
//! object with a `signature: NodeSignature` field bound by the
//! `signable_bytes()` canonical-bytes function. `DecisionReceipt` is
//! pinned by `routing_decision_serde_tag.rs`.
//!
//! Existing `operation_golden_vectors.rs` covers `OperationReceipt` CBOR
//! round-trip + a few `signable_bytes` axes. This pin adds residual:
//!   * JSON shape with explicit field-set pinning,
//!   * skip-when-None for `usage_metrics`,
//!   * `is_idempotent` predicate truth table,
//!   * `total_objects_produced` helper truth table,
//!   * JSON + CBOR cross-format consistency,
//!   * `signable_bytes` axis-distinctness for every payload field
//!     (`request_object_id`, `idempotency_key` presence/value,
//!     `outcome_object_ids`, `resource_object_ids`, `executed_at`,
//!     `executed_by`, `usage_metrics` presence/value),
//!   * `signable_bytes` magic prefix `FCP2-RECEIPT-V1` pinned.

use fcp_cbor::SchemaId;
use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectId, OperationReceipt, Provenance, TailscaleNodeId,
    UsageMetric, ZoneId,
};
use semver::Version;
use serde_json::json;

const fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn header(zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.operation", "receipt", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_700_000_100,
        provenance: Provenance::new(zone),
        refs: vec![obj(0xab)],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("executor"), [0u8; 64], 1_700_000_100)
}

fn populated_receipt() -> OperationReceipt {
    OperationReceipt {
        header: header(ZoneId::work()),
        request_object_id: obj(0x10),
        idempotency_key: Some("idem-1".to_string()),
        outcome_object_ids: vec![obj(0x20), obj(0x21)],
        resource_object_ids: vec![obj(0x30)],
        usage_metrics: Some(vec![UsageMetric::tokens(100), UsageMetric::api_credits(5)]),
        executed_at: 1_700_000_200,
        executed_by: TailscaleNodeId::new("executor-node"),
        signature: signature(),
    }
}

fn minimal_receipt() -> OperationReceipt {
    OperationReceipt {
        header: header(ZoneId::work()),
        request_object_id: obj(0x10),
        idempotency_key: None,
        outcome_object_ids: vec![],
        resource_object_ids: vec![],
        usage_metrics: None,
        executed_at: 1_700_000_200,
        executed_by: TailscaleNodeId::new("executor-node"),
        signature: signature(),
    }
}

#[test]
fn populated_receipt_full_field_set_pinned() {
    let r = populated_receipt();
    let v = serde_json::to_value(&r).unwrap();
    let obj_value = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "header",
        "request_object_id",
        "idempotency_key",
        "outcome_object_ids",
        "resource_object_ids",
        "usage_metrics",
        "executed_at",
        "executed_by",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj_value.keys().map(String::as_str).collect();
    assert_eq!(
        actual, expected,
        "OperationReceipt shape drift: {obj_value:?}"
    );
}

#[test]
fn minimal_receipt_omits_usage_metrics_when_none() {
    // usage_metrics has skip_serializing_if = "Option::is_none". When
    // None, must be OMITTED from wire form. idempotency_key has NO
    // skip_serializing_if → must serialize as null.
    let r = minimal_receipt();
    let v = serde_json::to_value(&r).unwrap();
    let obj_value = v.as_object().expect("must be object");

    assert!(
        !obj_value.contains_key("usage_metrics"),
        "usage_metrics must be omitted when None"
    );
    assert!(
        obj_value.contains_key("idempotency_key"),
        "idempotency_key must be present (no skip_serializing_if)"
    );
    assert_eq!(obj_value.get("idempotency_key"), Some(&json!(null)));
}

#[test]
fn empty_outcome_and_resource_vecs_serialize_as_empty_arrays() {
    // Receipts with no outcome/resource objects MUST still serialize the
    // [] (audit-critical: "no outputs" is a different statement from
    // "missing field"). Pin so a future skip-when-empty silently changes
    // the wire shape.
    let r = minimal_receipt();
    let v = serde_json::to_value(&r).unwrap();
    let obj_value = v.as_object().unwrap();
    assert_eq!(obj_value.get("outcome_object_ids"), Some(&json!([])));
    assert_eq!(obj_value.get("resource_object_ids"), Some(&json!([])));
}

#[test]
fn json_roundtrip_preserves_all_decision_critical_fields() {
    let r = populated_receipt();
    let bytes = serde_json::to_vec(&r).unwrap();
    let back: OperationReceipt = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.request_object_id, r.request_object_id);
    assert_eq!(back.idempotency_key, r.idempotency_key);
    assert_eq!(back.outcome_object_ids, r.outcome_object_ids);
    assert_eq!(back.resource_object_ids, r.resource_object_ids);
    assert_eq!(back.executed_at, r.executed_at);
    assert_eq!(back.executed_by, r.executed_by);

    let metrics = back.usage_metrics.as_ref().unwrap();
    assert_eq!(metrics.len(), 2);
    assert_eq!(metrics[0].kind, fcp_core::UsageMetricKind::Tokens);
    assert_eq!(metrics[0].amount, 100);
    assert_eq!(metrics[1].kind, fcp_core::UsageMetricKind::ApiCredits);
}

#[test]
fn json_and_cbor_decode_to_equivalent_receipt() {
    let r = populated_receipt();
    let json_bytes = serde_json::to_vec(&r).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&r, &mut cbor_bytes).unwrap();

    let from_json: OperationReceipt = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: OperationReceipt = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.request_object_id, from_cbor.request_object_id);
    assert_eq!(from_json.idempotency_key, from_cbor.idempotency_key);
    assert_eq!(from_json.outcome_object_ids, from_cbor.outcome_object_ids);
    assert_eq!(from_json.resource_object_ids, from_cbor.resource_object_ids);
    assert_eq!(from_json.executed_at, from_cbor.executed_at);
    assert_eq!(from_json.executed_by, from_cbor.executed_by);
}

#[test]
fn is_idempotent_truth_table() {
    let mut r = populated_receipt();
    r.idempotency_key = Some("k".to_string());
    assert!(r.is_idempotent(), "Some(key) must report idempotent");

    r.idempotency_key = None;
    assert!(!r.is_idempotent(), "None must report NOT idempotent");

    r.idempotency_key = Some(String::new()); // empty string
    assert!(
        r.is_idempotent(),
        "Some(empty string) is still Some — pin contract"
    );
}

#[test]
fn total_objects_produced_truth_table() {
    let mut r = minimal_receipt();
    assert_eq!(
        r.total_objects_produced(),
        0,
        "no outputs + no resources = 0"
    );

    r.outcome_object_ids = vec![obj(0x20)];
    assert_eq!(r.total_objects_produced(), 1);

    r.resource_object_ids = vec![obj(0x30), obj(0x31)];
    assert_eq!(r.total_objects_produced(), 3, "1 outcome + 2 resources = 3");

    r.outcome_object_ids = vec![obj(0x20), obj(0x21), obj(0x22)];
    assert_eq!(r.total_objects_produced(), 5);
}

#[test]
fn signable_bytes_starts_with_magic_prefix() {
    let r = populated_receipt();
    let bytes = r.signable_bytes();
    assert!(
        bytes.starts_with(b"FCP2-RECEIPT-V1"),
        "signable_bytes must start with FCP2-RECEIPT-V1 magic"
    );
}

#[test]
fn signable_bytes_axis_distinctness_for_request_object_id() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.request_object_id = obj(0xaa);
    b.request_object_id = obj(0xbb);
    assert_ne!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_idempotency_key_value() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.idempotency_key = Some("alpha".to_string());
    b.idempotency_key = Some("beta".to_string());
    assert_ne!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_idempotency_key_presence() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.idempotency_key = Some(String::new()); // empty Some
    b.idempotency_key = None;
    assert_ne!(
        a.signable_bytes(),
        b.signable_bytes(),
        "Some(\"\") vs None must produce distinct signable_bytes"
    );
}

#[test]
fn signable_bytes_axis_distinctness_for_outcome_object_ids() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.outcome_object_ids = vec![obj(0x20)];
    b.outcome_object_ids = vec![obj(0x21)];
    assert_ne!(a.signable_bytes(), b.signable_bytes());

    // Distinct counts also distinct.
    let mut c = populated_receipt();
    c.outcome_object_ids = vec![obj(0x20), obj(0x21)];
    let mut d = populated_receipt();
    d.outcome_object_ids = vec![obj(0x20)];
    assert_ne!(c.signable_bytes(), d.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_resource_object_ids() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.resource_object_ids = vec![obj(0x30)];
    b.resource_object_ids = vec![obj(0x31)];
    assert_ne!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_executed_at() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.executed_at = 1_700_000_000;
    b.executed_at = 1_700_000_001;
    assert_ne!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_executed_by() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.executed_by = TailscaleNodeId::new("node-alpha");
    b.executed_by = TailscaleNodeId::new("node-beta");
    assert_ne!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn signable_bytes_axis_distinctness_for_usage_metrics_presence() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.usage_metrics = Some(vec![UsageMetric::tokens(100)]);
    b.usage_metrics = None;
    assert_ne!(
        a.signable_bytes(),
        b.signable_bytes(),
        "Some(metrics) vs None must produce distinct signable_bytes"
    );
}

#[test]
fn signable_bytes_axis_distinctness_for_usage_metrics_value() {
    let mut a = populated_receipt();
    let mut b = populated_receipt();
    a.usage_metrics = Some(vec![UsageMetric::tokens(100)]);
    b.usage_metrics = Some(vec![UsageMetric::tokens(200)]);
    assert_ne!(a.signable_bytes(), b.signable_bytes());

    // Different metric kinds also produce distinct bytes.
    let mut c = populated_receipt();
    let mut d = populated_receipt();
    c.usage_metrics = Some(vec![UsageMetric::tokens(100)]);
    d.usage_metrics = Some(vec![UsageMetric::api_credits(100)]);
    assert_ne!(c.signable_bytes(), d.signable_bytes());
}

#[test]
fn signable_bytes_idempotent_under_signature_field_mutation() {
    // signable_bytes() must NOT include the signature field — so changing
    // signature should leave signable_bytes unchanged. This is the
    // canonical "the bytes you sign exclude the signature itself" contract.
    let a = populated_receipt();
    let bytes_before = a.signable_bytes();

    let mut b = a;
    b.signature = NodeSignature::new(NodeId::new("different"), [0xFF; 64], 9_999_999_999);
    let bytes_after = b.signable_bytes();

    assert_eq!(
        bytes_before, bytes_after,
        "signable_bytes must not depend on signature envelope"
    );
}

#[test]
fn signable_bytes_deterministic_across_repeated_calls() {
    let r = populated_receipt();
    let b1 = r.signable_bytes();
    let b2 = r.signable_bytes();
    let b3 = r.signable_bytes();
    assert_eq!(b1, b2);
    assert_eq!(b2, b3);
}

#[test]
fn cbor_roundtrip_preserves_usage_metrics_through_complex_payload() {
    let r = populated_receipt();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&r, &mut bytes).unwrap();
    let back: OperationReceipt = ciborium::de::from_reader(&bytes[..]).unwrap();

    let metrics = back.usage_metrics.unwrap();
    assert_eq!(metrics.len(), 2);
    assert_eq!(metrics[0].amount, 100);
    assert_eq!(metrics[1].amount, 5);
    assert_eq!(metrics[1].kind, fcp_core::UsageMetricKind::ApiCredits);
}

#[test]
fn zone_id_helper_returns_header_zone() {
    let r = populated_receipt();
    assert_eq!(r.zone_id(), &ZoneId::work());

    let mut r2 = populated_receipt();
    r2.header.zone_id = ZoneId::private();
    assert_eq!(r2.zone_id(), &ZoneId::private());
}
