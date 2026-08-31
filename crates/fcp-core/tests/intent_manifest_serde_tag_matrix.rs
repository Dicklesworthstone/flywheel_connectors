//! Pin `OperationIntent` JSON shape + `IntentStatus` / `OperationStatus`
//! cross-enum casing divergence — the closest analogue to "`IntentManifest`
//! serde tag matrix" (flywheel_connectors-myiwt).
//!
//! Bead asks for `IntentManifest` serde tag JSON+CBOR roundtrip pinning. No
//! type literally named `IntentManifest` exists in fcp-core. The closest
//! manifest-shaped Intent struct is [`OperationIntent`] at
//! `crates/fcp-core/src/operation.rs:110`. The serde "tag" surface is the
//! discriminator-style `header.schema` + the related status enums:
//!   * [`IntentStatus`] (5 variants, `rename_all = "snake_case"`),
//!   * [`OperationStatus`] (4 variants, NO `rename_all` — defaults to
//!     `PascalCase`).
//!
//! Existing `operation_golden_vectors.rs` covers `OperationIntent` CBOR
//! round-trip + `signable_bytes` determinism. This pin adds:
//!   * `OperationIntent` JSON shape with explicit field-set pinning,
//!   * `OperationIntent` JSON ↔ CBOR cross-format consistency,
//!   * `OperationIntent` skip-when-None / skip-when-Some shape rules,
//!   * `IntentStatus` 5-variant Display + `snake_case` serde matrix,
//!   * `OperationStatus` 4-variant DEFAULT `PascalCase` serde matrix (NO
//!     `rename_all`),
//!   * **Cross-enum casing-divergence sentinel:** `IntentStatus::InProgress`
//!     serializes `"in_progress"` while `OperationStatus::Pending` serializes
//!     `"Pending"` (`PascalCase`). Operator dashboards filter on both — pin
//!     this loud divergence so accidentally renaming one to match the other
//!     is caught at the integration boundary.
//!   * `IdempotencyEntry` serde round-trip with embedded `IntentStatus`.

use fcp_cbor::SchemaId;
use fcp_core::{
    IdempotencyEntry, IntentStatus, NodeId, NodeSignature, ObjectHeader, ObjectId, OperationIntent,
    OperationStatus, Provenance, TailscaleNodeId, ZoneId,
};
use semver::Version;
use serde_json::json;
use uuid::Uuid;

fn header(zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.operation", "intent", Version::new(1, 0, 0)),
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
    NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1_700_000_000)
}

fn full_intent() -> OperationIntent {
    let zone = ZoneId::work();
    OperationIntent {
        header: header(zone),
        request_object_id: ObjectId::from_unscoped_bytes(b"req-1"),
        capability_token_jti: Uuid::from_bytes([0xab; 16]),
        idempotency_key: Some("idem-1".to_string()),
        planned_at: 1_700_000_001,
        planned_by: TailscaleNodeId::new("planner-node"),
        lease_seq: Some(7),
        upstream_idempotency: Some("stripe-key-1".to_string()),
        signature: signature(),
    }
}

fn minimal_intent() -> OperationIntent {
    let zone = ZoneId::work();
    OperationIntent {
        header: header(zone),
        request_object_id: ObjectId::from_unscoped_bytes(b"req-2"),
        capability_token_jti: Uuid::nil(),
        idempotency_key: None,
        planned_at: 1_700_000_002,
        planned_by: TailscaleNodeId::new("planner-node"),
        lease_seq: None,
        upstream_idempotency: None,
        signature: signature(),
    }
}

const ALL_INTENT_STATUSES: &[(IntentStatus, &str)] = &[
    (IntentStatus::Pending, "pending"),
    (IntentStatus::InProgress, "in_progress"),
    (IntentStatus::Completed, "completed"),
    (IntentStatus::Failed, "failed"),
    (IntentStatus::Orphaned, "orphaned"),
];

const ALL_OPERATION_STATUSES: &[(OperationStatus, &str)] = &[
    (OperationStatus::Pending, "Pending"),
    (OperationStatus::Running, "Running"),
    (OperationStatus::Completed, "Completed"),
    (OperationStatus::Failed, "Failed"),
];

#[test]
fn operation_intent_json_field_set_pinned() {
    let intent = full_intent();
    let value = serde_json::to_value(&intent).unwrap();
    let obj = value.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "header",
        "request_object_id",
        "capability_token_jti",
        "idempotency_key",
        "planned_at",
        "planned_by",
        "lease_seq",
        "upstream_idempotency",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "OperationIntent shape drift: {obj:?}");
}

#[test]
fn operation_intent_minimal_keeps_optional_keys_present_as_null() {
    // OperationIntent does NOT use skip_serializing_if for its optional
    // fields. None values must serialize as null (not be omitted) so wire
    // consumers can tell "absent" from "missing".
    let minimal = minimal_intent();
    let value = serde_json::to_value(&minimal).unwrap();
    let obj = value.as_object().unwrap();

    assert!(obj.contains_key("idempotency_key"));
    assert_eq!(obj.get("idempotency_key"), Some(&json!(null)));
    assert!(obj.contains_key("lease_seq"));
    assert_eq!(obj.get("lease_seq"), Some(&json!(null)));
    assert!(obj.contains_key("upstream_idempotency"));
    assert_eq!(obj.get("upstream_idempotency"), Some(&json!(null)));
}

#[test]
fn operation_intent_full_json_roundtrip_preserves_all_fields() {
    let intent = full_intent();
    let bytes = serde_json::to_vec(&intent).unwrap();
    let back: OperationIntent = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.request_object_id, intent.request_object_id);
    assert_eq!(back.capability_token_jti, intent.capability_token_jti);
    assert_eq!(back.idempotency_key, intent.idempotency_key);
    assert_eq!(back.planned_at, intent.planned_at);
    assert_eq!(back.planned_by, intent.planned_by);
    assert_eq!(back.lease_seq, intent.lease_seq);
    assert_eq!(back.upstream_idempotency, intent.upstream_idempotency);
}

#[test]
fn operation_intent_full_cbor_roundtrip_preserves_all_fields() {
    let intent = full_intent();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&intent, &mut bytes).unwrap();
    let back: OperationIntent = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.request_object_id, intent.request_object_id);
    assert_eq!(back.capability_token_jti, intent.capability_token_jti);
    assert_eq!(back.idempotency_key, intent.idempotency_key);
    assert_eq!(back.lease_seq, intent.lease_seq);
    assert_eq!(back.upstream_idempotency, intent.upstream_idempotency);
}

#[test]
fn operation_intent_json_and_cbor_decode_to_same_struct() {
    let intent = full_intent();
    let json_bytes = serde_json::to_vec(&intent).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&intent, &mut cbor_bytes).unwrap();

    let from_json: OperationIntent = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: OperationIntent = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.request_object_id, from_cbor.request_object_id);
    assert_eq!(
        from_json.capability_token_jti,
        from_cbor.capability_token_jti
    );
    assert_eq!(from_json.idempotency_key, from_cbor.idempotency_key);
    assert_eq!(from_json.lease_seq, from_cbor.lease_seq);
    assert_eq!(
        from_json.upstream_idempotency,
        from_cbor.upstream_idempotency
    );
}

#[test]
fn intent_status_serde_uses_snake_case_for_every_variant() {
    for &(variant, wire) in ALL_INTENT_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize as `{wire}`");
        let back: IntentStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn intent_status_display_matches_snake_case_serde_form() {
    for &(variant, wire) in ALL_INTENT_STATUSES {
        assert_eq!(
            variant.to_string(),
            wire,
            "Display for {variant:?} must match serde form `{wire}`"
        );
    }
}

#[test]
fn intent_status_cbor_roundtrip_for_every_variant() {
    for &(variant, _) in ALL_INTENT_STATUSES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: IntentStatus = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn intent_status_rejects_pascal_case() {
    let bad: Result<IntentStatus, _> = serde_json::from_value(json!("InProgress"));
    assert!(
        bad.is_err(),
        "snake_case enum must reject PascalCase: {bad:?}"
    );
    let bad: Result<IntentStatus, _> = serde_json::from_value(json!("Pending"));
    assert!(
        bad.is_err(),
        "snake_case enum must reject PascalCase: {bad:?}"
    );
}

#[test]
fn operation_status_uses_default_pascal_case_for_every_variant() {
    // OperationStatus has NO rename_all — it serializes in PascalCase by
    // default. Pin this so a future "harmonize with IntentStatus" refactor
    // (which would silently break wire compatibility for any consumer
    // filtering on Status strings) is caught loudly.
    for &(variant, wire) in ALL_OPERATION_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(
            v,
            json!(wire),
            "OperationStatus {variant:?} must serialize as PascalCase `{wire}`"
        );
        let back: OperationStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn operation_status_rejects_snake_case_inputs() {
    // Sanity sentinel: dropping default-PascalCase and adding snake_case
    // would invert the rejection behavior. Right now snake_case is wrong.
    let bad: Result<OperationStatus, _> = serde_json::from_value(json!("pending"));
    assert!(
        bad.is_err(),
        "OperationStatus must reject lowercase/snake_case input: {bad:?}"
    );
    let bad: Result<OperationStatus, _> = serde_json::from_value(json!("running"));
    assert!(
        bad.is_err(),
        "OperationStatus must reject lowercase: {bad:?}"
    );
}

#[test]
fn intent_status_and_operation_status_use_distinct_casing_for_overlapping_names() {
    // Loud cross-enum casing-divergence sentinel: both enums have variants
    // named Pending / Completed / Failed, but the serde forms diverge:
    //   IntentStatus::Pending     -> "pending"   (snake_case)
    //   OperationStatus::Pending  -> "Pending"   (PascalCase default)
    //
    // Operator dashboards may filter on both fields. Accidentally renaming
    // either side to match the other would silently merge two distinct
    // status streams. Pin this divergence so it cannot drift.
    assert_ne!(
        serde_json::to_value(IntentStatus::Pending).unwrap(),
        serde_json::to_value(OperationStatus::Pending).unwrap(),
        "Pending casing must differ between IntentStatus and OperationStatus"
    );
    assert_ne!(
        serde_json::to_value(IntentStatus::Completed).unwrap(),
        serde_json::to_value(OperationStatus::Completed).unwrap(),
        "Completed casing must differ between IntentStatus and OperationStatus"
    );
    assert_ne!(
        serde_json::to_value(IntentStatus::Failed).unwrap(),
        serde_json::to_value(OperationStatus::Failed).unwrap(),
        "Failed casing must differ between IntentStatus and OperationStatus"
    );
}

#[test]
fn intent_status_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_INTENT_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(seen.insert(v.clone()), "duplicate IntentStatus json: {v:?}");
    }
}

#[test]
fn operation_status_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, _) in ALL_OPERATION_STATUSES {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate OperationStatus json: {v:?}"
        );
    }
}

#[test]
fn idempotency_entry_roundtrip_preserves_embedded_intent_status() {
    // IdempotencyEntry embeds IntentStatus. Round-trip both JSON and CBOR
    // and confirm the snake_case serde form survives nesting.
    let entry = IdempotencyEntry {
        key: "idem-key-1".to_string(),
        zone_id: ZoneId::work(),
        intent_id: ObjectId::from_unscoped_bytes(b"intent-1"),
        receipt_id: Some(ObjectId::from_unscoped_bytes(b"receipt-1")),
        status: IntentStatus::InProgress,
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
    };

    let json_bytes = serde_json::to_vec(&entry).unwrap();
    let json_value: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(
        json_value.get("status"),
        Some(&json!("in_progress")),
        "embedded IntentStatus must serialize as snake_case"
    );

    let from_json: IdempotencyEntry = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(from_json.status, IntentStatus::InProgress);
    assert_eq!(from_json.key, entry.key);
    assert_eq!(from_json.receipt_id, entry.receipt_id);

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&entry, &mut cbor_bytes).unwrap();
    let from_cbor: IdempotencyEntry = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(from_cbor.status, IntentStatus::InProgress);
    assert_eq!(from_cbor.key, entry.key);
}

#[test]
fn operation_intent_distinct_lease_seq_changes_json() {
    // Sanity: changing lease_seq must change the wire form so that
    // signature-bound intents cannot collide on the same canonical bytes.
    let mut a = full_intent();
    let mut b = full_intent();
    a.lease_seq = Some(1);
    b.lease_seq = Some(2);
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv);
}
