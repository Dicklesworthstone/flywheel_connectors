//! Pin `LeaseResponse` (the closest analogue to "`LeaseGrant`") +
//! `LeaseRequest` serde shape (flywheel_connectors-trwwc).
//!
//! Bead asks for `LeaseGrant Display formatting + serde`. No type
//! literally named `LeaseGrant` exists in fcp-core. The
//! lease-grant-shaped surface lives in two paired types in
//! `lease.rs`:
//!
//!  - `LeaseRequest` (`lease.rs:472`) — request to acquire or renew
//!    a lease.
//!  - `LeaseResponse` (`lease.rs:491`) — 3-variant externally-tagged
//!    enum carrying the response: `Granted(Box<Lease>)` (the actual
//!    lease grant), `Denied { ... }` (with current holder/expiry),
//!    `Invalid { reason }` (malformed request).
//!
//! Neither implements `Display`, so the bead's "Display formatting"
//! ask has no direct analogue. Pinning targets the externally-
//! tagged serde wire form on `LeaseResponse` + the full struct
//! shape on `LeaseRequest`.
//!
//! Targets:
//!
//!   1. **`LeaseResponse::Granted` JSON shape** — externally-tagged
//!      single-key form `{"Granted": {<lease fields>}}`.
//!   2. **`LeaseResponse::Denied` JSON shape** — single-key form
//!      with named struct fields (`current_holder`, `expires_at`,
//!      `current_seq`).
//!   3. **`LeaseResponse::Invalid` JSON shape** — single-key form
//!      with `reason` field.
//!   4. **JSON round-trip** preserves variant + payload for each.
//!   5. **CBOR round-trip preserves `Denied` + `Invalid`** (the
//!      payload-light variants). `Granted` holds a `Box<Lease>` with
//!      `ObjectId` via `hex_or_bytes` which intersects the known
//!      Content-shim quirk on internally-tagged enums but
//!      `LeaseResponse` is externally-tagged so this should round-trip
//!      cleanly — pinned explicitly.
//!   6. **`LeaseRequest` JSON shape pinned** — 5 fields including
//!      `Option<u64>` for `renew_seq`.
//!   7. **`LeaseRequest` JSON + CBOR round-trip**.
//!   8. **`PascalCase` tag canonical, `snake_case` rejected** — drift
//!      sentinel for any future `rename_all` swap on `LeaseResponse`.

use ciborium::value::Value as CborValue;
use fcp_cbor::SchemaId;
use fcp_core::{
    Lease, LeasePurpose, LeaseRequest, LeaseResponse, ObjectHeader, ObjectId, Provenance,
    SignatureSet, TailscaleNodeId, ZoneId,
};
use semver::Version;

fn build_lease() -> Lease {
    let zone = ZoneId::work();
    let subject = ObjectId::from_bytes([0x42; 32]);
    Lease {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1_000,
            provenance: Provenance::new(zone),
            refs: vec![subject],
            foreign_refs: vec![],
            ttl_secs: Some(3600),
            placement: None,
        },
        holder: TailscaleNodeId::new("holder-node"),
        lease_seq: 7,
        exp: 9_999_999,
        subject_object_id: subject,
        purpose: LeasePurpose::OperationExecution,
        quorum_signatures: SignatureSet::default(),
    }
}

fn denied_response() -> LeaseResponse {
    LeaseResponse::Denied {
        current_holder: TailscaleNodeId::new("holder-other"),
        expires_at: 1_700_000_000,
        current_seq: 42,
    }
}

fn invalid_response() -> LeaseResponse {
    LeaseResponse::Invalid {
        reason: "wrong zone".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. LeaseResponse::Granted JSON shape — externally-tagged
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_granted_serializes_as_externally_tagged_single_key_object() {
    let response = LeaseResponse::Granted(Box::new(build_lease()));
    let value = serde_json::to_value(&response).expect("serialize");
    let obj = value
        .as_object()
        .expect("LeaseResponse encodes as JSON object");
    assert_eq!(obj.len(), 1, "externally-tagged form is single-key");
    assert!(
        obj.contains_key("Granted"),
        "outer key MUST be PascalCase variant name `Granted` — got {value}"
    );
    let inner = obj.get("Granted").expect("Granted payload");
    let inner_obj = inner.as_object().expect("payload is JSON object");
    // Spot-check that the wrapped Lease fields are present via flatten.
    assert!(inner_obj.contains_key("holder"));
    assert!(inner_obj.contains_key("lease_seq"));
    assert!(inner_obj.contains_key("subject_object_id"));
    assert!(inner_obj.contains_key("purpose"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. LeaseResponse::Denied JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_denied_serializes_as_externally_tagged_single_key_object() {
    let response = denied_response();
    let value = serde_json::to_value(&response).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 1);
    assert!(obj.contains_key("Denied"));
    let inner = obj
        .get("Denied")
        .expect("payload")
        .as_object()
        .expect("inner object");
    assert_eq!(
        inner.get("current_holder").and_then(|v| v.as_str()),
        Some("holder-other")
    );
    assert_eq!(
        inner.get("expires_at").and_then(serde_json::Value::as_u64),
        Some(1_700_000_000)
    );
    assert_eq!(
        inner.get("current_seq").and_then(serde_json::Value::as_u64),
        Some(42)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. LeaseResponse::Invalid JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_invalid_serializes_with_reason_field() {
    let response = invalid_response();
    let value = serde_json::to_value(&response).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.len(), 1);
    assert!(obj.contains_key("Invalid"));
    let inner = obj
        .get("Invalid")
        .expect("payload")
        .as_object()
        .expect("inner");
    assert_eq!(
        inner.get("reason").and_then(|v| v.as_str()),
        Some("wrong zone")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON round-trip preserves variant + payload
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_granted_json_roundtrip_preserves_lease_payload() {
    let original_lease = build_lease();
    let response = LeaseResponse::Granted(Box::new(original_lease.clone()));
    let json = serde_json::to_string(&response).expect("serialize");
    let back: LeaseResponse = serde_json::from_str(&json).expect("deserialize");
    match back {
        LeaseResponse::Granted(l) => {
            assert_eq!(l.holder, original_lease.holder);
            assert_eq!(l.lease_seq, original_lease.lease_seq);
            assert_eq!(l.exp, original_lease.exp);
            assert_eq!(l.purpose, original_lease.purpose);
            assert_eq!(l.subject_object_id, original_lease.subject_object_id);
        }
        other => panic!("expected Granted, got {other:?}"),
    }
}

#[test]
fn lease_response_denied_json_roundtrip_preserves_payload() {
    let original = denied_response();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: LeaseResponse = serde_json::from_str(&json).expect("deserialize");
    match back {
        LeaseResponse::Denied {
            current_holder,
            expires_at,
            current_seq,
        } => {
            assert_eq!(current_holder.as_str(), "holder-other");
            assert_eq!(expires_at, 1_700_000_000);
            assert_eq!(current_seq, 42);
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn lease_response_invalid_json_roundtrip_preserves_reason() {
    let original = invalid_response();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: LeaseResponse = serde_json::from_str(&json).expect("deserialize");
    match back {
        LeaseResponse::Invalid { reason } => assert_eq!(reason, "wrong zone"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR round-trip — Denied and Invalid (payload-light)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_denied_cbor_roundtrip_preserves_payload() {
    let original = denied_response();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: LeaseResponse = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    match back {
        LeaseResponse::Denied {
            current_holder,
            expires_at,
            current_seq,
        } => {
            assert_eq!(current_holder.as_str(), "holder-other");
            assert_eq!(expires_at, 1_700_000_000);
            assert_eq!(current_seq, 42);
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn lease_response_invalid_cbor_roundtrip_preserves_reason() {
    let original = invalid_response();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: LeaseResponse = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    match back {
        LeaseResponse::Invalid { reason } => assert_eq!(reason, "wrong zone"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn lease_response_cbor_carries_externally_tagged_variant_key() {
    // Externally-tagged enum: CBOR encoding is a single-key map
    // with the variant name as the key. Pin via Value inspection.
    let response = denied_response();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&response, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("LeaseResponse MUST encode as CBOR Map, got {other:?}"),
    };
    assert_eq!(map.len(), 1, "externally-tagged form is single-key");
    let (key, _) = &map[0];
    match key {
        CborValue::Text(s) => assert_eq!(s, "Denied", "outer key MUST be variant name"),
        other => panic!("outer key MUST be Text, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. LeaseRequest JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_request_json_shape_preserves_all_5_fields() {
    let request = LeaseRequest {
        subject_object_id: ObjectId::from_bytes([0x42; 32]),
        zone_id: ZoneId::work(),
        requester: TailscaleNodeId::new("requester-node"),
        requested_ttl: 3_600,
        renew_seq: Some(15),
    };
    let value = serde_json::to_value(&request).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("subject_object_id"));
    assert!(obj.contains_key("zone_id"));
    assert!(obj.contains_key("requester"));
    assert!(obj.contains_key("requested_ttl"));
    assert!(obj.contains_key("renew_seq"));
    assert_eq!(
        obj.get("requester").and_then(|v| v.as_str()),
        Some("requester-node")
    );
    assert_eq!(
        obj.get("requested_ttl").and_then(serde_json::Value::as_u64),
        Some(3_600)
    );
    assert_eq!(
        obj.get("renew_seq").and_then(serde_json::Value::as_u64),
        Some(15)
    );
}

#[test]
fn lease_request_renew_seq_present_as_null_when_none() {
    // LeaseRequest::renew_seq has NO #[serde(skip_serializing_if)] —
    // pin that None serializes as JSON null (rather than being
    // omitted), distinct from skip_serializing_if behavior on
    // similar Optional fields elsewhere.
    let request = LeaseRequest {
        subject_object_id: ObjectId::from_bytes([0x00; 32]),
        zone_id: ZoneId::work(),
        requester: TailscaleNodeId::new("req"),
        requested_ttl: 60,
        renew_seq: None,
    };
    let value = serde_json::to_value(&request).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        obj.contains_key("renew_seq"),
        "renew_seq has no skip_serializing_if so MUST be present (as null) when None"
    );
    assert!(
        obj.get("renew_seq").is_some_and(serde_json::Value::is_null),
        "renew_seq MUST be JSON null when None"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. LeaseRequest JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_request_json_roundtrip_preserves_all_fields() {
    let original = LeaseRequest {
        subject_object_id: ObjectId::from_bytes([0xCC; 32]),
        zone_id: ZoneId::work(),
        requester: TailscaleNodeId::new("req-node"),
        requested_ttl: 7_200,
        renew_seq: Some(99),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: LeaseRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.subject_object_id, original.subject_object_id);
    assert_eq!(back.zone_id, original.zone_id);
    assert_eq!(back.requester, original.requester);
    assert_eq!(back.requested_ttl, original.requested_ttl);
    assert_eq!(back.renew_seq, original.renew_seq);
}

#[test]
fn lease_request_cbor_roundtrip_preserves_all_fields() {
    let original = LeaseRequest {
        subject_object_id: ObjectId::from_bytes([0xCC; 32]),
        zone_id: ZoneId::work(),
        requester: TailscaleNodeId::new("req-node"),
        requested_ttl: 7_200,
        renew_seq: None,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: LeaseRequest = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.subject_object_id, original.subject_object_id);
    assert_eq!(back.zone_id, original.zone_id);
    assert_eq!(back.requester, original.requester);
    assert_eq!(back.requested_ttl, original.requested_ttl);
    assert_eq!(back.renew_seq, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PascalCase canonical / snake_case rejected on LeaseResponse
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_response_rejects_snake_case_outer_key() {
    // LeaseResponse has NO #[serde(rename_all = ...)] — outer keys
    // are PascalCase variant names. Pin that snake_case is rejected
    // so any future rename_all swap is a deliberate visible change.
    let bad = serde_json::json!({
        "denied": {
            "current_holder": "node-x",
            "expires_at": 1,
            "current_seq": 1,
        }
    });
    let parsed = serde_json::from_value::<LeaseResponse>(bad);
    assert!(
        parsed.is_err(),
        "snake_case outer key MUST be rejected — wire form is PascalCase"
    );
}

#[test]
fn lease_response_rejects_unknown_variant() {
    let bad = serde_json::json!({"Unknown": {}});
    let parsed = serde_json::from_value::<LeaseResponse>(bad);
    assert!(parsed.is_err(), "unknown variant MUST be rejected");
}

#[test]
fn lease_response_three_variants_pairwise_distinct_via_serialization() {
    // Three variants — each serializes to a different outer-key
    // form. Pin that they remain pairwise distinct on the wire.
    let granted = LeaseResponse::Granted(Box::new(build_lease()));
    let denied = denied_response();
    let invalid = invalid_response();
    let g_json = serde_json::to_value(&granted).unwrap();
    let d_json = serde_json::to_value(&denied).unwrap();
    let i_json = serde_json::to_value(&invalid).unwrap();
    assert_ne!(g_json, d_json);
    assert_ne!(d_json, i_json);
    assert_ne!(g_json, i_json);
}
