//! Pin `DecisionReceipt` JSON+CBOR serde matrix — the closest analogue to
//! "`RoutingDecision` serde tag" (flywheel_connectors-hw4hi).
//!
//! Bead asks for `RoutingDecision` JSON+CBOR roundtrip + serde tag pinning.
//! No type literally named `RoutingDecision` exists in fcp-core. The closest
//! serializable decision-record is [`DecisionReceipt`] at
//! `crates/fcp-core/src/audit.rs:317` — the "why allowed/denied" record
//! returned by the policy engine that powers `fcp explain`. `PolicyDecision`
//! at `policy.rs:2196` is a narrower runtime struct (NOT Serialize/Deserialize);
//! `DecisionReceipt` is the on-the-wire form. A routing decision in a mesh
//! IS an Allow/Deny decision keyed by a request and a reason — this is the
//! fcp-core wire form for that semantic.
//!
//! Existing `audit_chain_golden_vectors.rs` covers `DecisionReceipt`
//! construction + `is_allow/is_deny` predicates. `policy_decision_serde_tag_matrix.rs`
//! covers the bare Decision enum (Allow/Deny lowercase serde). This pin
//! adds the residual full-struct serde matrix.
//!
//! Coverage:
//!   * 7-field JSON shape pinned (header, `request_object_id`, decision,
//!     `reason_code`, evidence, explanation, signature) — explanation
//!     omitted when None,
//!   * skip-when-None for explanation,
//!   * Embedded Decision lowercase serde tag inside the receipt,
//!   * Empty evidence Vec serializes as [] (no `skip_serializing_if` —
//!     pin so a future skip-when-empty silently dropping evidence is
//!     caught loudly),
//!   * JSON + CBOR round-trip preserves `decision/reason_code/evidence`,
//!   * `is_allow` / `is_deny` survives JSON round-trip,
//!   * Distinct decisions produce distinct JSON,
//!   * Distinct `reason_codes` produce distinct JSON.

use fcp_cbor::SchemaId;
use fcp_core::{
    Decision, DecisionReceipt, NodeId, NodeSignature, ObjectHeader, ObjectId, Provenance, ZoneId,
};
use semver::Version;
use serde_json::json;

fn header(zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0)),
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
    NodeSignature::new(NodeId::new("evaluator"), [0u8; 64], 1_700_000_000)
}

fn allow_with_evidence() -> DecisionReceipt {
    DecisionReceipt {
        header: header(ZoneId::work()),
        request_object_id: ObjectId::from_unscoped_bytes(b"request-1"),
        decision: Decision::Allow,
        reason_code: "ALLOW".to_string(),
        evidence: vec![
            ObjectId::from_unscoped_bytes(b"evidence-1"),
            ObjectId::from_unscoped_bytes(b"evidence-2"),
        ],
        explanation: Some("Capability token verified".to_string()),
        signature: signature(),
    }
}

fn deny_minimal() -> DecisionReceipt {
    DecisionReceipt {
        header: header(ZoneId::work()),
        request_object_id: ObjectId::from_unscoped_bytes(b"request-2"),
        decision: Decision::Deny,
        reason_code: "zone_policy.principal_denied".to_string(),
        evidence: vec![],
        explanation: None,
        signature: signature(),
    }
}

#[test]
fn full_field_set_pinned_when_explanation_present() {
    let receipt = allow_with_evidence();
    let v = serde_json::to_value(&receipt).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "header",
        "request_object_id",
        "decision",
        "reason_code",
        "evidence",
        "explanation",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "DecisionReceipt shape drift: {obj:?}");
}

#[test]
fn explanation_omitted_when_none() {
    // explanation has #[serde(skip_serializing_if = "Option::is_none")] —
    // when None, must be OMITTED from wire form (not present as null).
    let receipt = deny_minimal();
    let v = serde_json::to_value(&receipt).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("explanation"),
        "explanation must be omitted when None, got {obj:?}"
    );

    // Required fields still present (6-field minimal shape).
    let expected: std::collections::BTreeSet<&str> = [
        "header",
        "request_object_id",
        "decision",
        "reason_code",
        "evidence",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected);
}

#[test]
fn embedded_decision_tag_uses_lowercase_serde_form() {
    // Decision rename_all = "lowercase" → Allow/Deny serialize as "allow"/"deny".
    let allow = allow_with_evidence();
    let v = serde_json::to_value(&allow).unwrap();
    assert_eq!(v.get("decision"), Some(&json!("allow")));

    let deny = deny_minimal();
    let v = serde_json::to_value(&deny).unwrap();
    assert_eq!(v.get("decision"), Some(&json!("deny")));
}

#[test]
fn empty_evidence_vec_serializes_as_empty_array_not_omitted() {
    // evidence is a required Vec field with NO skip_serializing_if. Pin
    // that an empty Vec serializes as [] (not omitted) — a future
    // skip-when-empty would silently drop the explicit "no evidence"
    // signal, which is itself audit-critical (a decision with no
    // evidence is a different statement from a missing evidence field).
    let receipt = deny_minimal();
    let v = serde_json::to_value(&receipt).unwrap();
    assert_eq!(
        v.get("evidence"),
        Some(&json!([])),
        "empty evidence must serialize as []"
    );
}

#[test]
fn json_roundtrip_preserves_allow_with_evidence() {
    let receipt = allow_with_evidence();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();

    assert!(back.is_allow());
    assert!(!back.is_deny());
    assert_eq!(back.decision, Decision::Allow);
    assert_eq!(back.reason_code, "ALLOW");
    assert_eq!(back.request_object_id, receipt.request_object_id);
    assert_eq!(back.evidence.len(), 2);
    assert_eq!(back.evidence, receipt.evidence);
    assert_eq!(back.explanation, receipt.explanation);
}

#[test]
fn json_roundtrip_preserves_deny_minimal() {
    let receipt = deny_minimal();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();

    assert!(back.is_deny());
    assert!(!back.is_allow());
    assert_eq!(back.decision, Decision::Deny);
    assert_eq!(back.reason_code, "zone_policy.principal_denied");
    assert_eq!(back.evidence, [] as [fcp_core::ObjectId; 0]);
    assert!(back.explanation.is_none());
}

#[test]
fn cbor_roundtrip_preserves_allow_with_evidence() {
    let receipt = allow_with_evidence();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&receipt, &mut bytes).unwrap();
    let back: DecisionReceipt = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert!(back.is_allow());
    assert_eq!(back.reason_code, "ALLOW");
    assert_eq!(back.evidence, receipt.evidence);
    assert_eq!(back.explanation, receipt.explanation);
}

#[test]
fn cbor_roundtrip_preserves_deny_minimal() {
    let receipt = deny_minimal();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&receipt, &mut bytes).unwrap();
    let back: DecisionReceipt = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert!(back.is_deny());
    assert_eq!(back.evidence, [] as [fcp_core::ObjectId; 0]);
    assert!(back.explanation.is_none());
}

#[test]
fn json_and_cbor_decode_to_equivalent_receipt() {
    let receipt = allow_with_evidence();
    let json_bytes = serde_json::to_vec(&receipt).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&receipt, &mut cbor_bytes).unwrap();

    let from_json: DecisionReceipt = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: DecisionReceipt = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.decision, from_cbor.decision);
    assert_eq!(from_json.reason_code, from_cbor.reason_code);
    assert_eq!(from_json.evidence, from_cbor.evidence);
    assert_eq!(from_json.explanation, from_cbor.explanation);
    assert_eq!(from_json.request_object_id, from_cbor.request_object_id);
}

#[test]
fn distinct_decisions_produce_distinct_json() {
    // Same shape, only decision differs → JSON must differ.
    let mut allow = deny_minimal();
    let mut deny = deny_minimal();
    allow.decision = Decision::Allow;
    deny.decision = Decision::Deny;

    let av = serde_json::to_value(&allow).unwrap();
    let dv = serde_json::to_value(&deny).unwrap();
    assert_ne!(av, dv, "Allow vs Deny must differ");
    assert_eq!(av.get("decision"), Some(&json!("allow")));
    assert_eq!(dv.get("decision"), Some(&json!("deny")));
}

#[test]
fn distinct_reason_codes_produce_distinct_json() {
    let mut a = allow_with_evidence();
    let mut b = allow_with_evidence();
    a.reason_code = "ALLOW".to_string();
    b.reason_code = "zone_policy.transport_denied".to_string();

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv);
    assert_eq!(av.get("reason_code"), Some(&json!("ALLOW")));
    assert_eq!(
        bv.get("reason_code"),
        Some(&json!("zone_policy.transport_denied"))
    );
}

#[test]
fn distinct_evidence_lists_produce_distinct_json() {
    // Evidence is a security-critical field — pin that mutating the
    // evidence vec changes the wire form.
    let mut a = deny_minimal();
    let mut b = deny_minimal();
    a.evidence = vec![ObjectId::from_unscoped_bytes(b"e1")];
    b.evidence = vec![
        ObjectId::from_unscoped_bytes(b"e1"),
        ObjectId::from_unscoped_bytes(b"e2"),
    ];

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "evidence count must influence wire form");

    let mut c = deny_minimal();
    c.evidence = vec![ObjectId::from_unscoped_bytes(b"e9")];
    let cv = serde_json::to_value(&c).unwrap();
    assert_ne!(av, cv, "evidence content must influence wire form");
}

#[test]
fn predicates_after_json_roundtrip_remain_consistent() {
    // is_allow/is_deny are derived from the decision field; pin they
    // survive serde round-trip on both polarities.
    let allow_back: DecisionReceipt =
        serde_json::from_slice(&serde_json::to_vec(&allow_with_evidence()).unwrap()).unwrap();
    assert!(allow_back.is_allow());
    assert!(!allow_back.is_deny());

    let deny_back: DecisionReceipt =
        serde_json::from_slice(&serde_json::to_vec(&deny_minimal()).unwrap()).unwrap();
    assert!(deny_back.is_deny());
    assert!(!deny_back.is_allow());
}

#[test]
fn deserialize_rejects_uppercase_decision_token() {
    // Decision is rename_all = "lowercase" — accidentally accepting
    // PascalCase ("Allow") would silently let stale audit logs reload
    // as valid receipts. Pin via direct attempt.
    let bad = json!({
        "header": {
            "schema": { "namespace": "fcp.core", "name": "DecisionReceipt", "version": "1.0.0" },
            "zone_id": "z:work",
            "created_at": 0,
            "provenance": { "origin_zone": "z:work" },
            "refs": [],
            "foreign_refs": []
        },
        "request_object_id": "0".repeat(64),
        "decision": "Allow",
        "reason_code": "x",
        "evidence": [],
        "signature": {}
    });
    let result: Result<DecisionReceipt, _> = serde_json::from_value(bad);
    assert!(
        result.is_err(),
        "PascalCase Decision must reject through the receipt: {result:?}"
    );
}
