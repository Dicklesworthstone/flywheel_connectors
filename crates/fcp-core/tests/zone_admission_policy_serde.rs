//! Pin the zone-admission policy serde contract.
//!
//! No public fcp-core type is literally named `ZoneAdmissionPolicy`.
//! The admission surface for zones is `ZonePolicyObject`: it carries
//! principal, connector, capability, transport, and receipt policy that
//! `PolicyEngine` evaluates before allowing an invoke. This test keeps
//! that wire contract explicit while the FCP3 split is in progress.

use std::collections::BTreeSet;

use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityId, DecisionReceiptPolicy, ObjectHeader, PolicyPattern, Provenance, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};
use semver::Version;
use serde_json::{Value, json};

type ZoneAdmissionPolicy = ZonePolicyObject;

fn header(zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "ZonePolicyObject", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn pat(pattern: &str) -> PolicyPattern {
    PolicyPattern {
        pattern: pattern.to_string(),
    }
}

fn representative_policy() -> ZoneAdmissionPolicy {
    let zone = ZoneId::work();

    ZonePolicyObject {
        header: header(zone.clone()),
        zone_id: zone,
        principal_allow: vec![pat("user:alice"), pat("service:*")],
        principal_deny: vec![pat("user:blocked")],
        connector_allow: vec![pat("connector:github")],
        connector_deny: vec![pat("connector:untrusted-*")],
        capability_allow: vec![pat("cap.read"), pat("cap.write")],
        capability_deny: vec![pat("cap.admin")],
        capability_ceiling: vec![
            CapabilityId::from_static("cap.read"),
            CapabilityId::from_static("cap.write"),
        ],
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        },
        decision_receipts: DecisionReceiptPolicy {
            emit_on_allow: true,
            emit_on_deny: true,
        },
        usage_budget: None,
        requires_posture: None,
    }
}

fn value_of(policy: &ZoneAdmissionPolicy) -> Value {
    serde_json::to_value(policy).expect("serialize ZoneAdmissionPolicy as JSON value")
}

#[test]
fn zone_admission_policy_json_shape_is_pinned() {
    let value = value_of(&representative_policy());
    let object = value.as_object().expect("policy serializes as JSON object");
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();

    assert_eq!(
        keys,
        BTreeSet::from([
            "capability_allow",
            "capability_ceiling",
            "capability_deny",
            "connector_allow",
            "connector_deny",
            "decision_receipts",
            "header",
            "principal_allow",
            "principal_deny",
            "transport_policy",
            "zone_id",
        ]),
        "ZoneAdmissionPolicy top-level JSON fields drifted"
    );

    assert_eq!(value["zone_id"], json!("z:work"));
    assert_eq!(
        value["principal_allow"],
        json!([{ "pattern": "user:alice" }, { "pattern": "service:*" }])
    );
    assert_eq!(
        value["principal_deny"],
        json!([{ "pattern": "user:blocked" }])
    );
    assert_eq!(
        value["connector_allow"],
        json!([{ "pattern": "connector:github" }])
    );
    assert_eq!(
        value["connector_deny"],
        json!([{ "pattern": "connector:untrusted-*" }])
    );
    assert_eq!(
        value["capability_allow"],
        json!([{ "pattern": "cap.read" }, { "pattern": "cap.write" }])
    );
    assert_eq!(
        value["capability_deny"],
        json!([{ "pattern": "cap.admin" }])
    );
    assert_eq!(
        value["capability_ceiling"],
        json!(["cap.read", "cap.write"])
    );
    assert_eq!(
        value["transport_policy"],
        json!({
            "allow_lan": true,
            "allow_derp": true,
            "allow_funnel": false,
        })
    );
    assert_eq!(
        value["decision_receipts"],
        json!({
            "emit_on_allow": true,
            "emit_on_deny": true,
        })
    );
    assert!(
        value.get("usage_budget").is_none(),
        "absent usage_budget must stay omitted"
    );
    assert!(
        value.get("requires_posture").is_none(),
        "absent requires_posture must stay omitted"
    );
}

#[test]
fn zone_admission_policy_json_roundtrips() {
    let original = representative_policy();
    let json = serde_json::to_string(&original).expect("serialize JSON");
    let decoded: ZoneAdmissionPolicy = serde_json::from_str(&json).expect("deserialize JSON");

    assert_eq!(value_of(&decoded), value_of(&original));
}

#[test]
fn zone_admission_policy_cbor_roundtrips() {
    let original = representative_policy();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&original, &mut encoded).expect("serialize CBOR");

    let decoded: ZoneAdmissionPolicy =
        ciborium::de::from_reader(encoded.as_slice()).expect("deserialize CBOR");

    assert_eq!(value_of(&decoded), value_of(&original));
}

#[test]
fn zone_admission_policy_cbor_reencoding_is_stable_after_decode() {
    let original = representative_policy();
    let mut first = Vec::new();
    ciborium::ser::into_writer(&original, &mut first).expect("serialize CBOR");

    let decoded: ZoneAdmissionPolicy =
        ciborium::de::from_reader(first.as_slice()).expect("deserialize CBOR");
    let mut second = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut second).expect("re-serialize CBOR");

    assert_eq!(
        second, first,
        "ZoneAdmissionPolicy CBOR bytes must remain stable across decode/re-encode"
    );
}
