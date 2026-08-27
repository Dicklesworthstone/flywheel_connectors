//! Pin `PolicySimulationInput` serde JSON+CBOR roundtrip — the closest
//! analogue to "`PolicyEvaluationContext` serde"
//! (flywheel_connectors-usmtd).
//!
//! Bead asks for `PolicyEvaluationContext` JSON+CBOR roundtrip pinning. No
//! type literally named `PolicyEvaluationContext` exists in fcp-core; the
//! evaluation-context surface is split between [`PolicyDecisionInput<'a>`]
//! (a borrowing struct used by the engine, NOT serializable) and
//! [`PolicySimulationInput`] (the serializable wire form fed to
//! [`simulate_policy_decision`], at `crates/fcp-core/src/policy.rs:2192`).
//! `PolicySimulationInput` is the closest serializable evaluation-context.
//!
//! Coverage:
//!   * Defaults applied when optional fields are omitted from input
//!     (`transport=Lan`, `checkpoint_fresh=true`, `revocation_fresh=true`,
//!     `execution_approval_required=false`, `safety_tier=Safe`, plus all the
//!     None/empty-Vec defaults),
//!   * JSON round-trip preserves a fully-populated input,
//!   * CBOR round-trip preserves a fully-populated input,
//!   * JSON shape pinned for the minimum-required input (only required
//!     fields present), serializes every field including defaults,
//!   * `request_input_hash: Option<[u8; 32]>` serializes as a 32-element
//!     array (no `hex_or_bytes` adapter on this field — pin so adding one
//!     later breaks loudly),
//!   * Distinct flags on the bool axes produce distinct JSON,
//!   * Distinct `transport`/`safety_tier` values produce distinct JSON,
//!   * Cross-format consistency (JSON and CBOR decode to same struct).

use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityToken, ConnectorId, DecisionReceiptPolicy, InvokeRequest, ObjectHeader, ObjectId,
    OperationId, PolicySimulationInput, Provenance, RequestId, SafetyTier, TransportMode, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};
use semver::Version;
use serde_json::json;

fn header(zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
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

fn base_policy(zone: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: header(zone.clone()),
        zone_id: zone,
        principal_allow: vec![],
        principal_deny: vec![],
        connector_allow: vec![],
        connector_deny: vec![],
        capability_allow: vec![],
        capability_deny: vec![],
        capability_ceiling: vec![],
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn base_invoke(zone: ZoneId) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("req-eval-context"),
        connector_id: ConnectorId::new("test", "request_response", "1.0.0").unwrap(),
        operation: OperationId::from_static("op.test"),
        zone_id: zone,
        input: json!({ "k": "v" }),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn minimal_input() -> PolicySimulationInput {
    let zone = ZoneId::work();
    PolicySimulationInput {
        zone_policy: base_policy(zone.clone()),
        invoke_request: base_invoke(zone),
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: vec![],
        related_object_ids: vec![],
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: None,
        capability_id: None,
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    }
}

fn populated_input() -> PolicySimulationInput {
    let zone = ZoneId::work();
    let mut input = minimal_input();
    input.zone_policy = base_policy(zone.clone());
    input.invoke_request = base_invoke(zone);
    input.transport = TransportMode::Derp;
    input.checkpoint_fresh = false;
    input.revocation_fresh = false;
    input.execution_approval_required = true;
    input.related_object_ids = vec![
        ObjectId::from_unscoped_bytes(b"related-1"),
        ObjectId::from_unscoped_bytes(b"related-2"),
    ];
    input.request_object_id = Some(ObjectId::from_unscoped_bytes(b"req-obj"));
    input.request_input_hash = Some([0x42; 32]);
    input.safety_tier = SafetyTier::Risky;
    input.principal = Some("user:alice".to_string());
    input.capability_id = Some("cap.read".to_string());
    input.now_ms = Some(1_700_000_000_000);
    input
}

#[test]
fn omitted_optional_fields_use_documented_defaults() {
    // Pin the contract that callers can submit a minimum-shaped JSON object
    // (only `zone_policy` + `invoke_request`) and serde fills the documented
    // defaults: transport=Lan, checkpoint_fresh=true, revocation_fresh=true,
    // execution_approval_required=false, safety_tier=Safe, all the
    // None/Vec::new() fields.
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let invoke = base_invoke(zone);

    let minimal_json = json!({
        "zone_policy": policy,
        "invoke_request": invoke,
    });

    let parsed: PolicySimulationInput = serde_json::from_value(minimal_json).unwrap();
    assert_eq!(parsed.transport, TransportMode::Lan);
    assert!(parsed.checkpoint_fresh);
    assert!(parsed.revocation_fresh);
    assert!(!parsed.execution_approval_required);
    assert_eq!(parsed.safety_tier, SafetyTier::Safe);
    assert!(parsed.sanitizer_receipts.is_empty());
    assert_eq!(parsed.related_object_ids, [] as [fcp_core::ObjectId; 0]);
    assert!(parsed.request_object_id.is_none());
    assert!(parsed.request_input_hash.is_none());
    assert!(parsed.principal.is_none());
    assert!(parsed.capability_id.is_none());
    assert!(parsed.provenance_record.is_none());
    assert!(parsed.now_ms.is_none());
    assert!(parsed.posture_attestation.is_none());
}

#[test]
fn json_roundtrip_preserves_minimal_input_through_decision_critical_axes() {
    // Minimal input has the documented defaults; round-tripping through JSON
    // must preserve every decision-critical scalar axis.
    let input = minimal_input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let back: PolicySimulationInput = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.transport, input.transport);
    assert_eq!(back.checkpoint_fresh, input.checkpoint_fresh);
    assert_eq!(back.revocation_fresh, input.revocation_fresh);
    assert_eq!(
        back.execution_approval_required,
        input.execution_approval_required
    );
    assert_eq!(back.safety_tier, input.safety_tier);
    assert_eq!(back.related_object_ids.len(), 0);
}

#[test]
fn json_roundtrip_preserves_populated_input_on_every_axis() {
    let input = populated_input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let back: PolicySimulationInput = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.transport, input.transport);
    assert_eq!(back.checkpoint_fresh, input.checkpoint_fresh);
    assert_eq!(back.revocation_fresh, input.revocation_fresh);
    assert_eq!(
        back.execution_approval_required,
        input.execution_approval_required
    );
    assert_eq!(back.safety_tier, input.safety_tier);
    assert_eq!(back.related_object_ids, input.related_object_ids);
    assert_eq!(back.request_object_id, input.request_object_id);
    assert_eq!(back.request_input_hash, input.request_input_hash);
    assert_eq!(back.principal, input.principal);
    assert_eq!(back.capability_id, input.capability_id);
    assert_eq!(back.now_ms, input.now_ms);
}

#[test]
fn cbor_roundtrip_preserves_populated_input() {
    let input = populated_input();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&input, &mut bytes).unwrap();
    let back: PolicySimulationInput = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.transport, input.transport);
    assert_eq!(back.checkpoint_fresh, input.checkpoint_fresh);
    assert_eq!(back.revocation_fresh, input.revocation_fresh);
    assert_eq!(
        back.execution_approval_required,
        input.execution_approval_required
    );
    assert_eq!(back.safety_tier, input.safety_tier);
    assert_eq!(back.request_object_id, input.request_object_id);
    assert_eq!(back.request_input_hash, input.request_input_hash);
    assert_eq!(back.principal, input.principal);
    assert_eq!(back.capability_id, input.capability_id);
    assert_eq!(back.now_ms, input.now_ms);
    assert_eq!(back.related_object_ids, input.related_object_ids);
}

#[test]
fn json_shape_pins_top_level_field_set() {
    let input = minimal_input();
    let value = serde_json::to_value(&input).unwrap();
    let obj = value.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "zone_policy",
        "invoke_request",
        "transport",
        "checkpoint_fresh",
        "revocation_fresh",
        "execution_approval_required",
        "sanitizer_receipts",
        "related_object_ids",
        "request_object_id",
        "request_input_hash",
        "safety_tier",
        "principal",
        "capability_id",
        "provenance_record",
        "now_ms",
        "posture_attestation",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        actual, expected,
        "PolicySimulationInput JSON top-level field set drift"
    );
}

#[test]
fn request_input_hash_serializes_as_32_element_array_not_hex() {
    // The field is `Option<[u8; 32]>` WITHOUT a hex_or_bytes adapter — it
    // serializes as a 32-element JSON array. Pin this so a future addition
    // of hex_or_bytes (which would silently change the wire form to a hex
    // string) trips the test loudly.
    let mut input = minimal_input();
    input.request_input_hash = Some([0xab; 32]);
    let value = serde_json::to_value(&input).unwrap();
    let hash_value = value.get("request_input_hash").unwrap();

    let arr = hash_value
        .as_array()
        .expect("request_input_hash must serialize as array, not string");
    assert_eq!(arr.len(), 32);
    for byte in arr {
        assert_eq!(byte.as_u64(), Some(0xab));
    }
}

#[test]
fn distinct_freshness_flags_produce_distinct_json() {
    let mut a = minimal_input();
    let mut b = minimal_input();
    b.checkpoint_fresh = false;
    let mut c = minimal_input();
    c.revocation_fresh = false;

    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    let cv = serde_json::to_value(&c).unwrap();
    assert_ne!(av, bv, "checkpoint_fresh axis must change JSON");
    assert_ne!(av, cv, "revocation_fresh axis must change JSON");

    // Touching the field also changes Vec defaults.
    a.related_object_ids = vec![ObjectId::from_unscoped_bytes(b"r")];
    let with_related = serde_json::to_value(&a).unwrap();
    assert_ne!(with_related, av);
}

#[test]
fn distinct_transport_and_safety_tier_produce_distinct_json() {
    let lan = serde_json::to_value(minimal_input()).unwrap();

    let mut derp = minimal_input();
    derp.transport = TransportMode::Derp;
    let derp_v = serde_json::to_value(&derp).unwrap();
    assert_ne!(lan, derp_v, "transport axis must change JSON");

    let mut risky = minimal_input();
    risky.safety_tier = SafetyTier::Risky;
    let risky_v = serde_json::to_value(&risky).unwrap();
    assert_ne!(lan, risky_v, "safety_tier axis must change JSON");
}

#[test]
fn json_and_cbor_decode_to_same_input_for_decision_critical_axes() {
    let input = populated_input();
    let json_bytes = serde_json::to_vec(&input).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&input, &mut cbor_bytes).unwrap();

    let from_json: PolicySimulationInput = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: PolicySimulationInput = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    // Compare on every decision-critical axis (the struct itself is not
    // PartialEq because nested types like ZonePolicyObject aren't).
    assert_eq!(from_json.transport, from_cbor.transport);
    assert_eq!(from_json.checkpoint_fresh, from_cbor.checkpoint_fresh);
    assert_eq!(from_json.revocation_fresh, from_cbor.revocation_fresh);
    assert_eq!(
        from_json.execution_approval_required,
        from_cbor.execution_approval_required
    );
    assert_eq!(from_json.safety_tier, from_cbor.safety_tier);
    assert_eq!(from_json.related_object_ids, from_cbor.related_object_ids);
    assert_eq!(from_json.request_object_id, from_cbor.request_object_id);
    assert_eq!(from_json.request_input_hash, from_cbor.request_input_hash);
    assert_eq!(from_json.principal, from_cbor.principal);
    assert_eq!(from_json.capability_id, from_cbor.capability_id);
    assert_eq!(from_json.now_ms, from_cbor.now_ms);
}

#[test]
fn empty_required_collections_serialize_as_empty_arrays_not_omitted() {
    // sanitizer_receipts and related_object_ids are required Vec fields;
    // pin that they serialize as `[]` (no skip_serializing_if) — round-tripping
    // through a system that drops empty Vecs would silently lose the
    // explicit "no related objects" signal.
    let input = minimal_input();
    let value = serde_json::to_value(&input).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(
        obj.get("sanitizer_receipts"),
        Some(&json!([])),
        "sanitizer_receipts must serialize as []"
    );
    assert_eq!(
        obj.get("related_object_ids"),
        Some(&json!([])),
        "related_object_ids must serialize as []"
    );
}
