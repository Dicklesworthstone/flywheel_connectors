//! Pin lease-holder serde + handoff-validation invariants
//! (flywheel_connectors-4fus0).
//!
//! Bead asks for `LeaseHolder Display+FromStr roundtrip`. No type
//! literally named `LeaseHolder` exists in fcp-core. The "lease
//! holder" is the `holder: TailscaleNodeId` field carried on
//! `Lease` (lease.rs:114) and the paired `from_holder` /
//! `to_holder: TailscaleNodeId` fields on `LeaseHandoff`
//! (lease.rs:297-299). `TailscaleNodeId` Display + `FromStr` is
//! already pinned by `node_id_roundtrip.rs`, so this test focuses
//! on the LEASE-CONTEXT gaps that surface around the holder field:
//!
//!   1. **`Lease` JSON round-trip preserves `holder`** — the holder
//!      field travels with the lease envelope unchanged.
//!   2. **`Lease.holder` JSON shape is the bare validating
//!      `TailscaleNodeId` string** (via `try_from = "String"` /
//!      `into = "String"`).
//!   3. **`LeaseHandoff` JSON+CBOR round-trip preserves both
//!      `from_holder` and `to_holder`**.
//!   4. **`Lease` deserialization rejects malformed holder values**
//!      (uppercase, empty, non-canonical chars) via the
//!      `TailscaleNodeId::try_from` validation gate.
//!   5. **`validate_lease_handoff::SelfTransfer`** fires when
//!      `from_holder == to_holder` and its Display message names
//!      the offending holder verbatim.
//!   6. **`validate_lease_handoff::FromHolderMismatch`** fires when
//!      `active_lease.holder != handoff.from_holder` and surfaces
//!      both holders.
//!   7. **Holder Display agrees with `as_str()`** within the lease
//!      context — pin that the Lease's holder renders consistently
//!      across the audit log.
//!   8. **Distinct holder values are pairwise unequal** when
//!      embedded inside identical Lease envelopes — the holder
//!      field is part of structural Lease equality.

use fcp_cbor::SchemaId;
use fcp_core::{
    Lease, LeaseHandoff, LeasePurpose, LeaseTransferValidationError, ObjectHeader, ObjectId,
    Provenance, SignatureSet, TailscaleNodeId, ZoneId, validate_lease_handoff,
};
use semver::Version;

fn test_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn build_lease(holder: TailscaleNodeId, lease_seq: u64) -> Lease {
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
        holder,
        lease_seq,
        exp: 9_999_999,
        subject_object_id: subject,
        purpose: LeasePurpose::OperationExecution,
        quorum_signatures: SignatureSet::default(),
    }
}

const fn build_handoff(
    from: TailscaleNodeId,
    to: TailscaleNodeId,
    previous_seq: u64,
    next_seq: u64,
    subject: ObjectId,
    zone: ZoneId,
) -> LeaseHandoff {
    LeaseHandoff {
        previous_lease_id: ObjectId::from_bytes([0x11; 32]),
        next_lease_id: ObjectId::from_bytes([0x22; 32]),
        from_holder: from,
        to_holder: to,
        zone_id: zone,
        subject_object_id: subject,
        purpose: LeasePurpose::OperationExecution,
        previous_fencing_token: previous_seq,
        next_fencing_token: next_seq,
        transferred_at: 5_000,
        checkpoint_object_id: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Lease JSON round-trip preserves holder
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_json_roundtrip_preserves_holder_value() {
    let original = build_lease(test_node("holder-node-1"), 7);
    let json = serde_json::to_string(&original).expect("serialize");
    let back: Lease = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.holder, original.holder, "JSON round-trip lost holder");
    assert_eq!(back.holder.as_str(), "holder-node-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Lease.holder JSON shape is bare validating string
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_holder_json_shape_is_bare_string() {
    // TailscaleNodeId carries `#[serde(try_from = "String", into = "String")]`
    // — the wire form is the bare canonical id string.
    let lease = build_lease(test_node("alpha-host.example.com"), 1);
    let value = serde_json::to_value(&lease).expect("serialize");
    let holder_value = value.get("holder").expect("holder field");
    assert_eq!(
        holder_value,
        &serde_json::Value::String("alpha-host.example.com".to_string()),
        "Lease.holder MUST serialize as a bare validating string"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. LeaseHandoff JSON+CBOR round-trip preserves both holders
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_handoff_json_roundtrip_preserves_both_holder_fields() {
    let zone = ZoneId::work();
    let subject = ObjectId::from_bytes([0x42; 32]);
    let handoff = build_handoff(
        test_node("source-node"),
        test_node("target-node"),
        1,
        2,
        subject,
        zone,
    );

    let json = serde_json::to_string(&handoff).expect("serialize");
    let back: LeaseHandoff = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.from_holder.as_str(), "source-node");
    assert_eq!(back.to_holder.as_str(), "target-node");
    assert_eq!(back.from_holder, handoff.from_holder);
    assert_eq!(back.to_holder, handoff.to_holder);
}

#[test]
fn lease_handoff_cbor_roundtrip_preserves_both_holder_fields() {
    let zone = ZoneId::work();
    let subject = ObjectId::from_bytes([0x42; 32]);
    let handoff = build_handoff(
        test_node("source-node"),
        test_node("target-node"),
        1,
        2,
        subject,
        zone,
    );

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&handoff, &mut buf).expect("encode");
    let back: LeaseHandoff = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.from_holder, handoff.from_holder);
    assert_eq!(back.to_holder, handoff.to_holder);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Lease deserialization rejects malformed holder values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_deserialization_rejects_uppercase_holder() {
    // Build a valid Lease, swap the holder for an uppercase form on
    // the wire, and confirm `try_from = "String"` validation
    // rejects it. (TailscaleNodeId::try_from rejects uppercase.)
    let lease = build_lease(test_node("good-holder"), 1);
    let mut value = serde_json::to_value(&lease).expect("serialize");
    value["holder"] = serde_json::Value::String("UPPER-HOLDER".to_string());
    let result: Result<Lease, _> = serde_json::from_value(value);
    assert!(
        result.is_err(),
        "Lease deserialization MUST reject UPPER-HOLDER via TailscaleNodeId validation"
    );
}

#[test]
fn lease_deserialization_rejects_empty_holder() {
    let lease = build_lease(test_node("good-holder"), 1);
    let mut value = serde_json::to_value(&lease).expect("serialize");
    value["holder"] = serde_json::Value::String(String::new());
    let result: Result<Lease, _> = serde_json::from_value(value);
    assert!(
        result.is_err(),
        "Lease deserialization MUST reject empty holder"
    );
}

#[test]
fn lease_deserialization_rejects_holder_with_space() {
    let lease = build_lease(test_node("good-holder"), 1);
    let mut value = serde_json::to_value(&lease).expect("serialize");
    value["holder"] = serde_json::Value::String("with space".to_string());
    let result: Result<Lease, _> = serde_json::from_value(value);
    assert!(
        result.is_err(),
        "Lease deserialization MUST reject holder containing whitespace"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. SelfTransfer detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_handoff_rejects_self_transfer_with_holder_named() {
    let holder = test_node("same-node");
    let active = build_lease(holder.clone(), 1);
    // Make the active lease's subject/zone match the handoff so
    // self-transfer is the gate that fires (ordering of checks
    // pinned by lease.rs:415).
    let handoff = build_handoff(
        holder.clone(),
        holder.clone(),
        active.lease_seq,
        2,
        active.subject_object_id,
        active.zone_id().clone(),
    );

    let err = validate_lease_handoff(&active, &handoff, 5_000)
        .expect_err("self-transfer MUST be rejected");
    match err {
        LeaseTransferValidationError::SelfTransfer { holder: rejected } => {
            assert_eq!(
                rejected, holder,
                "error MUST carry the offending holder verbatim"
            );
        }
        other => panic!("expected SelfTransfer, got {other:?}"),
    }
}

#[test]
fn self_transfer_display_format_includes_holder_debug() {
    // Display format pinned by lease.rs:370:
    //   "lease handoff must transfer to a different holder (holder {holder:?})"
    let holder = test_node("loop-back-node");
    let err = LeaseTransferValidationError::SelfTransfer { holder };
    let s = err.to_string();
    assert!(
        s.starts_with("lease handoff must transfer to a different holder"),
        "SelfTransfer Display drift: {s}"
    );
    assert!(
        s.contains("loop-back-node"),
        "SelfTransfer Display MUST include offending holder id: {s}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. FromHolderMismatch detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_handoff_rejects_from_holder_mismatch() {
    let active_holder = test_node("real-holder");
    let active = build_lease(active_holder.clone(), 1);

    // handoff claims to come from a different node than the active
    // lease's holder.
    let claimed_from = test_node("imposter");
    let handoff = build_handoff(
        claimed_from.clone(),
        test_node("target"),
        active.lease_seq,
        2,
        active.subject_object_id,
        active.zone_id().clone(),
    );

    let err = validate_lease_handoff(&active, &handoff, 5_000)
        .expect_err("from_holder mismatch MUST be rejected");
    match err {
        LeaseTransferValidationError::FromHolderMismatch { expected, got } => {
            assert_eq!(expected, active_holder);
            assert_eq!(got, claimed_from);
        }
        other => panic!("expected FromHolderMismatch, got {other:?}"),
    }
}

#[test]
fn from_holder_mismatch_display_includes_both_holders() {
    let expected = test_node("expected-holder");
    let got = test_node("actual-holder");
    let err = LeaseTransferValidationError::FromHolderMismatch { expected, got };
    let s = err.to_string();
    assert!(
        s.starts_with("handoff source holder mismatch"),
        "FromHolderMismatch Display drift: {s}"
    );
    assert!(
        s.contains("expected-holder"),
        "expected holder MUST appear in display: {s}"
    );
    assert!(
        s.contains("actual-holder"),
        "actual holder MUST appear in display: {s}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Holder Display agreement within lease context
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_holder_renders_via_tailscale_node_id_as_str() {
    // The Lease.holder field's display surface is the underlying
    // TailscaleNodeId string. Pin that an embedded holder renders
    // consistently — operators reading audit logs see this exact
    // string per Lease.
    let lease = build_lease(test_node("audit-host.example.com"), 1);
    assert_eq!(lease.holder.as_str(), "audit-host.example.com");
    // And serializes as the same string.
    let value = serde_json::to_value(&lease).expect("serialize");
    let holder_str = value
        .get("holder")
        .and_then(|v| v.as_str())
        .expect("holder string");
    assert_eq!(holder_str, lease.holder.as_str());
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Distinct holders make Lease envelopes distinct (structural)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_holders_produce_distinct_lease_serializations() {
    // The holder field is part of the lease's wire identity — two
    // otherwise-identical leases with different holders MUST
    // produce different bytes.
    let lease_a = build_lease(test_node("holder-alpha"), 7);
    let lease_b = build_lease(test_node("holder-beta"), 7);
    let json_a = serde_json::to_string(&lease_a).expect("serialize a");
    let json_b = serde_json::to_string(&lease_b).expect("serialize b");
    assert_ne!(
        json_a, json_b,
        "different holder values MUST produce different JSON bytes"
    );

    // CBOR likewise.
    let mut buf_a = Vec::new();
    ciborium::ser::into_writer(&lease_a, &mut buf_a).expect("encode a");
    let mut buf_b = Vec::new();
    ciborium::ser::into_writer(&lease_b, &mut buf_b).expect("encode b");
    assert_ne!(
        buf_a, buf_b,
        "different holders MUST produce different CBOR"
    );
}

#[test]
fn handoff_swapping_from_and_to_holders_changes_serialization() {
    let zone = ZoneId::work();
    let subject = ObjectId::from_bytes([0x42; 32]);
    let h1 = build_handoff(test_node("x"), test_node("y"), 1, 2, subject, zone.clone());
    let h2 = build_handoff(test_node("y"), test_node("x"), 1, 2, subject, zone);

    let json_1 = serde_json::to_string(&h1).expect("serialize 1");
    let json_2 = serde_json::to_string(&h2).expect("serialize 2");
    assert_ne!(
        json_1, json_2,
        "swapping from_holder/to_holder MUST change JSON bytes"
    );
}
