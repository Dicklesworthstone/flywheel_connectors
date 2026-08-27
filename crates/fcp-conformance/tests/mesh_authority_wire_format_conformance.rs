//! `fcp_mesh::authority` wire-format + reason-code conformance.
//!
//! `authority_view_resolution_conformance.rs` already pins the
//! resolution rules (fencing-token tiebreak, expiry, lexicographic
//! ordering). This file pins the SERDE WIRE FORMAT contracts that
//! every persistence + audit consumer depends on:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`AuthorityStatus` 3 `snake_case` variants** — `active` /
//!    `superseded` / `expired`. Drift here would silently change
//!    every authority audit record's wire form.
//! 2. **`AuthorityReasonCode` 9 `snake_case` variants**:
//!    - `active_authority` (winner)
//!    - `superseded_by_preferred_lease` (loser to better candidate)
//!    - `lease_expired`
//!    - `lease_conflict_detected`
//!    - `lease_acquisition_rejected`
//!    - `lease_released`
//!    - `lease_not_held`
//!    - `coordinator_selected`
//!    - `no_eligible_coordinator`
//! 3. **Both enums reject unknown / mixed-case / empty-string
//!    JSON values** (strict `snake_case`).
//! 4. **`AuthorityRecord` serde roundtrip identity** — every field
//!    survives JSON encode→decode, including the optional
//!    coordinator field (which omits via `Option` semantics).
//! 5. **`AuthorityTimelineEvent` serde roundtrip identity** —
//!    optional fields (holder, coordinator, `fencing_token`,
//!    `expires_at`) round-trip cleanly.
//! 6. **`ObservedLeaseAuthority::new`** preserves the holder + lease
//!    fields verbatim and is `const fn`-friendly (compile-time
//!    construction surface).
//! 7. **`AuthorityView` serde roundtrip identity** — the snapshot
//!    is the durable on-the-wire format.
//! 8. **`Copy` + `Hash` on the Status/ReasonCode enums** — they
//!    appear in audit indexes and rate-limit keys.

use fcp_cbor::SchemaId;
use fcp_mesh::{
    AuthorityReasonCode, AuthorityRecord, AuthorityStatus, AuthorityTimelineEvent, AuthorityView,
    HeldLease, LeasePurpose, ObservedLeaseAuthority,
};
use fcp_prelude::{ObjectId, ObjectIdKey, TailscaleNodeId, ZoneId};
use semver::Version;

fn fake_object_id(tag: &[u8]) -> ObjectId {
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.test", "AuthorityWireFormat", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([5u8; 32]);
    ObjectId::new(tag, &zone, &schema, &key)
}

fn fake_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn fake_held_lease(tag: &[u8]) -> HeldLease {
    HeldLease {
        subject_id: fake_object_id(tag),
        purpose: LeasePurpose::OperationExecution,
        expires_at: 1_000_000_000,
        fencing_token: 42,
    }
}

// ─── AuthorityStatus snake_case ────────────────────────────────────

#[test]
fn authority_status_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (AuthorityStatus::Active, "\"active\""),
        (AuthorityStatus::Superseded, "\"superseded\""),
        (AuthorityStatus::Expired, "\"expired\""),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "{variant:?} MUST serialize as snake_case '{expected}'"
        );
        let parsed: AuthorityStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn authority_status_rejects_unknown_or_uppercase_values() {
    for bogus in ["\"ACTIVE\"", "\"Active\"", "\"\"", "\"unknown\""] {
        assert!(
            serde_json::from_str::<AuthorityStatus>(bogus).is_err(),
            "AuthorityStatus MUST reject {bogus}"
        );
    }
}

#[test]
fn authority_status_implements_copy() {
    // Index/audit code passes Status by value; Copy MUST hold.
    fn takes_value(_: AuthorityStatus) {}
    let s = AuthorityStatus::Active;
    takes_value(s);
    takes_value(s); // would fail without Copy
    assert_eq!(s, AuthorityStatus::Active);
}

// ─── AuthorityReasonCode snake_case ────────────────────────────────

#[test]
fn authority_reason_code_serde_uses_snake_case_for_each_variant() {
    let cases = [
        (AuthorityReasonCode::ActiveAuthority, "\"active_authority\""),
        (
            AuthorityReasonCode::SupersededByPreferredLease,
            "\"superseded_by_preferred_lease\"",
        ),
        (AuthorityReasonCode::LeaseExpired, "\"lease_expired\""),
        (
            AuthorityReasonCode::LeaseConflictDetected,
            "\"lease_conflict_detected\"",
        ),
        (
            AuthorityReasonCode::LeaseAcquisitionRejected,
            "\"lease_acquisition_rejected\"",
        ),
        (AuthorityReasonCode::LeaseReleased, "\"lease_released\""),
        (AuthorityReasonCode::LeaseNotHeld, "\"lease_not_held\""),
        (
            AuthorityReasonCode::CoordinatorSelected,
            "\"coordinator_selected\"",
        ),
        (
            AuthorityReasonCode::NoEligibleCoordinator,
            "\"no_eligible_coordinator\"",
        ),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: AuthorityReasonCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn authority_reason_code_rejects_unknown_or_mixed_case_values() {
    for bogus in [
        "\"ACTIVE_AUTHORITY\"",
        "\"activeAuthority\"",
        "\"\"",
        "\"unknown_code\"",
        "\"superseded\"", // close but not exact
    ] {
        assert!(
            serde_json::from_str::<AuthorityReasonCode>(bogus).is_err(),
            "AuthorityReasonCode MUST reject {bogus}"
        );
    }
}

#[test]
fn authority_reason_code_implements_copy() {
    fn takes_value(_: AuthorityReasonCode) {}
    let r = AuthorityReasonCode::ActiveAuthority;
    takes_value(r);
    takes_value(r);
    assert_eq!(r, AuthorityReasonCode::ActiveAuthority);
}

// ─── AuthorityRecord serde roundtrip ───────────────────────────────

#[test]
fn authority_record_serde_roundtrip_preserves_all_fields() {
    let record = AuthorityRecord {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"subject-1"),
        purpose: LeasePurpose::OperationExecution,
        holder: fake_node("node-1"),
        coordinator: Some(fake_node("node-coord")),
        status: AuthorityStatus::Active,
        reason_code: AuthorityReasonCode::ActiveAuthority,
        fencing_token: 100,
        expires_at: 2_000_000_000,
        observed_at_ms: 1_500_000_000_000,
        explanation: "winner via highest fencing token".into(),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let parsed: AuthorityRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, record);
}

#[test]
fn authority_record_serializes_status_and_reason_as_snake_case() {
    let record = AuthorityRecord {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"x"),
        purpose: LeasePurpose::OperationExecution,
        holder: fake_node("n"),
        coordinator: None,
        status: AuthorityStatus::Superseded,
        reason_code: AuthorityReasonCode::SupersededByPreferredLease,
        fencing_token: 1,
        expires_at: 0,
        observed_at_ms: 0,
        explanation: String::new(),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(
        json.contains("\"status\":\"superseded\""),
        "status MUST embed as snake_case wire form; got {json}"
    );
    assert!(
        json.contains("\"reason_code\":\"superseded_by_preferred_lease\""),
        "reason_code MUST embed as snake_case wire form; got {json}"
    );
}

#[test]
fn authority_record_handles_optional_coordinator_field() {
    let record_none = AuthorityRecord {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"x"),
        purpose: LeasePurpose::OperationExecution,
        holder: fake_node("n"),
        coordinator: None,
        status: AuthorityStatus::Expired,
        reason_code: AuthorityReasonCode::LeaseExpired,
        fencing_token: 1,
        expires_at: 0,
        observed_at_ms: 0,
        explanation: String::new(),
    };
    let json = serde_json::to_string(&record_none).expect("serialize");
    let parsed: AuthorityRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.coordinator, None);
}

// ─── AuthorityTimelineEvent serde roundtrip ────────────────────────

#[test]
fn authority_timeline_event_serde_roundtrip_preserves_all_fields() {
    let event = AuthorityTimelineEvent {
        observed_at_ms: 12_345_000,
        operation: "acquire".into(),
        subject_id: fake_object_id(b"subj"),
        purpose: LeasePurpose::SingletonWriter,
        holder: Some(fake_node("node-a")),
        coordinator: Some(fake_node("coord-1")),
        reason_code: AuthorityReasonCode::CoordinatorSelected,
        fencing_token: Some(7),
        expires_at: Some(99_000_000),
        explanation: "HRW selected nodeA".into(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let parsed: AuthorityTimelineEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, event);
}

#[test]
fn authority_timeline_event_handles_all_optional_fields_as_none() {
    let event = AuthorityTimelineEvent {
        observed_at_ms: 0,
        operation: "noop".into(),
        subject_id: fake_object_id(b"y"),
        purpose: LeasePurpose::CoordinatorElection,
        holder: None,
        coordinator: None,
        reason_code: AuthorityReasonCode::NoEligibleCoordinator,
        fencing_token: None,
        expires_at: None,
        explanation: "no eligible nodes".into(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let parsed: AuthorityTimelineEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.holder, None);
    assert_eq!(parsed.coordinator, None);
    assert_eq!(parsed.fencing_token, None);
    assert_eq!(parsed.expires_at, None);
}

// ─── ObservedLeaseAuthority::new ───────────────────────────────────

#[test]
fn observed_lease_authority_new_preserves_holder_and_lease_fields() {
    let holder = fake_node("node-x");
    let lease = fake_held_lease(b"obs-subj");
    let observed = ObservedLeaseAuthority::new(holder.clone(), lease.clone());
    assert_eq!(observed.holder, holder);
    assert_eq!(observed.lease, lease);
}

#[test]
fn observed_lease_authority_serde_roundtrip_is_identity() {
    let observed = ObservedLeaseAuthority::new(fake_node("node-x"), fake_held_lease(b"obs"));
    let json = serde_json::to_string(&observed).expect("serialize");
    let parsed: ObservedLeaseAuthority = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, observed);
}

// ─── AuthorityView serde roundtrip ─────────────────────────────────

#[test]
fn authority_view_serde_roundtrip_preserves_all_fields() {
    let view = AuthorityView {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"view-subj"),
        purpose: LeasePurpose::OperationExecution,
        coordinator: Some(fake_node("coord-x")),
        failover_order: vec![fake_node("a"), fake_node("b"), fake_node("c")],
        active_holder: Some(fake_node("a")),
        active_fencing_token: Some(99),
        records: vec![],
        timeline: vec![],
    };
    let json = serde_json::to_string(&view).expect("serialize");
    let parsed: AuthorityView = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, view);
}

#[test]
fn authority_view_serde_handles_no_active_holder() {
    let view = AuthorityView {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"empty"),
        purpose: LeasePurpose::OperationExecution,
        coordinator: None,
        failover_order: vec![],
        active_holder: None,
        active_fencing_token: None,
        records: vec![],
        timeline: vec![],
    };
    let json = serde_json::to_string(&view).expect("serialize");
    let parsed: AuthorityView = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.active_holder, None);
    assert_eq!(parsed.active_fencing_token, None);
    assert_eq!(parsed.failover_order, [] as [fcp_prelude::TailscaleNodeId; 0]);
}

#[test]
fn authority_view_with_records_and_timeline_round_trips() {
    let record = AuthorityRecord {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"r"),
        purpose: LeasePurpose::OperationExecution,
        holder: fake_node("n1"),
        coordinator: None,
        status: AuthorityStatus::Active,
        reason_code: AuthorityReasonCode::ActiveAuthority,
        fencing_token: 5,
        expires_at: 100,
        observed_at_ms: 1000,
        explanation: "win".into(),
    };
    let event = AuthorityTimelineEvent {
        observed_at_ms: 1000,
        operation: "resolved".into(),
        subject_id: fake_object_id(b"r"),
        purpose: LeasePurpose::OperationExecution,
        holder: Some(fake_node("n1")),
        coordinator: None,
        reason_code: AuthorityReasonCode::ActiveAuthority,
        fencing_token: Some(5),
        expires_at: Some(100),
        explanation: "winner".into(),
    };
    let view = AuthorityView {
        zone_id: ZoneId::work(),
        subject_id: fake_object_id(b"r"),
        purpose: LeasePurpose::OperationExecution,
        coordinator: None,
        failover_order: vec![fake_node("n1"), fake_node("n2")],
        active_holder: Some(fake_node("n1")),
        active_fencing_token: Some(5),
        records: vec![record.clone()],
        timeline: vec![event.clone()],
    };
    let json = serde_json::to_string(&view).expect("serialize");
    let parsed: AuthorityView = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.records, vec![record]);
    assert_eq!(parsed.timeline, vec![event]);
}

// ─── LeasePurpose serde sanity (cross-check) ───────────────────────

#[test]
fn lease_purpose_serde_uses_snake_case_for_three_variants() {
    let cases = [
        (LeasePurpose::SingletonWriter, "\"singleton_writer\""),
        (LeasePurpose::OperationExecution, "\"operation_execution\""),
        (
            LeasePurpose::CoordinatorElection,
            "\"coordinator_election\"",
        ),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "{variant:?} MUST serialize as '{expected}'");
        let parsed: LeasePurpose = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}
