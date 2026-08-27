//! Pin `CapabilityConstraints` predicate matrix + validation Display
//! formatting (flywheel_connectors-u34oi).
//!
//! Bead asks for "`CapabilityConstraint` Display formatting". No
//! singular `CapabilityConstraint` type exists in fcp-core — only
//! the plural `CapabilityConstraints` set type (capability.rs:1439).
//! `CapabilityConstraints` itself does NOT implement `Display`; the
//! Display surface that operators see is on the validation errors
//! it produces (`CredentialValidationError`, credential.rs:305).
//!
//! Tests pin what exists for the constraint set:
//!
//!   1. **`is_empty()` truth table** — true on default-constructed
//!      (every field empty/None), false when any single field is
//!      populated (each field exercised independently).
//!   2. **Default is the empty constraint set** — important because
//!      the docs (capability.rs:1472) call out "An empty constraint
//!      set means **deny all**" — this is the default-deny
//!      interpretation required by C3.4.
//!   3. **`is_credential_allowed()` semantics** — true only when the
//!      credential is explicitly listed; empty allow-list rejects
//!      everything (default-deny).
//!   4. **`validate_credential()` Ok ⇔ `is_credential_allowed`**.
//!   5. **`CredentialValidationError::NotInCredentialAllow` Display
//!      format** — exact `"credential {uuid} not in capability's
//!      credential_allow"` shape that operators see.
//!   6. **Error carries the offending `CredentialId` verbatim**.
//!   7. **Serde JSON round-trip** preserves all fields including
//!      empty Vec<>/None defaults.

use fcp_core::{CapabilityConstraints, CredentialId, CredentialValidationError};

const FIXED_UUID_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXED_UUID_B: &str = "00000000-0000-0000-0000-000000000001";

fn cred(uuid: &str) -> CredentialId {
    CredentialId::parse(uuid).expect("canonical uuid")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. is_empty() truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn default_is_empty_constraint_set() {
    let c = CapabilityConstraints::default();
    assert!(
        c.is_empty(),
        "DEFAULT-DENY REGRESSION: default CapabilityConstraints MUST be empty \
         (capability.rs:1472 documents 'empty == deny all')"
    );
    // And every field is its zero value.
    assert_eq!(c.resource_allow, [] as [std::string::String; 0]);
    assert_eq!(c.resource_deny, [] as [std::string::String; 0]);
    assert!(c.max_calls.is_none());
    assert!(c.max_bytes.is_none());
    assert!(c.idempotency_key.is_none());
    assert_eq!(c.credential_allow, [] as [fcp_core::CredentialId; 0]);
}

#[test]
fn is_empty_false_when_resource_allow_populated() {
    let mut c = CapabilityConstraints::default();
    c.resource_allow.push("https://api.example.com/*".into());
    assert!(
        !c.is_empty(),
        "is_empty MUST be false when resource_allow is set"
    );
}

#[test]
fn is_empty_false_when_resource_deny_populated() {
    let mut c = CapabilityConstraints::default();
    c.resource_deny.push("https://blocked.example.com/*".into());
    assert!(
        !c.is_empty(),
        "is_empty MUST be false when resource_deny is set"
    );
}

#[test]
fn is_empty_false_when_max_calls_set() {
    let c = CapabilityConstraints {
        max_calls: Some(100),
        ..Default::default()
    };
    assert!(!c.is_empty());
}

#[test]
fn is_empty_false_when_max_bytes_set() {
    let c = CapabilityConstraints {
        max_bytes: Some(1024),
        ..Default::default()
    };
    assert!(!c.is_empty());
}

#[test]
fn is_empty_false_when_idempotency_key_set() {
    let c = CapabilityConstraints {
        idempotency_key: Some("abc-123".to_string()),
        ..Default::default()
    };
    assert!(!c.is_empty());
}

#[test]
fn is_empty_false_when_credential_allow_populated() {
    let mut c = CapabilityConstraints::default();
    c.credential_allow.push(cred(FIXED_UUID_A));
    assert!(
        !c.is_empty(),
        "is_empty MUST be false when credential_allow is set"
    );
}

#[test]
fn is_empty_zero_max_calls_still_marks_non_empty() {
    // max_calls = Some(0) is still "set" — is_empty must NOT treat
    // zero as absence.
    let c = CapabilityConstraints {
        max_calls: Some(0),
        ..Default::default()
    };
    assert!(
        !c.is_empty(),
        "max_calls=Some(0) is a real constraint, not absence"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. is_credential_allowed() semantics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_credential_allow_rejects_every_credential() {
    // The doc (capability.rs:1487) says: "Empty credential_allow
    // implies no credentials are allowed (default deny)."
    let c = CapabilityConstraints::default();
    let id = cred(FIXED_UUID_A);
    assert!(
        !c.is_credential_allowed(&id),
        "DEFAULT-DENY REGRESSION: empty credential_allow MUST reject every credential"
    );
}

#[test]
fn listed_credential_is_allowed() {
    let id_a = cred(FIXED_UUID_A);
    let id_b = cred(FIXED_UUID_B);
    let c = CapabilityConstraints {
        credential_allow: vec![id_a],
        ..Default::default()
    };
    assert!(
        c.is_credential_allowed(&id_a),
        "listed credential MUST be allowed"
    );
    assert!(
        !c.is_credential_allowed(&id_b),
        "non-listed credential MUST NOT be allowed even when allow-list is non-empty"
    );
}

#[test]
fn multiple_listed_credentials_each_allowed() {
    let id_a = cred(FIXED_UUID_A);
    let id_b = cred(FIXED_UUID_B);
    let id_c = CredentialId::new();
    let c = CapabilityConstraints {
        credential_allow: vec![id_a, id_b],
        ..Default::default()
    };
    assert!(c.is_credential_allowed(&id_a));
    assert!(c.is_credential_allowed(&id_b));
    assert!(
        !c.is_credential_allowed(&id_c),
        "third credential not in list MUST be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. validate_credential() iff agreement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_credential_ok_iff_is_credential_allowed() {
    let id_a = cred(FIXED_UUID_A);
    let id_b = cred(FIXED_UUID_B);
    let c = CapabilityConstraints {
        credential_allow: vec![id_a],
        ..Default::default()
    };

    // Allowed → Ok.
    assert!(c.is_credential_allowed(&id_a));
    assert!(c.validate_credential(&id_a).is_ok());

    // Not allowed → Err with the offending CredentialId.
    assert!(!c.is_credential_allowed(&id_b));
    let err = c
        .validate_credential(&id_b)
        .expect_err("non-listed credential MUST be rejected");
    match err {
        CredentialValidationError::NotInCredentialAllow { credential_id } => {
            assert_eq!(
                credential_id, id_b,
                "error MUST carry the offending credential id verbatim"
            );
        }
        other => panic!("expected NotInCredentialAllow, got {other:?}"),
    }
}

#[test]
fn validate_credential_against_empty_allow_list_rejects_every_id() {
    let c = CapabilityConstraints::default();
    for fixture in [FIXED_UUID_A, FIXED_UUID_B] {
        let id = cred(fixture);
        let err = c
            .validate_credential(&id)
            .expect_err("empty allow-list MUST reject every credential");
        if let CredentialValidationError::NotInCredentialAllow { credential_id } = err {
            assert_eq!(credential_id, id);
        } else {
            panic!("expected NotInCredentialAllow for {fixture}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CredentialValidationError Display format pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn not_in_credential_allow_display_format_pinned() {
    let id = cred(FIXED_UUID_A);
    let err = CredentialValidationError::NotInCredentialAllow { credential_id: id };
    let display = err.to_string();
    // Format pinned by credential.rs:336-341:
    //   "credential {credential_id} not in capability's credential_allow"
    assert_eq!(
        display,
        format!("credential {FIXED_UUID_A} not in capability's credential_allow"),
        "FORMAT REGRESSION: NotInCredentialAllow Display drift"
    );
    assert!(
        display.contains(FIXED_UUID_A),
        "display message MUST include the offending uuid: {display}"
    );
}

#[test]
fn not_in_credential_allow_via_validate_has_pinned_display() {
    // The end-to-end path: validate_credential errs with a Display
    // that exactly matches the documented format.
    let id = cred(FIXED_UUID_B);
    let c = CapabilityConstraints::default();
    let err = c.validate_credential(&id).expect_err("rejected");
    assert_eq!(
        err.to_string(),
        format!("credential {FIXED_UUID_B} not in capability's credential_allow")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Serde JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_roundtrip_preserves_default_empty_set() {
    let c = CapabilityConstraints::default();
    let json = serde_json::to_string(&c).expect("serialize");
    let back: CapabilityConstraints = serde_json::from_str(&json).expect("deserialize");
    assert!(back.is_empty());
}

#[test]
fn serde_json_roundtrip_preserves_populated_constraints() {
    let id_a = cred(FIXED_UUID_A);
    let id_b = cred(FIXED_UUID_B);
    let original = CapabilityConstraints {
        resource_allow: vec!["https://api.example.com/*".into()],
        resource_deny: vec!["https://internal.example.com/*".into()],
        max_calls: Some(100),
        max_bytes: Some(1_048_576),
        idempotency_key: Some("op-abc-123".to_string()),
        credential_allow: vec![id_a, id_b],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: CapabilityConstraints = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.resource_allow, original.resource_allow);
    assert_eq!(back.resource_deny, original.resource_deny);
    assert_eq!(back.max_calls, original.max_calls);
    assert_eq!(back.max_bytes, original.max_bytes);
    assert_eq!(back.idempotency_key, original.idempotency_key);
    assert_eq!(back.credential_allow, original.credential_allow);
    assert!(!back.is_empty());

    // is_credential_allowed survives the round-trip.
    assert!(back.is_credential_allowed(&id_a));
    assert!(back.is_credential_allowed(&id_b));
}

#[test]
fn serde_json_default_omits_empty_fields() {
    // The struct uses skip_serializing_if on every field that's
    // defaulted to empty/None, so the JSON form of an empty
    // CapabilityConstraints is the empty object `{}`. Pin that.
    let c = CapabilityConstraints::default();
    let json = serde_json::to_string(&c).expect("serialize");
    assert_eq!(
        json, "{}",
        "FORMAT REGRESSION: empty CapabilityConstraints MUST serialize to `{{}}`; \
         got {json}"
    );
}
