//! Pin policy "route-key" dispatch — which `PolicyDecisionInput`
//! field maps to which `ZonePolicyObject` pattern list, in what
//! precedence (flywheel_connectors-kjs08).
//!
//! Bead asks for `PolicyRouter` route-key derivation. No type
//! literally named `PolicyRouter` exists in fcp-core. The routing
//! that the bead points at lives in `PolicyEngine::evaluate_invoke`
//! (policy.rs:2483) and its helper `check_pattern_lists`
//! (policy.rs:2718). The "route key" is the tuple of dimensions
//! `(principal, connector_id, capability_id)` — each of which is
//! independently dispatched into its own allow/deny pattern-list
//! pair on `ZonePolicyObject`. `PolicyPattern` (policy.rs:216) is
//! the glob matcher used per dimension.
//!
//! Pinning targets:
//!
//!   1. **Field → pattern-list dispatch** — `principal` is matched
//!      against `principal_*`, `connector_id` against `connector_*`,
//!      `capability_id` against `capability_*`. A deny pattern in
//!      the wrong list MUST NOT trigger that dimension's reason.
//!   2. **Deny precedence over Allow within a dimension** — if a
//!      principal matches both deny and allow, the deny wins.
//!   3. **Empty allow-list semantics** — an empty allow-list is
//!      "no allow-list constraint" (NOT default-deny); routing
//!      still passes that dimension. (Capability-allow semantics
//!      live separately on `capability_ceiling`.)
//!   4. **Non-empty allow-list MUST match** — otherwise the
//!      `*NotAllowed` reason fires.
//!   5. **Reason-code mapping per dimension** is exact and stable:
//!        - principal → `ZonePolicyPrincipalDenied` / `NotAllowed`
//!        - connector → `ZonePolicyConnectorDenied` / `NotAllowed`
//!        - capability → `ZonePolicyCapabilityDenied` / `NotAllowed`
//!   6. **Pattern semantics inside route key**: `*` and `?` and
//!      exact match all dispatch correctly through `PolicyPattern`.
//!   7. **`PolicyPattern` JSON shape is `{"pattern": "<glob>"}`**
//!      and round-trips.
//!   8. **Deny-check order across dimensions** (principal → connector
//!      → capability) is observable: when both principal and
//!      connector deny, the principal reason surfaces first.

use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityId, ConnectorId, Decision, DecisionReasonCode, ObjectHeader, ObjectId, OperationId,
    PolicyDecisionInput, PolicyEngine, PolicyPattern, PrincipalId, Provenance, ProvenanceRecord,
    SafetyTier, TransportMode, ZoneId, ZonePolicyObject, ZoneTransportPolicy,
};
use semver::Version;

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

fn empty_policy(zone: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: header(zone.clone()),
        zone_id: zone,
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: vec![],
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: fcp_core::DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn pat(s: &str) -> PolicyPattern {
    PolicyPattern {
        pattern: s.to_string(),
    }
}

fn input_for<'a>(
    zone: ZoneId,
    principal: &str,
    connector: &str,
    capability: CapabilityId,
) -> PolicyDecisionInput<'a> {
    PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-route-key"),
        zone_id: zone.clone(),
        principal: PrincipalId::new(principal).expect("principal"),
        connector_id: ConnectorId::from_static(Box::leak(connector.to_string().into_boxed_str())),
        operation_id: OperationId::from_static("op.read"),
        capability_id: capability,
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(zone),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Field → pattern-list dispatch (the route key)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_deny_only_fires_for_principal_field() {
    // Place a deny pattern that matches a connector id literal in
    // the PRINCIPAL deny list — it MUST NOT fire because the route
    // key for principal_deny is the principal field, not the
    // connector field.
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_deny = vec![pat("connector:foo")]; // matches connector text, in wrong list
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo", // would match if dispatched to wrong list
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "principal_deny pattern matching the connector literal MUST NOT fire — \
         dispatch is keyed by FIELD NAME, not just by pattern content"
    );
}

#[test]
fn connector_deny_only_fires_for_connector_field() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.connector_deny = vec![pat("user:alice")]; // matches principal literal, in wrong list
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "connector_deny pattern matching the principal literal MUST NOT fire"
    );
}

#[test]
fn capability_deny_only_fires_for_capability_field() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.capability_deny = vec![pat("user:alice")]; // matches principal literal
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "capability_deny pattern matching the principal literal MUST NOT fire"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Deny-precedence over Allow within a dimension
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_deny_wins_over_principal_allow() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_allow = vec![pat("user:*")];
    policy.principal_deny = vec![pat("user:alice")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "deny MUST win over allow within the same dimension"
    );
}

#[test]
fn connector_deny_wins_over_connector_allow() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.connector_allow = vec![pat("connector:*")];
    policy.connector_deny = vec![pat("connector:foo")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorDenied
    );
}

#[test]
fn capability_deny_wins_over_capability_allow() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.capability_allow = vec![pat("cap.*")];
    policy.capability_deny = vec![pat("cap.read")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityDenied
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Empty allow-list = no constraint (not default-deny)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_principal_allow_does_not_default_deny() {
    let zone = ZoneId::work();
    let policy = empty_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "anything:goes",
        "connector:any",
        CapabilityId::from_static("cap.any"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "empty pattern lists across all dimensions MUST allow — \
         these are NOT default-deny lists (capability_ceiling is the default-deny mechanism)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Non-empty allow-list MUST match
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_allow_non_empty_requires_match() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_allow = vec![pat("user:bob")]; // doesn't match alice
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed,
        "non-empty principal_allow MUST require an explicit match"
    );
}

#[test]
fn connector_allow_non_empty_requires_match() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.connector_allow = vec![pat("connector:trusted")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorNotAllowed
    );
}

#[test]
fn capability_allow_non_empty_requires_match() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.capability_allow = vec![pat("cap.write")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Cross-dimension deny precedence (principal → connector → capability)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_deny_short_circuits_before_connector_deny() {
    // When both principal and connector deny would fire, the
    // principal reason MUST surface first — this is the documented
    // dispatch order in check_pattern_lists.
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_deny = vec![pat("user:alice")];
    policy.connector_deny = vec![pat("connector:foo")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "principal deny MUST be reported first when multiple dimensions deny"
    );
}

#[test]
fn connector_deny_short_circuits_before_capability_deny() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.connector_deny = vec![pat("connector:foo")];
    policy.capability_deny = vec![pat("cap.read")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorDenied,
        "connector deny MUST be reported before capability deny"
    );
}

#[test]
fn all_denies_before_any_allow_check() {
    // capability_deny fires even when capability_allow would also
    // match — and it fires before any allow-list NotAllowed check
    // anywhere.
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_allow = vec![pat("user:bob")]; // would NotAllowed
    policy.capability_deny = vec![pat("cap.read")]; // also denies
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = input_for(
        zone,
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityDenied,
        "deny checks across all dimensions MUST run before any allow-list check"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Pattern glob semantics inside route key (PolicyPattern)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn star_glob_matches_through_route_key() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_deny = vec![pat("user:*")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    for principal in ["user:alice", "user:bob", "user:"] {
        let input = input_for(
            zone.clone(),
            principal,
            "connector:foo",
            CapabilityId::from_static("cap.read"),
        );
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyPrincipalDenied,
            "`*` in principal_deny MUST match {principal}"
        );
    }
}

#[test]
fn question_mark_glob_matches_one_ascii_char_through_route_key() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.connector_deny = vec![pat("connector:?")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // Matches single-char.
    let input = input_for(
        zone.clone(),
        "user:alice",
        "connector:x",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorDenied,
        "`?` MUST match a single ASCII char"
    );

    // Doesn't match multi-char.
    let input = input_for(
        zone,
        "user:alice",
        "connector:xy",
        CapabilityId::from_static("cap.read"),
    );
    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "`?` MUST NOT match more than one char"
    );
}

#[test]
fn exact_pattern_in_route_key_matches_only_exact_value() {
    let zone = ZoneId::work();
    let mut policy = empty_policy(zone.clone());
    policy.principal_deny = vec![pat("user:alice")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // Exact match denies.
    let input_exact = input_for(
        zone.clone(),
        "user:alice",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    assert_eq!(
        engine.evaluate_invoke(&input_exact).reason_code,
        DecisionReasonCode::ZonePolicyPrincipalDenied
    );

    // Different principal allows.
    let input_other = input_for(
        zone,
        "user:bob",
        "connector:foo",
        CapabilityId::from_static("cap.read"),
    );
    assert_eq!(
        engine.evaluate_invoke(&input_other).decision,
        Decision::Allow,
        "exact pattern MUST NOT match other principal values"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. PolicyPattern serde shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_pattern_json_form_pinned() {
    let p = pat("user:*");
    let json = serde_json::to_value(&p).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({"pattern": "user:*"}),
        "PolicyPattern JSON shape is `{{\"pattern\": <glob>}}`"
    );

    let back: PolicyPattern = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(back.pattern, "user:*");
    // Round-trip preserves serialization byte-for-byte.
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
}

#[test]
fn policy_pattern_cbor_roundtrip() {
    let p = pat("connector:*");
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&p, &mut buf).expect("encode");
    let back: PolicyPattern = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.pattern, "connector:*");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Decision reason-code labels are stable strings (audit-log key)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn route_key_reason_code_labels_are_stable_strings() {
    // These tokens land in audit logs — operators filter on them.
    // Format pinned by policy.rs:2112-2117 — `zone_policy.<dimension>_<verb>`
    // (NOTE the `.` separator between the namespace prefix and the
    // dimension token; the inter-word separator inside the suffix is `_`).
    assert_eq!(
        DecisionReasonCode::ZonePolicyPrincipalDenied.as_str(),
        "zone_policy.principal_denied"
    );
    assert_eq!(
        DecisionReasonCode::ZonePolicyConnectorDenied.as_str(),
        "zone_policy.connector_denied"
    );
    assert_eq!(
        DecisionReasonCode::ZonePolicyCapabilityDenied.as_str(),
        "zone_policy.capability_denied"
    );
    assert_eq!(
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed.as_str(),
        "zone_policy.principal_not_allowed"
    );
    assert_eq!(
        DecisionReasonCode::ZonePolicyConnectorNotAllowed.as_str(),
        "zone_policy.connector_not_allowed"
    );
    assert_eq!(
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed.as_str(),
        "zone_policy.capability_not_allowed"
    );
}
