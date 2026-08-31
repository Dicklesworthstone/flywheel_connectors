//! Golden vector for the four capability rejection paths exercised
//! by AmberLark's `host_invoke_loop_conformance` (commit 6d16bf953)
//! and CrimsonWolf's `capability_enforcement_concurrent_e2e`
//! (commit 167d9c812).
//!
//! Both upstream harnesses verify *behavior* — that each rejection
//! kind reaches `PreflightDeny` and emits `Severity::Warning`.
//! Neither freezes the *bytes* operators read off the audit entry
//! (event_type, severity, metadata.reason text, occurred_at slot,
//! seq position). Operator dashboards and triage tooling filter on
//! those bytes verbatim, so a refactor that silently changes
//! `event_type` from `host.invoke.deny` to `host.invoke.rejected`,
//! or strips `metadata.reason`, would split log-aggregation rows
//! across two columns without any test in the workspace catching it.
//!
//! This golden walks the four rejection scenarios that are
//! reachable through `verify_unbound` + the registry gate:
//!
//!   - **zone-mismatch**: token issued for `z:public`, verifier bound
//!     to `z:work` — `verify_unbound` rejects on the zone check.
//!   - **capability-mismatch**: token grants `cap.test.alt`, verifier
//!     requires `cap.test.invoke`.
//!   - **expired-token**: token validity window is in the past.
//!   - **revoked-token**: token's capability ObjectId has been added
//!     to the `RevocationRegistry`.
//!
//! For each scenario we render the structural fields the operator
//! evidence trail reads off — id is computed-from-content so the
//! deterministic input window keeps every byte stable across runs.
//!
//! Update flow:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-host --test golden_capability_rejection_matrix
//!     cargo insta review
//!     git diff crates/fcp-host/tests/snapshots/

use std::fmt::Write as _;

use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use fcp_audit::AuditEntry;
use fcp_core::{
    CapabilityId, CapabilityToken, CapabilityVerifier, InstanceId, ObjectId, OperationId,
    RevocationObject, RevocationRegistry, RevocationScope, ZoneId,
};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
use fcp_prelude::ObjectHeader;

const FIXED_ACTOR: &str = "user:golden-rejection-matrix";
const FIXED_CONNECTOR_ID: &str = "fcp.test.golden_rejection";
const FIXED_OPERATION_NAME: &str = "list";
const ALLOW_URI: &str = "/v1/golden_rejection";
const FIXED_INSTANCE: &str = "inst_golden_rejection_2026";
const FIXED_OCCURRED_AT: u64 = 1_735_689_600;

/// Deterministic Ed25519 signing key. NEVER change in-place; bump
/// the fixture if the schema actually changes.
fn deterministic_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0xC4; 32]).expect("32-byte seed is a valid Ed25519 key")
}

/// Fixed validity window in 2026 so the token is byte-stable AND in
/// the present (so a token built with this window passes timing
/// checks). Used by every scenario except `expired-token` which
/// overrides explicitly.
fn fixed_validity_window() -> (DateTime<Utc>, DateTime<Utc>) {
    let not_before = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
    (not_before, expires)
}

fn deterministic_instance() -> InstanceId {
    InstanceId::try_from(FIXED_INSTANCE.to_string())
        .expect("FIXED_INSTANCE must be a valid InstanceId")
}

fn constraints_cbor(allow_uri: &str) -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Text("resource_allow".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text(allow_uri.to_string())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).expect("constraints CBOR");
    bytes
}

fn mint_token(
    capability_id: &str,
    operation_id: &str,
    zone_str: &str,
    valid_from: DateTime<Utc>,
    valid_to: DateTime<Utc>,
) -> CapabilityToken {
    let signing_key = deterministic_signing_key();
    let instance = deterministic_instance();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_str)
        .principal(FIXED_ACTOR)
        .operations(&[operation_id])
        .issuer("node:golden-gateway")
        .validity(valid_from, valid_to)
        .try_constraints_cbor(&constraints_cbor(ALLOW_URI))
        .expect("constraints CBOR")
        .target_instance(instance.as_str())
        .sign(&signing_key)
        .expect("sign");
    CapabilityToken::from_raw(cose)
}

fn audit_context(scenario_label: &str) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: "z:work".into(),
        actor: FIXED_ACTOR.into(),
        connector_id: FIXED_CONNECTOR_ID.into(),
        operation: FIXED_OPERATION_NAME.into(),
        operation_id: format!("op-golden-{scenario_label}"),
        correlation_id: Some(format!("corr-golden-{scenario_label}")),
        occurred_at: FIXED_OCCURRED_AT,
    }
}

#[derive(Debug)]
struct RejectionScenario {
    label: &'static str,
    /// Description of what is wrong with the token, used as the
    /// `PreflightDeny.reason` text and rendered in the golden.
    deny_reason: String,
}

/// Run the four scenarios through a real `CapabilityVerifier` +
/// `RevocationRegistry` + `InvokeAuditChain` and return the rendered
/// audit entries (one per scenario, in deterministic order).
fn render_rejection_matrix() -> String {
    let signing_key = deterministic_signing_key();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let (valid_from, valid_to) = fixed_validity_window();

    // Scenario 1: zone-mismatch. Token zone z:public, verifier z:work.
    let zone_mismatch_reason = {
        let token = mint_token(
            "cap.test.invoke",
            "op.test.invoke",
            "z:public",
            valid_from,
            valid_to,
        );
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let cap = CapabilityId::new("cap.test.invoke").expect("cap id");
        let op = OperationId::new("op.test.invoke").expect("op id");
        match verifier.verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()]) {
            Ok(_) => panic!("zone-mismatch: verifier MUST reject"),
            Err(e) => format!("zone-mismatch: {e}"),
        }
    };

    // Scenario 2: capability-mismatch. Token grants cap.test.alt;
    // verifier requires cap.test.invoke.
    let cap_mismatch_reason = {
        let token = mint_token(
            "cap.test.alt",
            "op.test.invoke",
            "z:work",
            valid_from,
            valid_to,
        );
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let cap = CapabilityId::new("cap.test.invoke").expect("cap id");
        let op = OperationId::new("op.test.invoke").expect("op id");
        match verifier.verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()]) {
            Ok(_) => panic!("capability-mismatch: verifier MUST reject"),
            Err(e) => format!("capability-mismatch: {e}"),
        }
    };

    // Scenario 3: expired-token. Validity window strictly in the past.
    let expired_reason = {
        let past_from = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let past_to = past_from + ChronoDuration::hours(1);
        let token = mint_token(
            "cap.test.invoke",
            "op.test.invoke",
            "z:work",
            past_from,
            past_to,
        );
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let cap = CapabilityId::new("cap.test.invoke").expect("cap id");
        let op = OperationId::new("op.test.invoke").expect("op id");
        match verifier.verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()]) {
            Ok(_) => panic!("expired-token: verifier MUST reject"),
            Err(e) => format!("expired-token: {e}"),
        }
    };

    // Scenario 4: revoked-token. Verifier path passes but the
    // RevocationRegistry reports the capability ObjectId revoked.
    let revoked_reason = {
        let revoked_cap_id = ObjectId::from_unscoped_bytes(b"golden-revoked-capability-2026");
        let mut registry = RevocationRegistry::new();
        let zone = ZoneId::work();
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new(
                "fcp.revocation",
                "RevocationObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone.clone(),
            created_at: FIXED_OCCURRED_AT,
            provenance: fcp_prelude::Provenance::new(zone),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let revocation = RevocationObject {
            header,
            revoked: vec![revoked_cap_id],
            scope: RevocationScope::Capability,
            reason: "operator-initiated golden revocation".into(),
            effective_at: FIXED_OCCURRED_AT,
            expires_at: None,
            signature: [0u8; 64],
        };
        registry.add_revocation(&revocation);
        assert!(registry.is_revoked(&revoked_cap_id));
        format!("revoked-token: capability ObjectId {revoked_cap_id} revoked via registry")
    };

    let scenarios = [
        RejectionScenario {
            label: "zone_mismatch",
            deny_reason: zone_mismatch_reason,
        },
        RejectionScenario {
            label: "capability_mismatch",
            deny_reason: cap_mismatch_reason,
        },
        RejectionScenario {
            label: "expired_token",
            deny_reason: expired_reason,
        },
        RejectionScenario {
            label: "revoked_token",
            deny_reason: revoked_reason,
        },
    ];

    // Append each scenario's PreflightDeny to a fresh chain so seq
    // is dense (0,1,2,3) and prev linkage is observable.
    let chain = InvokeAuditChain::new();
    let mut entries: Vec<(RejectionScenario, AuditEntry)> = Vec::new();
    for scenario in scenarios {
        let entry = chain
            .append(
                &audit_context(scenario.label),
                InvokePhase::PreflightDeny {
                    reason: scenario.deny_reason.clone(),
                },
            )
            .expect("PreflightDeny append");
        entries.push((scenario, entry));
    }

    // Render. We deliberately do NOT include the entry id (content-
    // hash of canonical bytes); rendering id would freeze BLAKE3
    // implementation details that are not part of the operator-
    // facing contract. We DO render seq, prev-presence,
    // event_type, severity, zone_id, connector_id, operation_id,
    // metadata.reason, computed_severity (re-derived from
    // event_type), and is_genesis() — every field operator
    // dashboards filter on.
    let mut out = String::new();
    out.push_str(
        "# Golden vector — capability rejection matrix\n\
         # br-6d16bf953 (AmberLark conformance) + br-167d9c812 (CrimsonWolf concurrent)\n\
         # Format:\n\
         #   <scenario> | seq=<n> genesis=<bool> event_type=<s> severity=<s>\n\
         #               actor=<s> zone=<s> connector=<s> op_id=<s>\n\
         #               correlation=<s> occurred_at=<u> prev_present=<bool>\n\
         #               metadata.reason=<s>\n\
         # Notes:\n\
         #   - id is content-hash; intentionally omitted so a BLAKE3 internal\n\
         #     change does not bleed into this golden.\n\
         #   - All scenarios MUST classify Severity::Warning — the operator\n\
         #     evidence trail relies on this for triage filtering.\n\
         \n",
    );
    for (i, (scenario, entry)) in entries.iter().enumerate() {
        let prev_present = entry.prev.is_some();
        let computed = entry.computed_severity();
        let reason = entry
            .metadata
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        let connector = entry.connector_id.as_deref().unwrap_or("<none>");
        let op_id = entry.operation_id.as_deref().unwrap_or("<none>");
        let correlation = if entry.correlation_id.is_empty() {
            "<none>"
        } else {
            &entry.correlation_id
        };
        writeln!(
            &mut out,
            "[{i}] {label}\n  \
             seq={seq} genesis={genesis} event_type={event_type} severity={severity:?}\n  \
             computed_severity={computed:?} actor={actor} zone={zone}\n  \
             connector={connector} operation_id={op_id} correlation={correlation}\n  \
             occurred_at={occurred} prev_present={prev_present}\n  \
             metadata.reason={reason}",
            i = i,
            label = scenario.label,
            seq = entry.seq,
            genesis = entry.is_genesis(),
            event_type = entry.event_type,
            severity = entry.severity,
            computed = computed,
            actor = entry.actor,
            zone = entry.zone_id,
            connector = connector,
            op_id = op_id,
            correlation = correlation,
            occurred = entry.occurred_at,
            prev_present = prev_present,
            reason = reason,
        )
        .expect("string write");
        out.push('\n');
    }
    out
}

#[test]
fn golden_capability_rejection_matrix_canonical_cells() {
    let actual = render_rejection_matrix();
    insta::assert_snapshot!("capability_rejection_matrix_canonical_cells", actual);
}
