//! Revalidate admitted authority at the host-to-connector handoff.
//!
//! Admission can wait for durable storage and runtime selection. A successful
//! preflight is not a timeless grant. This is an additional fence for that wait,
//! not a substitute for admission, connector instance verification, or fencing
//! immediately before an external effect. It does not consume another quota
//! permit, reset an execution deadline, or authorize a replay.

use fcp_core::{CapabilityToken, CapabilityVerifier};
use fcp_crypto::cose::{CwtClaims, cwt_claims};
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_host::{CapabilityTokenVerifyRequest, HostError, HostResult};
use fcp_kernel::InvokeRequest;
use fcp_prelude::{
    ApprovalMode, Decision, PolicySimulationInput, TransportMode, simulate_policy_decision,
};

use super::super::{
    AppState, authoritative_persisted_capability_rejection_reason, capability_token_b64,
    claims_principal, enforce_live_capability_constraints, enforce_live_deployment_tier,
    live_constraint_resource_uri, request_input_hash, verify_approval_tokens,
    verify_live_hybrid_owner_capability, verify_live_revocation_cascade,
};

fn refusal(message: &str) -> HostError {
    HostError::PreflightFailed(message.to_owned())
}

/// Verify the signature before consulting any claim, including its clock bounds.
/// Required expiry and a present-but-malformed not-before claim fail closed.
fn verified_claims_at(
    token: &CapabilityToken,
    key: Option<&Ed25519VerifyingKey>,
    now: i64,
) -> HostResult<CwtClaims> {
    let key = key.ok_or_else(|| refusal("capability verification key unavailable at dispatch"))?;
    let claims = token
        .raw()
        .verify(key)
        .map_err(|_| refusal("capability signature rejected at dispatch"))?;
    require_live_times(&claims, now)?;
    Ok(claims)
}

fn require_live_times(claims: &CwtClaims, now: i64) -> HostResult<()> {
    if now < 0 {
        return Err(refusal("capability dispatch clock is invalid"));
    }
    if claims.get_expiration().is_none_or(|expires| now >= expires) {
        return Err(refusal(
            "capability expired or lacks a valid expiry at dispatch",
        ));
    }
    if claims.get(cwt_claims::NBF).is_some()
        && claims
            .get_not_before()
            .is_none_or(|not_before| now < not_before)
    {
        return Err(refusal("capability not-before claim rejected at dispatch"));
    }
    Ok(())
}

fn check_current_token(state: &AppState, request: &InvokeRequest) -> HostResult<CwtClaims> {
    let claims = verified_claims_at(
        &request.capability_token,
        state.capability_verifying_key.as_ref(),
        chrono::Utc::now().timestamp(),
    )?;
    verify_live_revocation_cascade(state, &request.capability_token, &claims)?;
    verify_live_hybrid_owner_capability(state, request)?;
    Ok(claims)
}

/// Use the same decision engine and approval-signature verifier as preflight.
/// The simulation receipt is an internal decision, never published as signed
/// evidence. Caller-supplied claims must already have passed signature checks.
fn check_policy(
    input: &PolicySimulationInput,
    approval_key: Option<&Ed25519VerifyingKey>,
) -> HostResult<()> {
    verify_approval_tokens(&input.invoke_request.approval_tokens, approval_key)
        .map_err(|_| refusal("approval signature rejected at dispatch"))?;
    let receipt = simulate_policy_decision(input)
        .map_err(|_| refusal("current zone policy could not be evaluated at dispatch"))?;
    if receipt.decision != Decision::Allow {
        return Err(refusal(
            "current zone policy or approval scope denied dispatch",
        ));
    }
    Ok(())
}

/// Called only for the exact request that already passed consuming admission.
/// The enclosing dispatch future supplies the original absolute deadline.
/// A refusal is returned before the caller sets its `dispatched` marker, so the
/// ordinary durable outcome/audit path records an undispatched host refusal.
/// Catalog, policy and token state are fresh observations, not an atomic global
/// snapshot. Connector-side instance and effect-time enforcement still apply.
pub(super) async fn revalidate(state: &AppState, request: &InvokeRequest) -> HostResult<()> {
    check_current_token(state, request)?;
    let introspection = state
        .discovery
        .introspect(&request.connector_id)
        .await
        .map_err(|_| refusal("connector operation catalog unavailable at dispatch"))?;
    let mut matching = introspection
        .tools
        .iter()
        .filter(|tool| tool.name == request.operation.as_str());
    let tool = matching
        .next()
        .ok_or_else(|| refusal("connector no longer exposes the admitted operation"))?;
    if matching.next().is_some() {
        return Err(refusal(
            "connector operation catalog is ambiguous at dispatch",
        ));
    }
    let verification = state
        .lifecycle
        .verify_capability_token(&CapabilityTokenVerifyRequest {
            token_cbor_b64: capability_token_b64(&request.capability_token)?,
            operation_id: Some(request.operation.to_string()),
            connector_id: Some(request.connector_id.to_string()),
        })
        .await
        .map_err(|_| refusal("persisted capability state unavailable at dispatch"))?;
    // Preserve the initial admission's independent pinned-key verification.
    // A lifecycle store without that key is not a revocation, but any other
    // authoritative rejection (including temporal/scope failure) must win.
    if !verification.valid
        && authoritative_persisted_capability_rejection_reason(
            &verification,
            "persisted capability rejected at dispatch",
        )
        .is_some()
    {
        return Err(refusal(
            "persisted capability state rejected the admitted request at dispatch",
        ));
    }
    let zone_policy = state
        .lookup_zone_policy(&request.zone_id)
        .await
        .map_err(|_| refusal("current zone policy unavailable at dispatch"))?;
    // Every async lookup completes before the final clock-sensitive checks.
    // None of these checks consumes/inspects quota or creates a new admission.
    let claims = check_current_token(state, request)?;
    let resource_uri = live_constraint_resource_uri(&request.input);
    let resources = resource_uri.iter().cloned().collect::<Vec<_>>();
    let key = state
        .capability_verifying_key
        .as_ref()
        .ok_or_else(|| refusal("capability verification key unavailable at dispatch"))?;
    let _verified_scope =
        CapabilityVerifier::without_instance_binding(key.to_bytes(), request.zone_id.clone())
            .verify_unbound(
                request.capability_token.clone(),
                &tool.capability,
                &request.operation,
                &resources,
            )
            .map_err(|_| refusal("capability scope no longer matches the dispatch operation"))?;
    let principal = claims_principal(&claims)
        .filter(|principal| !principal.trim().is_empty())
        .ok_or_else(|| refusal("verified dispatch principal is missing"))?;
    enforce_live_deployment_tier(request, tool.safety_tier)
        .map_err(|_| refusal("current deployment does not permit this operation tier"))?;
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| refusal("policy dispatch clock is invalid"))?;
    check_policy(
        &PolicySimulationInput {
            zone_policy,
            invoke_request: request.clone(),
            transport: TransportMode::Lan,
            // Retain the live preflight's host-local policy inputs. These are not
            // new claims of a mesh-wide checkpoint/freshness proof.
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: tool
                .approval_mode
                .is_some_and(|mode| !matches!(mode, ApprovalMode::None)),
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: Some(request_input_hash(&request.input)?),
            safety_tier: tool.safety_tier,
            principal: Some(principal.to_owned()),
            capability_id: Some(tool.capability.to_string()),
            provenance_record: None,
            now_ms: Some(now_ms),
            posture_attestation: None,
        },
        state.approval_verifying_key.as_ref(),
    )?;
    enforce_live_capability_constraints(request, &claims, principal, resource_uri.as_deref())
        .map_err(|_| refusal("capability constraints rejected the request at dispatch"))?;
    require_live_times(&claims, chrono::Utc::now().timestamp())
}

#[cfg(test)]
mod tests {
    use fcp_crypto::cose::CoseToken;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{
        ApprovalScope, ApprovalToken, CapabilityId, ConnectorId, OperationId, RequestId,
        SafetyTier, ZoneId,
    };

    use super::*;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[73; 32]).expect("fixture key")
    }

    fn claims() -> CwtClaims {
        CwtClaims::default()
            .custom(
                cwt_claims::SUB,
                ciborium::Value::Text("private-subject-marker".to_owned()),
            )
            .custom(cwt_claims::EXP, ciborium::Value::Integer(2000.into()))
            .custom(cwt_claims::NBF, ciborium::Value::Integer(1000.into()))
    }

    fn token(claims: &CwtClaims) -> CapabilityToken {
        CapabilityToken::from_raw(CoseToken::sign(&key(), claims).expect("sign fixture"))
    }

    #[test]
    fn dispatch_rejects_a_token_that_expired_after_admission() {
        let token = token(&claims());
        let verifying_key = key().verifying_key();
        verified_claims_at(&token, Some(&verifying_key), 1999).expect("initial admission time");
        for now in [2000, 2001, i64::MAX] {
            assert!(verified_claims_at(&token, Some(&verifying_key), now).is_err());
        }
    }

    #[test]
    fn dispatch_clock_bounds_are_inclusive_only_at_not_before() {
        let token = token(&claims());
        let verifying_key = key().verifying_key();
        assert!(verified_claims_at(&token, Some(&verifying_key), 999).is_err());
        assert!(verified_claims_at(&token, Some(&verifying_key), 1000).is_ok());
        assert!(verified_claims_at(&token, Some(&verifying_key), 2000).is_err());
    }

    #[test]
    fn dispatch_never_trusts_claims_without_the_current_verifying_key() {
        let token = token(&claims());
        assert!(verified_claims_at(&token, None, 1500).is_err());
        let other_key = Ed25519SigningKey::from_bytes(&[74; 32]).expect("different key");
        assert!(verified_claims_at(&token, Some(&other_key.verifying_key()), 1500).is_err());
    }

    #[test]
    fn dispatch_requires_integer_expiry() {
        let verifying_key = key().verifying_key();
        for claims in [
            CwtClaims::default(),
            claims().custom(cwt_claims::EXP, ciborium::Value::Text("2000".to_owned())),
            claims().custom(cwt_claims::EXP, ciborium::Value::Null),
        ] {
            assert!(verified_claims_at(&token(&claims), Some(&verifying_key), 1500).is_err());
        }
    }

    #[test]
    fn dispatch_rejects_malformed_not_before_instead_of_treating_it_as_absent() {
        let verifying_key = key().verifying_key();
        for value in [
            ciborium::Value::Text("1000".to_owned()),
            ciborium::Value::Null,
        ] {
            let token = token(&claims().custom(cwt_claims::NBF, value));
            assert!(verified_claims_at(&token, Some(&verifying_key), 1500).is_err());
        }
    }

    #[test]
    fn dispatch_allows_absent_not_before_but_not_an_invalid_clock() {
        let token = token(
            &CwtClaims::default()
                .custom(cwt_claims::EXP, ciborium::Value::Integer(i64::MAX.into())),
        );
        let verifying_key = key().verifying_key();
        assert!(verified_claims_at(&token, Some(&verifying_key), 0).is_ok());
        assert!(verified_claims_at(&token, Some(&verifying_key), i64::MAX - 1).is_ok());
        assert!(verified_claims_at(&token, Some(&verifying_key), -1).is_err());
    }

    #[test]
    fn dispatch_rejection_does_not_echo_the_token_or_its_subject() {
        let token = token(&claims());
        let error = verified_claims_at(&token, Some(&key().verifying_key()), 2000).unwrap_err();
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains("private-subject-marker"));
        assert!(!diagnostic.contains("2000"));
    }

    const POLICY_NOW_MS: u64 = 1_500_000;

    fn policy_input() -> PolicySimulationInput {
        let zone = ZoneId::work();
        let claims = claims().custom(
            cwt_claims::SUB,
            ciborium::Value::Text("user:alice".to_owned()),
        );
        let request = InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId::new("dispatch-policy-test"),
            connector_id: ConnectorId::from_static("connector:test"),
            operation: OperationId::from_static("op.read"),
            zone_id: zone.clone(),
            input: serde_json::json!({"value": "private-input-marker"}),
            capability_token: token(&claims),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        PolicySimulationInput {
            zone_policy: crate::host_runtime_policy(zone),
            request_input_hash: Some(request_input_hash(&request.input).expect("input hash")),
            invoke_request: request,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            safety_tier: SafetyTier::Safe,
            principal: Some("user:alice".to_owned()),
            capability_id: Some("cap.test.read".to_owned()),
            provenance_record: None,
            now_ms: Some(POLICY_NOW_MS),
            posture_attestation: None,
        }
    }

    fn pattern(value: &str) -> fcp_core::PolicyPattern {
        fcp_core::PolicyPattern {
            pattern: value.to_owned(),
        }
    }

    fn sign_approval(approval: &mut ApprovalToken) {
        let bytes = crate::approval_token_signing_bytes(approval).expect("approval bytes");
        approval.signature = Some(key().sign(&bytes).to_bytes().to_vec());
    }

    fn execution_approval(input: &PolicySimulationInput) -> ApprovalToken {
        let request = &input.invoke_request;
        let mut approval = ApprovalToken {
            token_id: "private-approval-marker".to_owned(),
            issued_at_ms: POLICY_NOW_MS - 10,
            expires_at_ms: POLICY_NOW_MS + 10,
            issuer: "owner".to_owned(),
            scope: ApprovalScope::Execution(fcp_core::ExecutionScope {
                connector_id: request.connector_id.to_string(),
                method_pattern: request.operation.to_string(),
                request_object_id: None,
                input_hash: input.request_input_hash,
                input_constraints: Vec::new(),
            }),
            zone_id: request.zone_id.clone(),
            signature: None,
            _state: std::marker::PhantomData,
        };
        sign_approval(&mut approval);
        approval
    }

    #[test]
    fn dispatch_rechecks_a_new_principal_deny() {
        let mut input = policy_input();
        check_policy(&input, None).expect("preflight policy allowed");
        input.zone_policy.principal_deny.push(pattern("user:alice"));
        let error = check_policy(&input, None).expect_err("new deny takes effect");
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains("user:alice"));
        assert!(!diagnostic.contains("private-input-marker"));
    }

    #[test]
    fn dispatch_rechecks_a_new_connector_deny() {
        let mut input = policy_input();
        check_policy(&input, None).expect("initial policy allowed");
        input
            .zone_policy
            .connector_deny
            .push(pattern("connector:test"));
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rechecks_a_new_capability_deny() {
        let mut input = policy_input();
        check_policy(&input, None).expect("initial policy allowed");
        input
            .zone_policy
            .capability_deny
            .push(pattern("cap.test.read"));
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rechecks_a_narrowed_capability_ceiling() {
        let mut input = policy_input();
        check_policy(&input, None).expect("initial policy allowed");
        input.zone_policy.capability_ceiling = vec![CapabilityId::from_static("cap.other")];
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rejects_policy_from_a_different_zone() {
        let mut input = policy_input();
        input.zone_policy = crate::host_runtime_policy(ZoneId::owner());
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rechecks_new_transport_restrictions() {
        let mut input = policy_input();
        check_policy(&input, None).expect("initial transport allowed");
        input.zone_policy.transport_policy.allow_lan = false;
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rejects_a_new_execution_approval_requirement() {
        let mut input = policy_input();
        check_policy(&input, None).expect("initial operation allowed");
        input.execution_approval_required = true;
        assert!(check_policy(&input, None).is_err());
    }

    #[test]
    fn dispatch_rechecks_signed_approval_expiry_after_admission() {
        let mut input = policy_input();
        input.execution_approval_required = true;
        input
            .invoke_request
            .approval_tokens
            .push(execution_approval(&input));
        let key = key().verifying_key();
        check_policy(&input, Some(&key)).expect("signed approval initially live");
        input.now_ms = Some(POLICY_NOW_MS + 11);
        assert!(check_policy(&input, Some(&key)).is_err());
    }

    #[test]
    fn dispatch_approval_requires_signature_and_configured_key() {
        let mut input = policy_input();
        input.execution_approval_required = true;
        input
            .invoke_request
            .approval_tokens
            .push(execution_approval(&input));
        let key = key().verifying_key();
        check_policy(&input, Some(&key)).expect("signature verifies");
        assert!(check_policy(&input, None).is_err());
        let original = input.invoke_request.approval_tokens[0].clone();
        input.invoke_request.approval_tokens[0].signature = None;
        assert!(check_policy(&input, Some(&key)).is_err());
        input.invoke_request.approval_tokens[0] = original;
        input.invoke_request.approval_tokens[0].expires_at_ms += 1;
        let error = check_policy(&input, Some(&key)).expect_err("tampered signed fields");
        assert!(!error.to_string().contains("private-approval-marker"));
    }

    #[test]
    fn dispatch_rejects_validly_signed_approval_for_different_input() {
        let mut input = policy_input();
        input.execution_approval_required = true;
        let mut approval = execution_approval(&input);
        if let ApprovalScope::Execution(scope) = &mut approval.scope {
            scope.input_hash = Some([0; 32]);
        }
        sign_approval(&mut approval);
        input.invoke_request.approval_tokens.push(approval);
        assert!(check_policy(&input, Some(&key().verifying_key())).is_err());
    }
}
