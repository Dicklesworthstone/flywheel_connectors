//! Revalidate admitted authority at the host-to-connector handoff.
//!
//! Admission can wait for durable storage and runtime selection. A successful
//! preflight is not a timeless grant. This is an additional fence for that wait,
//! not a substitute for admission, connector instance verification, or fencing
//! immediately before an external effect. It does not consume another quota
//! permit, reset an execution deadline, or authorize a replay.

use fcp_core::CapabilityToken;
use fcp_crypto::cose::{CwtClaims, cwt_claims};
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_host::{CapabilityTokenVerifyRequest, HostError, HostResult};
use fcp_kernel::InvokeRequest;

use super::super::{
    AppState, authoritative_persisted_capability_rejection_reason, capability_token_b64,
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
        return Err(refusal("capability expired or lacks a valid expiry at dispatch"));
    }
    if claims.get(cwt_claims::NBF).is_some()
        && claims.get_not_before().is_none_or(|not_before| now < not_before)
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

/// Called only for the exact request that already passed consuming admission.
/// The enclosing dispatch future supplies the original absolute deadline.
/// A refusal is returned before the caller sets its `dispatched` marker, so the
/// ordinary durable outcome/audit path records an undispatched host refusal.
pub(super) async fn revalidate(state: &AppState, request: &InvokeRequest) -> HostResult<()> {
    check_current_token(state, request)?;
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
        return Err(refusal("persisted capability state rejected the admitted request at dispatch"));
    }
    // Lifecycle verification can itself wait for a state lock. Do not let that
    // wait extend token life or hide a cascade/owner refusal. The caller also
    // rechecks holder membership immediately after this future returns.
    let claims = check_current_token(state, request)?;
    require_live_times(&claims, chrono::Utc::now().timestamp())
}

#[cfg(test)]
mod tests {
    use fcp_crypto::cose::CoseToken;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    use super::*;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[73; 32]).expect("fixture key")
    }

    fn claims() -> CwtClaims {
        CwtClaims::default()
            .custom(cwt_claims::SUB, ciborium::Value::Text("private-subject-marker".to_owned()))
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
        for value in [ciborium::Value::Text("1000".to_owned()), ciborium::Value::Null] {
            let token = token(&claims().custom(cwt_claims::NBF, value));
            assert!(verified_claims_at(&token, Some(&verifying_key), 1500).is_err());
        }
    }

    #[test]
    fn dispatch_allows_absent_not_before_but_not_an_invalid_clock() {
        let token = token(&CwtClaims::default().custom(
            cwt_claims::EXP, ciborium::Value::Integer(i64::MAX.into()),
        ));
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
}
