//! Refresh time-sensitive authority after runtime queues and preparation waits.
//!
//! Full capability, policy, quota and inventory admission happens elsewhere.
//! This immutable guard retains only the inputs needed to keep that admission
//! current. It never re-admits work, consumes a permit, or retries an effect.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fcp_core::{CapabilityToken, ZoneId};
use fcp_crypto::Ed25519VerifyingKey;
use fcp_host::mesh_routing::MeshInvokeOrigin;
use fcp_host::{
    CapabilityRevocationFence, ConnectorExecutionFence, HostError, HostResult,
    RevocationCascadeVerifier, RuntimeRevocationPermit, RuntimeRevocationService,
};
use fcp_kernel::InvokeRequest;

use super::{AppState, HybridOwnerInvokeEvidence, HybridOwnerProductionVerifier};

const REFUSAL: &str = "live connector lifecycle, capability, approval, mesh origin or revocation authority no longer permits queued execution";

struct AuthorityState {
    key: Ed25519VerifyingKey,
    token: CapabilityToken,
    zone: ZoneId,
    lifecycle_fence: CapabilityRevocationFence,
    execution_fence: Option<ConnectorExecutionFence>,
    origin: Option<MeshInvokeOrigin>,
    cascade: Arc<RevocationCascadeVerifier>,
    runtime_revocation: Option<Arc<RuntimeRevocationService>>,
    holder: Option<(Arc<fcp_host::mesh_routing::MeshRouter>, InvokeRequest)>,
    hybrid_owner: Option<(
        Arc<HybridOwnerProductionVerifier>,
        HybridOwnerInvokeEvidence,
    )>,
    approval_windows: Vec<(u64, u64)>,
    rejected: AtomicBool,
    effect_started: AtomicBool,
}

/// One immutable authority binding shared by an invocation's physical tickets.
#[derive(Clone)]
pub(super) struct LiveAuthorityDispatchGuard(Arc<AuthorityState>);

impl LiveAuthorityDispatchGuard {
    pub(super) fn new(
        state: &AppState,
        request: &InvokeRequest,
        lifecycle_fence: CapabilityRevocationFence,
        execution_fence: Option<ConnectorExecutionFence>,
        origin: Option<MeshInvokeOrigin>,
    ) -> HostResult<Self> {
        lifecycle_fence.require_current()?;
        if let Some(fence) = &execution_fence {
            fence.require_current()?;
        }
        if let Some(origin) = &origin {
            origin.require_current().map_err(|_| refused())?;
        }
        let key = state.capability_verifying_key.clone().ok_or_else(refused)?;
        let claims = super::invoke_jobs::verified_dispatch_claims_at(
            &request.capability_token,
            Some(&key),
            chrono::Utc::now().timestamp(),
        )
        .map_err(|_| refused())?;
        let holder = if claims.get_holder_node().is_some() {
            // The existing holder verifier binds exactly request ID, operation
            // and token JTI. Do not retain operation inputs or approval bodies.
            let binding = InvokeRequest {
                r#type: request.r#type.clone(),
                id: request.id.clone(),
                connector_id: request.connector_id.clone(),
                operation: request.operation.clone(),
                zone_id: request.zone_id.clone(),
                input: serde_json::Value::Null,
                capability_token: request.capability_token.clone(),
                holder_proof: request.holder_proof.clone(),
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            };
            Some((state.mesh.clone().ok_or_else(refused)?, binding))
        } else {
            None
        };
        let evidence = super::hybrid_owner_invoke_evidence(request).map_err(|_| refused())?;
        let hybrid_owner = match (state.hybrid_owner_verifier.clone(), evidence) {
            (Some(verifier), Some(evidence)) => Some((verifier, evidence)),
            (None, None) => None,
            _ => return Err(refused()),
        };
        let guard = Self(Arc::new(AuthorityState {
            key,
            token: request.capability_token.clone(),
            zone: request.zone_id.clone(),
            lifecycle_fence,
            execution_fence,
            origin,
            cascade: Arc::clone(&state.revocation_cascade),
            runtime_revocation: state.runtime_revocation.clone(),
            holder,
            hybrid_owner,
            // Full policy admission has already verified approval signatures
            // and scope. Conservatively retain every supplied approval's time
            // bound, including optional additional approval evidence.
            approval_windows: request
                .approval_tokens
                .iter()
                .map(|approval| (approval.issued_at_ms, approval.expires_at_ms))
                .collect(),
            rejected: AtomicBool::new(false),
            effect_started: AtomicBool::new(false),
        }));
        guard.0.lifecycle_fence.require_current()?;
        if let Some(fence) = &guard.0.execution_fence {
            fence.require_current()?;
        }
        if let Some(origin) = &guard.0.origin {
            origin.require_current().map_err(|_| refused())?;
        }
        Ok(guard)
    }

    /// File access and signature verification happen outside ownership locks.
    /// The returned permit rechecks clocks and lifecycle publication at use.
    pub(super) fn refresh(&self) -> HostResult<LiveAuthorityDispatchPermit> {
        self.refresh_inner().map_err(|_| {
            self.0.rejected.store(true, Ordering::Release);
            refused()
        })
    }

    fn refresh_inner(&self) -> HostResult<LiveAuthorityDispatchPermit> {
        if self.0.rejected.load(Ordering::Acquire) {
            return Err(refused());
        }
        self.0.lifecycle_fence.require_current()?;
        if let Some(fence) = &self.0.execution_fence {
            fence.require_current()?;
        }
        if let Some(origin) = &self.0.origin {
            origin.require_current().map_err(|_| refused())?;
        }
        let claims = super::invoke_jobs::verified_dispatch_claims_at(
            &self.0.token,
            Some(&self.0.key),
            chrono::Utc::now().timestamp(),
        )?;
        let token_id = super::revocation_cascade_token_id(&self.0.token, &claims)?;
        let issuer = super::revocation_cascade_issuer_kid(&self.0.token)?;
        let revocation = self
            .0
            .runtime_revocation
            .as_ref()
            .map(|service| service.verify_for_dispatch(&self.0.zone, token_id, issuer.clone()))
            .transpose()?;
        self.0
            .cascade
            .verify(token_id, issuer)
            .map_err(|_| refused())?;
        if let Some((router, request)) = &self.0.holder {
            router
                .verify_holder_proof(
                    request,
                    claims.get_holder_node().ok_or_else(refused)?,
                    claims
                        .get_jti()
                        .filter(|jti| !jti.is_empty())
                        .ok_or_else(refused)?,
                )
                .map_err(|_| refused())?;
        }
        if let Some((verifier, evidence)) = &self.0.hybrid_owner {
            verifier.verify_capability_token(&self.0.zone, &self.0.token, evidence)?;
        }
        let observed_at = Instant::now();
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| refused())?;
        let mut expires = milliseconds(claims.get_expiration().ok_or_else(refused)?)?;
        let mut not_before = claims
            .get_not_before()
            .map(|seconds| milliseconds(seconds.max(0)))
            .transpose()?
            .unwrap_or(0);
        for (issued, expiry) in &self.0.approval_windows {
            not_before = not_before.max(*issued);
            expires = expires.min(*expiry);
        }
        if now < not_before || now >= expires {
            return Err(refused());
        }
        // This is an immediate-use permit, never a cached grant for later RPCs.
        // The cap also avoids overflowing Instant for unusually long-lived CWTs.
        let deadline = observed_at + Duration::from_millis((expires - now).min(60_000));
        let permit = LiveAuthorityDispatchPermit {
            guard: self.clone(),
            revocation,
            not_before_ms: not_before,
            expires_at_ms: expires,
            deadline,
        };
        permit.require_current()?;
        Ok(permit)
    }

    pub(super) fn mark_effect_started(&self) {
        self.0.effect_started.store(true, Ordering::Release);
    }

    /// Record a selected runtime's refusal. A previously selected effect still
    /// prevents this marker from being treated as proof of non-execution.
    pub(super) fn record_dispatch_refusal(&self) {
        self.0.rejected.store(true, Ordering::Release);
    }

    /// Positive local proof of refusal before any effect ticket was selected.
    pub(super) fn refused_before_effect(&self) -> bool {
        self.0.rejected.load(Ordering::Acquire) && !self.0.effect_started.load(Ordering::Acquire)
    }
}

pub(super) struct LiveAuthorityDispatchPermit {
    guard: LiveAuthorityDispatchGuard,
    revocation: Option<RuntimeRevocationPermit>,
    not_before_ms: u64,
    expires_at_ms: u64,
    deadline: Instant,
}

impl LiveAuthorityDispatchPermit {
    /// Bounded clock/atomic reads and a nonblocking membership check: safe while
    /// holding selection ownership, without source I/O or signature verification.
    pub(super) fn is_current(&self) -> bool {
        let current = !self.guard.0.rejected.load(Ordering::Acquire)
            && self.guard.0.lifecycle_fence.is_current()
            && self
                .guard
                .0
                .execution_fence
                .as_ref()
                .is_none_or(ConnectorExecutionFence::is_current)
            && self
                .guard
                .0
                .origin
                .as_ref()
                .is_none_or(MeshInvokeOrigin::is_current_for_dispatch)
            && Instant::now() < self.deadline
            && u64::try_from(chrono::Utc::now().timestamp_millis())
                .is_ok_and(|now| now >= self.not_before_ms && now < self.expires_at_ms)
            && self
                .revocation
                .as_ref()
                .is_none_or(RuntimeRevocationPermit::is_current);
        if !current {
            self.guard.0.rejected.store(true, Ordering::Release);
        }
        current
    }

    pub(super) fn require_current(&self) -> HostResult<()> {
        if self.is_current() {
            Ok(())
        } else {
            Err(refused())
        }
    }
}

fn milliseconds(seconds: i64) -> HostResult<u64> {
    u64::try_from(
        i128::from(seconds)
            .saturating_mul(1000)
            .min(i128::from(u64::MAX)),
    )
    .map_err(|_| refused())
}

fn refused() -> HostError {
    HostError::PreflightFailed(REFUSAL.to_owned())
}
