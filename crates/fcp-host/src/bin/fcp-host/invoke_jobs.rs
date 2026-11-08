//! Bounded host ownership of local invocations and mesh forwarding.
//!
//! HTTP requests retain only a response receiver. The host retains each task
//! handle until the complete invocation/finalization job exits, so losing a
//! connection cannot abandon an observed connector result. Local dispatch waits
//! for its durable invocation admission; mesh forwarding reserves a separate
//! durable origin intent before sending. Both bind current ownership to the
//! persisted attempt. A forwarding job never asserts executor-local authority.
//!
//! This uses async-core's runtime-root admission, not a detached request task.
//! The absolute job deadline and shutdown drain below bound that ownership;
//! native command retirement remains owned by the cancellation controller.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fcp_async_core::channel::oneshot;
use fcp_async_core::task::{self, JoinHandle};
use fcp_host::{HostError, HostResult};
use fcp_kernel::InvokeResponse;
use futures_util::stream::{FuturesUnordered, StreamExt};

#[path = "dispatch_authority.rs"]
mod dispatch_authority;
pub(super) use dispatch_authority::verified_claims_at as verified_dispatch_claims_at;

const MAX_OWNED_INVOCATIONS: usize = 256;
pub(super) const FINALIZATION_GRACE: Duration = Duration::from_secs(5);
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(65);

pub(super) type ForwardResult = Result<InvokeResponse, (axum::http::StatusCode, String)>;

/// Apply the same current-authority fence before forwarding an already admitted
/// local operation. Remote-only operations remain the executor's responsibility.
pub(super) async fn revalidate_dispatch_authority(
    state: &super::AppState,
    request: &fcp_kernel::InvokeRequest,
) -> HostResult<()> {
    let generation = state.registry.version.load(Ordering::SeqCst);
    dispatch_authority::revalidate(state, request, generation)
        .await
        .map(|_| ())
}

#[must_use]
pub(super) fn finalization_deadline(execution_deadline: Instant) -> Instant {
    execution_deadline
        .checked_add(FINALIZATION_GRACE)
        .unwrap_or(execution_deadline)
}

struct InvocationJob {
    handle: JoinHandle<()>,
    activity: JobActivity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InvocationJobKind {
    Local,
    Forward,
}

#[derive(Clone)]
struct JobActivity {
    kind: InvocationJobKind,
    alive: Arc<AtomicBool>,
    attempt_id: Option<u64>,
}

struct JobLifetime(Arc<AtomicBool>);

impl Drop for JobLifetime {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct JobsState {
    accepting: bool,
    jobs: HashMap<String, InvocationJob>,
    /// Shutdown owns these handles outside the mutex, while queries still
    /// need to distinguish live jobs from unresolved persisted admissions.
    draining: HashMap<String, JobActivity>,
}

/// A bounded supervisor. No task callback needs to acquire its ownership lock.
pub(super) struct InvocationJobs {
    state: Mutex<JobsState>,
    capacity: usize,
}

impl InvocationJobs {
    #[must_use]
    pub(super) fn new() -> Self {
        Self::with_capacity(MAX_OWNED_INVOCATIONS)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(JobsState {
                accepting: true,
                jobs: HashMap::new(),
                draining: HashMap::new(),
            }),
            capacity,
        }
    }

    fn reap_finished(&self) {
        let retired = {
            let mut state = self.state.lock().expect("invocation jobs lock");
            let finished = state
                .jobs
                .iter()
                .filter(|(_, job)| job.handle.is_finished())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            finished
                .into_iter()
                .filter_map(|id| state.jobs.remove(&id))
                .collect::<Vec<_>>()
        };
        // Destructors run outside the ownership lock.
        drop(retired);
    }

    /// Admit exactly one task for this operation id and retain its handle
    /// before returning the HTTP response receiver.
    ///
    /// The future must persist admission before it dispatches a connector. A
    /// rejected spawn never polls the future and therefore cannot dispatch.
    pub(super) fn spawn<F>(
        &self,
        operation_id: String,
        execution_deadline: Instant,
        future: F,
    ) -> HostResult<oneshot::Receiver<HostResult<InvokeResponse>>>
    where
        F: Future<Output = HostResult<InvokeResponse>> + Send + 'static,
    {
        self.spawn_with_error(
            operation_id,
            execution_deadline,
            InvocationJobKind::Local,
            future,
            std::convert::identity,
        )
    }

    /// Retain a mesh forward without creating an executor-local admission.
    ///
    /// The future must append routing evidence before any peer send and enforce
    /// its execution deadline separately from the finalization grace. Signed
    /// peer HTTP status and response bodies pass through without remapping.
    pub(super) fn spawn_forward<F>(
        &self,
        operation_id: String,
        execution_deadline: Instant,
        future: F,
    ) -> HostResult<oneshot::Receiver<ForwardResult>>
    where
        F: Future<Output = ForwardResult> + Send + 'static,
    {
        self.spawn_with_error(
            operation_id,
            execution_deadline,
            InvocationJobKind::Forward,
            future,
            |_| {
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    "owned mesh forward exceeded its finalization deadline; the remote executor may have executed the operation and its outcome is unknown; do not automatically retry"
                        .to_string(),
                )
            },
        )
    }

    fn spawn_with_error<F, E>(
        &self,
        operation_id: String,
        execution_deadline: Instant,
        kind: InvocationJobKind,
        future: F,
        map_error: fn(HostError) -> E,
    ) -> HostResult<oneshot::Receiver<Result<InvokeResponse, E>>>
    where
        F: Future<Output = Result<InvokeResponse, E>> + Send + 'static,
        E: Send + 'static,
    {
        self.reap_finished();
        let mut state = self.state.lock().expect("invocation jobs lock");
        if !state.accepting {
            return Err(HostError::Unavailable(
                "host is draining admitted invocations".to_string(),
            ));
        }
        if state.jobs.contains_key(&operation_id) {
            return Err(HostError::PreflightFailed(format!(
                "operation `{operation_id}` already has an active host invocation"
            )));
        }
        if state.jobs.len() >= self.capacity {
            return Err(HostError::Unavailable(
                "host invocation capacity is exhausted".to_string(),
            ));
        }
        if Instant::now() >= execution_deadline {
            return Err(HostError::Unavailable(
                "invocation deadline expired before host admission".to_string(),
            ));
        }

        let deadline = finalization_deadline(execution_deadline);
        let (response_tx, response_rx) = oneshot::channel();
        let alive = Arc::new(AtomicBool::new(true));
        // Capture the guard before admission: dropping an unpolled task must
        // clear liveness too, not only tasks that reached their first poll.
        let lifetime = JobLifetime(Arc::clone(&alive));
        let handle = task::try_spawn(async move {
            let _lifetime = lifetime;
            let result = match fcp_async_core::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                future,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(map_error(HostError::Unavailable(
                    "host invocation finalization deadline expired; consult the invocation record before retrying"
                        .to_string(),
                ))),
            };
            // A disconnected client cannot cancel the completed host work.
            let _ = response_tx.send(result);
        })
        .map_err(|error| {
            HostError::Unavailable(format!("host invocation task admission failed: {error}"))
        })?;
        state.jobs.insert(
            operation_id,
            InvocationJob {
                handle,
                activity: JobActivity {
                    kind,
                    alive,
                    attempt_id: None,
                },
            },
        );
        drop(state);
        Ok(response_rx)
    }

    /// Report host job ownership, independently of a persisted observation.
    /// Physical native retirement can remain owned by the cancellation reaper
    /// after this returns false; it is never a no-side-effect assertion.
    #[must_use]
    pub(super) fn is_active(&self, operation_id: &str) -> bool {
        self.active_kind(operation_id).is_some()
    }

    /// Bind the current job only after its local admission or origin intent
    /// has persisted. Repeating the same binding is safe; replacing it is not.
    pub(super) fn bind_attempt(&self, ticket: &fcp_host::InvocationTicket) -> HostResult<()> {
        if ticket.attempt_id == 0 {
            return Err(HostError::Internal(
                "invocation ownership requires a positive durable attempt ID".to_string(),
            ));
        }
        let mut state = self.state.lock().expect("invocation jobs lock");
        let activity = if let Some(job) = state.jobs.get_mut(&ticket.operation_id) {
            &mut job.activity
        } else {
            state
                .draining
                .get_mut(&ticket.operation_id)
                .ok_or_else(|| {
                    HostError::Unavailable(
                        "invocation lost host ownership before attempt binding".to_string(),
                    )
                })?
        };
        if !activity.alive.load(Ordering::Acquire) {
            return Err(HostError::Unavailable(
                "invocation owner ended before attempt binding".to_string(),
            ));
        }
        if activity
            .attempt_id
            .is_some_and(|previous| previous != ticket.attempt_id)
        {
            return Err(HostError::Internal(
                "refusing to replace an owned invocation attempt".to_string(),
            ));
        }
        activity.attempt_id = Some(ticket.attempt_id);
        Ok(())
    }

    /// Observe liveness and job kind together, including during shutdown.
    #[must_use]
    pub(super) fn active_kind(&self, operation_id: &str) -> Option<InvocationJobKind> {
        self.active_observation(operation_id).map(|(kind, _)| kind)
    }

    /// Sample kind and durable identity under one ownership lock. An absent
    /// attempt means the current job has not finished durable admission yet.
    #[must_use]
    pub(super) fn active_observation(
        &self,
        operation_id: &str,
    ) -> Option<(InvocationJobKind, Option<u64>)> {
        let state = self.state.lock().expect("invocation jobs lock");
        if let Some(job) = state.jobs.get(operation_id)
            && !job.handle.is_finished()
            && job.activity.alive.load(Ordering::Acquire)
        {
            return Some((job.activity.kind, job.activity.attempt_id));
        }
        state
            .draining
            .get(operation_id)
            .filter(|activity| activity.alive.load(Ordering::Acquire))
            .map(|activity| (activity.kind, activity.attempt_id))
    }

    pub(super) fn stop_accepting(&self) {
        self.state.lock().expect("invocation jobs lock").accepting = false;
    }

    /// Stop admission before draining. Timed-out handles are dropped only
    /// after leaving the lock; their runtime guards retain physical retirement
    /// and unresolved durable records remain unsafe to replay.
    pub(super) async fn shutdown(&self, timeout: Duration) -> HostResult<()> {
        let jobs = {
            let mut state = self.state.lock().expect("invocation jobs lock");
            state.accepting = false;
            let active = state
                .jobs
                .iter()
                .map(|(id, job)| (id.clone(), job.activity.clone()))
                .collect::<Vec<_>>();
            state.draining.extend(active);
            std::mem::take(&mut state.jobs)
        };
        let mut pending = jobs
            .into_iter()
            .map(|(id, job)| async move { (id, job.handle.await) })
            .collect::<FuturesUnordered<_>>();
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut first_error = None;
        while !pending.is_empty() {
            match fcp_async_core::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                pending.next(),
            )
            .await
            {
                Ok(Some((id, result))) => {
                    let retired = self
                        .state
                        .lock()
                        .expect("invocation jobs lock")
                        .draining
                        .remove(&id);
                    drop(retired);
                    if let Err(error) = result {
                        first_error.get_or_insert_with(|| {
                            HostError::Unavailable(format!(
                                "owned invocation `{id}` did not finish normally: {error}"
                            ))
                        });
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    return Err(HostError::Unavailable(
                        "host invocation shutdown deadline expired; unresolved outcomes remain unknown"
                            .to_string(),
                    ));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Re-enter the executor-local pipeline with an optional parent deadline.
/// The boxed Send future also bounds the type recursion of MCP sampling jobs.
pub(super) fn execute<'a>(
    state: &'a std::sync::Arc<super::AppState>,
    request: fcp_kernel::InvokeRequest,
    asserted_principal: Option<String>,
    parent_deadline: Option<Instant>,
    relay: Option<fcp_host::RelayCancellationBinding>,
) -> std::pin::Pin<Box<dyn Future<Output = HostResult<InvokeResponse>> + Send + 'a>> {
    Box::pin(async move {
        request.validate_idempotency_key().map_err(|error| {
            HostError::InvalidFilter(format!("invalid invoke request: {error}"))
        })?;
        let started_at = Instant::now();
        let mut deadline = super::invocation_deadline(started_at, request.deadline_ms);
        if let Some(parent) = parent_deadline {
            deadline = deadline.min(parent);
        }
        let mut audit = fcp_host::InvokeAuditContext {
            zone_id: request.zone_id.to_string(),
            actor: asserted_principal
                .clone()
                .unwrap_or_else(|| "anonymous".to_string()),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            operation_id: request.id.to_string(),
            correlation_id: request.correlation_id.as_ref().map(ToString::to_string),
            occurred_at: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default(),
        };
        // Consuming admission, quota and runtime selection must belong to one
        // inventory generation. A publication requires fresh admission.
        let registry_generation = state.registry.version.load(Ordering::SeqCst);
        let preflight = match before_deadline(
            deadline,
            super::evaluate_live_admission(
                state,
                &request,
                asserted_principal.as_deref(),
                None,
                super::RateLimitMode::Consume,
            ),
            "preflight",
        )
        .await
        {
            Ok(preflight) => preflight,
            Err(error) => {
                append_deny(state, &audit, &error.to_string())?;
                return Err(error);
            }
        };
        if !preflight.allowed {
            let reason = preflight
                .reason
                .unwrap_or_else(|| "preflight denied invoke request".to_string());
            append_deny(state, &audit, &reason)?;
            return Err(HostError::PreflightFailed(reason));
        }
        if let Err(error) = state.registry.require_generation(registry_generation) {
            append_deny(state, &audit, &error.to_string())?;
            return Err(error);
        }

        // Preflight verified this exact token. Persist its authoritative
        // principal, including requests without an X-Principal header.
        let claims = request
            .capability_token
            .raw()
            .claims_unverified()
            .map_err(|error| {
                HostError::Internal(format!(
                    "verified invoke lost readable capability claims: {error}"
                ))
            })?;
        audit.actor = super::claims_principal(&claims)
            .filter(|principal| !principal.trim().is_empty())
            .ok_or_else(|| HostError::Internal("verified invoke lost its principal".to_string()))?
            .to_string();
        state
            .invoke_audit
            .append(&audit, fcp_host::InvokePhase::PreflightAllow)
            .map_err(|error| super::invoke_audit_unavailable("preflight allow", error))?;

        let job_state = std::sync::Arc::clone(state);
        let job_audit = audit.clone();
        let receiver = match state
            .invoke_jobs
            .spawn(request.id.to_string(), deadline, async move {
                run_owned(
                    &job_state,
                    request,
                    asserted_principal,
                    job_audit,
                    AdmittedInvocationContext {
                        started_at,
                        deadline,
                        relay,
                        registry_generation,
                    },
                )
                .await
            }) {
            Ok(receiver) => receiver,
            Err(error) => {
                let _ = append_dispatch_audit(
                    state,
                    &audit,
                    &Err(HostError::Unavailable(error.to_string())),
                    super::elapsed_millis(started_at),
                );
                return Err(error);
            }
        };
        receiver.await.map_err(|_| {
            HostError::Unavailable(
                "owned invocation ended without a response; inspect its invocation record before retrying"
                    .to_string(),
            )
        })?
    })
}

async fn before_deadline<T>(
    deadline: Instant,
    future: impl Future<Output = T>,
    phase: &str,
) -> HostResult<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HostError::Unavailable(format!(
            "invocation deadline expired before {phase}"
        )));
    }
    fcp_async_core::time::timeout(remaining, future)
        .await
        .map_err(|_| HostError::Unavailable(format!("invocation deadline expired during {phase}")))
}

fn append_deny(
    state: &super::AppState,
    audit: &fcp_host::InvokeAuditContext,
    reason: &str,
) -> HostResult<()> {
    state
        .invoke_audit
        .append(
            audit,
            fcp_host::InvokePhase::PreflightDeny {
                reason: reason.to_string(),
            },
        )
        .map(|_| ())
        .map_err(|error| super::invoke_audit_unavailable("preflight denial", error))
}

fn append_dispatch_audit(
    state: &super::AppState,
    audit: &fcp_host::InvokeAuditContext,
    result: &HostResult<InvokeResponse>,
    duration_ms: u64,
) -> HostResult<String> {
    let phase = match result {
        Ok(response) => fcp_host::InvokePhase::DispatchResult {
            receipt_id: response.receipt_id.as_ref().map(ToString::to_string),
            success: matches!(response.status, fcp_kernel::InvokeStatus::Ok),
            duration_ms,
        },
        Err(error) => fcp_host::InvokePhase::DispatchError {
            error: error.to_string(),
            duration_ms,
        },
    };
    state
        .invoke_audit
        .append(audit, phase)
        .map(|entry| entry.id)
        .map_err(|error| super::invoke_audit_unavailable("dispatch outcome", error))
}

/// The registration outlives the polled dispatch future. Native guards retain
/// selected command custody; an unpolled future is safe to release directly.
struct DispatchRegistration {
    controller: std::sync::Arc<fcp_host::CancellationController>,
    registration: fcp_host::CancellationRegistration,
    started: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for DispatchRegistration {
    fn drop(&mut self) {
        if self.started.load(std::sync::atomic::Ordering::SeqCst) {
            self.controller
                .complete_registration_when_settled(&self.registration);
        } else {
            self.controller.complete_registration(&self.registration);
        }
    }
}

async fn dispatch(
    state: &std::sync::Arc<super::AppState>,
    request: fcp_kernel::InvokeRequest,
    deadline: Instant,
    relay: Option<fcp_host::RelayCancellationBinding>,
    registry_generation: u64,
) -> (HostResult<InvokeResponse>, bool) {
    let target = before_deadline(
        deadline,
        state
            .registry
            .cancellation_target(&request.connector_id, deadline, registry_generation),
        "runtime selection",
    )
    .await
    .and_then(std::convert::identity);
    let (mut scope, runtime, warm_capture, wasi_capture, native_capture) = match target {
        Ok(target) => target,
        Err(error) => return (Err(error), false),
    };
    // The finalization allowance never grants time to start new connector IO.
    if Instant::now() >= deadline {
        return (
            Err(HostError::Unavailable(
                "invocation deadline expired before connector dispatch".to_string(),
            )),
            false,
        );
    }
    // Capture the signed origin registration on the exact runtime selected above.
    scope.relay = relay;
    let registration = match super::track_verified_cancellation_owner(
        state.cancellation.as_ref(),
        &request.id.to_string(),
        &request,
        scope,
    ) {
        Ok(registration) => registration,
        Err(error) => return (Err(error), false),
    };
    if let Some(capture) = native_capture.as_ref() {
        capture.bind_registration(&state.cancellation, registration.clone());
    }
    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let registration = DispatchRegistration {
        controller: std::sync::Arc::clone(&state.cancellation),
        registration,
        started: std::sync::Arc::clone(&started),
    };
    let dispatch_started = std::sync::Arc::clone(&started);
    let authority_observation = std::sync::Arc::new(std::sync::OnceLock::<
        super::live_authority::LiveAuthorityDispatchGuard,
    >::new());
    let authority_capture = std::sync::Arc::clone(&authority_observation);
    let request_id = request.id.clone();
    let result = before_deadline(
        deadline,
        async move {
            // Admission may have waited for durable storage and runtime selection.
            // Revalidate without spending another quota permit, before any IO.
            let lifecycle_fence = state.lifecycle.capability_revocation_fence();
            let tier = dispatch_authority::revalidate(state, &request, registry_generation).await?;
            super::recheck_admitted_holder_proof(state, &request)?;
            let authority_guard = super::live_authority::LiveAuthorityDispatchGuard::new(
                state,
                &request,
                lifecycle_fence,
            )?;
            let _ = authority_capture.set(authority_guard.clone());
            state.registry.require_generation(registry_generation)?;
            if Instant::now() >= deadline {
                return Err(HostError::Unavailable(
                    "invocation deadline expired before connector dispatch".to_string(),
                ));
            }
            let deployment_guard = super::deployment_evidence::DeploymentDispatchGuard::new(
                state.deployment_evidence.clone(),
                request.zone_id.clone(),
                tier,
            );
            if let Some(capture) = native_capture.as_ref() {
                // Warm-pool captures share this same logical invocation state.
                capture.bind_deployment_guard(deployment_guard.clone());
                capture.bind_authority_guard(authority_guard.clone());
            }
            dispatch_started.store(true, std::sync::atomic::Ordering::SeqCst);
            match runtime {
                super::ConnectorRuntime::Native(native) => match native_capture {
                    Some(capture) => native.invoke_with_termination(request, capture).await,
                    None => Err(HostError::Internal(
                        "native invocation cancellation capture is missing".to_string(),
                    )),
                },
                super::ConnectorRuntime::NativeWarmPool(pool) => {
                    pool.invoke_with_termination(request, warm_capture).await
                }
                super::ConnectorRuntime::Wasi(wasi) => {
                    let fence = state.registry.inventory_fence(registry_generation);
                    let operation = wasi.invoke_with_dispatch_guards(
                        request,
                        Some(&fence),
                        Some(&deployment_guard),
                        Some(&authority_guard),
                    );
                    match wasi_capture {
                        Some(capture) => capture.invoke(operation).await,
                        None => operation.await,
                    }
                }
                runtime => runtime.invoke(request).await,
            }
        },
        "connector dispatch",
    )
    .await
    .and_then(std::convert::identity);
    let result = result.and_then(|response| {
        if response.id != request_id {
            Err(HostError::RegistryError(
                "connector returned an invoke response for a different request".to_string(),
            ))
        } else {
            Ok(response)
        }
    });
    let dispatched = started.load(std::sync::atomic::Ordering::SeqCst)
        && !authority_observation
            .get()
            .is_some_and(|guard| guard.refused_before_effect());
    // before_deadline has dropped the dispatch future before this guard probes
    // settlement. Incomplete native retirement remains owned by the reaper.
    drop(registration);
    (result, dispatched)
}

fn terminal_observation(
    result: &HostResult<InvokeResponse>,
    dispatched: bool,
    deadline: Instant,
    duration_ms: u64,
) -> fcp_host::InvocationTerminal {
    let (outcome, receipt_id, http_status) = match result {
        Ok(response) => (
            match response.status {
                fcp_kernel::InvokeStatus::Ok => fcp_host::InvocationOutcome::Succeeded,
                fcp_kernel::InvokeStatus::Error => fcp_host::InvocationOutcome::ConnectorError,
            },
            response.receipt_id.as_ref().map(ToString::to_string),
            axum::http::StatusCode::OK.as_u16(),
        ),
        Err(error) => (
            if dispatched {
                // A timeout/cancel/transport error is not proof that the
                // provider did nothing. This outcome blocks automatic reuse.
                fcp_host::InvocationOutcome::OutcomeUnknown
            } else if Instant::now() >= deadline {
                fcp_host::InvocationOutcome::DeadlineExceeded
            } else {
                fcp_host::InvocationOutcome::HostError
            },
            None,
            super::host_error_status(error).as_u16(),
        ),
    };
    fcp_host::InvocationTerminal {
        outcome,
        receipt_id,
        duration_ms,
        http_status,
    }
}

async fn persist_finalization(
    state: &super::AppState,
    ticket: &fcp_host::InvocationTicket,
    finalization: fcp_host::InvocationFinalization,
    deadline: Instant,
) {
    let result = before_deadline(
        deadline,
        state
            .lifecycle
            .record_invocation_finalization(ticket, finalization),
        "invocation finalization persistence",
    )
    .await
    .and_then(std::convert::identity);
    if let Err(error) = result {
        tracing::warn!(
            event = "invoke_finalization_persist_error",
            operation_id = %ticket.operation_id,
            attempt_id = ticket.attempt_id,
            %error,
        );
    }
}

/// Preserve the original execution budget and inventory authority through
/// durable admission and ownership transfer to the host task.
struct AdmittedInvocationContext {
    started_at: Instant,
    deadline: Instant,
    relay: Option<fcp_host::RelayCancellationBinding>,
    registry_generation: u64,
}

async fn run_owned(
    state: &std::sync::Arc<super::AppState>,
    request: fcp_kernel::InvokeRequest,
    asserted_principal: Option<String>,
    audit: fcp_host::InvokeAuditContext,
    admitted: AdmittedInvocationContext,
) -> HostResult<InvokeResponse> {
    let AdmittedInvocationContext {
        started_at,
        deadline,
        relay,
        registry_generation,
    } = admitted;
    let remaining_ms = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let admission = fcp_host::InvocationAdmission {
        operation_id: request.id.to_string(),
        connector_id: request.connector_id.to_string(),
        operation: request.operation.to_string(),
        zone_id: request.zone_id.to_string(),
        principal: audit.actor.clone(),
        correlation_id: audit.correlation_id.clone(),
        deadline_at: chrono::Utc::now()
            + chrono::Duration::milliseconds(i64::try_from(remaining_ms).unwrap_or(i64::MAX)),
        idempotency: fcp_host::InvocationIdempotency::from_request(&request, &audit.actor)?,
        // Retain the exact-token alias as well as the verified principal. A
        // route change must not escape an earlier transparent relay's fence.
        transport_idempotency: fcp_host::InvocationIdempotency::from_relay_request(
            &request,
            asserted_principal.as_deref(),
        )?,
    };
    let ticket = match before_deadline(
        deadline,
        state.lifecycle.admit_invocation(admission),
        "durable invocation admission",
    )
    .await
    .and_then(std::convert::identity)
    {
        Ok(ticket) => ticket,
        Err(error) => {
            let _ = append_dispatch_audit(
                state,
                &audit,
                &Err(HostError::Unavailable(error.to_string())),
                super::elapsed_millis(started_at),
            );
            return Err(error);
        }
    };

    state.invoke_jobs.bind_attempt(&ticket)?;
    let (source_result, dispatched) =
        dispatch(state, request.clone(), deadline, relay, registry_generation).await;
    let duration_ms = super::elapsed_millis(started_at);
    let terminal = terminal_observation(&source_result, dispatched, deadline, duration_ms);
    let finalize_by = finalization_deadline(deadline);
    // Preserve the observed source outcome before any budget, receipt or
    // sampling await. Later enrichment must not overwrite this observation.
    let terminal_persistence = before_deadline(
        finalize_by,
        state.lifecycle.finish_invocation(&ticket, terminal),
        "terminal invocation persistence",
    )
    .await
    .and_then(std::convert::identity);

    let source_persisted = terminal_persistence.is_ok();
    let audit_persistence = append_dispatch_audit(state, &audit, &source_result, duration_ms);
    let audit_event_id = audit_persistence.as_ref().ok().cloned();
    let audit_persisted = audit_event_id.is_some();
    let budget_recorded = before_deadline(
        finalize_by,
        super::record_invoke_budget_usage(
            state.budget.as_ref(),
            Some(&request.zone_id),
            &request.connector_id,
            request.operation.as_str(),
            source_result.as_ref().ok(),
        ),
        "source budget accounting",
    )
    .await
    .unwrap_or(false);
    let receipt_recorded = match source_result.as_ref() {
        Ok(response) => before_deadline(
            finalize_by,
            super::record_invoke_receipt_summary(
                state.lifecycle.as_ref(),
                request.connector_id.as_str(),
                request.operation.as_str(),
                request.idempotency_key.clone(),
                response,
                duration_ms,
            ),
            "source receipt persistence",
        )
        .await
        .unwrap_or(false),
        Err(_) => false,
    };
    let sampling = request.operation.as_str() == super::MCP_SAMPLING_HANDLE_OPERATION;
    let mut finalization = fcp_host::InvocationFinalization {
        budget_recorded,
        receipt_recorded,
        audit_event_id,
        sampling_completed: None,
        sampling_operation_id: None,
        response_http_status: None,
    };

    // A sampling child can await IO. First retain the source's completed
    // finalization evidence, without marking the entire job reclaimable.
    if sampling {
        persist_finalization(state, &ticket, finalization.clone(), finalize_by).await;
    }
    let result = match terminal_persistence {
        Err(error) => Err(HostError::Unavailable(format!(
            "connector outcome could not be persisted; inspect the invocation record before retrying: {error}"
        ))),
        Ok(()) => match (source_result, audit_persistence) {
            // The source observation is already retained. Failed evidence
            // persistence cannot authorize a child effect or a completed job.
            (_, Err(error)) => Err(error),
            (Ok(response), Ok(_)) if sampling => {
                // A child transport failure may conceal an external effect.
                // Keep the parent unresolved until a complete child response
                // (or an observed no-sampling outcome) removes that ambiguity.
                finalization.sampling_completed = Some(false);
                match super::maybe_orchestrate_mcp_sampling(
                    state,
                    asserted_principal.as_deref(),
                    &request,
                    response,
                    &ticket,
                    deadline,
                )
                .await
                {
                    Ok((response, sampling_completed)) => {
                        finalization.sampling_completed = sampling_completed;
                        Ok(response)
                    }
                    Err(error) => Err(error),
                }
            }
            (result, Ok(_)) => result,
        },
    };
    if source_persisted && audit_persisted && finalization.sampling_completed != Some(false) {
        finalization.response_http_status = Some(match &result {
            Ok(_) => axum::http::StatusCode::OK.as_u16(),
            Err(error) => super::host_error_status(error).as_u16(),
        });
    }
    // This is the final write for this ticket. Unresolved sampling keeps its
    // parent fenced, even though the source observation itself is definite.
    // A completed response marker may make confirmed history reclaimable.
    persist_finalization(state, &ticket, finalization, finalize_by).await;
    match &result {
        Ok(response) => tracing::info!(
            event = "invoke_response",
            connector_id = %request.connector_id,
            operation = %request.operation,
            operation_id = %request.id,
            attempt_id = ticket.attempt_id,
            status = ?response.status,
            duration_ms = super::elapsed_millis(started_at),
            "owned invocation complete",
        ),
        Err(error) => tracing::warn!(
            event = "invoke_error",
            connector_id = %request.connector_id,
            operation = %request.operation,
            operation_id = %request.id,
            attempt_id = ticket.attempt_id,
            %error,
            duration_ms = super::elapsed_millis(started_at),
            "owned invocation failed",
        ),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct DispatchFixture {
        state: Arc<crate::AppState>,
        signing_key: fcp_crypto::ed25519::Ed25519SigningKey,
        request: fcp_kernel::InvokeRequest,
        invoke_count: Arc<AtomicUsize>,
        block_catalog: Arc<AtomicBool>,
        catalog_entered: oneshot::Receiver<()>,
        release_catalog: oneshot::Sender<()>,
        block_invoke: Arc<AtomicBool>,
        invoke_queued: oneshot::Receiver<()>,
        release_invoke: oneshot::Sender<()>,
    }

    fn dispatch_fixture() -> DispatchFixture {
        use crate::tests::{
            dispatcher_app_state, dispatcher_introspection, dispatcher_registry_with_connector,
            dispatcher_test_config, dispatcher_test_connector, test_capability_token,
        };
        use fcp_core::{ConnectorId, OperationId, RequestId, SafetyTier, ZoneId};

        const CONNECTOR: &str = "fcp.test.dispatch-generation:utility:1.0.0";
        const OPERATION: &str = "test.echo";
        const CAPABILITY: &str = "cap.test.echo";
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let (runner_tx, mut runner_rx) =
            fcp_async_core::channel::mpsc::channel::<crate::ConnectorRpcRequest>(8);
        let (entered_tx, catalog_entered) = oneshot::channel();
        let (release_catalog, release_rx) = oneshot::channel();
        let (queued_tx, invoke_queued) = oneshot::channel();
        let (release_invoke, release_invoke_rx) = oneshot::channel();
        let block_catalog = Arc::new(AtomicBool::new(false));
        let catalog_gate = Arc::clone(&block_catalog);
        let block_invoke = Arc::new(AtomicBool::new(false));
        let invoke_gate = Arc::clone(&block_invoke);
        let invoke_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&invoke_count);
        let runner_task = task::spawn(async move {
            let mut entered_tx = Some(entered_tx);
            let mut release_rx = Some(release_rx);
            let mut queued_tx = Some(queued_tx);
            let mut release_invoke_rx = Some(release_invoke_rx);
            while let Some(call) = runner_rx.recv().await {
                if call.method == "invoke" && invoke_gate.swap(false, Ordering::SeqCst) {
                    queued_tx.take().unwrap().send(()).unwrap();
                    release_invoke_rx.take().unwrap().await.unwrap();
                }
                if !call.rpc.try_begin() {
                    let _ = call.response_tx.send(Err(call.rpc.stop_error()));
                    continue;
                }
                let result = match call.method.as_str() {
                    "introspect" => {
                        if catalog_gate.swap(false, Ordering::SeqCst) {
                            entered_tx.take().unwrap().send(()).unwrap();
                            release_rx.take().unwrap().await.unwrap();
                        }
                        serde_json::to_value(dispatcher_introspection(
                            OPERATION,
                            CAPABILITY,
                            SafetyTier::Safe,
                        ))
                        .unwrap()
                    }
                    "health" => serde_json::json!({
                        "status": { "state": "ready" },
                        "uptime_ms": 0,
                    }),
                    "invoke" => {
                        count.fetch_add(1, Ordering::SeqCst);
                        let request: fcp_kernel::InvokeRequest =
                            serde_json::from_value(call.params).unwrap();
                        serde_json::to_value(InvokeResponse::ok(
                            request.id,
                            serde_json::json!({ "dispatched": true }),
                        ))
                        .unwrap()
                    }
                    method => panic!("unexpected fixture method {method}"),
                };
                assert!(call.rpc.try_settle_reply());
                let _ = call
                    .response_tx
                    .send(Ok(serde_json::json!({ "result": result })));
            }
        });
        let connector = dispatcher_test_connector(CONNECTOR, runner_tx, runner_task);
        let registry = dispatcher_registry_with_connector(
            CONNECTOR,
            connector,
            dispatcher_test_config(CONNECTOR),
        );
        let state = dispatcher_app_state(
            registry,
            Arc::new(fcp_host::HostAdminStateStore::new()),
            Some(signing_key.verifying_key()),
            HashMap::from([(ZoneId::work(), crate::host_runtime_policy(ZoneId::work()))]),
        );
        let request = fcp_kernel::InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static(CONNECTOR),
            operation: OperationId::from_static(OPERATION),
            zone_id: ZoneId::work(),
            input: serde_json::json!({ "value": "private-dispatch-fixture" }),
            capability_token: test_capability_token(
                &signing_key,
                CAPABILITY,
                OPERATION,
                ZoneId::work().as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: Some(10_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        DispatchFixture {
            state,
            signing_key,
            request,
            invoke_count,
            block_catalog,
            catalog_entered,
            release_catalog,
            block_invoke,
            invoke_queued,
            release_invoke,
        }
    }

    async fn publish_dispatch_fixture_change(state: &crate::AppState, change: &str) {
        let mut inventory = state.registry.inventory().await;
        match change {
            "zone" => inventory[0].allowed_zones = vec![fcp_core::ZoneId::owner().to_string()],
            "operation" => inventory[0].allowed_operations = vec!["test.other".to_string()],
            "deny-empty" => inventory[0].enforce_empty_allow_lists = true,
            "manifest" => inventory[0].enforce_operation_network_constraints = true,
            "runtime" => {
                inventory[0].runtime_network_enforcement =
                    crate::RuntimeNetworkEnforcement::HostEgressProxy;
            }
            "replace" => inventory[0].binary = "replacement-runtime".to_string(),
            "remove" => inventory.clear(),
            "unrelated" => {
                inventory.push(crate::tests::dispatcher_test_config(
                    "fcp.test.other:utility:1.0.0",
                ));
            }
            _ => panic!("unknown fixture change {change}"),
        }
        let replacement =
            crate::tests::registry_publication_fixture(&state.registry, inventory).await;
        state.registry.publish_configs(replacement).await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn dispatch_generation_keeps_unchanged_authorized_invocation_working() {
        let fixture = dispatch_fixture();
        let generation = fixture.state.registry.version.load(Ordering::SeqCst);
        let preflight =
            crate::evaluate_live_preflight(&fixture.state, &fixture.request, None).await;
        assert!(preflight.allowed, "{:?}", preflight.reason);
        let (result, dispatched) = dispatch(
            &fixture.state,
            fixture.request,
            Instant::now() + Duration::from_secs(10),
            None,
            generation,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert!(dispatched);
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn live_authority_rejects_revoked_or_unavailable_feed_after_native_queue_wait() {
        use fcp_evidence::CascadeHop;
        use fcp_host::{
            RUNTIME_REVOCATION_SCHEMA, RuntimeKeyRevocation, RuntimeRevocationConfig,
            RuntimeRevocationService, RuntimeRevocationSnapshot, RuntimeRevocationZoneConfig,
            RuntimeTokenRevocation,
        };
        for change in ["token", "issuer", "missing", "malformed", "stale"] {
            let mut fixture = dispatch_fixture();
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let source = root.join("snapshot.json");
            let owner = fcp_crypto::ed25519::Ed25519SigningKey::generate();
            let node = fcp_crypto::KeyId::from_bytes([91; 8]);
            let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
            let mut snapshot = RuntimeRevocationSnapshot {
                schema: RUNTIME_REVOCATION_SCHEMA.to_owned(),
                zone_id: fcp_core::ZoneId::work(),
                generation: 1,
                issued_at_ms: now - 1000,
                expires_at_ms: now + 60_000,
                issuance_to_node: vec![(fixture.signing_key.key_id(), node.clone())],
                node_to_owner: vec![(node, owner.key_id())],
                tokens: vec![],
                keys: vec![],
            };
            let publish = |snapshot: &RuntimeRevocationSnapshot| {
                std::fs::write(
                    &source,
                    serde_json::to_vec(&snapshot.sign(&owner).unwrap()).unwrap(),
                )
                .unwrap();
            };
            publish(&snapshot);
            let service = RuntimeRevocationService::open(RuntimeRevocationConfig {
                zones: vec![RuntimeRevocationZoneConfig {
                    zone_id: fcp_core::ZoneId::work(),
                    owner_public_key_hex: hex::encode(owner.verifying_key().to_bytes()),
                    snapshot_file: source.clone(),
                    checkpoint_file: root.join("checkpoint.json"),
                }],
            })
            .unwrap();
            Arc::get_mut(&mut fixture.state).unwrap().runtime_revocation = Some(Arc::new(service));
            let claims = fixture
                .request
                .capability_token
                .raw()
                .verify(&fixture.signing_key.verifying_key())
                .unwrap();
            let token_id =
                crate::revocation_cascade_token_id(&fixture.request.capability_token, &claims)
                    .unwrap();
            let preflight =
                crate::evaluate_live_preflight(&fixture.state, &fixture.request, None).await;
            assert!(preflight.allowed, "{change}: {:?}", preflight.reason);
            fixture.block_invoke.store(true, Ordering::SeqCst);
            let state = Arc::clone(&fixture.state);
            let generation = state.registry.version.load(Ordering::SeqCst);
            let request = fixture.request;
            let deadline = Instant::now() + Duration::from_secs(10);
            let pending =
                task::spawn(
                    async move { dispatch(&state, request, deadline, None, generation).await },
                );
            fixture.invoke_queued.await.unwrap();
            snapshot.generation = 2;
            match change {
                "token" => {
                    snapshot.tokens.push(RuntimeTokenRevocation {
                        token_id,
                        revoked_at_ms: now - 1000,
                    });
                    publish(&snapshot);
                }
                "issuer" => {
                    snapshot.keys.push(RuntimeKeyRevocation {
                        kid: fixture.signing_key.key_id(),
                        hop: CascadeHop::IssuerKey,
                        revoked_at_ms: now - 1000,
                    });
                    publish(&snapshot);
                }
                "missing" => std::fs::rename(&source, root.join("withdrawn.json")).unwrap(),
                "malformed" => std::fs::write(&source, b"invalid replacement").unwrap(),
                "stale" => {
                    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
                    snapshot.issued_at_ms = now - 2;
                    snapshot.expires_at_ms = now - 1;
                    publish(&snapshot);
                }
                _ => unreachable!(),
            }
            fixture.release_invoke.send(()).unwrap();
            let (result, dispatched) = pending.await.unwrap();
            assert!(
                matches!(&result, Err(HostError::PreflightFailed(_))),
                "{change}: {result:?}"
            );
            assert!(
                !dispatched,
                "{change}: no effect ticket reached the connector"
            );
            assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
            assert_eq!(
                terminal_observation(&result, dispatched, deadline, 0).outcome,
                fcp_host::InvocationOutcome::HostError
            );
            assert!(
                !result
                    .unwrap_err()
                    .to_string()
                    .contains("private-dispatch-fixture")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn live_authority_rejects_lifecycle_revocation_after_native_queue_wait() {
        let fixture = dispatch_fixture();
        fixture.block_invoke.store(true, Ordering::SeqCst);
        let state = Arc::clone(&fixture.state);
        let generation = state.registry.version.load(Ordering::SeqCst);
        let request = fixture.request;
        let pending = task::spawn(async move {
            dispatch(
                &state,
                request,
                Instant::now() + Duration::from_secs(10),
                None,
                generation,
            )
            .await
        });
        fixture.invoke_queued.await.unwrap();
        // Every published revocation changes authority, even when the target
        // was issued elsewhere and this host has no issuance row for it.
        fixture
            .state
            .lifecycle
            .revoke_token(&fcp_host::TokenRevocationRequest {
                token_id: "revoked-after-queue".to_string(),
                reason: None,
            })
            .await
            .unwrap();
        fixture.release_invoke.send(()).unwrap();
        let (result, dispatched) = pending.await.unwrap();
        assert!(matches!(result, Err(HostError::PreflightFailed(_))));
        assert!(!dispatched);
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn live_authority_expiry_after_native_queue_wait_never_reaches_connector() {
        for approval in [false, true] {
            let mut fixture = dispatch_fixture();
            let now = chrono::Utc::now();
            let expires = now.timestamp() + 2;
            if approval {
                let key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
                Arc::get_mut(&mut fixture.state)
                    .unwrap()
                    .approval_verifying_key = Some(key.verifying_key());
                let mut token = fcp_core::ApprovalToken::approved(
                    "queued-approval",
                    u64::try_from(now.timestamp_millis()).unwrap() - 1000,
                    u64::try_from(expires).unwrap() * 1000,
                    "owner:test",
                    fcp_core::ApprovalScope::Execution(fcp_core::ExecutionScope {
                        connector_id: fixture.request.connector_id.to_string(),
                        method_pattern: fixture.request.operation.to_string(),
                        request_object_id: None,
                        input_hash: None,
                        input_constraints: vec![],
                    }),
                    fixture.request.zone_id.clone(),
                    None,
                );
                token.signature = Some(
                    key.sign(&crate::approval_token_signing_bytes(&token).unwrap())
                        .to_bytes()
                        .to_vec(),
                );
                fixture.request.approval_tokens.push(token);
            } else {
                let claims = fixture
                    .request
                    .capability_token
                    .raw()
                    .verify(&fixture.signing_key.verifying_key())
                    .unwrap()
                    .custom(
                        fcp_crypto::cose::cwt_claims::EXP,
                        ciborium::Value::Integer(expires.into()),
                    );
                fixture.request.capability_token = fcp_core::CapabilityToken::from_raw(
                    fcp_crypto::cose::CoseToken::sign(&fixture.signing_key, &claims).unwrap(),
                );
            }
            fixture.block_invoke.store(true, Ordering::SeqCst);
            let state = Arc::clone(&fixture.state);
            let generation = state.registry.version.load(Ordering::SeqCst);
            let request = fixture.request;
            let pending = task::spawn(async move {
                dispatch(
                    &state,
                    request,
                    Instant::now() + Duration::from_secs(10),
                    None,
                    generation,
                )
                .await
            });
            fixture.invoke_queued.await.unwrap();
            while chrono::Utc::now().timestamp() < expires {
                fcp_async_core::time::sleep(Duration::from_millis(20)).await;
            }
            fixture.release_invoke.send(()).unwrap();
            let (result, dispatched) = pending.await.unwrap();
            assert!(
                matches!(&result, Err(HostError::PreflightFailed(_))),
                "approval={approval}: {result:?}"
            );
            assert!(!dispatched);
            assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn live_authority_does_not_relabel_an_already_selected_effect_as_undispatched() {
        let fixture = dispatch_fixture();
        let guard = crate::live_authority::LiveAuthorityDispatchGuard::new(
            &fixture.state,
            &fixture.request,
            fixture.state.lifecycle.capability_revocation_fence(),
        )
        .unwrap();
        let invocation =
            crate::NativeInvocationTermination::new(Instant::now() + Duration::from_secs(10));
        invocation.bind_authority_guard(guard.clone());
        let active = invocation.register_rpc_for_method("invoke");
        assert!(active.try_begin());
        fixture
            .state
            .lifecycle
            .revoke_token(&fcp_host::TokenRevocationRequest {
                token_id: "later-revocation".to_string(),
                reason: None,
            })
            .await
            .unwrap();
        let queued = invocation.register_rpc_for_method("invoke");
        assert!(!queued.try_begin());
        assert!(!guard.refused_before_effect());
        assert!(
            active.try_settle_reply(),
            "active work retains its definite response boundary"
        );
        let unknown: HostResult<InvokeResponse> =
            Err(HostError::Unavailable("lost response".to_string()));
        assert_eq!(
            terminal_observation(&unknown, !guard.refused_before_effect(), Instant::now(), 0)
                .outcome,
            fcp_host::InvocationOutcome::OutcomeUnknown
        );
    }

    #[fcp_async_core::runtime::test]
    async fn dispatch_generation_fences_replaced_or_removed_runtime_after_selection() {
        for change in [
            "zone",
            "operation",
            "deny-empty",
            "manifest",
            "runtime",
            "replace",
            "remove",
        ] {
            let fixture = dispatch_fixture();
            let generation = fixture.state.registry.version.load(Ordering::SeqCst);
            let preflight =
                crate::evaluate_live_preflight(&fixture.state, &fixture.request, None).await;
            assert!(preflight.allowed, "{change}: {:?}", preflight.reason);
            fixture.block_catalog.store(true, Ordering::SeqCst);
            let state = Arc::clone(&fixture.state);
            let request = fixture.request;
            let pending = task::spawn(async move {
                dispatch(
                    &state,
                    request,
                    Instant::now() + Duration::from_secs(10),
                    None,
                    generation,
                )
                .await
            });
            // Runtime selection completed; publishing must not wait for its
            // external catalog response or authorize the captured old runtime.
            fixture.catalog_entered.await.unwrap();
            publish_dispatch_fixture_change(&fixture.state, change).await;
            fixture.release_catalog.send(()).unwrap();
            let (result, dispatched) = pending.await.unwrap();
            let error = result.expect_err("publication must fence the captured runtime");
            assert!(
                error.to_string().contains("inventory changed"),
                "{change}: {error}"
            );
            assert!(!dispatched, "{change}: stale authority reached dispatch");
            assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0, "{change}");
            assert!(!error.to_string().contains("private-dispatch-fixture"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn dispatch_generation_cannot_change_during_consuming_preflight() {
        let fixture = dispatch_fixture();
        let state = Arc::clone(&fixture.state);
        let request = fixture.request;
        let operation_id = request.id.to_string();
        fixture.block_catalog.store(true, Ordering::SeqCst);
        let pending = task::spawn(async move { execute(&state, request, None, None, None).await });
        fixture.catalog_entered.await.unwrap();
        publish_dispatch_fixture_change(&fixture.state, "unrelated").await;
        fixture.release_catalog.send(()).unwrap();
        let error = pending
            .await
            .unwrap()
            .expect_err("preflight generation changed");
        assert!(error.to_string().contains("inventory changed"), "{error}");
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
        assert!(!fixture.state.invoke_jobs.is_active(&operation_id));
    }

    #[fcp_async_core::runtime::test]
    async fn dispatch_generation_fences_invoke_waiting_for_native_actor_selection() {
        for change in ["zone", "operation", "replace", "remove"] {
            let fixture = dispatch_fixture();
            let generation = fixture.state.registry.version.load(Ordering::SeqCst);
            let preflight =
                crate::evaluate_live_preflight(&fixture.state, &fixture.request, None).await;
            assert!(preflight.allowed, "{change}: {:?}", preflight.reason);
            fixture.block_invoke.store(true, Ordering::SeqCst);
            let state = Arc::clone(&fixture.state);
            let request = fixture.request;
            let pending = task::spawn(async move {
                dispatch(
                    &state,
                    request,
                    Instant::now() + Duration::from_secs(10),
                    None,
                    generation,
                )
                .await
            });
            // Outer checks passed and the effect RPC reached the actor queue,
            // but the physical ticket has not been selected yet.
            fixture.invoke_queued.await.unwrap();
            publish_dispatch_fixture_change(&fixture.state, change).await;
            fixture.release_invoke.send(()).unwrap();
            let (result, dispatched) = pending.await.unwrap();
            let error = result.expect_err("stale queued invoke must not be selected");
            assert!(
                error.to_string().contains("inventory changed"),
                "{change}: {error}"
            );
            // Preserve conservative ownership/outcome tracking for session
            // work already handed to the runtime before this effect refusal.
            assert!(
                dispatched,
                "{change}: fixture did not reach the runtime queue"
            );
            assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0, "{change}");
            assert!(!error.to_string().contains("private-dispatch-fixture"));
        }
    }

    fn reply() -> InvokeResponse {
        InvokeResponse::ok(
            fcp_kernel::RequestId::new("owned-job"),
            serde_json::json!({}),
        )
    }

    #[fcp_async_core::runtime::test]
    async fn owned_attempt_binding_is_immutable_and_survives_shutdown_handoff() {
        let jobs = Arc::new(InvocationJobs::with_capacity(1));
        let (release_tx, release_rx) = oneshot::channel();
        let receiver = jobs
            .spawn_forward(
                "bound-forward".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    release_rx.await.expect("release owned forward");
                    Ok(reply())
                },
            )
            .expect("admit unbound forward");
        assert_eq!(
            jobs.active_observation("bound-forward"),
            Some((InvocationJobKind::Forward, None))
        );
        let mut ticket = fcp_host::InvocationTicket {
            operation_id: "bound-forward".to_string(),
            attempt_id: 0,
        };
        assert!(jobs.bind_attempt(&ticket).is_err());
        ticket.attempt_id = 17;
        jobs.bind_attempt(&ticket)
            .expect("bind durable reservation");
        jobs.bind_attempt(&ticket)
            .expect("repeat identical binding");
        let mut replacement = ticket.clone();
        replacement.attempt_id = 18;
        assert!(jobs.bind_attempt(&replacement).is_err());
        assert_eq!(
            jobs.active_observation("bound-forward"),
            Some((InvocationJobKind::Forward, Some(17)))
        );

        let draining_jobs = Arc::clone(&jobs);
        let draining =
            task::spawn(async move { draining_jobs.shutdown(Duration::from_secs(2)).await });
        fcp_async_core::time::timeout(Duration::from_secs(1), async {
            loop {
                let handed_off = jobs
                    .state
                    .lock()
                    .expect("jobs lock")
                    .draining
                    .contains_key("bound-forward");
                if handed_off {
                    break;
                }
                task::yield_now().await;
            }
        })
        .await
        .expect("shutdown takes ownership");
        jobs.bind_attempt(&ticket)
            .expect("binding remains in draining owner");
        assert!(jobs.bind_attempt(&replacement).is_err());
        assert_eq!(
            jobs.active_observation("bound-forward"),
            Some((InvocationJobKind::Forward, Some(17)))
        );
        release_tx.send(()).expect("release draining job");
        receiver
            .await
            .expect("response channel")
            .expect("forward result");
        draining.await.expect("drain task").expect("drain complete");
        assert_eq!(jobs.active_observation("bound-forward"), None);
        assert!(jobs.bind_attempt(&ticket).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn disconnected_waiter_does_not_abandon_owned_finalization() {
        let jobs = InvocationJobs::with_capacity(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (finalized_tx, finalized_rx) = oneshot::channel();
        let receiver = jobs
            .spawn(
                "owned-job".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    started_tx.send(()).expect("started receiver");
                    release_rx.await.expect("release job");
                    finalized_tx.send(()).expect("finalization observer");
                    Ok(reply())
                },
            )
            .expect("admit");
        started_rx.await.expect("job started");
        drop(receiver);
        release_tx
            .send(())
            .expect("job still owned after disconnect");
        finalized_rx.await.expect("host finalized after disconnect");
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
    }

    #[fcp_async_core::runtime::test]
    async fn disconnected_forward_waiter_retains_job_until_observation_finishes() {
        let jobs = InvocationJobs::with_capacity(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (observed_tx, observed_rx) = oneshot::channel();
        let receiver = jobs
            .spawn_forward(
                "forwarded-job".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    started_tx.send(()).expect("started observer");
                    release_rx.await.expect("release forward");
                    observed_tx.send(()).expect("outcome observer");
                    Err((
                        axum::http::StatusCode::BAD_GATEWAY,
                        "executor outcome remains unknown".to_string(),
                    ))
                },
            )
            .expect("admit forward");
        started_rx.await.expect("forward started");
        drop(receiver);
        assert_eq!(
            jobs.active_kind("forwarded-job"),
            Some(InvocationJobKind::Forward)
        );
        release_tx.send(()).expect("forward still owned");
        observed_rx
            .await
            .expect("forward observation after disconnect");
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
        assert_eq!(jobs.active_kind("forwarded-job"), None);
    }

    #[fcp_async_core::runtime::test]
    async fn forwarded_responses_preserve_executor_http_status_body_and_success() {
        use axum::http::StatusCode;

        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let jobs = InvocationJobs::with_capacity(1);
            let expected_body = format!("executor response with status {status}");
            let body = expected_body.clone();
            let receiver = jobs
                .spawn_forward(
                    "forwarded-error".to_string(),
                    Instant::now() + Duration::from_secs(5),
                    async move { Err((status, body)) },
                )
                .expect("admit forward");
            let error = receiver
                .await
                .expect("response channel")
                .expect_err("peer error");
            assert_eq!(error, (status, expected_body));
            jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
        }

        let jobs = InvocationJobs::with_capacity(1);
        let response = InvokeResponse::ok(
            fcp_kernel::RequestId::new("executor-reply"),
            serde_json::json!({"remote_result": {"retained": true}}),
        );
        let expected = serde_json::to_value(&response).expect("expected response");
        let receiver = jobs
            .spawn_forward(
                "forwarded-success".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move { Ok(response) },
            )
            .expect("admit forward");
        let response = receiver
            .await
            .expect("response channel")
            .expect("peer success");
        assert_eq!(
            serde_json::to_value(response).expect("response JSON"),
            expected
        );
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
    }

    #[fcp_async_core::runtime::test]
    async fn local_and_forward_jobs_share_duplicate_and_capacity_rejection_without_polling() {
        for owner in [InvocationJobKind::Local, InvocationJobKind::Forward] {
            let jobs = InvocationJobs::with_capacity(1);
            let (release_tx, release_rx) = oneshot::channel();
            let deadline = Instant::now() + Duration::from_secs(5);
            match owner {
                InvocationJobKind::Local => drop(
                    jobs.spawn("first".to_string(), deadline, async move {
                        release_rx.await.expect("release local job");
                        Ok(reply())
                    })
                    .expect("admit local owner"),
                ),
                InvocationJobKind::Forward => drop(
                    jobs.spawn_forward("first".to_string(), deadline, async move {
                        release_rx.await.expect("release forward job");
                        Ok(reply())
                    })
                    .expect("admit forward owner"),
                ),
            }
            assert_eq!(jobs.active_kind("first"), Some(owner));
            let polled = Arc::new(AtomicBool::new(false));
            for id in ["first", "second"] {
                let local_polled = Arc::clone(&polled);
                let local_error = jobs
                    .spawn(id.to_string(), deadline, async move {
                        local_polled.store(true, Ordering::SeqCst);
                        Ok(reply())
                    })
                    .expect_err("local admission rejected");
                let forward_polled = Arc::clone(&polled);
                let forward_error = jobs
                    .spawn_forward(id.to_string(), deadline, async move {
                        forward_polled.store(true, Ordering::SeqCst);
                        Ok(reply())
                    })
                    .expect_err("forward admission rejected");
                for error in [local_error, forward_error] {
                    if id == "first" {
                        assert!(matches!(error, HostError::PreflightFailed(_)));
                    } else {
                        assert!(matches!(error, HostError::Unavailable(_)));
                    }
                }
            }
            assert!(!polled.load(Ordering::SeqCst));
            release_tx.send(()).expect("owner retained its receiver");
            jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn shared_shutdown_preserves_local_and_forward_kinds_and_stops_new_forwards() {
        let jobs = InvocationJobs::with_capacity(2);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (local_started_tx, local_started_rx) = oneshot::channel();
        let (local_release_tx, local_release_rx) = oneshot::channel();
        let local_receiver = jobs
            .spawn("draining-local".to_string(), deadline, async move {
                local_started_tx.send(()).expect("local observer");
                local_release_rx.await.expect("release local");
                Ok(reply())
            })
            .expect("admit local");
        let (forward_started_tx, forward_started_rx) = oneshot::channel();
        let (forward_release_tx, forward_release_rx) = oneshot::channel();
        let forward_receiver = jobs
            .spawn_forward("draining-forward".to_string(), deadline, async move {
                forward_started_tx.send(()).expect("forward observer");
                forward_release_rx.await.expect("release forward");
                Ok(reply())
            })
            .expect("admit forward");
        local_started_rx.await.expect("local started");
        forward_started_rx.await.expect("forward started");
        let mut shutdown = Box::pin(jobs.shutdown(Duration::from_secs(1)));
        assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
        assert_eq!(
            jobs.active_kind("draining-local"),
            Some(InvocationJobKind::Local)
        );
        assert_eq!(
            jobs.active_kind("draining-forward"),
            Some(InvocationJobKind::Forward)
        );
        let polled = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&polled);
        assert!(
            jobs.spawn_forward("late-forward".to_string(), deadline, async move {
                captured.store(true, Ordering::SeqCst);
                Ok(reply())
            })
            .is_err()
        );
        assert!(!polled.load(Ordering::SeqCst));
        local_release_tx.send(()).expect("release local");
        forward_release_tx.send(()).expect("release forward");
        shutdown.await.expect("shared drain");
        local_receiver
            .await
            .expect("local channel")
            .expect("local result");
        forward_receiver
            .await
            .expect("forward channel")
            .expect("forward result");
        assert_eq!(jobs.active_kind("draining-local"), None);
        assert_eq!(jobs.active_kind("draining-forward"), None);
    }

    #[fcp_async_core::runtime::test]
    async fn duplicate_and_capacity_rejection_never_poll_another_dispatch() {
        let jobs = InvocationJobs::with_capacity(1);
        let (release_tx, release_rx) = oneshot::channel();
        let receiver = jobs
            .spawn(
                "first".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    release_rx.await.expect("release");
                    Ok(reply())
                },
            )
            .expect("first admission");
        let dispatched = Arc::new(AtomicBool::new(false));
        for id in ["first", "second"] {
            let dispatched = Arc::clone(&dispatched);
            assert!(
                jobs.spawn(
                    id.to_string(),
                    Instant::now() + Duration::from_secs(5),
                    async move {
                        dispatched.store(true, Ordering::SeqCst);
                        Ok(reply())
                    },
                )
                .is_err()
            );
        }
        assert!(!dispatched.load(Ordering::SeqCst));
        release_tx.send(()).expect("release first");
        receiver.await.expect("response channel").expect("response");
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
    }

    #[test]
    fn expired_admission_never_polls_dispatch_or_requires_a_runtime() {
        let jobs = InvocationJobs::new();
        let dispatched = Arc::new(AtomicBool::new(false));
        let capture = Arc::clone(&dispatched);
        assert!(
            jobs.spawn("expired".to_string(), Instant::now(), async move {
                capture.store(true, Ordering::SeqCst);
                Ok(reply())
            })
            .is_err()
        );
        assert!(!dispatched.load(Ordering::SeqCst));
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
        let capture = Arc::clone(&dispatched);
        assert!(
            jobs.spawn_forward("expired-forward".to_string(), Instant::now(), async move {
                capture.store(true, Ordering::SeqCst);
                Ok(reply())
            })
            .is_err()
        );
        assert!(!dispatched.load(Ordering::SeqCst));
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
    }

    #[test]
    fn runtime_admission_failure_does_not_occupy_a_slot() {
        let jobs = InvocationJobs::with_capacity(1);
        let error = jobs
            .spawn(
                "outside-runtime".to_string(),
                Instant::now() + Duration::from_secs(5),
                async { Ok(reply()) },
            )
            .expect_err("no runtime");
        assert!(error.to_string().contains("task admission failed"));
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
        let error = jobs
            .spawn_forward(
                "forward-outside-runtime".to_string(),
                Instant::now() + Duration::from_secs(5),
                async { Ok(reply()) },
            )
            .expect_err("no runtime");
        assert!(error.to_string().contains("task admission failed"));
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_stops_admission_before_waiting_for_existing_jobs() {
        let jobs = InvocationJobs::with_capacity(2);
        let (release_tx, release_rx) = oneshot::channel();
        let receiver = jobs
            .spawn(
                "draining".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    release_rx.await.expect("release");
                    Ok(reply())
                },
            )
            .expect("admit");
        jobs.stop_accepting();
        assert!(
            jobs.spawn(
                "late".to_string(),
                Instant::now() + Duration::from_secs(5),
                async { Ok(reply()) },
            )
            .is_err()
        );
        release_tx.send(()).expect("release");
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
        receiver.await.expect("channel").expect("response");
    }
    #[fcp_async_core::runtime::test]
    async fn blocked_admission_cannot_spend_finalization_grace_on_dispatch() {
        let jobs = InvocationJobs::with_capacity(1);
        let dispatched = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&dispatched);
        let (_release_tx, release_rx) = oneshot::channel::<()>();
        let deadline = Instant::now() + Duration::from_millis(200);
        let receiver = jobs
            .spawn("blocked-admission".to_string(), deadline, async move {
                before_deadline(deadline, release_rx, "durable invocation admission")
                    .await?
                    .expect("admission gate");
                observed.store(true, Ordering::SeqCst);
                Ok(reply())
            })
            .expect("admit host job");
        let error = receiver
            .await
            .expect("owned response")
            .expect_err("execution deadline expires before finalization grace");
        assert!(error.to_string().contains("durable invocation admission"));
        assert!(!dispatched.load(Ordering::SeqCst));
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
    }

    #[fcp_async_core::runtime::test]
    async fn liveness_remains_visible_while_shutdown_owns_join_handles() {
        let jobs = InvocationJobs::with_capacity(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let receiver = jobs
            .spawn(
                "draining-live".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    started_tx.send(()).expect("started observer");
                    release_rx.await.expect("release");
                    Ok(reply())
                },
            )
            .expect("admit");
        started_rx.await.expect("started");
        let mut shutdown = Box::pin(jobs.shutdown(Duration::from_secs(1)));
        assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
        assert!(jobs.is_active("draining-live"));
        assert!(jobs.state.lock().expect("jobs").jobs.is_empty());
        release_tx.send(()).expect("release job");
        shutdown.await.expect("drain");
        assert!(!jobs.is_active("draining-live"));
        receiver.await.expect("response channel").expect("result");
    }

    struct DropObserver(Option<oneshot::Sender<()>>);

    impl Drop for DropObserver {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_timeout_aborts_owned_job_and_eventually_clears_liveness() {
        let jobs = InvocationJobs::with_capacity(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let observer = DropObserver(Some(dropped_tx));
        let receiver = jobs
            .spawn(
                "shutdown-timeout".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    let _observer = observer;
                    started_tx.send(()).expect("started observer");
                    std::future::pending::<()>().await;
                    Ok(reply())
                },
            )
            .expect("admit");
        started_rx.await.expect("started");
        assert!(jobs.shutdown(Duration::ZERO).await.is_err());
        // Abort wakes the task; it does not synchronously drop its future in
        // shutdown's caller. Wait for the actual future destructor.
        dropped_rx.await.expect("owned future retired");
        assert!(receiver.await.is_err());
        assert!(!jobs.is_active("shutdown-timeout"));
    }

    #[fcp_async_core::runtime::test]
    async fn panicked_owned_job_closes_waiter_and_is_reported_during_shutdown() {
        let jobs = InvocationJobs::with_capacity(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let receiver = jobs
            .spawn(
                "panicked-job".to_string(),
                Instant::now() + Duration::from_secs(5),
                async move {
                    started_tx.send(()).expect("started observer");
                    release_rx.await.expect("release");
                    panic!("injected owned invocation panic");
                },
            )
            .expect("admit");
        started_rx.await.expect("started");
        release_tx.send(()).expect("release panic");
        assert!(jobs.shutdown(Duration::from_secs(1)).await.is_err());
        assert!(receiver.await.is_err());
        assert!(!jobs.is_active("panicked-job"));
    }
}
