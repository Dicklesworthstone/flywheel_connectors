//! Bounded host ownership of admitted local invocations.
//!
//! HTTP requests retain only a response receiver. The host retains each task
//! handle until the complete invocation/finalization job exits, so losing a
//! connection cannot abandon an observed connector result. Dispatch still waits
//! for the durable ownership record written by the job itself.
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

const MAX_OWNED_INVOCATIONS: usize = 256;
pub(super) const FINALIZATION_GRACE: Duration = Duration::from_secs(5);
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(65);

#[must_use]
pub(super) fn finalization_deadline(execution_deadline: Instant) -> Instant {
    execution_deadline
        .checked_add(FINALIZATION_GRACE)
        .unwrap_or(execution_deadline)
}

struct InvocationJob {
    handle: JoinHandle<()>,
    alive: Arc<AtomicBool>,
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
    draining: HashMap<String, Arc<AtomicBool>>,
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
                Err(_) => Err(HostError::Unavailable(
                    "host invocation finalization deadline expired; consult the invocation record before retrying"
                        .to_string(),
                )),
            };
            // A disconnected client cannot cancel the completed host work.
            let _ = response_tx.send(result);
        })
        .map_err(|error| {
            HostError::Unavailable(format!("host invocation task admission failed: {error}"))
        })?;
        state.jobs.insert(operation_id, InvocationJob { handle, alive });
        drop(state);
        Ok(response_rx)
    }

    /// Report host job ownership, independently of a persisted observation.
    /// Physical native retirement can remain owned by the cancellation reaper
    /// after this returns false; it is never a no-side-effect assertion.
    #[must_use]
    pub(super) fn is_active(&self, operation_id: &str) -> bool {
        let state = self.state.lock().expect("invocation jobs lock");
        state
            .jobs
            .get(operation_id)
            .is_some_and(|job| !job.handle.is_finished())
            || state
                .draining
                .get(operation_id)
                .is_some_and(|alive| alive.load(Ordering::Acquire))
    }

    pub(super) fn stop_accepting(&self) {
        self.state
            .lock()
            .expect("invocation jobs lock")
            .accepting = false;
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
                .map(|(id, job)| (id.clone(), Arc::clone(&job.alive)))
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
        let preflight = match before_deadline(
            deadline,
            super::evaluate_live_preflight(state, &request, asserted_principal.as_deref()),
            "preflight",
        )
        .await
        {
            Ok(preflight) => preflight,
            Err(error) => {
                append_deny(state, &audit, &error.to_string());
                return Err(error);
            }
        };
        if !preflight.allowed {
            let reason = preflight
                .reason
                .unwrap_or_else(|| "preflight denied invoke request".to_string());
            append_deny(state, &audit, &reason);
            return Err(HostError::PreflightFailed(reason));
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
            .ok_or_else(|| {
                HostError::Internal("verified invoke lost its principal".to_string())
            })?
            .to_string();
        if let Err(error) = state
            .invoke_audit
            .append(&audit, fcp_host::InvokePhase::PreflightAllow)
        {
            tracing::warn!(event = "invoke_audit_append_error", phase = "allow", %error);
        }

        let job_state = std::sync::Arc::clone(state);
        let job_audit = audit.clone();
        let receiver = match state.invoke_jobs.spawn(
            request.id.to_string(),
            deadline,
            async move {
                run_owned(
                    &job_state,
                    request,
                    asserted_principal,
                    started_at,
                    deadline,
                    job_audit,
                )
                .await
            },
        ) {
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
) {
    if let Err(error) = state.invoke_audit.append(
        audit,
        fcp_host::InvokePhase::PreflightDeny {
            reason: reason.to_string(),
        },
    ) {
        tracing::warn!(event = "invoke_audit_append_error", phase = "deny", %error);
    }
}

fn append_dispatch_audit(
    state: &super::AppState,
    audit: &fcp_host::InvokeAuditContext,
    result: &HostResult<InvokeResponse>,
    duration_ms: u64,
) -> Option<String> {
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
    match state.invoke_audit.append(audit, phase) {
        Ok(entry) => Some(entry.id),
        Err(error) => {
            tracing::warn!(event = "invoke_audit_append_error", phase = "dispatch", %error);
            None
        }
    }
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
) -> (HostResult<InvokeResponse>, bool) {
    let target = before_deadline(
        deadline,
        state.registry.cancellation_target(&request.connector_id, deadline),
        "runtime selection",
    )
    .await
    .and_then(std::convert::identity);
    let (scope, runtime, warm_capture, wasi_capture, native_capture) = match target {
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
    let request_id = request.id.clone();
    let result = before_deadline(
        deadline,
        async move {
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
                super::ConnectorRuntime::Wasi(wasi) => match wasi_capture {
                    Some(capture) => capture.invoke(wasi.invoke(request)).await,
                    None => wasi.invoke(request).await,
                },
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
    let dispatched = started.load(std::sync::atomic::Ordering::SeqCst);
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

async fn run_owned(
    state: &std::sync::Arc<super::AppState>,
    request: fcp_kernel::InvokeRequest,
    asserted_principal: Option<String>,
    started_at: Instant,
    deadline: Instant,
    audit: fcp_host::InvokeAuditContext,
) -> HostResult<InvokeResponse> {
    let remaining_ms = u64::try_from(
        deadline.saturating_duration_since(Instant::now()).as_millis(),
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

    let (source_result, dispatched) = dispatch(state, request.clone(), deadline).await;
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

    let audit_event_id = append_dispatch_audit(state, &audit, &source_result, duration_ms);
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
        Ok(()) => match source_result {
            Ok(response) if sampling => {
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
            result => result,
        },
    };
    if finalization.sampling_completed != Some(false) {
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
    use std::sync::atomic::{AtomicBool, Ordering};

    fn reply() -> InvokeResponse {
        InvokeResponse::ok(fcp_kernel::RequestId::new("owned-job"), serde_json::json!({}))
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
        release_tx.send(()).expect("job still owned after disconnect");
        finalized_rx.await.expect("host finalized after disconnect");
        jobs.shutdown(Duration::from_secs(1)).await.expect("drain");
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
