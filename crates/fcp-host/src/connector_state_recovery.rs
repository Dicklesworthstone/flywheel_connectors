//! Bounded recovery of one exact state root from independently granted donors.
//!
//! Only downloading is retryable. Every attempt owns its own page assembly and
//! resource reservation. Once a complete export enters import, ANY error or
//! cancellation is terminal: a durable write may already have been admitted.

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use futures_util::future::{Either, select};
use serde::{Deserialize, Serialize};

use crate::{
    ConnectorStatePullRequest, ConnectorStatePullResponse, ConnectorStateReplicationService,
    HostError, HostResult, MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES,
};

/// Schema for a recovery receipt, distinct from a single-donor pull receipt.
pub const CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION: &str = "fcp.host.state-recovery.v1";
/// Maximum distinct, explicitly granted donors in one recovery operation.
pub const MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES: usize = 8;
/// Hard bound on an operator's complete recovery request, including wrappers.
pub const MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES: usize =
    MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES * (MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES + 1024)
        + 1024;
/// Hard deadline covering all downloads and the single import attempt.
pub const MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS: u64 = 60_000;

// Revalidate a waiting donor even if its network future never wakes again.
// This is an owned timer, not another request, task, retry, or donor attempt.
const RECOVERY_AUTHORITY_RECHECK_INTERVAL: Duration = Duration::from_millis(100);

const fn default_attempt_timeout_ms() -> u64 {
    10_000
}

const fn default_total_timeout_ms() -> u64 {
    MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS
}

/// Ordered recovery sources selected by the operator, never by a remote peer.
///
/// All candidates must name the SAME connector/zone/instance/root and resource
/// limits. Only the peer and its independently configured grant may differ.
/// This does not discover a newer root, choose a quorum, activate state, or
/// authorize connector execution. At most one download is active at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateRecoveryRequest {
    /// One to eight distinct donors, in operator-selected attempt order.
    pub candidates: Vec<ConnectorStatePullRequest>,
    /// Deadline for one complete download, not a fresh deadline on every page.
    #[serde(default = "default_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,
    /// Total deadline, including the import after a successful download.
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u64,
}

impl ConnectorStateRecoveryRequest {
    /// Check shape, exact-root agreement, distinct donors, and bounded budgets.
    /// This validates no grants; use the service's `validate_recovery` for that.
    ///
    /// # Errors
    /// Rejects empty/oversized plans, duplicate donors or grants, changed scope,
    /// root or limits, malformed metadata, and zero or excessive deadlines.
    pub fn validate(&self) -> HostResult<()> {
        if self.candidates.is_empty()
            || self.candidates.len() > MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES
            || self.attempt_timeout_ms == 0
            || self.total_timeout_ms == 0
            || self.attempt_timeout_ms > self.total_timeout_ms
            || self.total_timeout_ms > MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS
        {
            return Err(invalid(
                "invalid state-recovery donor count or deadline budget",
            ));
        }
        let first = &self.candidates[0].request;
        let mut peers = HashSet::new();
        let mut grants = HashSet::new();
        for candidate in &self.candidates {
            candidate.request.to_json()?;
            if candidate.peer_node.is_empty()
                || candidate.peer_node.len() > 512
                || candidate.peer_node.trim() != candidate.peer_node.as_str()
                || candidate.peer_node.chars().any(char::is_control)
                || candidate
                    .peer_node
                    .parse::<fcp_core::TailscaleNodeId>()
                    .is_err()
                || !peers.insert(candidate.peer_node.as_str())
                || !grants.insert(candidate.request.grant_id.as_str())
                || candidate.request.scope != first.scope
                || candidate.request.root_object_id != first.root_object_id
                || candidate.request.limits != first.limits
            {
                return Err(invalid(
                    "state recovery requires distinct donors and grants for one exact scope, root and set of limits",
                ));
            }
        }
        Ok(())
    }
}

/// Outcome of a donor download, not a claim about connector execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStateRecoveryOutcome {
    /// Download, page validation, or current transport authority failed.
    DownloadFailed,
    /// This donor's entire download exceeded its attempt deadline.
    DownloadDeadline,
    /// The complete export passed import and was retained in the replica store.
    Retained,
}

/// Bounded, redaction-safe account of one attempted donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateRecoveryAttempt {
    /// Operator-selected donor, not a donor-supplied URL or identity.
    pub peer_node: String,
    /// Exact local import grant associated with this donor.
    pub grant_id: String,
    /// No provider-controlled error strings or state bytes are included.
    pub outcome: ConnectorStateRecoveryOutcome,
}

/// Successful replica-only recovery, including the selected donor's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateRecoveryResponse {
    /// Always `CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION`.
    pub schema_version: String,
    /// Nonempty prefix of the requested donors; only the final entry retained.
    pub attempts: Vec<ConnectorStateRecoveryAttempt>,
    /// Ordinary exact-root receipt, binding the successful peer and grant.
    pub replica: ConnectorStatePullResponse,
}

impl ConnectorStateReplicationService {
    /// Validate EVERY candidate's local grant before any network traffic.
    ///
    /// # Errors
    /// Rejects malformed plans or any candidate lacking exact import authority.
    pub fn validate_recovery(&self, request: &ConnectorStateRecoveryRequest) -> HostResult<()> {
        request.validate()?;
        for candidate in &request.candidates {
            self.validate_pull(candidate)?;
        }
        Ok(())
    }

    /// Download from independently authorized donors in order, then import once.
    ///
    /// The fetcher receives a candidate index and one bounded page request. It
    /// MUST use a new signed nonce and return only a successful, authenticated
    /// reply from that candidate's pinned transport incarnation. The authority
    /// callback MUST recheck that same incarnation, including at publication.
    /// Neither callback may perform a local replica import itself.
    ///
    /// Failed downloads discard all partial bytes before the next donor starts.
    /// The next attempt starts at offset zero with no inherited digest. Quotas
    /// apply independently to each download; total work is bounded by eight
    /// attempts and one overall deadline. Admission saturation fails fast rather
    /// than trying another peer to evade the service's shared resource limits.
    /// While a download is pending, local grant and pinned transport authority
    /// are checked before and after every read poll, including wake-ups between
    /// timer ticks. An owned 100 ms timer also checks never-waking reads.
    /// Revocation discards that download before trying the next independently
    /// authorized donor.
    ///
    /// Once import starts, no failure is retryable here, even when it appears to
    /// be validation-only. Timeout/cancellation during import may leave admitted
    /// persistent work running under the existing store contract. A caller must
    /// inspect replica state, not automatically retry an ambiguous operation.
    /// The total budget includes initial validation and fences the final result,
    /// including an import that returns ready after consuming its deadline.
    /// Timers cannot preempt blocking work inside a single future poll; late
    /// results are rejected when control returns, without claiming rollback.
    ///
    /// # Errors
    /// Rejects invalid authority, exhausted downloads, resource saturation, total
    /// deadline expiry, and all ordinary replica validation/publication failures.
    pub async fn recover_from_peers<F, Fut, A>(
        &self,
        request: &ConnectorStateRecoveryRequest,
        mut fetch_page: F,
        authorize_transport: A,
    ) -> HostResult<ConnectorStateRecoveryResponse>
    where
        F: FnMut(usize, String) -> Fut,
        Fut: Future<Output = HostResult<String>>,
        A: Fn(usize) -> HostResult<()> + Send + Sync,
    {
        let started = Instant::now();
        self.validate_recovery(request)?;
        let total_budget = Duration::from_millis(request.total_timeout_ms);
        let attempt_budget = Duration::from_millis(request.attempt_timeout_ms);
        let recovery = async {
            let mut attempts = Vec::with_capacity(request.candidates.len());
            for (index, candidate) in request.candidates.iter().enumerate() {
                check_deadline(started, total_budget)?;
                // Recheck local authority after prior attempts and before new
                // admission. A malformed/expired local grant is not a retry hint.
                self.validate_pull(candidate)?;
                let permit = self
                    .runtime
                    .admit(&candidate.peer_node, candidate.request.limits)?;
                let attempt_started = Instant::now();
                let download = self.download_paged_admitted(
                    candidate,
                    |wire| fetch_page(index, wire),
                    || {
                        authorize_transport(index)?;
                        check_deadline(started, total_budget)?;
                        check_deadline(attempt_started, attempt_budget)
                    },
                    &permit,
                );
                let download = read_while_authorized(download, || {
                    self.validate_pull(candidate)?;
                    authorize_transport(index)
                });
                let downloaded = within_recovery_budget(
                    attempt_started, attempt_budget, download,
                ).await;
                // Ready futures and synchronous callbacks need not yield to a
                // timer. Fence admission explicitly as well as timing out waits.
                check_deadline(started, total_budget)?;
                let outcome = match downloaded {
                    Ok(Ok(wire)) if attempt_started.elapsed() < attempt_budget => {
                        // Deliberately outside the retryable download result.
                        // Keep this SAME permit until import ends or is dropped.
                        let replica = self
                            .import_admitted(
                                candidate,
                                &wire,
                                || {
                                    authorize_transport(index)?;
                                    check_deadline(started, total_budget)
                                },
                                &permit,
                            )
                            .await?;
                        attempts.push(attempt(candidate, ConnectorStateRecoveryOutcome::Retained));
                        return Ok(ConnectorStateRecoveryResponse {
                            schema_version: CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION.to_owned(),
                            attempts,
                            replica,
                        });
                    }
                    Ok(Err(_)) if attempt_started.elapsed() < attempt_budget => {
                        ConnectorStateRecoveryOutcome::DownloadFailed
                    }
                    _ => ConnectorStateRecoveryOutcome::DownloadDeadline,
                };
                // The failed future (and its assembly) is gone before its permit
                // is released. No retained bytes escape into the next attempt.
                drop(permit);
                tracing::warn!(
                    event = "fcp.connector_state.recovery_download_failed",
                    peer = %candidate.peer_node,
                    attempt = index + 1,
                    outcome = ?outcome,
                    "discarded a failed state download before replica import"
                );
                attempts.push(attempt(candidate, outcome));
            }
            Err(HostError::Unavailable(
                "no configured donor supplied a complete state export; no replica import was attempted".to_owned(),
            ))
        };
        within_recovery_budget(started, total_budget, recovery)
            .await
            .map_err(|_| deadline_error())?
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecoveryBudgetElapsed;

/// Use the caller's original elapsed budget, not a fresh budget at first poll.
/// The clock-injected core permits deterministic ready/pending boundary tests.
pub(super) async fn within_recovery_budget<F: Future>(
    started: Instant,
    budget: Duration,
    future: F,
) -> Result<F::Output, RecoveryBudgetElapsed> {
    within_recovery_budget_at(budget, || started.elapsed(), future).await
}

async fn within_recovery_budget_at<F, N>(
    budget: Duration,
    elapsed: N,
    future: F,
) -> Result<F::Output, RecoveryBudgetElapsed>
where
    F: Future,
    N: Fn() -> Duration,
{
    let remaining = budget
        .checked_sub(elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RecoveryBudgetElapsed)?;
    let mut future = pin!(future);
    let guarded = poll_fn(|cx| {
        if elapsed() >= budget {
            return Poll::Ready(Err(RecoveryBudgetElapsed));
        }
        let outcome = future.as_mut().poll(cx);
        // A synchronous callback or ready storage operation can exhaust the
        // budget without giving the timeout future another poll. A pending
        // result can do the same without registering any wake-up at all.
        if elapsed() >= budget {
            return Poll::Ready(Err(RecoveryBudgetElapsed));
        }
        outcome.map(Ok)
    });
    fcp_async_core::time::timeout(remaining, guarded)
        .await
        .map_err(|_| RecoveryBudgetElapsed)?
}

/// Guard read-only transfer work, never replica publication. The same future
/// survives timer ticks; neither requests nor deadlines are restarted. Every
/// poll is fenced, including a network wake-up before the next timer tick.
/// A denied post-poll check withholds either a ready value or a pending read;
/// it cannot preempt synchronous work within that poll or undo admitted work.
pub(super) async fn read_while_authorized<F, T, A>(read: F, authorize: A) -> HostResult<T>
where
    F: Future<Output = HostResult<T>>,
    A: Fn() -> HostResult<()>,
{
    read_while_authorized_with_tick(read, authorize, || {
        fcp_async_core::time::sleep(RECOVERY_AUTHORITY_RECHECK_INTERVAL)
    })
    .await
}

async fn read_while_authorized_with_tick<F, T, A, W, Tick>(
    read: F,
    authorize: A,
    mut next_tick: W,
) -> HostResult<T>
where
    F: Future<Output = HostResult<T>>,
    A: Fn() -> HostResult<()>,
    W: FnMut() -> Tick,
    Tick: Future<Output = ()>,
{
    let mut read = pin!(read);
    let guarded = poll_fn(|cx| {
        if let Err(error) = authorize() {
            return Poll::Ready(Err(error));
        }
        let outcome = read.as_mut().poll(cx);
        if let Err(error) = authorize() {
            return Poll::Ready(Err(error));
        }
        outcome
    });
    let mut guarded = pin!(guarded);
    loop {
        authorize()?;
        let tick = pin!(next_tick());
        // Poll the timer first so its deadline is anchored before potentially
        // expensive work in the read. Both futures remain owned by this scope.
        match select(tick, guarded.as_mut()).await {
            Either::Left(_) => {}
            Either::Right((result, _)) => {
                authorize()?;
                return result;
            }
        }
    }
}

fn check_deadline(started: Instant, budget: Duration) -> HostResult<()> {
    if started.elapsed() >= budget {
        Err(deadline_error())
    } else {
        Ok(())
    }
}

fn deadline_error() -> HostError {
    HostError::Unavailable(
        "state-recovery total deadline elapsed; an admitted durable write may still complete"
            .to_owned(),
    )
}

fn attempt(
    candidate: &ConnectorStatePullRequest,
    outcome: ConnectorStateRecoveryOutcome,
) -> ConnectorStateRecoveryAttempt {
    ConnectorStateRecoveryAttempt {
        peer_node: candidate.peer_node.clone(),
        grant_id: candidate.request.grant_id.clone(),
        outcome,
    }
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}

#[cfg(test)]
#[path = "connector_state_recovery_tests.rs"]
mod tests;

#[cfg(test)]
mod budget_tests {
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use super::*;

    struct MarkDropped<'a>(&'a AtomicBool);

    impl Drop for MarkDropped<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn revoked() -> HostError {
        HostError::PreflightFailed("fixture donor authority revoked".to_owned())
    }

    #[fcp_async_core::runtime::test]
    async fn exhausted_budget_never_polls_work_and_drops_its_custody() {
        let polled = AtomicUsize::new(0);
        let dropped = AtomicBool::new(false);
        let guard = MarkDropped(&dropped);
        let work = async {
            let _guard = guard;
            polled.fetch_add(1, Ordering::SeqCst);
            42
        };
        let result = within_recovery_budget_at(
            Duration::from_millis(10),
            || Duration::from_millis(10),
            work,
        ).await;
        assert_eq!(result, Err(RecoveryBudgetElapsed));
        assert_eq!(polled.load(Ordering::SeqCst), 0);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn unexpired_budget_preserves_success_and_failure_values() {
        let success = within_recovery_budget_at(
            Duration::from_secs(1), || Duration::ZERO, async { Ok::<_, u8>(42) },
        ).await;
        let failure = within_recovery_budget_at(
            Duration::from_secs(1), || Duration::ZERO, async { Err::<u8, _>(7) },
        ).await;
        assert_eq!(success, Ok(Ok(42)));
        assert_eq!(failure, Ok(Err(7)));
    }

    #[fcp_async_core::runtime::test]
    async fn ready_import_result_after_the_deadline_is_not_a_success() {
        let elapsed_ms = AtomicU64::new(0);
        let result = within_recovery_budget_at(
            Duration::from_millis(10),
            || Duration::from_millis(elapsed_ms.load(Ordering::SeqCst)),
            async {
                // Model an admitted write returning ready after a long poll.
                // Its completion cannot be undone by rejecting this receipt.
                elapsed_ms.store(10, Ordering::SeqCst);
                Ok::<_, HostError>("retained")
            },
        ).await;
        assert!(matches!(result, Err(RecoveryBudgetElapsed)));
    }

    #[fcp_async_core::runtime::test]
    async fn pending_poll_that_exhausts_budget_needs_no_wake_to_be_rejected() {
        let elapsed_ms = AtomicU64::new(0);
        let polls = AtomicUsize::new(0);
        let work = poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            elapsed_ms.store(11, Ordering::SeqCst);
            Poll::<u8>::Pending
        });
        let result = within_recovery_budget_at(
            Duration::from_millis(10),
            || Duration::from_millis(elapsed_ms.load(Ordering::SeqCst)),
            work,
        ).await;
        assert_eq!(result, Err(RecoveryBudgetElapsed));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn real_deadline_drops_a_never_waking_child() {
        let dropped = AtomicBool::new(false);
        let guard = MarkDropped(&dropped);
        let work = async {
            let _guard = guard;
            pending::<u8>().await
        };
        let result = within_recovery_budget(
            Instant::now(), Duration::from_millis(10), work,
        ).await;
        assert_eq!(result, Err(RecoveryBudgetElapsed));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn authority_denial_precedes_the_first_download_poll() {
        let polls = AtomicUsize::new(0);
        let result = read_while_authorized(
            async {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            },
            || Err(revoked()),
        ).await;
        assert!(matches!(result, Err(HostError::PreflightFailed(_))));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn authority_is_rechecked_after_a_ready_download() {
        let allowed = AtomicBool::new(true);
        let result = read_while_authorized(
            async {
                allowed.store(false, Ordering::SeqCst);
                Ok("private-state")
            },
            || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
        ).await;
        let error = result.unwrap_err();
        assert!(matches!(error, HostError::PreflightFailed(_)));
        assert!(!error.to_string().contains("private-state"));
    }

    #[fcp_async_core::runtime::test]
    async fn revoked_never_waking_donor_is_abandoned_before_its_attempt_deadline() {
        let allowed = AtomicBool::new(true);
        let dropped = AtomicBool::new(false);
        let polls = AtomicUsize::new(0);
        let guard = MarkDropped(&dropped);
        let work = async {
            let _guard = guard;
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                allowed.store(false, Ordering::SeqCst);
                // No wake: the post-poll authority fence must reject this now.
                Poll::<HostResult<u8>>::Pending
            }).await
        };
        let result = within_recovery_budget(
            Instant::now(),
            Duration::from_secs(5),
            read_while_authorized(work, || {
                if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) }
            }),
        ).await;
        assert!(matches!(result, Ok(Err(HostError::PreflightFailed(_)))));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn cancelling_authority_watch_drops_its_original_read() {
        let dropped = AtomicBool::new(false);
        let guard = MarkDropped(&dropped);
        let work = async {
            let _guard = guard;
            pending::<HostResult<u8>>().await
        };
        let mut watched = Box::pin(read_while_authorized(work, || Ok(())));
        assert!(futures_util::poll!(watched.as_mut()).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));
        drop(watched);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn budget_and_authority_futures_are_send_with_send_inputs() {
        fn assert_send<T: Send>(_: &T) {}
        let watched = read_while_authorized(async { Ok::<_, HostError>(42) }, || Ok(()));
        assert_send(&watched);
        let bounded = within_recovery_budget(Instant::now(), Duration::from_secs(1), watched);
        assert_send(&bounded);
    }

    #[fcp_async_core::runtime::test]
    async fn revoked_read_cannot_resume_between_authority_ticks() {
        let allowed = AtomicBool::new(true);
        let polls = AtomicUsize::new(0);
        let dropped = AtomicBool::new(false);
        let guard = MarkDropped(&dropped);
        let read = async {
            let _guard = guard;
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                Poll::<HostResult<()>>::Pending
            })
            .await
        };
        let mut watched = Box::pin(read_while_authorized_with_tick(
            read,
            || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
            pending::<()>,
        ));
        assert!(futures_util::poll!(watched.as_mut()).is_pending());
        allowed.store(false, Ordering::SeqCst);
        // Simulate a socket wake before the timer, which never fires here.
        assert!(matches!(
            futures_util::poll!(watched.as_mut()),
            Poll::Ready(Err(HostError::PreflightFailed(_)))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn revocation_inside_a_pending_poll_does_not_wait_for_a_tick() {
        let allowed = AtomicBool::new(true);
        let polls = AtomicUsize::new(0);
        let read = poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            allowed.store(false, Ordering::SeqCst);
            Poll::<HostResult<()>>::Pending
        });
        let mut watched = Box::pin(read_while_authorized_with_tick(
            read,
            || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
            pending::<()>,
        ));
        assert!(matches!(
            futures_util::poll!(watched.as_mut()),
            Poll::Ready(Err(HostError::PreflightFailed(_)))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn timer_ticks_keep_the_same_read_and_drop_it_on_independent_revocation() {
        let allowed = AtomicBool::new(true);
        let tick_ready = AtomicBool::new(false);
        let trigger = &tick_ready;
        let tick_count = AtomicUsize::new(0);
        let read_starts = AtomicUsize::new(0);
        let dropped = AtomicBool::new(false);
        let guard = MarkDropped(&dropped);
        let read = async {
            let _guard = guard;
            read_starts.fetch_add(1, Ordering::SeqCst);
            pending::<HostResult<()>>().await
        };
        let mut watched = Box::pin(read_while_authorized_with_tick(
            read,
            || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
            || {
                tick_count.fetch_add(1, Ordering::SeqCst);
                poll_fn(move |_| {
                    if trigger.swap(false, Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
            },
        ));
        assert!(futures_util::poll!(watched.as_mut()).is_pending());
        tick_ready.store(true, Ordering::SeqCst);
        assert!(futures_util::poll!(watched.as_mut()).is_pending());
        assert_eq!(tick_count.load(Ordering::SeqCst), 2);
        assert_eq!(read_starts.load(Ordering::SeqCst), 1);
        assert!(!dropped.load(Ordering::SeqCst));
        allowed.store(false, Ordering::SeqCst);
        tick_ready.store(true, Ordering::SeqCst);
        assert!(matches!(
            futures_util::poll!(watched.as_mut()),
            Poll::Ready(Err(HostError::PreflightFailed(_)))
        ));
        assert_eq!(read_starts.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn authority_changed_by_tick_construction_prevents_read_admission() {
        let allowed = AtomicBool::new(true);
        let polls = AtomicUsize::new(0);
        let mut watched = Box::pin(read_while_authorized_with_tick(
            async {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
            || {
                allowed.store(false, Ordering::SeqCst);
                pending::<()>()
            },
        ));
        assert!(matches!(
            futures_util::poll!(watched.as_mut()),
            Poll::Ready(Err(HostError::PreflightFailed(_)))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn read_errors_are_preserved_only_while_authority_is_current() {
        for revoke in [false, true] {
            let allowed = AtomicBool::new(true);
            let result = read_while_authorized_with_tick(
                async {
                    allowed.store(!revoke, Ordering::SeqCst);
                    Err::<(), _>(HostError::Unavailable("private diagnostic".to_owned()))
                },
                || if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err(revoked()) },
                pending::<()>,
            )
            .await;
            if revoke {
                let error = result.unwrap_err();
                assert!(matches!(error, HostError::PreflightFailed(_)));
                assert!(!error.to_string().contains("private diagnostic"));
            } else {
                assert!(matches!(result, Err(HostError::Unavailable(message)) if message == "private diagnostic"));
            }
        }
    }
}
