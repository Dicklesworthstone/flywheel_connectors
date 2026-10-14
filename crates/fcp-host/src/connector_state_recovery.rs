//! Bounded recovery of one exact state root from independently granted donors.
//!
//! Only downloading is retryable. Every attempt owns its own page assembly and
//! resource reservation. Once a complete export enters import, ANY error or
//! cancellation is terminal: a durable write may already have been admitted.

use std::collections::HashSet;
use std::future::Future;
use std::time::{Duration, Instant};

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
    MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES * (MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES + 1024) + 1024;
/// Hard deadline covering all downloads and the single import attempt.
pub const MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS: u64 = 60_000;

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
            return Err(invalid("invalid state-recovery donor count or deadline budget"));
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
                || candidate.peer_node.parse::<fcp_core::TailscaleNodeId>().is_err()
                || !peers.insert(candidate.peer_node.as_str())
                || !grants.insert(candidate.request.grant_id.as_str())
                || candidate.request.scope != first.scope
                || candidate.request.root_object_id != first.root_object_id
                || candidate.request.limits != first.limits
            {
                return Err(invalid("state recovery requires distinct donors and grants for one exact scope, root and set of limits"));
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
    ///
    /// Once import starts, no failure is retryable here, even when it appears to
    /// be validation-only. Timeout/cancellation during import may leave admitted
    /// persistent work running under the existing store contract. A caller must
    /// inspect replica state, not automatically retry an ambiguous operation.
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
        self.validate_recovery(request)?;
        let started = Instant::now();
        let total_budget = Duration::from_millis(request.total_timeout_ms);
        let attempt_budget = Duration::from_millis(request.attempt_timeout_ms);
        let recovery = async {
            let mut attempts = Vec::with_capacity(request.candidates.len());
            for (index, candidate) in request.candidates.iter().enumerate() {
                check_deadline(started, total_budget)?;
                // Recheck local authority after prior attempts and before new
                // admission. A malformed/expired local grant is not a retry hint.
                self.validate_pull(candidate)?;
                let permit = self.runtime.admit(&candidate.peer_node, candidate.request.limits)?;
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
                let downloaded = fcp_async_core::time::timeout(attempt_budget, download).await;
                // Ready futures and synchronous callbacks need not yield to a
                // timer. Fence admission explicitly as well as timing out waits.
                check_deadline(started, total_budget)?;
                let outcome = match downloaded {
                    Ok(Ok(wire)) if attempt_started.elapsed() < attempt_budget => {
                        // Deliberately outside the retryable download result.
                        // Keep this SAME permit until import ends or is dropped.
                        let replica = self
                            .import_admitted(candidate, &wire, || {
                                authorize_transport(index)?;
                                check_deadline(started, total_budget)
                            }, &permit)
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
        fcp_async_core::time::timeout(total_budget, recovery)
            .await
            .map_err(|_| deadline_error())?
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
        "state-recovery total deadline elapsed; an admitted durable write may still complete".to_owned(),
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
