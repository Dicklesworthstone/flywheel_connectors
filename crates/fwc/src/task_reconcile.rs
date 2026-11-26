//! Verify retained invocation evidence for one durably bound saved-task step.
//!
//! The caller reads the protected invocation API on the bound host. This module
//! neither sends an invocation nor recovers a result body. Pin the first matching
//! journal and attempt before examining completion so later observations cannot
//! silently switch to newer history, even after an active or unknown outcome.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use fcp_host::{
    InvocationIdempotency, InvocationOutcome, InvocationQueryResponse, InvocationRecord,
    MeshInvocationIdentity, MeshInvocationObservation, MeshInvocationOutcome, MeshInvocationRecord,
};
use fcp_kernel::InvokeStatus;
use serde::{Deserialize, Serialize};

/// Payload-free identity synced after preflight and before an actual invoke.
/// The transport binding commits to the exact token, idempotency key and
/// effect-affecting request without treating a token subject hint as authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskInvocationBinding {
    pub request_id: String,
    pub host: String,
    pub connector_id: String,
    pub operation: String,
    pub zone_id: String,
    pub principal: Option<String>,
    pub transport_idempotency: fcp_host::InvocationIdempotency,
}

const MAX_METADATA_BYTES: usize = 512;
const MAX_MESH_TARGETS: usize = 256;

/// The selected host journal, distinct from the invocation's result class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskInvocationSource {
    /// The selected host executed the invocation locally.
    Local,
    /// The selected host retained custody of a mesh forward.
    Mesh,
}

/// Immutable selection captured even when completion remains uncertain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInvocationAttempt {
    /// Which journal produced the observation.
    pub source: TaskInvocationSource,
    /// Positive host-assigned attempt generation.
    pub attempt_id: u64,
}

/// What a successful reconciliation actually proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskInvocationCompletionSource {
    /// Local execution and its required finalization completed successfully.
    LocalFinalized,
    /// The entry host durably observed a matching successful mesh response.
    /// This is not proof of executor-global finalization or a cached result.
    MeshOriginObserved,
}

/// Payload-free completion evidence retained by a saved task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInvocationCompletion {
    /// Scope of the completion claim.
    pub source: TaskInvocationCompletionSource,
    /// Exact attempt selected before completion was accepted.
    pub attempt_id: u64,
    /// Time the host admitted that attempt.
    pub admitted_at: DateTime<Utc>,
    /// Time the host recorded its terminal observation.
    pub finished_at: DateTime<Utc>,
    /// Optional connector receipt reference, never its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Local audit reference when full local finalization was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<String>,
}

impl TaskInvocationCompletion {
    /// Recover the immutable observation selection this completion belongs to.
    #[must_use]
    pub const fn attempt(&self) -> TaskInvocationAttempt {
        TaskInvocationAttempt {
            source: match self.source {
                TaskInvocationCompletionSource::LocalFinalized => TaskInvocationSource::Local,
                TaskInvocationCompletionSource::MeshOriginObserved => TaskInvocationSource::Mesh,
            },
            attempt_id: self.attempt_id,
        }
    }
}

/// A refusal to infer saved-task completion. None of these permits replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileFailure {
    /// The saved request binding or pinned attempt is malformed.
    InvalidBinding,
    /// The lookup host is not the exact canonical host recorded before send.
    WrongHost,
    /// This host no longer retains matching invocation evidence.
    MissingEvidence,
    /// The response contains competing local and mesh records.
    ConflictingEvidence,
    /// A later observation changed the pinned attempt or journal.
    AttemptChanged,
    /// Request identity or a known verified principal does not match.
    IdentityMismatch,
    /// The exact-token key/effect binding is missing or differs.
    EffectBindingMismatch,
    /// Retained evidence is internally inconsistent.
    InvalidHistory,
    /// The selected host still owns an unfinished job for this request.
    ActiveHostJob,
    /// The selected record does not establish crash-durable history.
    NonDurable,
    /// A matching record has no terminal completion observation.
    IncompleteEvidence,
    /// The retained source or final response did not establish success.
    UnsuccessfulOutcome,
    /// Required accounting, audit, receipt, response, or child evidence is absent.
    IncompleteFinalization,
}

impl ReconcileFailure {
    /// Stable machine-readable reason without host or request-controlled text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "invalid-task-invocation-binding",
            Self::WrongHost => "task-invocation-host-mismatch",
            Self::MissingEvidence => "task-invocation-history-unavailable",
            Self::ConflictingEvidence => "task-invocation-history-conflict",
            Self::AttemptChanged => "task-invocation-attempt-changed",
            Self::IdentityMismatch => "task-invocation-identity-mismatch",
            Self::EffectBindingMismatch => "task-invocation-effects-mismatch",
            Self::InvalidHistory => "task-invocation-history-invalid",
            Self::ActiveHostJob => "task-invocation-still-active",
            Self::NonDurable => "task-invocation-history-not-durable",
            Self::IncompleteEvidence => "task-invocation-completion-unobserved",
            Self::UnsuccessfulOutcome => "task-invocation-not-successful",
            Self::IncompleteFinalization => "task-invocation-finalization-incomplete",
        }
    }

    /// Fixed diagnostic suitable for task output; it never echoes evidence data.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "The saved invocation binding or attempt pin is invalid.",
            Self::WrongHost => {
                "Invocation evidence must come from the host recorded before dispatch."
            }
            Self::MissingEvidence => {
                "The selected invocation history is unavailable; missing history does not prove \
                 that the operation had no effects."
            }
            Self::ConflictingEvidence => {
                "The host returned competing local and mesh invocation evidence."
            }
            Self::AttemptChanged => {
                "The retained invocation changed its pinned journal or attempt; a newer attempt \
                 cannot resolve the original one."
            }
            Self::IdentityMismatch => {
                "The retained invocation does not match the saved request identity."
            }
            Self::EffectBindingMismatch => {
                "The retained invocation lacks the exact saved transport and effect binding."
            }
            Self::InvalidHistory => "The retained invocation evidence is internally inconsistent.",
            Self::ActiveHostJob => {
                "The host still owns an unfinished invocation job; completion remains unproven."
            }
            Self::NonDurable => {
                "The invocation record does not establish durable completion across host failure."
            }
            Self::IncompleteEvidence => {
                "The retained invocation has no terminal completion observation."
            }
            Self::UnsuccessfulOutcome => {
                "The retained invocation does not establish a successful final response."
            }
            Self::IncompleteFinalization => {
                "The retained invocation lacks complete accounting, audit, receipt, response, \
                 or child finalization evidence."
            }
        }
    }
}

impl std::fmt::Display for ReconcileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ReconcileFailure {}

/// Bind an observation without inferring completion or authorizing another send.
///
/// Both host strings must already use the administrative client's canonical
/// endpoint. A missing previous pin allows one positive attempt to be selected;
/// the caller must persist the returned pin before accepting later observations.
/// Active, non-durable, and explicitly unknown records can still establish a
/// pin. They cannot establish completion.
///
/// # Errors
/// Refuses missing, conflicting, malformed, or differently bound evidence and
/// any change to a previously pinned attempt or local/mesh journal.
pub fn bind_observation(
    binding: &TaskInvocationBinding,
    selected_host: &str,
    expected: Option<&TaskInvocationAttempt>,
    response: &InvocationQueryResponse,
) -> Result<TaskInvocationAttempt, ReconcileFailure> {
    if !valid_binding(binding) || expected.is_some_and(|pin| pin.attempt_id == 0) {
        return Err(ReconcileFailure::InvalidBinding);
    }
    if binding.host != selected_host {
        return Err(ReconcileFailure::WrongHost);
    }
    let selected = match (&response.invocation, &response.mesh_invocation) {
        (Some(record), None) => {
            validate_local_binding(binding, record)?;
            TaskInvocationAttempt {
                source: TaskInvocationSource::Local,
                attempt_id: record.ticket.attempt_id,
            }
        }
        (None, Some(record)) => {
            validate_mesh_binding(binding, record)?;
            TaskInvocationAttempt {
                source: TaskInvocationSource::Mesh,
                attempt_id: record.ticket.attempt_id,
            }
        }
        (None, None) => return Err(ReconcileFailure::MissingEvidence),
        (Some(_), Some(_)) => return Err(ReconcileFailure::ConflictingEvidence),
    };
    if selected.attempt_id == 0 {
        return Err(ReconcileFailure::InvalidHistory);
    }
    if expected.is_some_and(|pin| *pin != selected) {
        return Err(ReconcileFailure::AttemptChanged);
    }
    Ok(selected)
}

/// Verify success for an already pinned observation without reconstructing output.
///
/// Local success requires explicit final response and accounting decisions;
/// historical records lacking those markers remain uncertain. Mesh success is
/// deliberately labeled as a durable origin observation of the validated final
/// response, not executor-global finalization. The enclosing task determines
/// whether all remaining steps also have completion evidence.
///
/// # Errors
/// Refuses a binding change, active owner, non-durable history, unknown or failed
/// outcome, incomplete local finalization, or inconsistent mesh target history.
pub fn verify_completion(
    binding: &TaskInvocationBinding,
    selected_host: &str,
    expected: &TaskInvocationAttempt,
    response: &InvocationQueryResponse,
) -> Result<TaskInvocationCompletion, ReconcileFailure> {
    bind_observation(binding, selected_host, Some(expected), response)?;
    if response.host_job_active {
        return Err(ReconcileFailure::ActiveHostJob);
    }
    match (&response.invocation, &response.mesh_invocation) {
        (Some(record), None) => verify_local_completion(record),
        (None, Some(record)) => verify_mesh_completion(record),
        _ => Err(ReconcileFailure::ConflictingEvidence),
    }
}

fn valid_metadata(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_METADATA_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_idempotency(binding: &InvocationIdempotency) -> bool {
    valid_digest(&binding.scope_digest) && valid_digest(&binding.effect_digest)
}

fn valid_binding(binding: &TaskInvocationBinding) -> bool {
    [
        binding.request_id.as_str(),
        binding.connector_id.as_str(),
        binding.operation.as_str(),
        binding.zone_id.as_str(),
    ]
    .into_iter()
    .all(valid_metadata)
        && !binding.host.trim().is_empty()
        && !binding.host.chars().any(char::is_control)
        && binding.principal.as_deref().is_none_or(valid_metadata)
        && valid_idempotency(&binding.transport_idempotency)
}

fn validate_local_binding(
    binding: &TaskInvocationBinding,
    record: &InvocationRecord,
) -> Result<(), ReconcileFailure> {
    let admission = &record.admission;
    if record.ticket.operation_id != binding.request_id
        || admission.operation_id != binding.request_id
        || admission.connector_id != binding.connector_id
        || admission.operation != binding.operation
        || admission.zone_id != binding.zone_id
        || !valid_metadata(&admission.principal)
        || binding
            .principal
            .as_ref()
            .is_some_and(|principal| *principal != admission.principal)
    {
        return Err(ReconcileFailure::IdentityMismatch);
    }
    if admission.transport_idempotency.as_ref() != Some(&binding.transport_idempotency) {
        return Err(ReconcileFailure::EffectBindingMismatch);
    }
    if admission
        .idempotency
        .as_ref()
        .is_none_or(|value| !valid_idempotency(value))
        || admission.deadline_at <= record.admitted_at
        || record.terminal.is_some() != record.finished_at.is_some()
        || record
            .finished_at
            .is_some_and(|finished| finished < record.admitted_at)
        || (record.finalization.is_some() && record.terminal.is_none())
        || record.terminal.as_ref().is_some_and(|terminal| {
            !(100..=599).contains(&terminal.http_status)
                || terminal
                    .receipt_id
                    .as_deref()
                    .is_some_and(|id| !valid_metadata(id))
        })
        || record.finalization.as_ref().is_some_and(|finalization| {
            finalization
                .audit_event_id
                .as_deref()
                .is_some_and(|id| !valid_metadata(id))
                || finalization
                    .sampling_operation_id
                    .as_deref()
                    .is_some_and(|id| !valid_metadata(id) || id == binding.request_id)
                || finalization
                    .response_http_status
                    .is_some_and(|status| !(100..=599).contains(&status))
                || (finalization.sampling_completed == Some(true)
                    && finalization.sampling_operation_id.is_none())
        })
    {
        return Err(ReconcileFailure::InvalidHistory);
    }
    Ok(())
}

fn validate_mesh_binding(
    binding: &TaskInvocationBinding,
    record: &MeshInvocationRecord,
) -> Result<(), ReconcileFailure> {
    let intent = &record.intent;
    if record.ticket.operation_id != binding.request_id
        || intent.operation_id != binding.request_id
        || intent.connector_id != binding.connector_id
        || intent.operation != binding.operation
        || intent.zone_id != binding.zone_id
    {
        return Err(ReconcileFailure::IdentityMismatch);
    }
    let transport = match &intent.identity {
        MeshInvocationIdentity::VerifiedPrincipal { principal } => {
            if !valid_metadata(principal)
                || binding
                    .principal
                    .as_ref()
                    .is_some_and(|expected| expected != principal)
            {
                return Err(ReconcileFailure::IdentityMismatch);
            }
            if intent
                .idempotency
                .as_ref()
                .is_none_or(|value| !valid_idempotency(value))
            {
                return Err(ReconcileFailure::InvalidHistory);
            }
            intent.transport_idempotency.as_ref()
        }
        MeshInvocationIdentity::TokenBoundRelay {
            capability_digest,
            asserted_principal,
        } => {
            // Saved-task invokes send no asserted-principal header. A decoded
            // caller hint is already bound by the exact opaque capability, but
            // this relay record does not establish a verified principal.
            if asserted_principal.is_some() {
                return Err(ReconcileFailure::IdentityMismatch);
            }
            if !valid_digest(capability_digest) || intent.transport_idempotency.is_some() {
                return Err(ReconcileFailure::InvalidHistory);
            }
            intent.idempotency.as_ref()
        }
    };
    if transport != Some(&binding.transport_idempotency) {
        return Err(ReconcileFailure::EffectBindingMismatch);
    }
    validate_mesh_history(record)
}

fn validate_mesh_history(record: &MeshInvocationRecord) -> Result<(), ReconcileFailure> {
    if !valid_metadata(&record.intent.origin_node)
        || !valid_metadata(&record.intent.target_node)
        || record.intent.deadline_at <= record.admitted_at
        || record.terminal.is_some() != record.finished_at.is_some()
        || record
            .finished_at
            .is_some_and(|finished| finished < record.admitted_at)
        || record.attempts.is_empty()
        || record.attempts.len() > MAX_MESH_TARGETS
        || record.attempts[0].target_node != record.intent.target_node
    {
        return Err(ReconcileFailure::InvalidHistory);
    }
    let mut targets = HashSet::with_capacity(record.attempts.len());
    let mut selected_at = record.admitted_at;
    for (index, attempt) in record.attempts.iter().enumerate() {
        if !valid_metadata(&attempt.target_node)
            || !targets.insert(attempt.target_node.as_str())
            || attempt.selected_at < selected_at
            || record
                .finished_at
                .is_some_and(|finished| attempt.selected_at > finished)
            || matches!(
                attempt.observation.as_ref(),
                Some(MeshInvocationObservation::ResponseObserved { http_status })
                    if !(100..=599).contains(http_status)
            )
            || (index + 1 < record.attempts.len()
                && attempt.observation != Some(MeshInvocationObservation::NotDelivered))
        {
            return Err(ReconcileFailure::InvalidHistory);
        }
        selected_at = attempt.selected_at;
    }
    if let Some(terminal) = &record.terminal {
        if !(100..=599).contains(&terminal.http_status)
            || terminal
                .receipt_id
                .as_deref()
                .is_some_and(|id| !valid_metadata(id))
        {
            return Err(ReconcileFailure::InvalidHistory);
        }
        match terminal.outcome {
            MeshInvocationOutcome::Succeeded | MeshInvocationOutcome::ConnectorError => {
                if !(200..300).contains(&terminal.http_status)
                    || !record.attempts.last().is_some_and(|attempt| {
                        matches!(
                            attempt.observation.as_ref(),
                            Some(MeshInvocationObservation::ResponseObserved { http_status })
                                if (200..300).contains(http_status)
                        )
                    })
                {
                    return Err(ReconcileFailure::InvalidHistory);
                }
            }
            MeshInvocationOutcome::NotDelivered => {
                if terminal.receipt_id.is_some()
                    || record.attempts.iter().any(|attempt| {
                        attempt.observation != Some(MeshInvocationObservation::NotDelivered)
                    })
                {
                    return Err(ReconcileFailure::InvalidHistory);
                }
            }
            MeshInvocationOutcome::OutcomeUnknown => {}
        }
    }
    Ok(())
}

fn verify_local_completion(
    record: &InvocationRecord,
) -> Result<TaskInvocationCompletion, ReconcileFailure> {
    if !record.durable {
        return Err(ReconcileFailure::NonDurable);
    }
    let terminal = record
        .terminal
        .as_ref()
        .ok_or(ReconcileFailure::IncompleteEvidence)?;
    let finished_at = record
        .finished_at
        .ok_or(ReconcileFailure::IncompleteEvidence)?;
    if terminal.outcome != InvocationOutcome::Succeeded
        || !(200..300).contains(&terminal.http_status)
    {
        return Err(ReconcileFailure::UnsuccessfulOutcome);
    }
    let finalization = record
        .finalization
        .as_ref()
        .ok_or(ReconcileFailure::IncompleteFinalization)?;
    if finalization
        .response_status
        .as_ref()
        .is_some_and(|status| *status != InvokeStatus::Ok)
    {
        return Err(ReconcileFailure::UnsuccessfulOutcome);
    }
    if !finalization.budget_finalized
        || finalization.response_status != Some(InvokeStatus::Ok)
        || !finalization
            .response_http_status
            .is_some_and(|status| (200..300).contains(&status))
        || finalization.audit_event_id.is_none()
        || (terminal.receipt_id.is_some() && !finalization.receipt_recorded)
        || finalization.sampling_completed == Some(false)
        || (finalization.sampling_operation_id.is_some()
            && finalization.sampling_completed != Some(true))
    {
        return Err(ReconcileFailure::IncompleteFinalization);
    }
    Ok(TaskInvocationCompletion {
        source: TaskInvocationCompletionSource::LocalFinalized,
        attempt_id: record.ticket.attempt_id,
        admitted_at: record.admitted_at,
        finished_at,
        receipt_id: terminal.receipt_id.clone(),
        audit_event_id: finalization.audit_event_id.clone(),
    })
}

fn verify_mesh_completion(
    record: &MeshInvocationRecord,
) -> Result<TaskInvocationCompletion, ReconcileFailure> {
    if !record.durable {
        return Err(ReconcileFailure::NonDurable);
    }
    let terminal = record
        .terminal
        .as_ref()
        .ok_or(ReconcileFailure::IncompleteEvidence)?;
    let finished_at = record
        .finished_at
        .ok_or(ReconcileFailure::IncompleteEvidence)?;
    if terminal.outcome != MeshInvocationOutcome::Succeeded {
        return Err(ReconcileFailure::UnsuccessfulOutcome);
    }
    Ok(TaskInvocationCompletion {
        source: TaskInvocationCompletionSource::MeshOriginObserved,
        attempt_id: record.ticket.attempt_id,
        admitted_at: record.admitted_at,
        finished_at,
        receipt_id: terminal.receipt_id.clone(),
        audit_event_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_host::{
        InvocationAdmission, InvocationFinalization, InvocationTerminal, InvocationTicket,
        MeshInvocationAttempt, MeshInvocationIntent, MeshInvocationTerminal,
    };

    fn binding() -> TaskInvocationBinding {
        TaskInvocationBinding {
            request_id: "task-attempt-salted-step-1".to_owned(),
            host: "https://host.example".to_owned(),
            connector_id: "fcp.github:enterprise:v1".to_owned(),
            operation: "github.create_issue".to_owned(),
            zone_id: "z:work".to_owned(),
            principal: Some("user:owner".to_owned()),
            transport_idempotency: InvocationIdempotency {
                scope_digest: "a".repeat(64),
                effect_digest: "b".repeat(64),
            },
        }
    }

    fn principal_binding() -> InvocationIdempotency {
        InvocationIdempotency {
            scope_digest: "c".repeat(64),
            effect_digest: "d".repeat(64),
        }
    }

    fn admitted_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-21T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn local_response(binding: &TaskInvocationBinding) -> InvocationQueryResponse {
        let admitted_at = admitted_at();
        InvocationQueryResponse {
            invocation: Some(InvocationRecord {
                budget_requests_reserved: false,
                budget_usage_digest: None,
                capability_response: None,
                ticket: InvocationTicket {
                    operation_id: binding.request_id.clone(),
                    attempt_id: 7,
                },
                admission: InvocationAdmission {
                    operation_id: binding.request_id.clone(),
                    connector_id: binding.connector_id.clone(),
                    operation: binding.operation.clone(),
                    zone_id: binding.zone_id.clone(),
                    principal: "user:owner".to_owned(),
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(principal_binding()),
                    transport_idempotency: Some(binding.transport_idempotency.clone()),
                },
                admitted_at,
                terminal: Some(InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: Some("receipt-final".to_owned()),
                    duration_ms: 1000,
                    http_status: 200,
                }),
                finished_at: Some(admitted_at + chrono::Duration::seconds(1)),
                finalization: Some(InvocationFinalization {
                    budget_recorded: true,
                    budget_finalized: true,
                    receipt_recorded: true,
                    audit_event_id: Some("audit-final".to_owned()),
                    sampling_operation_id: None,
                    sampling_completed: None,
                    response_http_status: Some(200),
                    response_status: Some(InvokeStatus::Ok),
                }),
                durable: true,
            }),
            mesh_invocation: None,
            host_job_active: false,
        }
    }

    fn mesh_response(binding: &TaskInvocationBinding, relay: bool) -> InvocationQueryResponse {
        let admitted_at = admitted_at();
        InvocationQueryResponse {
            invocation: None,
            mesh_invocation: Some(MeshInvocationRecord {
                ticket: InvocationTicket {
                    operation_id: binding.request_id.clone(),
                    attempt_id: 7,
                },
                intent: MeshInvocationIntent {
                    operation_id: binding.request_id.clone(),
                    connector_id: binding.connector_id.clone(),
                    operation: binding.operation.clone(),
                    zone_id: binding.zone_id.clone(),
                    origin_node: "node-origin".to_owned(),
                    target_node: "node-first".to_owned(),
                    identity: if relay {
                        MeshInvocationIdentity::TokenBoundRelay {
                            capability_digest: "e".repeat(64),
                            asserted_principal: None,
                        }
                    } else {
                        MeshInvocationIdentity::VerifiedPrincipal {
                            principal: "user:owner".to_owned(),
                        }
                    },
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(if relay {
                        binding.transport_idempotency.clone()
                    } else {
                        principal_binding()
                    }),
                    transport_idempotency: (!relay).then(|| binding.transport_idempotency.clone()),
                },
                admitted_at,
                attempts: vec![
                    MeshInvocationAttempt {
                        target_node: "node-first".to_owned(),
                        selected_at: admitted_at,
                        observation: Some(MeshInvocationObservation::NotDelivered),
                    },
                    MeshInvocationAttempt {
                        target_node: "node-final".to_owned(),
                        selected_at: admitted_at + chrono::Duration::seconds(1),
                        observation: Some(MeshInvocationObservation::ResponseObserved {
                            http_status: 200,
                        }),
                    },
                ],
                terminal: Some(MeshInvocationTerminal {
                    outcome: MeshInvocationOutcome::Succeeded,
                    http_status: 200,
                    duration_ms: 2000,
                    receipt_id: Some("receipt-remote".to_owned()),
                }),
                finished_at: Some(admitted_at + chrono::Duration::seconds(2)),
                durable: true,
            }),
            host_job_active: false,
        }
    }

    fn pin(source: TaskInvocationSource) -> TaskInvocationAttempt {
        TaskInvocationAttempt {
            source,
            attempt_id: 7,
        }
    }

    #[test]
    fn local_completion_retains_only_exact_durable_metadata() {
        let binding = binding();
        let response = local_response(&binding);
        let observed = bind_observation(&binding, &binding.host, None, &response).unwrap();
        assert_eq!(observed, pin(TaskInvocationSource::Local));
        let proof = verify_completion(&binding, &binding.host, &observed, &response).unwrap();
        assert_eq!(proof.attempt(), observed);
        assert_eq!(proof.source, TaskInvocationCompletionSource::LocalFinalized);
        assert_eq!(proof.receipt_id.as_deref(), Some("receipt-final"));
        assert_eq!(proof.audit_event_id.as_deref(), Some("audit-final"));
        let encoded = serde_json::to_value(&proof).unwrap();
        for absent in [
            "result",
            "input",
            "capability_token",
            "idempotency_key",
            "retry",
        ] {
            assert!(
                encoded.get(absent).is_none(),
                "{absent} must not be reconstructed"
            );
        }
        assert_eq!(
            serde_json::from_value::<TaskInvocationCompletion>(encoded).unwrap(),
            proof
        );
    }

    #[test]
    fn completed_no_budget_and_no_receipt_decisions_are_recoverable() {
        let binding = binding();
        let mut response = local_response(&binding);
        let record = response.invocation.as_mut().unwrap();
        record.terminal.as_mut().unwrap().receipt_id = None;
        let finalization = record.finalization.as_mut().unwrap();
        finalization.budget_recorded = false;
        finalization.receipt_recorded = false;
        assert!(
            verify_completion(
                &binding,
                &binding.host,
                &pin(TaskInvocationSource::Local),
                &response
            )
            .is_ok()
        );
        response
            .invocation
            .as_mut()
            .unwrap()
            .finalization
            .as_mut()
            .unwrap()
            .budget_finalized = false;
        assert_eq!(
            verify_completion(
                &binding,
                &binding.host,
                &pin(TaskInvocationSource::Local),
                &response
            ),
            Err(ReconcileFailure::IncompleteFinalization)
        );
    }

    #[test]
    fn active_and_unknown_observations_pin_history_without_claiming_success() {
        let binding = binding();
        let complete = local_response(&binding);
        let mut response = complete.clone();
        let record = response.invocation.as_mut().unwrap();
        record.terminal = None;
        record.finished_at = None;
        record.finalization = None;
        response.host_job_active = true;
        let observed = bind_observation(&binding, &binding.host, None, &response).unwrap();
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::ActiveHostJob)
        );
        response.host_job_active = false;
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::IncompleteEvidence)
        );
        response.invocation.as_mut().unwrap().terminal = Some(InvocationTerminal {
            outcome: InvocationOutcome::OutcomeUnknown,
            receipt_id: None,
            duration_ms: 1000,
            http_status: 503,
        });
        response.invocation.as_mut().unwrap().finished_at =
            Some(admitted_at() + chrono::Duration::seconds(1));
        assert_eq!(
            bind_observation(&binding, &binding.host, Some(&observed), &response),
            Ok(observed.clone())
        );
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::UnsuccessfulOutcome)
        );
        assert!(verify_completion(&binding, &binding.host, &observed, &complete).is_ok());
    }

    #[test]
    fn pinned_attempt_cannot_roll_forward_or_switch_journals() {
        let binding = binding();
        let mut response = local_response(&binding);
        let observed = bind_observation(&binding, &binding.host, None, &response).unwrap();
        response.invocation.as_mut().unwrap().ticket.attempt_id += 1;
        assert_eq!(
            bind_observation(&binding, &binding.host, Some(&observed), &response),
            Err(ReconcileFailure::AttemptChanged)
        );
        assert_eq!(
            verify_completion(
                &binding,
                &binding.host,
                &observed,
                &mesh_response(&binding, false)
            ),
            Err(ReconcileFailure::AttemptChanged)
        );
        response.invocation = None;
        assert_eq!(
            bind_observation(&binding, &binding.host, Some(&observed), &response),
            Err(ReconcileFailure::MissingEvidence)
        );
    }

    #[test]
    fn conflicting_journals_and_zero_attempts_never_establish_a_pin() {
        let binding = binding();
        let mut response = local_response(&binding);
        response.mesh_invocation = mesh_response(&binding, false).mesh_invocation;
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::ConflictingEvidence)
        );
        response.mesh_invocation = None;
        response.invocation.as_mut().unwrap().ticket.attempt_id = 0;
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::InvalidHistory)
        );
        let invalid_pin = TaskInvocationAttempt {
            source: TaskInvocationSource::Local,
            attempt_id: 0,
        };
        assert_eq!(
            bind_observation(&binding, &binding.host, Some(&invalid_pin), &response),
            Err(ReconcileFailure::InvalidBinding)
        );
    }

    #[test]
    fn host_identity_and_both_transport_digests_are_exact() {
        type Change = fn(&mut InvocationRecord);
        let binding = binding();
        let response = local_response(&binding);
        assert_eq!(
            bind_observation(&binding, "https://other.example", None, &response),
            Err(ReconcileFailure::WrongHost)
        );
        let identity_changes: [Change; 6] = [
            |r: &mut InvocationRecord| r.ticket.operation_id = "other-request".to_owned(),
            |r: &mut InvocationRecord| r.admission.operation_id = "other-request".to_owned(),
            |r: &mut InvocationRecord| r.admission.connector_id = "other-connector".to_owned(),
            |r: &mut InvocationRecord| r.admission.operation = "other-operation".to_owned(),
            |r: &mut InvocationRecord| r.admission.zone_id = "z:private".to_owned(),
            |r: &mut InvocationRecord| r.admission.principal = "other-principal".to_owned(),
        ];
        for change in identity_changes {
            let mut changed = response.clone();
            change(changed.invocation.as_mut().unwrap());
            assert_eq!(
                bind_observation(&binding, &binding.host, None, &changed),
                Err(ReconcileFailure::IdentityMismatch)
            );
        }
        let effect_changes: [Change; 3] = [
            |r: &mut InvocationRecord| r.admission.transport_idempotency = None,
            |r: &mut InvocationRecord| {
                r.admission
                    .transport_idempotency
                    .as_mut()
                    .unwrap()
                    .scope_digest = "f".repeat(64);
            },
            |r: &mut InvocationRecord| {
                r.admission
                    .transport_idempotency
                    .as_mut()
                    .unwrap()
                    .effect_digest = "f".repeat(64);
            },
        ];
        for change in effect_changes {
            let mut changed = response.clone();
            change(changed.invocation.as_mut().unwrap());
            assert_eq!(
                bind_observation(&binding, &binding.host, None, &changed),
                Err(ReconcileFailure::EffectBindingMismatch)
            );
        }
    }

    #[test]
    fn principal_scoped_idempotency_cannot_replace_the_transport_alias() {
        let binding = binding();
        let mut response = local_response(&binding);
        let admission = &mut response.invocation.as_mut().unwrap().admission;
        admission.idempotency = Some(binding.transport_idempotency.clone());
        admission.transport_idempotency = None;
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::EffectBindingMismatch)
        );
        let mut mesh = mesh_response(&binding, false);
        let intent = &mut mesh.mesh_invocation.as_mut().unwrap().intent;
        intent.idempotency = Some(binding.transport_idempotency.clone());
        intent.transport_idempotency = None;
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &mesh),
            Err(ReconcileFailure::EffectBindingMismatch)
        );
    }

    #[test]
    fn no_principal_hint_still_requires_the_exact_opaque_binding() {
        let mut binding = binding();
        binding.principal = None;
        let response = local_response(&binding);
        assert!(
            verify_completion(
                &binding,
                &binding.host,
                &pin(TaskInvocationSource::Local),
                &response
            )
            .is_ok()
        );
        let mut invalid = binding.clone();
        invalid.transport_idempotency.scope_digest = "not-a-digest".to_owned();
        assert_eq!(
            bind_observation(&invalid, &invalid.host, None, &response),
            Err(ReconcileFailure::InvalidBinding)
        );
    }

    #[test]
    fn local_success_requires_durability_and_each_applicable_finalization_marker() {
        type Change = fn(&mut InvocationRecord);
        let binding = binding();
        let cases: [(Change, ReconcileFailure); 11] = [
            (|r| r.durable = false, ReconcileFailure::NonDurable),
            (
                |r| r.terminal.as_mut().unwrap().outcome = InvocationOutcome::ConnectorError,
                ReconcileFailure::UnsuccessfulOutcome,
            ),
            (
                |r| r.terminal.as_mut().unwrap().http_status = 500,
                ReconcileFailure::UnsuccessfulOutcome,
            ),
            (
                |r| r.finalization = None,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().budget_finalized = false,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().receipt_recorded = false,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().audit_event_id = None,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().response_status = None,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().response_status = Some(InvokeStatus::Error),
                ReconcileFailure::UnsuccessfulOutcome,
            ),
            (
                |r| r.finalization.as_mut().unwrap().response_http_status = None,
                ReconcileFailure::IncompleteFinalization,
            ),
            (
                |r| r.finalization.as_mut().unwrap().response_http_status = Some(502),
                ReconcileFailure::IncompleteFinalization,
            ),
        ];
        for (change, refusal) in cases {
            let mut response = local_response(&binding);
            change(response.invocation.as_mut().unwrap());
            assert_eq!(
                verify_completion(
                    &binding,
                    &binding.host,
                    &pin(TaskInvocationSource::Local),
                    &response
                ),
                Err(refusal)
            );
        }
    }

    #[test]
    fn sampling_child_error_cannot_hide_behind_source_success_and_http_200() {
        let binding = binding();
        let mut response = local_response(&binding);
        let finalization = response
            .invocation
            .as_mut()
            .unwrap()
            .finalization
            .as_mut()
            .unwrap();
        finalization.sampling_operation_id = Some("sampling-child".to_owned());
        finalization.sampling_completed = Some(true);
        finalization.response_status = Some(InvokeStatus::Error);
        assert_eq!(
            verify_completion(
                &binding,
                &binding.host,
                &pin(TaskInvocationSource::Local),
                &response
            ),
            Err(ReconcileFailure::UnsuccessfulOutcome)
        );
        response
            .invocation
            .as_mut()
            .unwrap()
            .finalization
            .as_mut()
            .unwrap()
            .response_status = Some(InvokeStatus::Ok);
        assert!(
            verify_completion(
                &binding,
                &binding.host,
                &pin(TaskInvocationSource::Local),
                &response
            )
            .is_ok()
        );
        for completed in [None, Some(false)] {
            response
                .invocation
                .as_mut()
                .unwrap()
                .finalization
                .as_mut()
                .unwrap()
                .sampling_completed = completed;
            assert_eq!(
                verify_completion(
                    &binding,
                    &binding.host,
                    &pin(TaskInvocationSource::Local),
                    &response
                ),
                Err(ReconcileFailure::IncompleteFinalization)
            );
        }
    }

    #[test]
    fn inconsistent_local_terminal_timeline_and_child_identity_are_rejected() {
        type Change = fn(&mut InvocationRecord);
        let binding = binding();
        let changes: [Change; 6] = [
            |r: &mut InvocationRecord| r.finished_at = None,
            |r: &mut InvocationRecord| r.terminal = None,
            |r: &mut InvocationRecord| {
                r.finished_at = Some(r.admitted_at - chrono::Duration::seconds(1));
            },
            |r: &mut InvocationRecord| {
                r.finalization.as_mut().unwrap().audit_event_id = Some(String::new());
            },
            |r: &mut InvocationRecord| {
                r.finalization.as_mut().unwrap().sampling_operation_id =
                    Some(r.ticket.operation_id.clone());
            },
            |r: &mut InvocationRecord| {
                r.finalization.as_mut().unwrap().sampling_completed = Some(true);
            },
        ];
        for change in changes {
            let mut response = local_response(&binding);
            change(response.invocation.as_mut().unwrap());
            assert_eq!(
                bind_observation(&binding, &binding.host, None, &response),
                Err(ReconcileFailure::InvalidHistory)
            );
        }
    }

    #[test]
    fn verified_and_opaque_mesh_success_remain_origin_observations() {
        let binding = binding();
        for relay in [false, true] {
            let response = mesh_response(&binding, relay);
            let observed = bind_observation(&binding, &binding.host, None, &response).unwrap();
            let proof = verify_completion(&binding, &binding.host, &observed, &response).unwrap();
            assert_eq!(proof.attempt(), pin(TaskInvocationSource::Mesh));
            assert_eq!(
                proof.source,
                TaskInvocationCompletionSource::MeshOriginObserved
            );
            assert!(proof.audit_event_id.is_none());
            assert_eq!(
                serde_json::to_value(&proof).unwrap()["source"],
                "mesh_origin_observed"
            );
        }
    }

    #[test]
    fn mesh_principal_and_relay_namespaces_cannot_be_substituted() {
        let binding = binding();
        let mut response = mesh_response(&binding, false);
        response.mesh_invocation.as_mut().unwrap().intent.identity =
            MeshInvocationIdentity::VerifiedPrincipal {
                principal: "other-principal".to_owned(),
            };
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::IdentityMismatch)
        );
        let mut response = mesh_response(&binding, true);
        response
            .mesh_invocation
            .as_mut()
            .unwrap()
            .intent
            .transport_idempotency = Some(binding.transport_idempotency.clone());
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::InvalidHistory)
        );
        let mut response = mesh_response(&binding, true);
        response.mesh_invocation.as_mut().unwrap().intent.identity =
            MeshInvocationIdentity::TokenBoundRelay {
                capability_digest: "e".repeat(64),
                asserted_principal: binding.principal.clone(),
            };
        assert_eq!(
            bind_observation(&binding, &binding.host, None, &response),
            Err(ReconcileFailure::IdentityMismatch)
        );
    }

    #[test]
    fn mesh_completion_requires_one_coherent_non_delivery_and_response_chain() {
        type Change = fn(&mut MeshInvocationRecord);
        let binding = binding();
        let changes: [Change; 11] = [
            |r: &mut MeshInvocationRecord| r.attempts.clear(),
            |r: &mut MeshInvocationRecord| {
                r.attempts[0].target_node = "unselected-peer".to_owned();
            },
            |r: &mut MeshInvocationRecord| {
                r.attempts[1].target_node = r.attempts[0].target_node.clone();
            },
            |r: &mut MeshInvocationRecord| {
                r.attempts[0].observation = Some(MeshInvocationObservation::OutcomeUnknown);
            },
            |r: &mut MeshInvocationRecord| {
                r.attempts[0].observation =
                    Some(MeshInvocationObservation::ResponseObserved { http_status: 200 });
            },
            |r: &mut MeshInvocationRecord| r.attempts[1].observation = None,
            |r: &mut MeshInvocationRecord| {
                r.attempts[1].observation =
                    Some(MeshInvocationObservation::ResponseObserved { http_status: 500 });
            },
            |r: &mut MeshInvocationRecord| r.terminal.as_mut().unwrap().http_status = 500,
            |r: &mut MeshInvocationRecord| r.finished_at = None,
            |r: &mut MeshInvocationRecord| {
                r.attempts[1].selected_at = r.admitted_at - chrono::Duration::seconds(1);
            },
            |r: &mut MeshInvocationRecord| {
                r.attempts[1].selected_at = r.finished_at.unwrap() + chrono::Duration::seconds(1);
            },
        ];
        for change in changes {
            let mut response = mesh_response(&binding, false);
            change(response.mesh_invocation.as_mut().unwrap());
            assert_eq!(
                bind_observation(&binding, &binding.host, None, &response),
                Err(ReconcileFailure::InvalidHistory)
            );
        }
    }

    #[test]
    fn mesh_active_uncertain_failed_and_non_durable_records_never_complete() {
        let binding = binding();
        let mut response = mesh_response(&binding, false);
        response.host_job_active = true;
        let observed = bind_observation(&binding, &binding.host, None, &response).unwrap();
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::ActiveHostJob)
        );
        response.host_job_active = false;
        response.mesh_invocation.as_mut().unwrap().durable = false;
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::NonDurable)
        );
        response.mesh_invocation.as_mut().unwrap().durable = true;
        for outcome in [
            MeshInvocationOutcome::ConnectorError,
            MeshInvocationOutcome::OutcomeUnknown,
        ] {
            response
                .mesh_invocation
                .as_mut()
                .unwrap()
                .terminal
                .as_mut()
                .unwrap()
                .outcome = outcome;
            assert_eq!(
                verify_completion(&binding, &binding.host, &observed, &response),
                Err(ReconcileFailure::UnsuccessfulOutcome)
            );
        }
        let record = response.mesh_invocation.as_mut().unwrap();
        record.terminal = None;
        record.finished_at = None;
        assert_eq!(
            bind_observation(&binding, &binding.host, Some(&observed), &response),
            Ok(observed.clone())
        );
        assert_eq!(
            verify_completion(&binding, &binding.host, &observed, &response),
            Err(ReconcileFailure::IncompleteEvidence)
        );
    }

    #[test]
    fn refusals_do_not_echo_host_or_invocation_private_metadata() {
        let binding = binding();
        let mut response = local_response(&binding);
        response.invocation.as_mut().unwrap().admission.principal = "private-canary".to_owned();
        let refusal = bind_observation(&binding, &binding.host, None, &response).unwrap_err();
        assert_eq!(refusal.code(), "task-invocation-identity-mismatch");
        assert!(!refusal.to_string().contains("private-canary"));
        assert!(!refusal.to_string().contains(&binding.host));
    }
}
