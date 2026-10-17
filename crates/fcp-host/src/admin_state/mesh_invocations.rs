//! Durable entry-host observations of mesh forwarding.
//!
//! These records describe routing custody, not executor-local authorization.
//! A reservation is synced before transport is polled. Its selected target is
//! therefore potentially delivered until the transport proves non-delivery.
//! Incomplete observations survive restart as uncertainty and fence replay.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    HostAdminStateSnapshot, HostAdminStateStore, InvocationIdempotency, InvocationQueryResponse,
    InvocationTicket, MAX_RETAINED_INVOCATIONS, invocation_idempotency_conflict,
    invocation_relay_capability_digest, invocation_state_error, validate_invocation_metadata,
};
use crate::{HostError, HostResult};

const MAX_MESH_INVOCATION_TARGETS: usize = 256;
// Opaque relays have no locally established caller authority. Their unresolved
// evidence must not exhaust the shared capacity reserved for verified work.
const MAX_UNVERIFIED_MESH_INVOCATIONS: usize = 256;

/// How an entry host binds a forwarding reservation to its caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshInvocationIdentity {
    /// Full origin admission established this principal.
    VerifiedPrincipal {
        /// Principal obtained from the already verified capability.
        principal: String,
    },
    /// A transparent relay cannot assert executor authorization.
    ///
    /// The namespace binds the exact opaque capability; the asserted header
    /// is bound as an effect constraint, so changing it cannot escape a key.
    /// Renewed credentials create another namespace; it is not a verified
    /// principal or a mesh-wide semantic idempotency guarantee. New verified
    /// admissions retain this opaque namespace as an additional alias, so a
    /// local/remote route change cannot escape a retained exact-token key.
    TokenBoundRelay {
        /// Domain-separated digest of the exact capability encoding.
        capability_digest: String,
        /// Unverified identity assertion forwarded to the executor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asserted_principal: Option<String>,
    },
}

/// Payload-free origin intent persisted before any peer send.
///
/// This is an entry-host reservation, not an FCP OperationIntent or an
/// executor-local InvocationAdmission. It never stores credentials, raw
/// idempotency keys, inputs, or result bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInvocationIntent {
    /// Caller-visible invocation identifier.
    pub operation_id: String,
    /// Requested connector identity.
    pub connector_id: String,
    /// Requested connector operation.
    pub operation: String,
    /// Requested zone; executor admission remains authoritative.
    pub zone_id: String,
    /// Entry node retaining custody of the forward.
    pub origin_node: String,
    /// Initially selected executor.
    pub target_node: String,
    /// Explicit authority or opaque-token basis of the reservation.
    pub identity: MeshInvocationIdentity,
    /// Optional tracing correlation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Deadline shared with the retained forwarding job.
    pub deadline_at: DateTime<Utc>,
    /// Optional key/effect binding in the namespace described by identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<InvocationIdempotency>,
    /// Exact-token alias of a verified principal's idempotency scope.
    ///
    /// TokenBoundRelay already uses that namespace as its primary binding and
    /// leaves this absent. Old verified records without an alias remain
    /// readable, but their discarded credentials cannot be reconstructed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_idempotency: Option<InvocationIdempotency>,
}

impl MeshInvocationIntent {
    /// Construct metadata after route selection and any origin admission.
    ///
    /// Supply a verified principal only after the complete local origin gate
    /// has succeeded. Transparent remote-only forwarding must pass None.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata, conflicting asserted identity, invalid
    /// idempotency keys, or an unencodable capability/effect binding.
    pub fn from_request(
        request: &fcp_kernel::InvokeRequest,
        origin_node: &str,
        target_node: &str,
        asserted_principal: Option<&str>,
        verified_principal: Option<&str>,
        deadline_at: DateTime<Utc>,
    ) -> HostResult<Self> {
        request.validate_idempotency_key().map_err(|_| {
            HostError::InvalidFilter("invalid mesh invocation idempotency key".to_string())
        })?;
        if let Some(asserted) = asserted_principal {
            validate_invocation_metadata(asserted, "asserted principal")?;
        }
        let (identity, idempotency, transport_idempotency) =
            if let Some(principal) = verified_principal {
                validate_invocation_metadata(principal, "verified principal")?;
                if asserted_principal.is_some_and(|asserted| asserted != principal) {
                    return Err(HostError::InvalidFilter(
                        "mesh invocation asserted principal differs from verified principal"
                            .to_string(),
                    ));
                }
                (
                    MeshInvocationIdentity::VerifiedPrincipal {
                        principal: principal.to_string(),
                    },
                    InvocationIdempotency::from_request(request, principal)?,
                    InvocationIdempotency::from_relay_request(request, asserted_principal)?,
                )
            } else {
                let capability_digest = invocation_relay_capability_digest(request)?;
                let idempotency = InvocationIdempotency::from_relay_parts(
                    request,
                    &capability_digest,
                    asserted_principal,
                )?;
                (
                    MeshInvocationIdentity::TokenBoundRelay {
                        capability_digest,
                        asserted_principal: asserted_principal.map(str::to_owned),
                    },
                    idempotency,
                    None,
                )
            };
        let intent = Self {
            operation_id: request.id.to_string(),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            zone_id: request.zone_id.to_string(),
            origin_node: origin_node.to_string(),
            target_node: target_node.to_string(),
            identity,
            correlation_id: request.correlation_id.as_ref().map(ToString::to_string),
            deadline_at,
            idempotency,
            transport_idempotency,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> HostResult<()> {
        for (name, value) in [
            ("operation_id", self.operation_id.as_str()),
            ("connector_id", self.connector_id.as_str()),
            ("operation", self.operation.as_str()),
            ("zone_id", self.zone_id.as_str()),
            ("origin_node", self.origin_node.as_str()),
            ("target_node", self.target_node.as_str()),
        ] {
            validate_invocation_metadata(value, name)?;
        }
        if let Some(correlation_id) = &self.correlation_id {
            validate_invocation_metadata(correlation_id, "correlation_id")?;
        }
        match &self.identity {
            MeshInvocationIdentity::VerifiedPrincipal { principal } => {
                validate_invocation_metadata(principal, "verified principal")?;
            }
            MeshInvocationIdentity::TokenBoundRelay {
                capability_digest,
                asserted_principal,
            } => {
                InvocationIdempotency {
                    scope_digest: capability_digest.clone(),
                    effect_digest: capability_digest.clone(),
                }
                .validate()?;
                if let Some(asserted) = asserted_principal {
                    validate_invocation_metadata(asserted, "asserted principal")?;
                }
            }
        }
        if let Some(binding) = &self.idempotency {
            binding.validate()?;
        }
        if let Some(binding) = &self.transport_idempotency {
            binding.validate()?;
            if !self.has_verified_scope() || self.idempotency.is_none() {
                return Err(HostError::InvalidFilter(
                    "mesh transport alias requires a verified principal-scoped binding".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn transport_binding(&self) -> Option<&InvocationIdempotency> {
        if self.has_verified_scope() {
            self.transport_idempotency.as_ref()
        } else {
            self.idempotency.as_ref()
        }
    }

    const fn has_verified_scope(&self) -> bool {
        matches!(
            self.identity,
            MeshInvocationIdentity::VerifiedPrincipal { .. }
        )
    }
}

/// What authenticated transport established about one selected executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshInvocationObservation {
    /// Transport proved this attempt was not delivered.
    NotDelivered,
    /// An authenticated peer reply was observed.
    ///
    /// HTTP status alone does not establish connector success or no effect.
    ResponseObserved {
        /// Status carried by the authenticated peer response.
        http_status: u16,
    },
    /// Delivery or completion cannot be determined safely.
    OutcomeUnknown,
}

/// One durable executor selection and its transport observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInvocationAttempt {
    /// Selected executor identity.
    pub target_node: String,
    /// Time selection was committed before transport could be polled.
    pub selected_at: DateTime<Utc>,
    /// Missing means the selected executor may have received the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<MeshInvocationObservation>,
}

/// Result classification after the entry host finishes processing a forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshInvocationOutcome {
    /// Every selected target was conclusively not delivered.
    NotDelivered,
    /// A matching, valid successful InvokeResponse was observed.
    Succeeded,
    /// A matching, valid connector-error InvokeResponse was observed.
    ConnectorError,
    /// The connector result or required origin finalization is uncertain.
    OutcomeUnknown,
}

/// Metadata recorded after response validation, audit, and budget processing.
///
/// A signed HTTP error or malformed response alone cannot establish no effect.
/// This record is not a response cache or executor-global finalization proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInvocationTerminal {
    /// Known result class, or explicit uncertainty.
    pub outcome: MeshInvocationOutcome,
    /// Final status returned by this entry host.
    pub http_status: u16,
    /// Elapsed forwarding duration.
    pub duration_ms: u64,
    /// Receipt reference from a validated InvokeResponse, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

/// Retained evidence of one entry-host forwarding reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInvocationRecord {
    /// Globally ordered attempt identity shared with local invocation records.
    pub ticket: InvocationTicket,
    /// Payload-free request binding and original route.
    pub intent: MeshInvocationIntent,
    /// Time the entry host persisted its reservation.
    pub admitted_at: DateTime<Utc>,
    /// Ordered executor selections; only proven non-delivery allows another.
    pub attempts: Vec<MeshInvocationAttempt>,
    /// Completed origin processing or explicit recovery uncertainty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<MeshInvocationTerminal>,
    /// Time the terminal classification was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Whether file and directory synchronization backed the reservation.
    pub durable: bool,
}

impl MeshInvocationRecord {
    pub(super) fn is_unresolved(&self) -> bool {
        self.terminal
            .as_ref()
            .is_none_or(|terminal| terminal.outcome == MeshInvocationOutcome::OutcomeUnknown)
    }

    fn validate(&self) -> HostResult<()> {
        self.intent.validate()?;
        if self.ticket.operation_id != self.intent.operation_id
            || self.ticket.attempt_id == 0
            || self.attempts.is_empty()
            || self.attempts.len() > MAX_MESH_INVOCATION_TARGETS
            || self.attempts[0].target_node != self.intent.target_node
            || self.terminal.is_some() != self.finished_at.is_some()
        {
            return Err(HostError::Internal(
                "persisted mesh invocation structure is inconsistent".to_string(),
            ));
        }
        let mut targets = HashSet::new();
        for (index, attempt) in self.attempts.iter().enumerate() {
            validate_invocation_metadata(&attempt.target_node, "target_node")?;
            if !targets.insert(attempt.target_node.as_str()) {
                return Err(HostError::Internal(
                    "mesh invocation repeats an executor selection".to_string(),
                ));
            }
            validate_observation(attempt.observation.as_ref())?;
            if index + 1 < self.attempts.len()
                && attempt.observation != Some(MeshInvocationObservation::NotDelivered)
            {
                return Err(HostError::Internal(
                    "mesh invocation advanced without proven non-delivery".to_string(),
                ));
            }
        }
        if let Some(terminal) = &self.terminal {
            self.validate_terminal(terminal)?;
        }
        Ok(())
    }

    fn validate_terminal(&self, terminal: &MeshInvocationTerminal) -> HostResult<()> {
        if !(100..=599).contains(&terminal.http_status) {
            return Err(HostError::InvalidFilter(
                "mesh invocation HTTP status must be in 100..=599".to_string(),
            ));
        }
        if let Some(receipt_id) = &terminal.receipt_id {
            validate_invocation_metadata(receipt_id, "receipt_id")?;
        }
        match terminal.outcome {
            MeshInvocationOutcome::NotDelivered => {
                if terminal.receipt_id.is_some()
                    || self.attempts.iter().any(|attempt| {
                        attempt.observation != Some(MeshInvocationObservation::NotDelivered)
                    })
                {
                    return Err(HostError::InvalidFilter(
                        "mesh non-delivery requires proof for every selected executor".to_string(),
                    ));
                }
            }
            MeshInvocationOutcome::Succeeded | MeshInvocationOutcome::ConnectorError => {
                let observed = self
                    .attempts
                    .last()
                    .and_then(|attempt| attempt.observation.as_ref());
                if !matches!(
                    observed,
                    Some(MeshInvocationObservation::ResponseObserved { http_status })
                        if (200..=299).contains(http_status)
                ) || !(200..=299).contains(&terminal.http_status)
                {
                    return Err(HostError::InvalidFilter(
                        "known mesh result requires a successful authenticated response envelope"
                            .to_string(),
                    ));
                }
            }
            MeshInvocationOutcome::OutcomeUnknown => {}
        }
        Ok(())
    }
}

fn validate_observation(observation: Option<&MeshInvocationObservation>) -> HostResult<()> {
    if let Some(MeshInvocationObservation::ResponseObserved { http_status }) = observation
        && !(100..=599).contains(http_status)
    {
        return Err(HostError::InvalidFilter(
            "mesh peer HTTP status must be in 100..=599".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn recover_transport_idempotency(
    binding: &InvocationIdempotency,
    unresolved: bool,
    scoped_effects: &mut HashMap<String, String>,
    unresolved_scopes: &mut HashSet<String>,
) -> HostResult<()> {
    binding.validate().map_err(|_| {
        HostError::Internal("persisted transport idempotency binding is invalid".to_string())
    })?;
    // The exact-token namespace is shared by relay primary bindings and the
    // transport aliases of verified local or mesh invocations.
    let scope = format!("relay:{}", binding.scope_digest);
    if scoped_effects
        .insert(scope.clone(), binding.effect_digest.clone())
        .is_some_and(|previous| previous != binding.effect_digest)
    {
        return Err(HostError::Internal(
            "persisted transport idempotency effects are inconsistent".to_string(),
        ));
    }
    if unresolved && !unresolved_scopes.insert(scope) {
        return Err(HostError::Internal(
            "persisted transport idempotency scope has overlapping unresolved attempts".to_string(),
        ));
    }
    Ok(())
}

impl HostAdminStateSnapshot {
    pub(super) fn check_mesh_invocation_conflicts(
        &self,
        operation_id: &str,
        idempotency: Option<&InvocationIdempotency>,
        verified_scope: bool,
        transport_idempotency: Option<&InvocationIdempotency>,
    ) -> Result<(), fcp_kernel::LifecycleError> {
        for record in self.mesh_invocations.iter().rev() {
            if record.ticket.operation_id == operation_id && record.is_unresolved() {
                return Err(invocation_idempotency_conflict(
                    "invocation identifier has an unresolved mesh forward",
                    &record.ticket,
                ));
            }
            let verified_previous = if verified_scope && record.intent.has_verified_scope() {
                record.intent.idempotency.as_ref()
            } else {
                None
            };
            for (binding, previous) in [
                (idempotency, verified_previous),
                (transport_idempotency, record.intent.transport_binding()),
            ] {
                let (Some(binding), Some(previous)) = (binding, previous) else {
                    continue;
                };
                if binding.scope_digest != previous.scope_digest {
                    continue;
                }
                if binding.effect_digest != previous.effect_digest {
                    return Err(invocation_idempotency_conflict(
                        "idempotency key is already bound to different mesh invocation effects",
                        &record.ticket,
                    ));
                }
                if record.is_unresolved() {
                    return Err(invocation_idempotency_conflict(
                        "idempotency key has an unresolved mesh forward",
                        &record.ticket,
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn check_local_invocation_conflicts(
        &self,
        operation_id: &str,
        idempotency: Option<&InvocationIdempotency>,
        transport_idempotency: Option<&InvocationIdempotency>,
    ) -> Result<(), fcp_kernel::LifecycleError> {
        for record in self.invocations.iter().rev() {
            if record.ticket.operation_id == operation_id && record.is_unresolved() {
                return Err(invocation_idempotency_conflict(
                    "invocation identifier has an unresolved local attempt",
                    &record.ticket,
                ));
            }
            for (binding, previous) in [
                (idempotency, record.admission.idempotency.as_ref()),
                (
                    transport_idempotency,
                    record.admission.transport_idempotency.as_ref(),
                ),
            ] {
                let (Some(binding), Some(previous)) = (binding, previous) else {
                    continue;
                };
                if binding.scope_digest != previous.scope_digest {
                    continue;
                }
                if binding.effect_digest != previous.effect_digest {
                    return Err(invocation_idempotency_conflict(
                        "idempotency key is already bound to different invocation effects",
                        &record.ticket,
                    ));
                }
                if record.is_unresolved() {
                    return Err(invocation_idempotency_conflict(
                        "idempotency key has an unresolved attempt",
                        &record.ticket,
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn reserve_invocation_history_slot(
        &mut self,
    ) -> Result<(), fcp_kernel::LifecycleError> {
        while self.invocations.len() + self.mesh_invocations.len() >= MAX_RETAINED_INVOCATIONS {
            let local = self
                .invocations
                .iter()
                .enumerate()
                .filter(|(_, record)| !record.is_unresolved())
                .min_by_key(|(_, record)| record.ticket.attempt_id)
                .map(|(index, record)| (index, record.ticket.attempt_id));
            let mesh = self
                .mesh_invocations
                .iter()
                .enumerate()
                .filter(|(_, record)| !record.is_unresolved())
                .min_by_key(|(_, record)| record.ticket.attempt_id)
                .map(|(index, record)| (index, record.ticket.attempt_id));
            match (local, mesh) {
                (Some((index, local_id)), Some((_, mesh_id))) if local_id < mesh_id => {
                    self.invocations.remove(index);
                }
                (_, Some((index, _))) => {
                    self.mesh_invocations.remove(index);
                }
                (Some((index, _)), None) => {
                    self.invocations.remove(index);
                }
                (None, None) => {
                    return Err(invocation_state_error(
                        "retained invocation history is full of unresolved or unfinished attempts",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn recover_mesh_invocations_after_restart(
        &mut self,
        now: DateTime<Utc>,
        generations: &mut HashSet<u64>,
        scoped_effects: &mut HashMap<String, String>,
        unresolved_scopes: &mut HashSet<String>,
        unresolved_operations: &mut HashSet<String>,
    ) -> HostResult<bool> {
        let mut changed = false;
        for record in &mut self.mesh_invocations {
            record.validate()?;
            if record.ticket.attempt_id >= self.next_invocation_attempt_id
                || !generations.insert(record.ticket.attempt_id)
            {
                return Err(HostError::Internal(
                    "persisted mesh and local invocation attempt identities overlap".to_string(),
                ));
            }
            if record.terminal.is_none() {
                let not_delivered = record.attempts.iter().all(|attempt| {
                    attempt.observation == Some(MeshInvocationObservation::NotDelivered)
                });
                if !not_delivered
                    && let Some(attempt) = record.attempts.last_mut()
                    && attempt.observation.is_none()
                {
                    attempt.observation = Some(MeshInvocationObservation::OutcomeUnknown);
                }
                record.terminal = Some(MeshInvocationTerminal {
                    outcome: if not_delivered {
                        MeshInvocationOutcome::NotDelivered
                    } else {
                        MeshInvocationOutcome::OutcomeUnknown
                    },
                    http_status: 503,
                    duration_ms: u64::try_from(
                        now.signed_duration_since(record.admitted_at)
                            .num_milliseconds(),
                    )
                    .unwrap_or(0),
                    receipt_id: None,
                });
                record.finished_at = Some(now);
                changed = true;
            }
            if record.is_unresolved()
                && !unresolved_operations.insert(record.ticket.operation_id.clone())
            {
                return Err(HostError::Internal(
                    "persisted invocation identifier has overlapping unresolved attempts"
                        .to_string(),
                ));
            }
            if record.intent.has_verified_scope()
                && let Some(binding) = &record.intent.idempotency
            {
                if scoped_effects
                    .insert(binding.scope_digest.clone(), binding.effect_digest.clone())
                    .is_some_and(|previous| previous != binding.effect_digest)
                {
                    return Err(HostError::Internal(
                        "persisted mesh invocation idempotency effects are inconsistent"
                            .to_string(),
                    ));
                }
                if record.is_unresolved() && !unresolved_scopes.insert(binding.scope_digest.clone())
                {
                    return Err(HostError::Internal(
                        "persisted mesh invocation idempotency scope has overlapping unresolved attempts"
                            .to_string(),
                    ));
                }
            }
            if let Some(binding) = record.intent.transport_binding() {
                recover_transport_idempotency(
                    binding,
                    record.is_unresolved(),
                    scoped_effects,
                    unresolved_scopes,
                )?;
            }
        }
        if self
            .mesh_invocations
            .iter()
            .filter(|record| !record.intent.has_verified_scope() && record.is_unresolved())
            .count()
            > MAX_UNVERIFIED_MESH_INVOCATIONS
        {
            return Err(HostError::Internal(
                "persisted unresolved opaque mesh history exceeds its reserved capacity"
                    .to_string(),
            ));
        }
        Ok(changed)
    }
}

impl HostAdminStateStore {
    /// Reserve entry-host custody before polling any mesh invoke transport.
    ///
    /// The first selected target is potentially delivered until an explicit
    /// transport observation proves otherwise. The reservation shares attempt
    /// generations, unresolved operation-ID fencing, history capacity, and
    /// verified principal key scopes with executor-local invocations. Opaque
    /// relays have a separate unresolved sublimit so unverified requests cannot
    /// consume all retained capacity for locally verified work.
    ///
    /// # Errors
    ///
    /// Rejects expiry, conflicting unresolved work/effects, history exhaustion,
    /// generation overflow, malformed metadata, or failed durable persistence.
    pub async fn reserve_mesh_invocation(
        &self,
        intent: MeshInvocationIntent,
    ) -> HostResult<InvocationTicket> {
        intent.validate()?;
        let durable = self.state_path.is_some() && cfg!(unix);
        self.apply_mutation(|snapshot| {
            let now = Utc::now();
            if intent.deadline_at <= now {
                return Err(invocation_state_error("mesh invocation reservation deadline expired"));
            }
            snapshot.check_mesh_invocation_conflicts(
                &intent.operation_id,
                intent.idempotency.as_ref(),
                intent.has_verified_scope(),
                intent.transport_binding(),
            )?;
            let verified_binding = if intent.has_verified_scope() {
                intent.idempotency.as_ref()
            } else {
                None
            };
            snapshot.check_local_invocation_conflicts(
                &intent.operation_id,
                verified_binding,
                intent.transport_binding(),
            )?;
            if !intent.has_verified_scope()
                && snapshot
                    .mesh_invocations
                    .iter()
                    .filter(|record| !record.intent.has_verified_scope() && record.is_unresolved())
                    .count()
                    >= MAX_UNVERIFIED_MESH_INVOCATIONS
            {
                return Err(invocation_state_error(
                    "unverified mesh invocation capacity is exhausted; unresolved relay outcomes require reconciliation",
                ));
            }
            snapshot.reserve_invocation_history_slot()?;
            let attempt_id = snapshot.next_invocation_attempt_id;
            let next_attempt_id = attempt_id.checked_add(1).ok_or_else(|| {
                invocation_state_error("invocation attempt generation exhausted")
            })?;
            let ticket = InvocationTicket {
                operation_id: intent.operation_id.clone(),
                attempt_id,
            };
            let first = MeshInvocationAttempt {
                target_node: intent.target_node.clone(),
                selected_at: now,
                observation: None,
            };
            snapshot.mesh_invocations.push(MeshInvocationRecord {
                ticket: ticket.clone(),
                intent,
                admitted_at: now,
                attempts: vec![first],
                terminal: None,
                finished_at: None,
                durable,
            });
            snapshot.next_invocation_attempt_id = next_attempt_id;
            Ok(ticket)
        })
        .await
        .map_err(|error| HostError::Unavailable(error.to_string()))
    }

    /// Persist an alternate executor only after proven prior non-delivery.
    ///
    /// # Errors
    ///
    /// Rejects unknown/finished tickets, expiry, repeated targets, exhausted
    /// target history, ambiguity, or persistence failure.
    pub async fn select_mesh_invocation_target(
        &self,
        ticket: &InvocationTicket,
        target_node: &str,
    ) -> HostResult<()> {
        validate_invocation_metadata(target_node, "target_node")?;
        self.apply_mutation(|snapshot| {
            let record = snapshot
                .mesh_invocations
                .iter_mut()
                .find(|record| record.ticket == *ticket)
                .ok_or_else(|| invocation_state_error("unknown mesh invocation ticket"))?;
            if record.terminal.is_some()
                || record.intent.deadline_at <= Utc::now()
                || record.attempts.len() >= MAX_MESH_INVOCATION_TARGETS
                || record.attempts.iter().any(|attempt| attempt.target_node == target_node)
                || record.attempts.last().and_then(|attempt| attempt.observation.as_ref())
                    != Some(&MeshInvocationObservation::NotDelivered)
            {
                return Err(invocation_state_error(
                    "mesh alternate requires an unfinished live reservation and proven non-delivery",
                ));
            }
            record.attempts.push(MeshInvocationAttempt {
                target_node: target_node.to_string(),
                selected_at: Utc::now(),
                observation: None,
            });
            Ok(())
        })
        .await
        .map_err(|error| HostError::Unavailable(error.to_string()))
    }

    /// Persist transport evidence for the exact currently selected executor.
    ///
    /// A signed HTTP response is transport evidence only. The caller must
    /// validate the matching InvokeResponse before recording a known outcome.
    ///
    /// # Errors
    ///
    /// Rejects stale targets, conflicting evidence, finished/unknown tickets,
    /// invalid HTTP status, or persistence failure. Exact repetition is safe.
    pub async fn observe_mesh_invocation(
        &self,
        ticket: &InvocationTicket,
        target_node: &str,
        observation: MeshInvocationObservation,
    ) -> HostResult<()> {
        validate_invocation_metadata(target_node, "target_node")?;
        validate_observation(Some(&observation))?;
        self.apply_mutation(|snapshot| {
            let record = snapshot
                .mesh_invocations
                .iter_mut()
                .find(|record| record.ticket == *ticket)
                .ok_or_else(|| invocation_state_error("unknown mesh invocation ticket"))?;
            if record.terminal.is_some() {
                return Err(invocation_state_error(
                    "mesh invocation already has a terminal outcome",
                ));
            }
            let attempt = record.attempts.last_mut().ok_or_else(|| {
                invocation_state_error("mesh invocation has no selected executor")
            })?;
            if attempt.target_node != target_node {
                return Err(invocation_state_error(
                    "mesh observation targets a stale executor",
                ));
            }
            if let Some(previous) = &attempt.observation {
                if previous == &observation {
                    return Ok(());
                }
                return Err(invocation_state_error(
                    "refusing to overwrite mesh invocation delivery evidence",
                ));
            }
            attempt.observation = Some(observation);
            Ok(())
        })
        .await
        .map_err(|error| HostError::Unavailable(error.to_string()))
    }

    /// Finish origin processing after response validation and finalization.
    ///
    /// Succeeded and ConnectorError require a matching valid InvokeResponse,
    /// not merely a signed HTTP status. NotDelivered requires transport proof
    /// for every selected executor. Unknown outcomes remain replay-fenced.
    ///
    /// # Errors
    ///
    /// Rejects invalid/contradictory evidence, an unknown ticket, an attempt to
    /// replace a terminal outcome, or persistence failure.
    pub async fn finish_mesh_invocation(
        &self,
        ticket: &InvocationTicket,
        terminal: MeshInvocationTerminal,
    ) -> HostResult<()> {
        self.apply_mutation(|snapshot| {
            let record = snapshot
                .mesh_invocations
                .iter_mut()
                .find(|record| record.ticket == *ticket)
                .ok_or_else(|| invocation_state_error("unknown mesh invocation ticket"))?;
            record
                .validate_terminal(&terminal)
                .map_err(|error| invocation_state_error(&error.to_string()))?;
            if let Some(previous) = &record.terminal {
                if previous == &terminal {
                    return Ok(());
                }
                return Err(invocation_state_error(
                    "refusing to overwrite a recorded mesh invocation outcome",
                ));
            }
            record.terminal = Some(terminal);
            record.finished_at = Some(Utc::now());
            Ok(())
        })
        .await
        .map_err(|error| HostError::Unavailable(error.to_string()))
    }

    /// Read one retained origin reservation without inferring execution effects.
    pub async fn mesh_invocation_record(
        &self,
        operation_id: &str,
        attempt_id: Option<u64>,
    ) -> Option<MeshInvocationRecord> {
        self.state
            .read()
            .await
            .mesh_invocations
            .iter()
            .rev()
            .find(|record| {
                record.ticket.operation_id == operation_id
                    && attempt_id.is_none_or(|id| record.ticket.attempt_id == id)
            })
            .cloned()
    }

    /// Select local or forwarding evidence under one snapshot read.
    ///
    /// Latest means the greatest shared attempt generation. Exact lookup never
    /// substitutes evidence for another local or remote attempt. Liveness is a
    /// separate current-process observation supplied by the host handler.
    pub async fn invocation_observation(
        &self,
        operation_id: &str,
        attempt_id: Option<u64>,
    ) -> InvocationQueryResponse {
        let snapshot = self.state.read().await;
        let local = snapshot
            .invocations
            .iter()
            .filter(|record| {
                record.ticket.operation_id == operation_id
                    && attempt_id.is_none_or(|id| record.ticket.attempt_id == id)
            })
            .max_by_key(|record| record.ticket.attempt_id);
        let mesh = snapshot
            .mesh_invocations
            .iter()
            .filter(|record| {
                record.ticket.operation_id == operation_id
                    && attempt_id.is_none_or(|id| record.ticket.attempt_id == id)
            })
            .max_by_key(|record| record.ticket.attempt_id);
        let mesh_is_latest = mesh.is_some_and(|mesh| {
            local.is_none_or(|local| mesh.ticket.attempt_id > local.ticket.attempt_id)
        });
        InvocationQueryResponse {
            invocation: if mesh_is_latest { None } else { local.cloned() },
            mesh_invocation: if mesh_is_latest { mesh.cloned() } else { None },
            host_job_active: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        InvocationAdmission, InvocationFinalization, InvocationOutcome, InvocationTerminal,
    };
    use fcp_kernel::{ConnectorId, InvokeRequest, OperationId, RequestId, ZoneId};
    use fcp_prelude::CapabilityToken;

    fn request(id: &str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(id),
            connector_id: ConnectorId::from_static("fcp.test.mesh-origin:utility:1.0.0"),
            operation: OperationId::from_static("send"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"message": "private-mesh-input", "count": 1}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some("private-mesh-idempotency-key".to_string()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn intent(request: &InvokeRequest, principal: Option<&str>) -> MeshInvocationIntent {
        MeshInvocationIntent::from_request(
            request,
            "origin-node",
            "executor-one",
            None,
            principal,
            Utc::now() + chrono::Duration::seconds(60),
        )
        .unwrap()
    }

    fn local_admission(request: &InvokeRequest) -> InvocationAdmission {
        InvocationAdmission {
            operation_id: request.id.to_string(),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            zone_id: request.zone_id.to_string(),
            principal: "owner".to_string(),
            correlation_id: None,
            deadline_at: Utc::now() + chrono::Duration::seconds(60),
            idempotency: InvocationIdempotency::from_request(request, "owner").unwrap(),
            transport_idempotency: InvocationIdempotency::from_relay_request(request, None)
                .unwrap(),
        }
    }

    fn terminal(outcome: MeshInvocationOutcome) -> MeshInvocationTerminal {
        MeshInvocationTerminal {
            outcome,
            http_status: match outcome {
                MeshInvocationOutcome::Succeeded | MeshInvocationOutcome::ConnectorError => 200,
                MeshInvocationOutcome::NotDelivered => 503,
                MeshInvocationOutcome::OutcomeUnknown => 502,
            },
            duration_ms: 7,
            receipt_id: None,
        }
    }

    async fn complete_local(store: &HostAdminStateStore, ticket: &InvocationTicket) {
        store
            .finish_invocation(
                ticket,
                InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: None,
                    duration_ms: 1,
                    http_status: 200,
                },
            )
            .await
            .unwrap();
        store
            .record_invocation_finalization(
                ticket,
                InvocationFinalization {
                    response_http_status: Some(200),
                    ..InvocationFinalization::default()
                },
            )
            .await
            .unwrap();
    }

    #[derive(Clone, Copy, Debug)]
    enum EntryMode {
        Local,
        VerifiedMesh,
        OpaqueMesh,
    }

    const CROSS_MODE_PAIRS: [(EntryMode, EntryMode); 4] = [
        (EntryMode::Local, EntryMode::OpaqueMesh),
        (EntryMode::OpaqueMesh, EntryMode::Local),
        (EntryMode::VerifiedMesh, EntryMode::OpaqueMesh),
        (EntryMode::OpaqueMesh, EntryMode::VerifiedMesh),
    ];

    async fn admit_entry(
        store: &HostAdminStateStore,
        source: &InvokeRequest,
        mode: EntryMode,
    ) -> HostResult<InvocationTicket> {
        match mode {
            EntryMode::Local => store.admit_invocation(local_admission(source)).await,
            EntryMode::VerifiedMesh => {
                store
                    .reserve_mesh_invocation(intent(source, Some("owner")))
                    .await
            }
            EntryMode::OpaqueMesh => store.reserve_mesh_invocation(intent(source, None)).await,
        }
    }

    async fn complete_entry(
        store: &HostAdminStateStore,
        ticket: &InvocationTicket,
        mode: EntryMode,
    ) {
        if matches!(mode, EntryMode::Local) {
            complete_local(store, ticket).await;
        } else {
            store
                .observe_mesh_invocation(
                    ticket,
                    "executor-one",
                    MeshInvocationObservation::ResponseObserved { http_status: 200 },
                )
                .await
                .unwrap();
            store
                .finish_mesh_invocation(ticket, terminal(MeshInvocationOutcome::Succeeded))
                .await
                .unwrap();
        }
    }

    #[test]
    fn relay_binding_is_payload_free_and_never_claims_verified_authority() {
        let source = request("initial");
        let relay = intent(&source, None);
        let verified = intent(&source, Some("owner"));
        assert!(matches!(
            relay.identity,
            MeshInvocationIdentity::TokenBoundRelay { .. }
        ));
        assert_eq!(
            verified.identity,
            MeshInvocationIdentity::VerifiedPrincipal {
                principal: "owner".to_string()
            },
        );
        assert_ne!(
            relay.idempotency.as_ref().unwrap().scope_digest,
            verified.idempotency.as_ref().unwrap().scope_digest,
        );
        assert_ne!(
            relay.idempotency.as_ref().unwrap().effect_digest,
            verified.idempotency.as_ref().unwrap().effect_digest,
            "opaque relay effects also bind the asserted identity constraint",
        );
        assert_eq!(
            verified.idempotency,
            InvocationIdempotency::from_request(&source, "owner").unwrap(),
        );

        let mut retry = source.clone();
        retry.id = RequestId::new("new-request-id");
        retry.deadline_ms = Some(10);
        retry.lease_seq = Some(999);
        assert_eq!(relay.idempotency, intent(&retry, None).idempotency);
        retry.input = serde_json::json!({"message": "different effects"});
        assert_ne!(
            relay.idempotency.as_ref().unwrap().effect_digest,
            intent(&retry, None).idempotency.unwrap().effect_digest,
        );
        let asserted = MeshInvocationIntent::from_request(
            &source,
            "origin-node",
            "executor-one",
            Some("owner"),
            None,
            relay.deadline_at,
        )
        .unwrap();
        assert!(matches!(
            asserted.identity,
            MeshInvocationIdentity::TokenBoundRelay { .. }
        ));
        assert_eq!(
            asserted.idempotency.as_ref().unwrap().scope_digest,
            relay.idempotency.as_ref().unwrap().scope_digest,
        );
        assert_ne!(
            asserted.idempotency.as_ref().unwrap().effect_digest,
            relay.idempotency.as_ref().unwrap().effect_digest,
        );
        assert!(
            MeshInvocationIntent::from_request(
                &source,
                "origin-node",
                "executor-one",
                Some("other"),
                Some("owner"),
                relay.deadline_at,
            )
            .is_err()
        );
        let json = serde_json::to_string(&relay).unwrap();
        for secret in [
            "private-mesh-input",
            "private-mesh-idempotency-key",
            "capability_token",
        ] {
            assert!(!json.contains(secret));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn mesh_reservation_recovers_ambiguity_and_fences_local_route_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let source = request("mesh-origin");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let ticket = store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        assert_eq!(ticket.attempt_id, 1);
        assert_eq!(
            store
                .mesh_invocation_record("mesh-origin", None)
                .await
                .unwrap()
                .durable,
            cfg!(unix),
        );
        store
            .observe_mesh_invocation(
                &ticket,
                "executor-one",
                MeshInvocationObservation::NotDelivered,
            )
            .await
            .unwrap();
        store
            .select_mesh_invocation_target(&ticket, "executor-two")
            .await
            .unwrap();
        drop(store);

        let reopened = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let record = reopened
            .mesh_invocation_record("mesh-origin", None)
            .await
            .unwrap();
        assert_eq!(record.ticket, ticket);
        assert_eq!(record.attempts.len(), 2);
        assert_eq!(
            record.attempts[0].observation,
            Some(MeshInvocationObservation::NotDelivered),
        );
        assert_eq!(
            record.attempts[1].observation,
            Some(MeshInvocationObservation::OutcomeUnknown),
        );
        assert_eq!(
            record.terminal.as_ref().unwrap().outcome,
            MeshInvocationOutcome::OutcomeUnknown,
        );
        assert!(
            reopened
                .admit_invocation(local_admission(&source))
                .await
                .is_err()
        );
        let mut retry = source.clone();
        retry.id = RequestId::new("new-mesh-request");
        let refusal = reopened
            .reserve_mesh_invocation(intent(&retry, None))
            .await
            .unwrap_err();
        assert!(refusal.to_string().contains("mesh-origin"));
        assert!(refusal.to_string().contains("attempt_id=1"));
        assert!(
            reopened
                .finish_mesh_invocation(&ticket, terminal(MeshInvocationOutcome::NotDelivered))
                .await
                .is_err()
        );
        drop(reopened);

        let reopened = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        assert_eq!(
            reopened
                .mesh_invocation_record("mesh-origin", None)
                .await
                .unwrap(),
            record,
        );
        let persisted = std::fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("private-mesh-input"));
        assert!(!persisted.contains("private-mesh-idempotency-key"));
    }

    #[fcp_async_core::runtime::test]
    async fn proven_non_delivery_recovers_without_inventing_execution() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let source = request("never-delivered");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let ticket = store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        store
            .observe_mesh_invocation(
                &ticket,
                "executor-one",
                MeshInvocationObservation::NotDelivered,
            )
            .await
            .unwrap();
        // Crash after durable proof but before a final HTTP response.
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        let record = reopened
            .mesh_invocation_record("never-delivered", None)
            .await
            .unwrap();
        assert_eq!(
            record.terminal.unwrap().outcome,
            MeshInvocationOutcome::NotDelivered,
        );
        let retry = reopened
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        assert!(retry.attempt_id > ticket.attempt_id);
    }

    #[fcp_async_core::runtime::test]
    async fn verified_key_reservations_are_atomic_across_local_and_mesh_admission() {
        for mesh_first in [false, true] {
            let store = Arc::new(HostAdminStateStore::new());
            let local = request("local");
            let mut remote = local.clone();
            remote.id = RequestId::new("remote");
            let mesh_intent = intent(&remote, Some("owner"));
            if mesh_first {
                let (mesh, local) = futures_util::future::join(
                    store.reserve_mesh_invocation(mesh_intent),
                    store.admit_invocation(local_admission(&local)),
                )
                .await;
                assert!(mesh.is_ok());
                assert!(local.is_err());
            } else {
                let (local, mesh) = futures_util::future::join(
                    store.admit_invocation(local_admission(&local)),
                    store.reserve_mesh_invocation(mesh_intent),
                )
                .await;
                assert!(local.is_ok());
                assert!(mesh.is_err());
            }
            let snapshot = store.state.read().await;
            assert_eq!(
                snapshot.invocations.len() + snapshot.mesh_invocations.len(),
                1
            );
            assert_eq!(snapshot.next_invocation_attempt_id, 2);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn latest_and_exact_queries_use_one_shared_attempt_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let source = request("shared-id");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let local = store
            .admit_invocation(local_admission(&source))
            .await
            .unwrap();
        complete_local(&store, &local).await;
        let mesh = store
            .reserve_mesh_invocation(intent(&source, Some("owner")))
            .await
            .unwrap();
        assert!(mesh.attempt_id > local.attempt_id);
        let latest = store.invocation_observation("shared-id", None).await;
        assert!(latest.invocation.is_none());
        assert_eq!(latest.mesh_invocation.unwrap().ticket, mesh);
        let historical = store
            .invocation_observation("shared-id", Some(local.attempt_id))
            .await;
        assert_eq!(historical.invocation.unwrap().ticket, local);
        assert!(historical.mesh_invocation.is_none());
        assert!(!historical.host_job_active);
        let absent = store
            .invocation_observation("different-id", Some(mesh.attempt_id))
            .await;
        assert!(absent.invocation.is_none());
        assert!(absent.mesh_invocation.is_none());

        store
            .observe_mesh_invocation(
                &mesh,
                "executor-one",
                MeshInvocationObservation::ResponseObserved { http_status: 200 },
            )
            .await
            .unwrap();
        let mut success = terminal(MeshInvocationOutcome::Succeeded);
        success.receipt_id = Some("remote-receipt".to_string());
        store
            .finish_mesh_invocation(&mesh, success.clone())
            .await
            .unwrap();
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        let latest = reopened.invocation_observation("shared-id", None).await;
        let record = latest.mesh_invocation.unwrap();
        assert_eq!(record.ticket, mesh);
        assert_eq!(record.terminal, Some(success));
        assert!(latest.invocation.is_none());
        assert!(
            reopened
                .invocation_observation("shared-id", Some(local.attempt_id))
                .await
                .invocation
                .is_some()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn transport_evidence_is_monotone_and_signed_errors_remain_uncertain() {
        let store = HostAdminStateStore::new();
        let source = request("monotone");
        let ticket = store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        assert!(
            store
                .select_mesh_invocation_target(&ticket, "executor-two")
                .await
                .is_err()
        );
        assert!(
            store
                .observe_mesh_invocation(
                    &ticket,
                    "wrong-target",
                    MeshInvocationObservation::NotDelivered,
                )
                .await
                .is_err()
        );
        assert!(
            store
                .observe_mesh_invocation(
                    &ticket,
                    "executor-one",
                    MeshInvocationObservation::ResponseObserved { http_status: 999 },
                )
                .await
                .is_err()
        );
        store
            .observe_mesh_invocation(
                &ticket,
                "executor-one",
                MeshInvocationObservation::ResponseObserved { http_status: 500 },
            )
            .await
            .unwrap();
        assert!(
            store
                .finish_mesh_invocation(&ticket, terminal(MeshInvocationOutcome::ConnectorError))
                .await
                .is_err()
        );
        assert!(
            store
                .finish_mesh_invocation(&ticket, terminal(MeshInvocationOutcome::NotDelivered))
                .await
                .is_err()
        );
        assert!(
            store
                .observe_mesh_invocation(
                    &ticket,
                    "executor-one",
                    MeshInvocationObservation::NotDelivered,
                )
                .await
                .is_err()
        );
        let unknown = terminal(MeshInvocationOutcome::OutcomeUnknown);
        store
            .finish_mesh_invocation(&ticket, unknown.clone())
            .await
            .unwrap();
        store
            .finish_mesh_invocation(&ticket, unknown)
            .await
            .unwrap();
        assert!(
            store
                .select_mesh_invocation_target(&ticket, "executor-two")
                .await
                .is_err()
        );
        assert!(
            store
                .finish_mesh_invocation(&ticket, terminal(MeshInvocationOutcome::Succeeded))
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn unfinalized_reply_stays_unknown_after_restart() {
        for http_status in [200, 403, 500] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.json");
            let source = request("observed-reply");
            let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
            let ticket = store
                .reserve_mesh_invocation(intent(&source, Some("owner")))
                .await
                .unwrap();
            store
                .observe_mesh_invocation(
                    &ticket,
                    "executor-one",
                    MeshInvocationObservation::ResponseObserved { http_status },
                )
                .await
                .unwrap();
            drop(store);
            let reopened = HostAdminStateStore::with_state_path(path).unwrap();
            let record = reopened
                .mesh_invocation_record("observed-reply", None)
                .await
                .unwrap();
            assert_eq!(
                record.attempts[0].observation,
                Some(MeshInvocationObservation::ResponseObserved { http_status }),
            );
            assert_eq!(
                record.terminal.unwrap().outcome,
                MeshInvocationOutcome::OutcomeUnknown,
            );
            let mut new_id = source.clone();
            new_id.id = RequestId::new("same-effects-new-id");
            assert!(
                reopened
                    .admit_invocation(local_admission(&new_id))
                    .await
                    .is_err()
            );
            assert!(
                reopened
                    .reserve_mesh_invocation(intent(&new_id, Some("owner")))
                    .await
                    .is_err()
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn failed_mesh_persistence_does_not_admit_and_fences_all_writes() {
        let directory = tempfile::tempdir().unwrap();
        let obstruction = directory.path().join("not-a-directory");
        std::fs::write(&obstruction, b"occupied").unwrap();
        let mut store =
            HostAdminStateStore::with_state_path(obstruction.join("state.json")).unwrap();
        let source = request("persistence-failed");
        assert!(
            store
                .reserve_mesh_invocation(intent(&source, None))
                .await
                .is_err()
        );
        assert!(
            store
                .mesh_invocation_record("persistence-failed", None)
                .await
                .is_none()
        );
        assert_eq!(store.state.read().await.next_invocation_attempt_id, 1);
        store.state_path = Some(directory.path().join("repaired.json"));
        assert!(
            store
                .admit_invocation(local_admission(&source))
                .await
                .is_err()
        );
        assert!(
            store
                .reserve_mesh_invocation(intent(&source, None))
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn retention_is_shared_and_never_discards_uncertain_forwards() {
        let store = HostAdminStateStore::new();
        let source = request("uncertain");
        let ticket = store
            .reserve_mesh_invocation(intent(&source, Some("owner")))
            .await
            .unwrap();
        let template = store
            .mesh_invocation_record("uncertain", None)
            .await
            .unwrap();
        {
            let mut snapshot = store.state.write().await;
            for index in 1..MAX_RETAINED_INVOCATIONS {
                let mut record = template.clone();
                record.ticket.operation_id = format!("retained-{index}");
                record
                    .intent
                    .operation_id
                    .clone_from(&record.ticket.operation_id);
                record.intent.idempotency = None;
                record.intent.transport_idempotency = None;
                record.ticket.attempt_id = u64::try_from(index).unwrap() + 1;
                snapshot.mesh_invocations.push(record);
            }
            snapshot.next_invocation_attempt_id =
                u64::try_from(MAX_RETAINED_INVOCATIONS).unwrap() + 1;
        }
        let mut independent = request("independent");
        independent.idempotency_key = None;
        assert!(
            store
                .admit_invocation(local_admission(&independent))
                .await
                .is_err()
        );
        assert!(
            store
                .reserve_mesh_invocation(intent(&independent, None))
                .await
                .is_err()
        );
        {
            let mut snapshot = store.state.write().await;
            let completed = &mut snapshot.mesh_invocations[1];
            completed.attempts[0].observation = Some(MeshInvocationObservation::NotDelivered);
            completed.terminal = Some(terminal(MeshInvocationOutcome::NotDelivered));
            completed.finished_at = Some(Utc::now());
        }
        let local = store
            .admit_invocation(local_admission(&independent))
            .await
            .unwrap();
        assert!(local.attempt_id > ticket.attempt_id);
        assert!(
            store
                .mesh_invocation_record("retained-1", None)
                .await
                .is_none()
        );
        assert_eq!(
            store
                .mesh_invocation_record("uncertain", None)
                .await
                .unwrap()
                .ticket,
            ticket
        );
        assert!(
            store
                .mesh_invocation_record("retained-2", None)
                .await
                .is_some()
        );
        assert_eq!(
            store.state.read().await.mesh_invocations.len() + 1,
            MAX_RETAINED_INVOCATIONS,
        );
    }

    #[fcp_async_core::runtime::test]
    async fn recovery_rejects_cross_kind_generation_and_scope_corruption() {
        let store = HostAdminStateStore::new();
        let local_request = request("local");
        let local = store
            .admit_invocation(local_admission(&local_request))
            .await
            .unwrap();
        let mut remote_request = local_request.clone();
        remote_request.id = RequestId::new("remote");
        remote_request.idempotency_key = None;
        let mesh = store
            .reserve_mesh_invocation(intent(&remote_request, Some("owner")))
            .await
            .unwrap();
        let original = store.state.read().await.clone();

        let mut duplicate_generation = original.clone();
        duplicate_generation.mesh_invocations[0].ticket.attempt_id = local.attempt_id;
        assert!(
            duplicate_generation
                .recover_invocations_after_restart(Utc::now())
                .is_err()
        );

        let mut duplicate_identifier = original.clone();
        duplicate_identifier.mesh_invocations[0]
            .ticket
            .operation_id
            .clone_from(&local.operation_id);
        duplicate_identifier.mesh_invocations[0]
            .intent
            .operation_id
            .clone_from(&local.operation_id);
        assert!(
            duplicate_identifier
                .recover_invocations_after_restart(Utc::now())
                .is_err()
        );

        let mut duplicate_scope = original.clone();
        duplicate_scope.mesh_invocations[0].intent.idempotency =
            original.invocations[0].admission.idempotency.clone();
        assert!(
            duplicate_scope
                .recover_invocations_after_restart(Utc::now())
                .is_err()
        );

        let mut invented_non_delivery = original;
        invented_non_delivery.mesh_invocations[0].terminal =
            Some(terminal(MeshInvocationOutcome::NotDelivered));
        invented_non_delivery.mesh_invocations[0].finished_at = Some(Utc::now());
        assert!(
            invented_non_delivery
                .recover_invocations_after_restart(Utc::now())
                .is_err()
        );
        assert!(mesh.attempt_id > local.attempt_id);
    }

    #[fcp_async_core::runtime::test]
    async fn changing_asserted_identity_cannot_escape_an_unresolved_relay_key() {
        let store = HostAdminStateStore::new();
        let source = request("opaque-owner");
        let ticket = store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        let mut retry = source.clone();
        retry.id = RequestId::new("new-opaque-id");
        let changed_assertion = MeshInvocationIntent::from_request(
            &retry,
            "origin-node",
            "executor-one",
            Some("owner"),
            None,
            Utc::now() + chrono::Duration::seconds(60),
        )
        .unwrap();
        let refusal = store
            .reserve_mesh_invocation(changed_assertion)
            .await
            .unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("different mesh invocation effects")
        );
        assert!(refusal.to_string().contains("opaque-owner"));
        assert!(
            store
                .mesh_invocation_record("new-opaque-id", None)
                .await
                .is_none()
        );
        assert_eq!(
            store
                .mesh_invocation_record("opaque-owner", None)
                .await
                .unwrap()
                .ticket,
            ticket
        );
    }

    #[fcp_async_core::runtime::test]
    async fn opaque_uncertainty_cannot_exhaust_verified_invocation_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let source = request("opaque-first");
        store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        let template = store
            .mesh_invocation_record("opaque-first", None)
            .await
            .unwrap();
        {
            let mut snapshot = store.state.write().await;
            for index in 1..MAX_UNVERIFIED_MESH_INVOCATIONS {
                let mut record = template.clone();
                record.ticket.operation_id = format!("opaque-{index}");
                record
                    .intent
                    .operation_id
                    .clone_from(&record.ticket.operation_id);
                record.intent.idempotency = None;
                record.ticket.attempt_id = u64::try_from(index).unwrap() + 1;
                snapshot.mesh_invocations.push(record);
            }
            snapshot.next_invocation_attempt_id =
                u64::try_from(MAX_UNVERIFIED_MESH_INVOCATIONS).unwrap() + 1;
        }
        let mut extra = source.clone();
        extra.id = RequestId::new("extra-opaque");
        extra.idempotency_key = None;
        let denied = store
            .reserve_mesh_invocation(intent(&extra, None))
            .await
            .unwrap_err();
        assert!(
            denied
                .to_string()
                .contains("unverified mesh invocation capacity")
        );
        assert!(
            store
                .mesh_invocation_record("extra-opaque", None)
                .await
                .is_none()
        );

        let mut trusted_local = extra.clone();
        trusted_local.id = RequestId::new("trusted-local");
        assert!(
            store
                .admit_invocation(local_admission(&trusted_local))
                .await
                .is_ok()
        );
        let mut trusted_remote = extra;
        trusted_remote.id = RequestId::new("trusted-remote");
        assert!(
            store
                .reserve_mesh_invocation(intent(&trusted_remote, Some("owner")))
                .await
                .is_ok()
        );
        drop(store);

        // Persisted trusted work also commits the saturated opaque history.
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        assert_eq!(
            reopened
                .mesh_invocation_record("opaque-first", None)
                .await
                .unwrap()
                .terminal
                .unwrap()
                .outcome,
            MeshInvocationOutcome::OutcomeUnknown,
        );
        let mut retry = source;
        retry.id = RequestId::new("still-bounded-after-restart");
        retry.idempotency_key = None;
        assert!(
            reopened
                .reserve_mesh_invocation(intent(&retry, None))
                .await
                .is_err()
        );
        retry.id = RequestId::new("trusted-after-restart");
        assert!(
            reopened
                .admit_invocation(local_admission(&retry))
                .await
                .is_ok()
        );
    }

    #[test]
    fn exact_token_alias_preserves_the_existing_relay_namespace() {
        use super::super::{invocation_effect_digest, invocation_idempotency_digest};

        let source = request("alias-format");
        // Freeze the first persisted relay layout: assertions affect effects,
        // never the scope. Verified aliases must collide with that old layout.
        let capability_digest = invocation_idempotency_digest(
            "fcp.host.mesh.relay.capability.v1",
            &source.capability_token.raw().to_cbor().unwrap(),
        )
        .unwrap();
        let legacy_binding = InvocationIdempotency {
            scope_digest: invocation_idempotency_digest(
                "fcp.host.mesh.relay.scope.v1",
                &(
                    source.zone_id.as_str(),
                    source.connector_id.as_str(),
                    source.operation.as_str(),
                    capability_digest.as_str(),
                    source.idempotency_key.as_deref().unwrap(),
                ),
            )
            .unwrap(),
            effect_digest: invocation_idempotency_digest(
                "fcp.host.mesh.relay.effect.v1",
                &(invocation_effect_digest(&source).unwrap(), None::<&str>),
            )
            .unwrap(),
        };
        assert_eq!(
            InvocationIdempotency::from_relay_request(&source, None).unwrap(),
            Some(legacy_binding.clone()),
        );
        assert_eq!(
            intent(&source, None).idempotency,
            Some(legacy_binding.clone())
        );
        assert_eq!(
            intent(&source, Some("owner")).transport_idempotency,
            Some(legacy_binding.clone()),
        );
        assert_eq!(
            local_admission(&source).transport_idempotency,
            Some(legacy_binding.clone()),
        );
        let asserted = InvocationIdempotency::from_relay_request(&source, Some("owner"))
            .unwrap()
            .unwrap();
        assert_eq!(asserted.scope_digest, legacy_binding.scope_digest);
        assert_ne!(asserted.effect_digest, legacy_binding.effect_digest);
        let mut no_key = source;
        no_key.idempotency_key = None;
        assert!(
            InvocationIdempotency::from_relay_request(&no_key, None)
                .unwrap()
                .is_none()
        );
        assert!(
            intent(&no_key, Some("owner"))
                .transport_idempotency
                .is_none()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn unresolved_exact_token_keys_fence_every_mode_change_after_restart() {
        for (original_mode, retry_mode) in CROSS_MODE_PAIRS {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.json");
            let source = request("original-mode");
            let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
            let ticket = admit_entry(&store, &source, original_mode).await.unwrap();
            let mut retry = source.clone();
            retry.id = RequestId::new("new-id-other-mode");
            let refusal = admit_entry(&store, &retry, retry_mode).await.unwrap_err();
            assert!(refusal.to_string().contains(&ticket.operation_id));
            assert!(
                refusal
                    .to_string()
                    .contains(&format!("attempt_id={}", ticket.attempt_id))
            );
            assert_eq!(store.state.read().await.next_invocation_attempt_id, 2);
            drop(store);

            let reopened = HostAdminStateStore::with_state_path(path).unwrap();
            let refusal = admit_entry(&reopened, &retry, retry_mode)
                .await
                .unwrap_err();
            assert!(refusal.to_string().contains(&ticket.operation_id));
            assert!(refusal.to_string().contains("unresolved"));
            let observation = reopened
                .invocation_observation(&ticket.operation_id, Some(ticket.attempt_id))
                .await;
            match original_mode {
                EntryMode::Local => {
                    assert_eq!(
                        observation.invocation.unwrap().terminal.unwrap().outcome,
                        InvocationOutcome::OutcomeUnknown,
                    );
                }
                EntryMode::VerifiedMesh | EntryMode::OpaqueMesh => {
                    let record = observation.mesh_invocation.unwrap();
                    assert_eq!(
                        record.terminal.unwrap().outcome,
                        MeshInvocationOutcome::OutcomeUnknown,
                    );
                    if matches!(original_mode, EntryMode::OpaqueMesh) {
                        // First-version opaque records have no alias field.
                        assert!(record.intent.transport_idempotency.is_none());
                    }
                }
            }
            assert_eq!(reopened.state.read().await.next_invocation_attempt_id, 2);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_cross_mode_alias_reservations_have_one_owner() {
        for (first_mode, second_mode) in CROSS_MODE_PAIRS {
            let store = HostAdminStateStore::new();
            let first_request = request("concurrent-first");
            let mut second_request = first_request.clone();
            second_request.id = RequestId::new("concurrent-second");
            let (first, second) = futures_util::future::join(
                admit_entry(&store, &first_request, first_mode),
                admit_entry(&store, &second_request, second_mode),
            )
            .await;
            assert_ne!(first.is_ok(), second.is_ok());
            let (ticket, refusal) = match (first, second) {
                (Ok(ticket), Err(refusal)) | (Err(refusal), Ok(ticket)) => (ticket, refusal),
                _ => panic!("exact-token aliases admitted zero or two owners"),
            };
            assert!(refusal.to_string().contains(&ticket.operation_id));
            assert!(
                refusal
                    .to_string()
                    .contains(&format!("attempt_id={}", ticket.attempt_id))
            );
            let snapshot = store.state.read().await;
            assert_eq!(
                snapshot.invocations.len() + snapshot.mesh_invocations.len(),
                1
            );
            assert_eq!(snapshot.next_invocation_attempt_id, 2);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn completed_cross_mode_bindings_reject_changed_effects_but_allow_same_effects() {
        for (original_mode, retry_mode) in CROSS_MODE_PAIRS {
            let store = HostAdminStateStore::new();
            let source = request("completed-binding");
            let ticket = admit_entry(&store, &source, original_mode).await.unwrap();
            complete_entry(&store, &ticket, original_mode).await;
            let mut retry = source.clone();
            retry.id = RequestId::new("changed-effects");
            retry.input = serde_json::json!({"message": "different effect"});
            let refusal = admit_entry(&store, &retry, retry_mode).await.unwrap_err();
            assert!(refusal.to_string().contains("different"));
            assert!(refusal.to_string().contains(&ticket.operation_id));
            retry.input = source.input;
            let next = admit_entry(&store, &retry, retry_mode).await.unwrap();
            assert!(next.attempt_id > ticket.attempt_id);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn a_completed_semantic_match_does_not_skip_the_transport_alias() {
        let store = HostAdminStateStore::new();
        let source = request("completed-principal");
        let original = local_admission(&source);
        let ticket = store.admit_invocation(original.clone()).await.unwrap();
        complete_local(&store, &ticket).await;
        let mut retry = source.clone();
        retry.id = RequestId::new("same-principal-changed-header");
        let changed_assertion = MeshInvocationIntent::from_request(
            &retry,
            "origin-node",
            "executor-one",
            Some("owner"),
            Some("owner"),
            Utc::now() + chrono::Duration::seconds(60),
        )
        .unwrap();
        assert_eq!(changed_assertion.idempotency, original.idempotency);
        let refusal = store
            .reserve_mesh_invocation(changed_assertion)
            .await
            .unwrap_err();
        assert!(refusal.to_string().contains("different invocation effects"));
        assert!(refusal.to_string().contains(&ticket.operation_id));

        // A matching completed primary also cannot hide another mode's
        // currently unresolved exact-token reservation.
        retry.id = RequestId::new("opaque-pending");
        let opaque = store
            .reserve_mesh_invocation(intent(&retry, None))
            .await
            .unwrap();
        retry.id = RequestId::new("verified-after-opaque");
        let refusal = store
            .reserve_mesh_invocation(intent(&retry, Some("owner")))
            .await
            .unwrap_err();
        assert!(refusal.to_string().contains("unresolved mesh forward"));
        assert!(refusal.to_string().contains(&opaque.operation_id));
    }

    #[fcp_async_core::runtime::test]
    async fn recovery_checks_transport_alias_overlaps_and_effects_across_all_modes() {
        for (original_mode, retry_mode) in CROSS_MODE_PAIRS {
            let store = HostAdminStateStore::new();
            let source = request("historical-completion");
            let first = admit_entry(&store, &source, original_mode).await.unwrap();
            complete_entry(&store, &first, original_mode).await;
            let mut retry = source;
            retry.id = RequestId::new("current-pending");
            let second = admit_entry(&store, &retry, retry_mode).await.unwrap();
            let original = store.state.read().await.clone();
            let mut valid = original.clone();
            assert!(valid.recover_invocations_after_restart(Utc::now()).is_ok());

            let mut overlap = original.clone();
            if let Some(record) = overlap
                .invocations
                .iter_mut()
                .find(|record| record.ticket == first)
            {
                record.terminal = None;
                record.finished_at = None;
                record.finalization = None;
            } else {
                let record = overlap
                    .mesh_invocations
                    .iter_mut()
                    .find(|record| record.ticket == first)
                    .unwrap();
                record.terminal = None;
                record.finished_at = None;
                // A successful reply without finalization becomes unknown.
            }
            let refusal = overlap
                .recover_invocations_after_restart(Utc::now())
                .unwrap_err();
            assert!(refusal.to_string().contains("transport idempotency scope"));
            assert!(refusal.to_string().contains("overlapping unresolved"));

            let mut conflicting_effects = original;
            let binding = if let Some(record) = conflicting_effects
                .invocations
                .iter_mut()
                .find(|record| record.ticket == second)
            {
                record.admission.transport_idempotency.as_mut().unwrap()
            } else {
                let record = conflicting_effects
                    .mesh_invocations
                    .iter_mut()
                    .find(|record| record.ticket == second)
                    .unwrap();
                if record.intent.has_verified_scope() {
                    record.intent.transport_idempotency.as_mut().unwrap()
                } else {
                    record.intent.idempotency.as_mut().unwrap()
                }
            };
            binding.effect_digest = if binding.effect_digest == "0".repeat(64) {
                "1".repeat(64)
            } else {
                "0".repeat(64)
            };
            let refusal = conflicting_effects
                .recover_invocations_after_restart(Utc::now())
                .unwrap_err();
            assert!(
                refusal
                    .to_string()
                    .contains("transport idempotency effects")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn malformed_transport_alias_linkage_is_rejected_on_admission_and_recovery() {
        for mode in [
            EntryMode::Local,
            EntryMode::VerifiedMesh,
            EntryMode::OpaqueMesh,
        ] {
            let store = HostAdminStateStore::new();
            let source = request("invalid-alias");
            let refusal = match mode {
                EntryMode::Local => {
                    let mut admission = local_admission(&source);
                    admission.idempotency = None;
                    store.admit_invocation(admission).await
                }
                EntryMode::VerifiedMesh => {
                    let mut invalid = intent(&source, Some("owner"));
                    invalid.idempotency = None;
                    store.reserve_mesh_invocation(invalid).await
                }
                EntryMode::OpaqueMesh => {
                    let mut invalid = intent(&source, None);
                    invalid.transport_idempotency = invalid.idempotency.clone();
                    store.reserve_mesh_invocation(invalid).await
                }
            };
            assert!(refusal.is_err());
            assert_eq!(store.state.read().await.next_invocation_attempt_id, 1);
            admit_entry(&store, &source, mode).await.unwrap();
            let mut persisted = store.state.read().await.clone();
            match mode {
                EntryMode::Local => persisted.invocations[0].admission.idempotency = None,
                EntryMode::VerifiedMesh => persisted.mesh_invocations[0].intent.idempotency = None,
                EntryMode::OpaqueMesh => {
                    let intent = &mut persisted.mesh_invocations[0].intent;
                    intent.transport_idempotency = intent.idempotency.clone();
                }
            }
            assert!(
                persisted
                    .recover_invocations_after_restart(Utc::now())
                    .is_err()
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn historical_verified_records_remain_readable_without_invented_aliases() {
        for mode in [EntryMode::Local, EntryMode::VerifiedMesh] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.json");
            let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
            let source = request("legacy-verified");
            let ticket = match mode {
                EntryMode::Local => {
                    let mut admission = local_admission(&source);
                    admission.transport_idempotency = None;
                    store.admit_invocation(admission).await.unwrap()
                }
                EntryMode::VerifiedMesh => {
                    let mut legacy = intent(&source, Some("owner"));
                    legacy.transport_idempotency = None;
                    store.reserve_mesh_invocation(legacy).await.unwrap()
                }
                EntryMode::OpaqueMesh => unreachable!(),
            };
            assert!(
                !std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("transport_idempotency")
            );
            drop(store);
            let reopened = HostAdminStateStore::with_state_path(path).unwrap();
            let observation = reopened
                .invocation_observation(&ticket.operation_id, Some(ticket.attempt_id))
                .await;
            if let Some(record) = observation.invocation {
                assert!(record.admission.transport_idempotency.is_none());
            } else {
                assert!(
                    observation
                        .mesh_invocation
                        .unwrap()
                        .intent
                        .transport_idempotency
                        .is_none()
                );
            }
            let mut retry = source;
            retry.id = RequestId::new("legacy-same-principal-new-id");
            let refusal = admit_entry(&reopened, &retry, mode).await.unwrap_err();
            assert!(refusal.to_string().contains("unresolved"));
            assert!(refusal.to_string().contains(&ticket.operation_id));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn admission_and_alternate_limits_fail_before_transport() {
        let store = HostAdminStateStore::new();
        let source = request("bounded");
        let mut expired = intent(&source, None);
        expired.deadline_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(store.reserve_mesh_invocation(expired).await.is_err());
        let mut malformed = intent(&source, None);
        malformed.target_node = "invalid\nnode".to_string();
        assert!(store.reserve_mesh_invocation(malformed).await.is_err());
        assert_eq!(store.state.read().await.next_invocation_attempt_id, 1);
        let ticket = store
            .reserve_mesh_invocation(intent(&source, None))
            .await
            .unwrap();
        {
            let mut snapshot = store.state.write().await;
            let record = &mut snapshot.mesh_invocations[0];
            record.attempts[0].observation = Some(MeshInvocationObservation::NotDelivered);
            for index in 1..MAX_MESH_INVOCATION_TARGETS {
                record.attempts.push(MeshInvocationAttempt {
                    target_node: format!("executor-{index}"),
                    selected_at: Utc::now(),
                    observation: Some(MeshInvocationObservation::NotDelivered),
                });
            }
        }
        assert!(
            store
                .select_mesh_invocation_target(&ticket, "one-too-many")
                .await
                .is_err()
        );
        let record = store.mesh_invocation_record("bounded", None).await.unwrap();
        assert_eq!(record.attempts.len(), MAX_MESH_INVOCATION_TARGETS);
        store
            .finish_mesh_invocation(&ticket, terminal(MeshInvocationOutcome::NotDelivered))
            .await
            .unwrap();
        {
            let mut snapshot = store.state.write().await;
            snapshot.next_invocation_attempt_id = u64::MAX;
        }
        assert!(
            store
                .reserve_mesh_invocation(intent(&source, None))
                .await
                .is_err()
        );
    }
}
