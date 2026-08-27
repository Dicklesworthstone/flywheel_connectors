//! Chat coordination helpers shared by connector implementations.
//!
//! The types in this module model the connector-local part of thread ownership:
//! a stable claim key, a short-lived mention tracker, and a small ownership
//! checker that can be used by tests or in-process connector fixtures. Durable
//! backends such as Agent Mail reservations or mesh gossip can implement
//! [`ThreadOwnershipChecker`] without changing connector call sites.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{ConnectorId, FcpError, ZoneId, async_trait};
use serde::{Deserialize, Serialize};

/// Default chat ownership and mention TTL: five minutes.
pub const DEFAULT_THREAD_OWNERSHIP_TTL: Duration = Duration::from_secs(300);

/// FCP error code used when a peer owns a chat thread.
pub const THREAD_OWNED_BY_PEER_ERROR_CODE: u16 = 4090;

/// FCP error code used when fail-closed coordination cannot decide ownership.
pub const THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE: u16 = 5090;

/// Stable reason returned when Agent Mail cannot decide ownership.
pub const AGENT_MAIL_UNAVAILABLE_REASON: &str = "agent_mail_unavailable";

/// Stable reason returned when the caller cancels chat ownership before a claim.
pub const THREAD_OWNERSHIP_CANCELLED_REASON: &str = "request_cancelled";

/// Prefix used for Agent Mail chat-thread reservation keys.
pub const CHAT_THREAD_RESERVATION_PREFIX: &str = "chat-thread://";

/// Default Agent Mail retry count after the first unavailable claim attempt.
pub const AGENT_MAIL_CLAIM_RETRY_ATTEMPTS: usize = 1;

/// Connector-level policy for chat messages without a native thread id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmMode {
    /// Skip ownership checks for direct messages without a thread id.
    Skip,
    /// Treat the conversation id as both channel and thread id.
    #[default]
    TreatAsThread,
}

/// Backend selected by connector-level chat coordination config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatCoordinationBackend {
    /// Agent Mail exclusive file reservations.
    #[default]
    AgentMail,
    /// Mesh gossip claim propagation.
    MeshGossip,
    /// In-process checker, primarily for fixtures and tests.
    InMemory,
}

/// Reason a connector call site skips chat coordination for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatCoordinationSkipReason {
    /// Coordination is disabled by live config.
    Disabled,
    /// The channel is outside the configured rollout allowlist.
    ChannelNotAllowed,
    /// The message had no thread id and direct-message mode is skip.
    ThreadlessDmSkipped,
}

/// Redaction-safe event type for chat coordination audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatCoordinationAuditEvent {
    /// Connector is about to ask a backend for thread ownership.
    ClaimAttempt,
    /// Backend returned an ownership decision.
    ClaimOutcome,
    /// Connector skipped ownership checks by policy.
    CoordinationSkipped,
    /// Connector executed the outbound send.
    SendExecuted,
    /// Connector denied the outbound send.
    SendDenied,
}

/// Redaction-safe structured audit record for chat coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCoordinationAuditRecord {
    event: ChatCoordinationAuditEvent,
    backend: ChatCoordinationBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimant_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<u16>,
}

impl ChatCoordinationAuditRecord {
    /// Build a redacted claim-attempt record.
    #[must_use]
    pub fn claim_attempt(
        key: &ClaimKey,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
    ) -> Self {
        Self {
            event: ChatCoordinationAuditEvent::ClaimAttempt,
            backend,
            claim_key: Some(key.redacted()),
            channel_id: Some(key.channel_id().redacted()),
            claimant_agent_id: Some(claimant_agent_id.redacted()),
            owner_agent_id: None,
            outcome: None,
            reason: None,
            error_code: None,
        }
    }

    /// Build a redacted claim-outcome record.
    #[must_use]
    pub fn claim_outcome(
        key: &ClaimKey,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
        outcome: &ClaimOutcome,
    ) -> Self {
        let (outcome_label, owner_agent_id, reason, error_code) = match outcome {
            ClaimOutcome::Granted(owner) => ("granted", Some(owner.redacted()), None, None),
            ClaimOutcome::AlreadyOwned(owner) => (
                "already_owned",
                Some(owner.redacted()),
                None,
                Some(THREAD_OWNED_BY_PEER_ERROR_CODE),
            ),
            ClaimOutcome::Indeterminate(reason) => {
                ("indeterminate", None, Some(reason.clone()), None)
            }
        };
        Self {
            event: ChatCoordinationAuditEvent::ClaimOutcome,
            backend,
            claim_key: Some(key.redacted()),
            channel_id: Some(key.channel_id().redacted()),
            claimant_agent_id: Some(claimant_agent_id.redacted()),
            owner_agent_id,
            outcome: Some(outcome_label.to_owned()),
            reason,
            error_code,
        }
    }

    /// Build a redacted coordination-skipped record.
    #[must_use]
    pub fn coordination_skipped(
        channel_id: &ChannelId,
        backend: ChatCoordinationBackend,
        reason: ChatCoordinationSkipReason,
    ) -> Self {
        Self {
            event: ChatCoordinationAuditEvent::CoordinationSkipped,
            backend,
            claim_key: None,
            channel_id: Some(channel_id.redacted()),
            claimant_agent_id: None,
            owner_agent_id: None,
            outcome: Some("skipped".to_owned()),
            reason: Some(skip_reason_label(reason).to_owned()),
            error_code: None,
        }
    }

    /// Build a redacted send-executed record.
    #[must_use]
    pub fn send_executed(
        key: &ClaimKey,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
        degraded_reason: Option<&str>,
    ) -> Self {
        Self {
            event: ChatCoordinationAuditEvent::SendExecuted,
            backend,
            claim_key: Some(key.redacted()),
            channel_id: Some(key.channel_id().redacted()),
            claimant_agent_id: Some(claimant_agent_id.redacted()),
            owner_agent_id: None,
            outcome: Some("executed".to_owned()),
            reason: degraded_reason.map(ToOwned::to_owned),
            error_code: None,
        }
    }

    /// Build a redacted send-denied record.
    #[must_use]
    pub fn send_denied(
        key: &ClaimKey,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
        error: &FcpError,
        owner_agent_id: Option<&AgentId>,
        reason: Option<&str>,
    ) -> Self {
        Self {
            event: ChatCoordinationAuditEvent::SendDenied,
            backend,
            claim_key: Some(key.redacted()),
            channel_id: Some(key.channel_id().redacted()),
            claimant_agent_id: Some(claimant_agent_id.redacted()),
            owner_agent_id: owner_agent_id.map(AgentId::redacted),
            outcome: Some("denied".to_owned()),
            reason: reason.map(ToOwned::to_owned),
            error_code: Some(error.numeric_code()),
        }
    }

    /// Event type for this record.
    #[must_use]
    pub const fn event(&self) -> ChatCoordinationAuditEvent {
        self.event
    }

    /// Backend that produced or guided this record.
    #[must_use]
    pub const fn backend(&self) -> ChatCoordinationBackend {
        self.backend
    }

    /// Redacted claim key, if a claim key was available.
    #[must_use]
    pub fn claim_key(&self) -> Option<&str> {
        self.claim_key.as_deref()
    }

    /// Redacted channel id, if one was available.
    #[must_use]
    pub fn channel_id(&self) -> Option<&str> {
        self.channel_id.as_deref()
    }

    /// Redacted claimant agent id, if one was available.
    #[must_use]
    pub fn claimant_agent_id(&self) -> Option<&str> {
        self.claimant_agent_id.as_deref()
    }

    /// Redacted owner agent id, if one was available.
    #[must_use]
    pub fn owner_agent_id(&self) -> Option<&str> {
        self.owner_agent_id.as_deref()
    }

    /// Stable outcome label, if one was set.
    #[must_use]
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Redaction-safe reason label, if one was set.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Numeric FCP error code, if the record describes a denial.
    #[must_use]
    pub const fn error_code(&self) -> Option<u16> {
        self.error_code
    }
}

/// Agent Mail reservation request for a chat-thread ownership claim.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentMailThreadReservationRequest {
    reservation_key: String,
    claim_key: ClaimKey,
    claimant_agent_id: AgentId,
    ttl: Duration,
}

impl AgentMailThreadReservationRequest {
    /// Build an Agent Mail reservation request for a claim key.
    #[must_use]
    pub fn new(claim_key: ClaimKey, claimant_agent_id: AgentId, ttl: Duration) -> Self {
        let reservation_key = agent_mail_thread_reservation_key(&claim_key);
        Self {
            reservation_key,
            claim_key,
            claimant_agent_id,
            ttl,
        }
    }

    /// Reservation key passed to the Agent Mail file-reservation backend.
    #[must_use]
    pub fn reservation_key(&self) -> &str {
        &self.reservation_key
    }

    /// Claim key represented by this reservation request.
    #[must_use]
    pub const fn claim_key(&self) -> &ClaimKey {
        &self.claim_key
    }

    /// Agent attempting to claim the thread.
    #[must_use]
    pub const fn claimant_agent_id(&self) -> &AgentId {
        &self.claimant_agent_id
    }

    /// Requested Agent Mail lease TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl fmt::Debug for AgentMailThreadReservationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claim_key = self.claim_key.redacted();
        let claimant_agent_id = self.claimant_agent_id.redacted();
        f.debug_struct("AgentMailThreadReservationRequest")
            .field("reservation_key", &self.reservation_key)
            .field("claim_key", &claim_key)
            .field("claimant_agent_id", &claimant_agent_id)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Outcome returned by an Agent Mail chat-thread reservation client.
#[derive(Clone, PartialEq, Eq)]
pub enum AgentMailThreadReservationOutcome {
    /// Exclusive reservation was acquired.
    Granted,
    /// Another agent already owns the reservation.
    Conflict {
        /// Agent that currently owns the reservation.
        owner_agent_id: AgentId,
    },
    /// Agent Mail was unreachable or could not make a decision.
    Unavailable {
        /// Redaction-safe reason code for diagnostics.
        reason: String,
    },
}

impl AgentMailThreadReservationOutcome {
    /// Build a conflict outcome.
    #[must_use]
    pub const fn conflict(owner_agent_id: AgentId) -> Self {
        Self::Conflict { owner_agent_id }
    }

    /// Build an unavailable outcome.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }
}

impl fmt::Debug for AgentMailThreadReservationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted => f.write_str("Granted"),
            Self::Conflict { owner_agent_id } => f
                .debug_struct("Conflict")
                .field("owner_agent_id", &owner_agent_id.redacted())
                .finish(),
            Self::Unavailable { reason } => f
                .debug_struct("Unavailable")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Minimal Agent Mail reservation client surface used by the SDK checker.
#[async_trait]
pub trait AgentMailThreadReservationClient: Send + Sync {
    /// Attempt to acquire an exclusive Agent Mail reservation for the request.
    async fn claim_thread_reservation(
        &self,
        cx: &fcp_async_core::Cx,
        request: &AgentMailThreadReservationRequest,
    ) -> AgentMailThreadReservationOutcome;
}

/// Thread ownership checker backed by Agent Mail exclusive reservations.
pub struct AgentMailThreadOwnershipChecker<C> {
    client: C,
    ttl: Duration,
    retry_attempts: usize,
}

impl<C> AgentMailThreadOwnershipChecker<C> {
    /// Create a checker using the default chat ownership TTL.
    #[must_use]
    pub const fn new(client: C) -> Self {
        Self::with_ttl(client, DEFAULT_THREAD_OWNERSHIP_TTL)
    }

    /// Create a checker with a custom Agent Mail reservation TTL.
    #[must_use]
    pub const fn with_ttl(client: C, ttl: Duration) -> Self {
        Self {
            client,
            ttl,
            retry_attempts: AGENT_MAIL_CLAIM_RETRY_ATTEMPTS,
        }
    }

    /// Configure retry attempts after the first unavailable Agent Mail response.
    #[must_use]
    pub const fn with_retry_attempts(mut self, retry_attempts: usize) -> Self {
        self.retry_attempts = retry_attempts;
        self
    }

    /// Agent Mail reservation TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Retry attempts after the first unavailable response.
    #[must_use]
    pub const fn retry_attempts(&self) -> usize {
        self.retry_attempts
    }

    /// Borrow the underlying reservation client.
    #[must_use]
    pub const fn client(&self) -> &C {
        &self.client
    }

    /// Build the Agent Mail reservation request for a claim.
    #[must_use]
    pub fn request_for(
        &self,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> AgentMailThreadReservationRequest {
        AgentMailThreadReservationRequest::new(key, agent_id, self.ttl)
    }
}

impl<C> fmt::Debug for AgentMailThreadOwnershipChecker<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentMailThreadOwnershipChecker")
            .field("client", &"<agent-mail-thread-reservation-client>")
            .field("ttl", &self.ttl)
            .field("retry_attempts", &self.retry_attempts)
            .finish()
    }
}

#[async_trait]
impl<C> ThreadOwnershipChecker for AgentMailThreadOwnershipChecker<C>
where
    C: AgentMailThreadReservationClient,
{
    async fn claim(
        &self,
        cx: &fcp_async_core::Cx,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome {
        let request = self.request_for(key, agent_id);
        for _ in 0..=self.retry_attempts {
            if cx.checkpoint().is_err() {
                return ClaimOutcome::Indeterminate(THREAD_OWNERSHIP_CANCELLED_REASON.to_owned());
            }
            match self.client.claim_thread_reservation(cx, &request).await {
                AgentMailThreadReservationOutcome::Granted => {
                    return ClaimOutcome::Granted(request.claimant_agent_id().clone());
                }
                AgentMailThreadReservationOutcome::Conflict { owner_agent_id } => {
                    return ClaimOutcome::AlreadyOwned(owner_agent_id);
                }
                AgentMailThreadReservationOutcome::Unavailable { .. } => {}
            }
        }
        ClaimOutcome::Indeterminate(AGENT_MAIL_UNAVAILABLE_REASON.to_owned())
    }
}

/// Connector action selected by chat coordination policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatCoordinationAction {
    /// Claim ownership for the computed key before sending.
    Claim {
        /// Claim key to acquire before the outbound send.
        key: ClaimKey,
    },
    /// Skip ownership checks for the given reason.
    Skip {
        /// Reason the claim was skipped.
        reason: ChatCoordinationSkipReason,
    },
}

impl ChatCoordinationAction {
    /// Return the claim key when this action requires a claim.
    #[must_use]
    pub const fn claim_key(&self) -> Option<&ClaimKey> {
        match self {
            Self::Claim { key } => Some(key),
            Self::Skip { .. } => None,
        }
    }
}

/// Connector send candidate evaluated by chat coordination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatCoordinationSendRequest {
    zone: ZoneId,
    connector: ConnectorId,
    channel: ChannelId,
    thread: Option<ThreadId>,
    claimant: AgentId,
}

impl ChatCoordinationSendRequest {
    /// Build a send candidate for an outbound chat operation.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
        claimant_agent_id: AgentId,
    ) -> Self {
        Self {
            zone: zone_id,
            connector: connector_id,
            channel: channel_id,
            thread: thread_id,
            claimant: claimant_agent_id,
        }
    }

    /// Zone namespace for the send.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone
    }

    /// Connector namespace for the send.
    #[must_use]
    pub const fn connector_id(&self) -> &ConnectorId {
        &self.connector
    }

    /// Channel or conversation id for the send.
    #[must_use]
    pub const fn channel_id(&self) -> &ChannelId {
        &self.channel
    }

    /// Native thread id, when the platform provides one.
    #[must_use]
    pub const fn thread_id(&self) -> Option<&ThreadId> {
        self.thread.as_ref()
    }

    /// Agent attempting the outbound send.
    #[must_use]
    pub const fn claimant_agent_id(&self) -> &AgentId {
        &self.claimant
    }
}

/// Connector-facing chat coordination policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatCoordinationConfig {
    enabled: bool,
    ttl: Duration,
    fail_open: bool,
    allowlist_channels: Vec<ChannelId>,
    backend: ChatCoordinationBackend,
    dm_mode: DmMode,
}

impl ChatCoordinationConfig {
    /// Create the default enabled, fail-open chat coordination policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether ownership coordination is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Claim and mention TTL selected by live config.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether indeterminate backend outcomes should proceed.
    #[must_use]
    pub const fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// Empty allowlist means all channels are coordinated.
    #[must_use]
    pub fn allowlist_channels(&self) -> &[ChannelId] {
        &self.allowlist_channels
    }

    /// Selected durable coordination backend.
    #[must_use]
    pub const fn backend(&self) -> ChatCoordinationBackend {
        self.backend
    }

    /// Direct-message handling mode.
    #[must_use]
    pub const fn dm_mode(&self) -> DmMode {
        self.dm_mode
    }

    /// Return a copy with coordination enabled or disabled.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Return a copy with a custom TTL.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Return a copy with fail-open behavior changed.
    #[must_use]
    pub const fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// Return a copy with an explicit channel rollout allowlist.
    #[must_use]
    pub fn with_allowlist_channels<I, C>(mut self, channels: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<ChannelId>,
    {
        self.allowlist_channels = channels.into_iter().map(Into::into).collect();
        self
    }

    /// Return a copy with a selected backend.
    #[must_use]
    pub const fn with_backend(mut self, backend: ChatCoordinationBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Return a copy with a selected direct-message policy.
    #[must_use]
    pub const fn with_dm_mode(mut self, dm_mode: DmMode) -> Self {
        self.dm_mode = dm_mode;
        self
    }

    /// Whether `channel_id` is inside the configured rollout allowlist.
    #[must_use]
    pub fn channel_is_allowed(&self, channel_id: &ChannelId) -> bool {
        self.allowlist_channels.is_empty()
            || self
                .allowlist_channels
                .iter()
                .any(|allowed| allowed == channel_id)
    }

    /// Select the claim action for a candidate outbound chat message.
    #[must_use]
    pub fn action_for_message(
        &self,
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
    ) -> ChatCoordinationAction {
        if !self.enabled {
            return ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::Disabled,
            };
        }
        if !self.channel_is_allowed(&channel_id) {
            return ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ChannelNotAllowed,
            };
        }
        ClaimKey::for_chat_message(zone_id, connector_id, channel_id, thread_id, self.dm_mode)
            .map_or_else(
                || ChatCoordinationAction::Skip {
                    reason: ChatCoordinationSkipReason::ThreadlessDmSkipped,
                },
                |key| ChatCoordinationAction::Claim { key },
            )
    }

    /// Map a backend claim outcome through this policy's fail-open setting.
    #[must_use]
    pub fn decision_for_claim_outcome(&self, outcome: ClaimOutcome) -> ChatClaimDecision {
        ChatClaimDecision::from_claim_outcome(outcome, self.fail_open)
    }

    /// Evaluate chat coordination before an outbound connector send.
    ///
    /// This is the connector-facing facade: it applies live policy, optionally
    /// claims ownership through the supplied checker, and returns both the send
    /// decision and the redaction-safe audit records that describe the path.
    pub async fn claim_before_send<C>(
        &self,
        cx: &fcp_async_core::Cx,
        checker: &C,
        request: ChatCoordinationSendRequest,
    ) -> ChatCoordinationSendDecision
    where
        C: ThreadOwnershipChecker + ?Sized,
    {
        let ChatCoordinationSendRequest {
            zone,
            connector,
            channel,
            thread,
            claimant,
        } = request;
        let audit_channel_id = channel.clone();
        let action = self.action_for_message(zone, connector, channel, thread);
        match action {
            ChatCoordinationAction::Skip { reason } => ChatCoordinationSendDecision::new(
                ChatCoordinationAction::Skip { reason },
                None,
                ChatClaimDecision::Proceed,
                vec![ChatCoordinationAuditRecord::coordination_skipped(
                    &audit_channel_id,
                    self.backend,
                    reason,
                )],
            ),
            ChatCoordinationAction::Claim { key } => {
                let mut audit_records = vec![ChatCoordinationAuditRecord::claim_attempt(
                    &key,
                    self.backend,
                    &claimant,
                )];
                let outcome = checker.claim(cx, key.clone(), claimant.clone()).await;
                audit_records.push(ChatCoordinationAuditRecord::claim_outcome(
                    &key,
                    self.backend,
                    &claimant,
                    &outcome,
                ));
                let decision = self.decision_for_claim_outcome(outcome.clone());
                ChatCoordinationSendDecision::new(
                    ChatCoordinationAction::Claim { key },
                    Some(outcome),
                    decision,
                    audit_records,
                )
            }
        }
    }
}

impl Default for ChatCoordinationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: DEFAULT_THREAD_OWNERSHIP_TTL,
            fail_open: true,
            allowlist_channels: Vec::new(),
            backend: ChatCoordinationBackend::AgentMail,
            dm_mode: DmMode::TreatAsThread,
        }
    }
}

/// Connector send decision after applying a claim backend outcome.
#[derive(Debug, Clone)]
pub enum ChatClaimDecision {
    /// Send may continue normally.
    Proceed,
    /// Send may continue, but should emit degraded coordination diagnostics.
    DegradedProceed {
        /// Redaction-safe backend reason.
        reason: String,
    },
    /// Send must be denied with this FCP error.
    Deny(FcpError),
}

impl ChatClaimDecision {
    /// Map a raw claim outcome into connector send behavior.
    #[must_use]
    pub fn from_claim_outcome(outcome: ClaimOutcome, fail_open: bool) -> Self {
        match outcome {
            ClaimOutcome::Granted(_) => Self::Proceed,
            ClaimOutcome::AlreadyOwned(owner) => Self::Deny(thread_owned_by_peer_error(&owner)),
            ClaimOutcome::Indeterminate(reason) if reason == THREAD_OWNERSHIP_CANCELLED_REASON => {
                Self::Deny(thread_ownership_indeterminate_error(&reason))
            }
            ClaimOutcome::Indeterminate(reason) if fail_open => Self::DegradedProceed { reason },
            ClaimOutcome::Indeterminate(reason) => {
                Self::Deny(thread_ownership_indeterminate_error(&reason))
            }
        }
    }

    /// Whether the connector should perform the outbound send.
    #[must_use]
    pub const fn should_send(&self) -> bool {
        matches!(self, Self::Proceed | Self::DegradedProceed { .. })
    }

    /// Borrow the denial error, if any.
    #[must_use]
    pub const fn denial_error(&self) -> Option<&FcpError> {
        match self {
            Self::Deny(error) => Some(error),
            Self::Proceed | Self::DegradedProceed { .. } => None,
        }
    }
}

/// Connector-facing result of applying chat coordination before a send.
#[derive(Debug, Clone)]
pub struct ChatCoordinationSendDecision {
    action: ChatCoordinationAction,
    claim_outcome: Option<ClaimOutcome>,
    decision: ChatClaimDecision,
    audit_records: Vec<ChatCoordinationAuditRecord>,
}

impl ChatCoordinationSendDecision {
    const fn new(
        action: ChatCoordinationAction,
        claim_outcome: Option<ClaimOutcome>,
        decision: ChatClaimDecision,
        audit_records: Vec<ChatCoordinationAuditRecord>,
    ) -> Self {
        Self {
            action,
            claim_outcome,
            decision,
            audit_records,
        }
    }

    /// Policy action chosen for the outbound message.
    #[must_use]
    pub const fn action(&self) -> &ChatCoordinationAction {
        &self.action
    }

    /// Backend claim outcome, when a claim was attempted.
    #[must_use]
    pub const fn claim_outcome(&self) -> Option<&ClaimOutcome> {
        self.claim_outcome.as_ref()
    }

    /// Final connector send decision.
    #[must_use]
    pub const fn decision(&self) -> &ChatClaimDecision {
        &self.decision
    }

    /// Redaction-safe audit records emitted before the connector send.
    #[must_use]
    pub fn audit_records(&self) -> &[ChatCoordinationAuditRecord] {
        &self.audit_records
    }

    /// Whether the connector should perform the outbound send.
    #[must_use]
    pub const fn should_send(&self) -> bool {
        self.decision.should_send()
    }

    /// Borrow the denial error, if the send must be blocked.
    #[must_use]
    pub const fn denial_error(&self) -> Option<&FcpError> {
        self.decision.denial_error()
    }

    /// Redaction-safe degraded reason for fail-open sends.
    #[must_use]
    pub fn degraded_reason(&self) -> Option<&str> {
        match &self.decision {
            ChatClaimDecision::DegradedProceed { reason } => Some(reason.as_str()),
            ChatClaimDecision::Proceed | ChatClaimDecision::Deny(_) => None,
        }
    }

    /// Backend reason associated with an indeterminate claim, if any.
    #[must_use]
    pub fn indeterminate_reason(&self) -> Option<&str> {
        match &self.claim_outcome {
            Some(ClaimOutcome::Indeterminate(reason)) => Some(reason.as_str()),
            Some(ClaimOutcome::Granted(_) | ClaimOutcome::AlreadyOwned(_)) | None => None,
        }
    }

    /// Claim key selected for this send, when ownership was attempted.
    #[must_use]
    pub const fn claim_key(&self) -> Option<&ClaimKey> {
        self.action.claim_key()
    }

    /// Peer owner that blocked the send, when known.
    #[must_use]
    pub const fn owner_agent_id(&self) -> Option<&AgentId> {
        match &self.claim_outcome {
            Some(ClaimOutcome::AlreadyOwned(owner)) => Some(owner),
            Some(ClaimOutcome::Granted(_) | ClaimOutcome::Indeterminate(_)) | None => None,
        }
    }

    /// Build the post-claim audit record for a successful connector send.
    #[must_use]
    pub fn send_executed_audit_record(
        &self,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
    ) -> Option<ChatCoordinationAuditRecord> {
        if !self.should_send() {
            return None;
        }
        self.claim_key().map(|key| {
            ChatCoordinationAuditRecord::send_executed(
                key,
                backend,
                claimant_agent_id,
                self.degraded_reason()
                    .or_else(|| self.indeterminate_reason()),
            )
        })
    }

    /// Build the post-claim audit record for a denied connector send.
    #[must_use]
    pub fn send_denied_audit_record(
        &self,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
    ) -> Option<ChatCoordinationAuditRecord> {
        let key = self.claim_key()?;
        let error = self.denial_error()?;
        Some(ChatCoordinationAuditRecord::send_denied(
            key,
            backend,
            claimant_agent_id,
            error,
            self.owner_agent_id(),
            self.degraded_reason()
                .or_else(|| self.indeterminate_reason()),
        ))
    }
}

/// Agent identifier used in chat coordination decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentId(String);

impl AgentId {
    /// Create an agent id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw agent id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("agent:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for AgentId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for AgentId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for AgentId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Platform channel or conversation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(String);

impl ChannelId {
    /// Create a channel id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw channel id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("channel:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ChannelId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ChannelId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for ChannelId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Platform thread identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(String);

impl ThreadId {
    /// Create a thread id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw thread id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic redacted form for audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("thread:{}", fnv1a64(self.0.as_bytes()))
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ThreadId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ThreadId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for ThreadId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Stable namespace for a chat ownership claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::struct_field_names)]
pub struct ClaimKey {
    zone_id: ZoneId,
    connector_id: ConnectorId,
    channel_id: ChannelId,
    thread_id: ThreadId,
}

impl ClaimKey {
    /// Create a claim key for a concrete chat thread.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: ThreadId,
    ) -> Self {
        Self {
            zone_id,
            connector_id,
            channel_id,
            thread_id,
        }
    }

    /// Create a claim key for a platform message.
    ///
    /// Returns `None` for threadless messages when [`DmMode::Skip`] is active.
    #[must_use]
    pub fn for_chat_message(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
        dm_mode: DmMode,
    ) -> Option<Self> {
        let thread_id = match thread_id {
            Some(thread_id) => thread_id,
            None if matches!(dm_mode, DmMode::TreatAsThread) => {
                ThreadId::new(channel_id.as_str().to_owned())
            }
            None => return None,
        };
        Some(Self::new(zone_id, connector_id, channel_id, thread_id))
    }

    /// Zone namespace for the claim.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Connector namespace for the claim.
    #[must_use]
    pub const fn connector_id(&self) -> &ConnectorId {
        &self.connector_id
    }

    /// Channel namespace for the claim.
    #[must_use]
    pub const fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    /// Thread namespace for the claim.
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }

    /// Redacted key suitable for structured audit logs.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.zone_id.as_str(),
            self.connector_id.as_str(),
            self.channel_id.redacted(),
            self.thread_id.redacted()
        )
    }
}

/// Telegram entity that can mention an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelegramMentionEntity {
    /// Textual `@username` mention.
    Mention {
        /// Mentioned username, with or without a leading `@`.
        username: String,
    },
    /// Telegram `text_mention` entity carrying a concrete user id.
    TextMention {
        /// Mentioned Telegram user id.
        user_id: String,
    },
}

impl TelegramMentionEntity {
    /// Create a textual `@username` entity.
    #[must_use]
    pub fn mention(username: impl Into<String>) -> Self {
        Self::Mention {
            username: username.into(),
        }
    }

    /// Create a `text_mention` entity with a Telegram user id.
    #[must_use]
    pub fn text_mention(user_id: impl Into<String>) -> Self {
        Self::TextMention {
            user_id: user_id.into(),
        }
    }
}

/// Normalize a Slack channel, group, DM, MPIM, or workspace id.
///
/// The helper strips `slack:` and `channel:` prefixes case-insensitively,
/// uppercases the remaining id, and accepts canonical ids beginning with
/// `C`, `D`, `G`, `U`, or `W`.
#[must_use]
pub fn normalize_slack_channel_id(raw: &str) -> Option<ChannelId> {
    let trimmed = raw.trim();
    let stripped = strip_ascii_prefix(trimmed, "slack:")
        .or_else(|| strip_ascii_prefix(trimmed, "channel:"))
        .unwrap_or(trimmed);
    let normalized = stripped.to_ascii_uppercase();
    let mut chars = normalized.chars();
    let first = chars.next()?;
    if !matches!(first, 'C' | 'D' | 'G' | 'U' | 'W') {
        return None;
    }
    if chars.all(|ch| ch.is_ascii_alphanumeric()) {
        Some(ChannelId::new(normalized))
    } else {
        None
    }
}

/// Return true when Slack text mentions an agent by user token or literal name.
///
/// This recognizes `<@USERID>` and `<@USERID|label>` tokens plus an ASCII
/// case-insensitive literal `@AgentName` fallback. Literal matching avoids
/// email-like tokens such as `name@AgentName.test`.
#[must_use]
pub fn slack_text_mentions_agent(text: &str, bot_user_id: &str, agent_name: &str) -> bool {
    angle_token_mentions(text, "<@", bot_user_id, Some('|'))
        || literal_at_mention_matches(text, agent_name)
}

/// Return true when Discord text mentions an agent by user token or owned role.
///
/// User mentions support both `<@USERID>` and legacy `<@!USERID>` forms. Role
/// mentions match `<@&ROLEID>` only when the caller supplies that role id.
#[must_use]
pub fn discord_text_mentions_agent<'a, I, S>(text: &str, user_id: &str, role_ids: I) -> bool
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a,
{
    angle_token_mentions(text, "<@", user_id, None)
        || angle_token_mentions(text, "<@!", user_id, None)
        || role_ids
            .into_iter()
            .any(|role_id| angle_token_mentions(text, "<@&", role_id.as_ref(), None))
}

/// Return true when Telegram entities mention an agent username or user id.
#[must_use]
pub fn telegram_entities_mention_agent(
    entities: &[TelegramMentionEntity],
    agent_username: &str,
    agent_user_id: &str,
) -> bool {
    let expected_username = normalized_telegram_username(agent_username);
    entities.iter().any(|entity| match entity {
        TelegramMentionEntity::Mention { username } => {
            let username = normalized_telegram_username(username);
            !expected_username.is_empty() && username.eq_ignore_ascii_case(&expected_username)
        }
        TelegramMentionEntity::TextMention { user_id } => {
            !agent_user_id.is_empty() && user_id == agent_user_id
        }
    })
}

/// Return true when a structured user-id mention list includes the agent.
///
/// This is the common path for Matrix `m.mentions.user_ids` and Teams
/// `body.mentions[].mentioned.user.id` style payloads.
#[must_use]
pub fn structured_user_mentions_agent<'a, I, S>(mentioned_user_ids: I, agent_user_id: &str) -> bool
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a,
{
    !agent_user_id.is_empty()
        && mentioned_user_ids
            .into_iter()
            .any(|user_id| user_id.as_ref() == agent_user_id)
}

/// Return true when Matrix `m.mentions.user_ids` includes the agent.
#[must_use]
pub fn matrix_mentions_agent<'a, I, S>(mentioned_user_ids: I, agent_user_id: &str) -> bool
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a,
{
    structured_user_mentions_agent(mentioned_user_ids, agent_user_id)
}

/// Return true when Teams structured mentions include the agent.
#[must_use]
pub fn teams_mentions_agent<'a, I, S>(mentioned_user_ids: I, agent_user_id: &str) -> bool
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a,
{
    structured_user_mentions_agent(mentioned_user_ids, agent_user_id)
}

/// Return true when Mattermost `props.mentions` JSON includes the agent.
///
/// Mattermost stores mentions as a JSON array of user ids in the post props.
/// Malformed JSON or non-array payloads return false.
#[must_use]
pub fn mattermost_props_mentions_agent(props_mentions_json: &str, agent_user_id: &str) -> bool {
    if agent_user_id.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(props_mentions_json) else {
        return false;
    };
    let Some(mentions) = value.as_array() else {
        return false;
    };
    mentions
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|user_id| user_id == agent_user_id)
}

/// Return true when text contains a standalone literal `@name` mention.
#[must_use]
pub fn literal_at_mention_matches(text: &str, name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }

    let mut search_start = 0;
    while let Some(relative_at) = text[search_start..].find('@') {
        let at_index = search_start + relative_at;
        let candidate_start = at_index + 1;
        let candidate_end = candidate_start + name.len();
        if !is_literal_mention_boundary_before(text, at_index) {
            search_start = candidate_start;
            continue;
        }
        if text
            .get(candidate_start..candidate_end)
            .is_some_and(|candidate| {
                candidate.eq_ignore_ascii_case(name)
                    && is_literal_mention_boundary_after(text, candidate_end)
            })
        {
            return true;
        }
        search_start = candidate_start;
    }
    false
}

/// Short-lived record that an agent was mentioned in a thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionRecord {
    agent_id: AgentId,
    observed_at: Instant,
    expires_at: Instant,
}

impl MentionRecord {
    /// Agent that was mentioned.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Time when the mention was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }

    /// Time when the mention record expires.
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// In-memory mention tracker with lazy expiration.
#[derive(Debug)]
pub struct MentionTracker {
    ttl: Duration,
    mentions: Mutex<HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>>,
}

impl MentionTracker {
    /// Create an empty tracker with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            mentions: Mutex::new(HashMap::new()),
        }
    }

    /// Create an empty tracker with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configured mention TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Record that `agent_id` was mentioned in `key`.
    pub fn stamp(&self, key: ClaimKey, agent_id: AgentId, observed_at: Instant) {
        let record = MentionRecord {
            agent_id: agent_id.clone(),
            observed_at,
            expires_at: observed_at + self.ttl,
        };
        let mut mentions = self.lock_mentions();
        mentions.entry(key).or_default().insert(agent_id, record);
    }

    /// Return the active mention record for a specific agent, if present.
    #[must_use]
    pub fn record_for(
        &self,
        key: &ClaimKey,
        agent_id: &AgentId,
        now: Instant,
    ) -> Option<MentionRecord> {
        let mut mentions = self.lock_mentions();
        prune_mentions(&mut mentions, now);
        mentions
            .get(key)
            .and_then(|agents| agents.get(agent_id).cloned())
    }

    /// Return all active mentioned agents for the key.
    #[must_use]
    pub fn mentioned_agents(&self, key: &ClaimKey, now: Instant) -> Vec<AgentId> {
        let mut agents = {
            let mut mentions = self.lock_mentions();
            prune_mentions(&mut mentions, now);
            mentions
                .get(key)
                .map(|records| records.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        agents.sort();
        agents
    }

    /// Number of active mention records after lazy pruning.
    #[must_use]
    pub fn active_len(&self, now: Instant) -> usize {
        let mut mentions = self.lock_mentions();
        prune_mentions(&mut mentions, now);
        mentions.values().map(HashMap::len).sum()
    }

    fn lock_mentions(&self) -> MutexGuard<'_, HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>> {
        self.mentions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for MentionTracker {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_THREAD_OWNERSHIP_TTL)
    }
}

/// Current owner record for a chat thread claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRecord {
    owner_agent_id: AgentId,
    claimed_at: Instant,
    renewed_at: Instant,
    expires_at: Instant,
}

impl OwnershipRecord {
    /// Agent that currently owns the claim.
    #[must_use]
    pub const fn owner_agent_id(&self) -> &AgentId {
        &self.owner_agent_id
    }

    /// Time when the claim was first acquired.
    #[must_use]
    pub const fn claimed_at(&self) -> Instant {
        self.claimed_at
    }

    /// Time when the claim was last renewed.
    #[must_use]
    pub const fn renewed_at(&self) -> Instant {
        self.renewed_at
    }

    /// Time when the claim expires without renewal.
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Result of a thread ownership claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The claimant may proceed.
    Granted(AgentId),
    /// A peer currently owns the thread.
    AlreadyOwned(AgentId),
    /// The backend could not make a reliable decision.
    Indeterminate(String),
}

impl ClaimOutcome {
    /// Returns true when the claimant may proceed.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }

    /// Owner that blocked the claim, if this is [`ClaimOutcome::AlreadyOwned`].
    #[must_use]
    pub const fn blocking_owner(&self) -> Option<&AgentId> {
        match self {
            Self::AlreadyOwned(owner) => Some(owner),
            Self::Granted(_) | Self::Indeterminate(_) => None,
        }
    }
}

/// Create the standard FCP error for a peer-owned chat thread.
#[must_use]
pub fn thread_owned_by_peer_error(owner_agent_id: &AgentId) -> FcpError {
    FcpError::Unauthorized {
        code: THREAD_OWNED_BY_PEER_ERROR_CODE,
        message: format!("thread_owned_by_peer:{owner_agent_id}"),
    }
}

/// Create the standard FCP error for fail-closed indeterminate ownership.
#[must_use]
pub fn thread_ownership_indeterminate_error(reason: &str) -> FcpError {
    FcpError::ConnectorUnavailable {
        code: THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE,
        message: format!("thread_ownership_indeterminate:{reason}"),
    }
}

/// Async claim backend used by connector call sites.
#[async_trait]
pub trait ThreadOwnershipChecker: Send + Sync {
    /// Claim ownership for `agent_id` on `key`.
    async fn claim(
        &self,
        cx: &fcp_async_core::Cx,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome;
}

/// In-memory ownership checker for tests and single-process fixtures.
#[derive(Debug)]
pub struct InMemoryThreadOwnershipChecker {
    ttl: Duration,
    claims: Mutex<HashMap<ClaimKey, OwnershipRecord>>,
}

impl InMemoryThreadOwnershipChecker {
    /// Create an empty checker with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            claims: Mutex::new(HashMap::new()),
        }
    }

    /// Create an empty checker with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configured claim TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Synchronously claim a thread at a caller-supplied time.
    pub fn claim_now(&self, key: ClaimKey, agent_id: AgentId, now: Instant) -> ClaimOutcome {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        let outcome = match claims.get_mut(&key) {
            Some(record) if record.owner_agent_id == agent_id => {
                record.renewed_at = now;
                record.expires_at = now + self.ttl;
                ClaimOutcome::Granted(agent_id)
            }
            Some(record) => ClaimOutcome::AlreadyOwned(record.owner_agent_id.clone()),
            None => {
                claims.insert(
                    key,
                    OwnershipRecord {
                        owner_agent_id: agent_id.clone(),
                        claimed_at: now,
                        renewed_at: now,
                        expires_at: now + self.ttl,
                    },
                );
                ClaimOutcome::Granted(agent_id)
            }
        };
        drop(claims);
        outcome
    }

    /// Claim a thread while respecting active mention records.
    ///
    /// If one or more agents were mentioned and `agent_id` was not among them,
    /// the claim is denied before touching the ownership map. If multiple
    /// agents were mentioned, normal first-claim-wins semantics decide between
    /// them.
    pub fn claim_with_mentions_now(
        &self,
        mentions: &MentionTracker,
        key: ClaimKey,
        agent_id: AgentId,
        now: Instant,
    ) -> ClaimOutcome {
        let mentioned_agents = mentions.mentioned_agents(&key, now);
        if !mentioned_agents.iter().any(|agent| agent == &agent_id) {
            if let Some(owner) = mentioned_agents.first().cloned() {
                return ClaimOutcome::AlreadyOwned(owner);
            }
        }
        self.claim_now(key, agent_id, now)
    }

    /// Release a claim when the current owner matches.
    ///
    /// Returns true when a claim was removed.
    pub fn release(&self, key: &ClaimKey, agent_id: &AgentId, now: Instant) -> bool {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        let removed = if claims
            .get(key)
            .is_some_and(|record| &record.owner_agent_id == agent_id)
        {
            claims.remove(key);
            true
        } else {
            false
        };
        drop(claims);
        removed
    }

    /// Return the active owner record for a claim key.
    #[must_use]
    pub fn record_for(&self, key: &ClaimKey, now: Instant) -> Option<OwnershipRecord> {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        claims.get(key).cloned()
    }

    /// Number of active claims after lazy pruning.
    #[must_use]
    pub fn active_len(&self, now: Instant) -> usize {
        let mut claims = self.lock_claims();
        prune_claims(&mut claims, now);
        claims.len()
    }

    fn lock_claims(&self) -> MutexGuard<'_, HashMap<ClaimKey, OwnershipRecord>> {
        self.claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for InMemoryThreadOwnershipChecker {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_THREAD_OWNERSHIP_TTL)
    }
}

#[async_trait]
impl ThreadOwnershipChecker for InMemoryThreadOwnershipChecker {
    async fn claim(
        &self,
        _cx: &fcp_async_core::Cx,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome {
        self.claim_now(key, agent_id, Instant::now())
    }
}

fn prune_mentions(mentions: &mut HashMap<ClaimKey, HashMap<AgentId, MentionRecord>>, now: Instant) {
    mentions.retain(|_, records| {
        records.retain(|_, record| !record.is_expired(now));
        !records.is_empty()
    });
}

fn prune_claims(claims: &mut HashMap<ClaimKey, OwnershipRecord>, now: Instant) {
    claims.retain(|_, record| !record.is_expired(now));
}

fn agent_mail_thread_reservation_key(key: &ClaimKey) -> String {
    format!(
        "{CHAT_THREAD_RESERVATION_PREFIX}{}/{}/{}/{}",
        key.zone_id().as_str(),
        key.connector_id().as_str(),
        key.channel_id().redacted(),
        key.thread_id().redacted()
    )
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn angle_token_mentions(
    text: &str,
    prefix: &str,
    target_id: &str,
    split_delimiter: Option<char>,
) -> bool {
    if target_id.is_empty() {
        return false;
    }

    let mut search_start = 0;
    while let Some(relative_start) = text[search_start..].find(prefix) {
        let token_start = search_start + relative_start + prefix.len();
        let Some(relative_end) = text[token_start..].find('>') else {
            return false;
        };
        let token_end = token_start + relative_end;
        let candidate = &text[token_start..token_end];
        let candidate_id = split_delimiter.map_or(candidate, |delimiter| {
            candidate
                .split_once(delimiter)
                .map_or(candidate, |(id, _)| id)
        });
        if candidate_id.eq_ignore_ascii_case(target_id) {
            return true;
        }
        search_start = token_end + 1;
    }
    false
}

fn normalized_telegram_username(username: &str) -> String {
    username.trim().trim_start_matches('@').to_owned()
}

fn is_literal_mention_boundary_before(text: &str, at_index: usize) -> bool {
    text[..at_index]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_literal_mention_word_char(ch))
}

fn is_literal_mention_boundary_after(text: &str, candidate_end: usize) -> bool {
    text.get(candidate_end..)
        .and_then(|remaining| remaining.chars().next())
        .is_none_or(|ch| !is_literal_mention_word_char(ch))
}

const fn is_literal_mention_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

const fn skip_reason_label(reason: ChatCoordinationSkipReason) -> &'static str {
    match reason {
        ChatCoordinationSkipReason::Disabled => "disabled",
        ChatCoordinationSkipReason::ChannelNotAllowed => "channel_not_allowed",
        ChatCoordinationSkipReason::ThreadlessDmSkipped => "threadless_dm_skipped",
    }
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0001_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{ConnectorId, ZoneId};

    fn connector(id: &'static str) -> ConnectorId {
        ConnectorId::from_static(id)
    }

    fn key_for(connector_id: ConnectorId) -> ClaimKey {
        ClaimKey::new(
            ZoneId::work(),
            connector_id,
            ChannelId::new("C123"),
            ThreadId::new("1700000000.000100"),
        )
    }

    fn agent(id: &str) -> AgentId {
        AgentId::new(id)
    }

    fn current_test_cx() -> fcp_async_core::Cx {
        fcp_async_core::Cx::current().expect("test runtime provides a current Cx")
    }

    struct ScriptedAgentMailReservationClient {
        outcomes: Mutex<VecDeque<AgentMailThreadReservationOutcome>>,
        requests: Mutex<Vec<AgentMailThreadReservationRequest>>,
    }

    impl ScriptedAgentMailReservationClient {
        fn new(outcomes: impl IntoIterator<Item = AgentMailThreadReservationOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<AgentMailThreadReservationRequest> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl AgentMailThreadReservationClient for ScriptedAgentMailReservationClient {
        async fn claim_thread_reservation(
            &self,
            _cx: &fcp_async_core::Cx,
            request: &AgentMailThreadReservationRequest,
        ) -> AgentMailThreadReservationOutcome {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.clone());
            self.outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| {
                    AgentMailThreadReservationOutcome::unavailable(AGENT_MAIL_UNAVAILABLE_REASON)
                })
        }
    }

    fn run_agent_mail_claim<C>(
        checker: &AgentMailThreadOwnershipChecker<C>,
        key: ClaimKey,
        agent_id: AgentId,
    ) -> ClaimOutcome
    where
        C: AgentMailThreadReservationClient,
    {
        fcp_async_core::runtime::block_on_sync(async {
            let cx = current_test_cx();
            checker.claim(&cx, key, agent_id).await
        })
        .expect("test runtime starts")
    }

    fn run_claim_before_send<C>(
        config: &ChatCoordinationConfig,
        checker: &C,
        channel_id: &str,
        thread_id: Option<&str>,
        agent_id: &str,
    ) -> ChatCoordinationSendDecision
    where
        C: ThreadOwnershipChecker + ?Sized,
    {
        fcp_async_core::runtime::block_on_sync(async {
            let cx = current_test_cx();
            config
                .claim_before_send(
                    &cx,
                    checker,
                    ChatCoordinationSendRequest::new(
                        ZoneId::work(),
                        connector("slack:chat:1.0.0"),
                        ChannelId::new(channel_id),
                        thread_id.map(ThreadId::new),
                        agent(agent_id),
                    ),
                )
                .await
        })
        .expect("test runtime starts")
    }

    #[test]
    fn chat_coordination_config_defaults_match_parent_policy() {
        let config = ChatCoordinationConfig::default();

        assert!(config.enabled());
        assert_eq!(config.ttl(), DEFAULT_THREAD_OWNERSHIP_TTL);
        assert!(config.fail_open());
        assert_eq!(config.allowlist_channels(), []);
        assert_eq!(config.backend(), ChatCoordinationBackend::AgentMail);
        assert_eq!(config.dm_mode(), DmMode::TreatAsThread);
        assert!(config.channel_is_allowed(&ChannelId::new("C123")));
    }

    #[test]
    fn chat_coordination_action_respects_enabled_and_allowlist() {
        let disabled = ChatCoordinationConfig::new().with_enabled(false);
        assert!(matches!(
            disabled.action_for_message(
                ZoneId::work(),
                connector("slack:chat:1.0.0"),
                ChannelId::new("C123"),
                Some(ThreadId::new("1700000000.000100"))
            ),
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::Disabled
            }
        ));

        let allowed = ChatCoordinationConfig::new()
            .with_allowlist_channels([ChannelId::new("C123"), ChannelId::new("C456")]);
        assert!(matches!(
            allowed.action_for_message(
                ZoneId::work(),
                connector("slack:chat:1.0.0"),
                ChannelId::new("C999"),
                Some(ThreadId::new("1700000000.000100"))
            ),
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ChannelNotAllowed
            }
        ));
        assert!(matches!(
            allowed.action_for_message(
                ZoneId::work(),
                connector("slack:chat:1.0.0"),
                ChannelId::new("C123"),
                Some(ThreadId::new("1700000000.000100"))
            ),
            ChatCoordinationAction::Claim { .. }
        ));
    }

    #[test]
    fn chat_coordination_action_handles_threadless_dm_modes() {
        let channel = ChannelId::new("signal-dm-42");
        let skipped = ChatCoordinationConfig::new()
            .with_dm_mode(DmMode::Skip)
            .action_for_message(
                ZoneId::work(),
                connector("signal:chat:1.0.0"),
                channel.clone(),
                None,
            );
        assert!(matches!(
            skipped,
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ThreadlessDmSkipped
            }
        ));

        let treated = ChatCoordinationConfig::new().action_for_message(
            ZoneId::work(),
            connector("signal:chat:1.0.0"),
            channel.clone(),
            None,
        );
        assert!(matches!(
            treated,
            ChatCoordinationAction::Claim { ref key }
                if key.channel_id() == &channel && key.thread_id().as_str() == channel.as_str()
        ));
    }

    #[test]
    fn claim_before_send_reports_skip_reasons_without_claiming() {
        let checker = InMemoryThreadOwnershipChecker::new();

        let disabled = run_claim_before_send(
            &ChatCoordinationConfig::new().with_enabled(false),
            &checker,
            "C123",
            Some("1700000000.000100"),
            "alice",
        );
        assert!(disabled.should_send());
        assert!(disabled.claim_outcome().is_none());
        assert!(matches!(
            disabled.action(),
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::Disabled
            }
        ));
        assert_eq!(disabled.audit_records().len(), 1);
        assert_eq!(
            disabled.audit_records()[0].event(),
            ChatCoordinationAuditEvent::CoordinationSkipped
        );
        assert_eq!(disabled.audit_records()[0].reason(), Some("disabled"));

        let outside_allowlist = run_claim_before_send(
            &ChatCoordinationConfig::new().with_allowlist_channels([ChannelId::new("C999")]),
            &checker,
            "C123",
            Some("1700000000.000100"),
            "alice",
        );
        assert!(outside_allowlist.should_send());
        assert!(matches!(
            outside_allowlist.action(),
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ChannelNotAllowed
            }
        ));
        assert_eq!(
            outside_allowlist.audit_records()[0].reason(),
            Some("channel_not_allowed")
        );

        let threadless_dm = run_claim_before_send(
            &ChatCoordinationConfig::new().with_dm_mode(DmMode::Skip),
            &checker,
            "D123",
            None,
            "alice",
        );
        assert!(threadless_dm.should_send());
        assert!(matches!(
            threadless_dm.action(),
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ThreadlessDmSkipped
            }
        ));
        assert_eq!(
            threadless_dm.audit_records()[0].reason(),
            Some("threadless_dm_skipped")
        );
    }

    #[test]
    fn claim_decision_maps_claim_outcomes_to_send_policy() {
        let granted =
            ChatClaimDecision::from_claim_outcome(ClaimOutcome::Granted(agent("alice")), true);
        assert!(granted.should_send());
        assert!(granted.denial_error().is_none());

        let owned =
            ChatClaimDecision::from_claim_outcome(ClaimOutcome::AlreadyOwned(agent("alice")), true);
        assert!(!owned.should_send());
        assert!(matches!(
            owned.denial_error(),
            Some(FcpError::Unauthorized {
                code: THREAD_OWNED_BY_PEER_ERROR_CODE,
                message,
            }) if message == "thread_owned_by_peer:alice"
        ));

        let degraded = ChatClaimDecision::from_claim_outcome(
            ClaimOutcome::Indeterminate("agent_mail_unavailable".to_owned()),
            true,
        );
        assert!(degraded.should_send());
        assert!(matches!(
            degraded,
            ChatClaimDecision::DegradedProceed { ref reason }
                if reason == "agent_mail_unavailable"
        ));

        let denied = ChatClaimDecision::from_claim_outcome(
            ClaimOutcome::Indeterminate("agent_mail_unavailable".to_owned()),
            false,
        );
        assert!(!denied.should_send());
        assert!(matches!(
            denied.denial_error(),
            Some(FcpError::ConnectorUnavailable {
                code: THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE,
                message,
            }) if message == "thread_ownership_indeterminate:agent_mail_unavailable"
        ));
    }

    #[test]
    fn config_decision_uses_live_fail_open_value() {
        let fail_open = ChatCoordinationConfig::new().with_fail_open(true);
        let fail_closed = ChatCoordinationConfig::new().with_fail_open(false);

        assert!(
            fail_open
                .decision_for_claim_outcome(ClaimOutcome::Indeterminate(
                    "agent_mail_unavailable".to_owned()
                ))
                .should_send()
        );
        assert!(
            fail_closed
                .decision_for_claim_outcome(ClaimOutcome::Indeterminate(
                    "agent_mail_unavailable".to_owned()
                ))
                .denial_error()
                .is_some()
        );
    }

    #[test]
    fn audit_claim_attempt_serializes_only_redacted_identifiers() {
        let key = key_for(connector("slack:chat:1.0.0"));
        let record = ChatCoordinationAuditRecord::claim_attempt(
            &key,
            ChatCoordinationBackend::AgentMail,
            &agent("alice"),
        );
        let json = serde_json::to_string(&record).expect("record serializes");

        assert_eq!(record.event(), ChatCoordinationAuditEvent::ClaimAttempt);
        assert_eq!(record.backend(), ChatCoordinationBackend::AgentMail);
        assert_eq!(record.outcome(), None);
        assert!(json.contains(r#""event":"claim_attempt""#));
        assert!(json.contains(r#""backend":"agent_mail""#));
        assert!(json.contains("agent:"));
        assert!(json.contains("channel:"));
        assert!(json.contains("thread:"));
        assert!(!json.contains("alice"));
        assert!(!json.contains("C123"));
        assert!(!json.contains("1700000000.000100"));
    }

    #[test]
    fn audit_claim_outcome_records_peer_owner_without_plaintext_owner() {
        let key = key_for(connector("slack:chat:1.0.0"));
        let record = ChatCoordinationAuditRecord::claim_outcome(
            &key,
            ChatCoordinationBackend::AgentMail,
            &agent("bob"),
            &ClaimOutcome::AlreadyOwned(agent("alice")),
        );
        let json = serde_json::to_value(&record).expect("record serializes");

        assert_eq!(record.event(), ChatCoordinationAuditEvent::ClaimOutcome);
        assert_eq!(record.outcome(), Some("already_owned"));
        assert_eq!(record.error_code(), Some(THREAD_OWNED_BY_PEER_ERROR_CODE));
        assert!(
            record
                .owner_agent_id()
                .is_some_and(|owner| owner.starts_with("agent:"))
        );
        assert_eq!(json["outcome"], "already_owned");
        assert_eq!(json["error_code"], THREAD_OWNED_BY_PEER_ERROR_CODE);
        assert!(!json.to_string().contains("alice"));
        assert!(!json.to_string().contains("bob"));
    }

    #[test]
    fn audit_skipped_record_hashes_channel_and_labels_reason() {
        let record = ChatCoordinationAuditRecord::coordination_skipped(
            &ChannelId::new("C123"),
            ChatCoordinationBackend::MeshGossip,
            ChatCoordinationSkipReason::ChannelNotAllowed,
        );
        let json = serde_json::to_value(&record).expect("record serializes");

        assert_eq!(
            record.event(),
            ChatCoordinationAuditEvent::CoordinationSkipped
        );
        assert_eq!(record.backend(), ChatCoordinationBackend::MeshGossip);
        assert_eq!(record.claim_key(), None);
        assert_eq!(record.reason(), Some("channel_not_allowed"));
        assert!(
            record
                .channel_id()
                .is_some_and(|channel| channel.starts_with("channel:"))
        );
        assert_eq!(json["event"], "coordination_skipped");
        assert_eq!(json["backend"], "mesh_gossip");
        assert_eq!(json["outcome"], "skipped");
        assert!(json.get("claim_key").is_none());
        assert!(!json.to_string().contains("C123"));
    }

    #[test]
    fn audit_send_records_capture_execution_and_denial_codes() {
        let key = key_for(connector("slack:chat:1.0.0"));
        let claimant = agent("bob");
        let executed = ChatCoordinationAuditRecord::send_executed(
            &key,
            ChatCoordinationBackend::InMemory,
            &claimant,
            Some("agent_mail_unavailable"),
        );
        assert_eq!(executed.event(), ChatCoordinationAuditEvent::SendExecuted);
        assert_eq!(executed.outcome(), Some("executed"));
        assert_eq!(executed.reason(), Some("agent_mail_unavailable"));
        assert_eq!(executed.error_code(), None);

        let owner = agent("alice");
        let error = thread_owned_by_peer_error(&owner);
        let denied = ChatCoordinationAuditRecord::send_denied(
            &key,
            ChatCoordinationBackend::AgentMail,
            &claimant,
            &error,
            Some(&owner),
            Some("thread_owned_by_peer"),
        );
        let json = serde_json::to_string(&denied).expect("record serializes");

        assert_eq!(denied.event(), ChatCoordinationAuditEvent::SendDenied);
        assert_eq!(denied.outcome(), Some("denied"));
        assert_eq!(denied.error_code(), Some(THREAD_OWNED_BY_PEER_ERROR_CODE));
        assert!(
            denied
                .claimant_agent_id()
                .is_some_and(|id| id.starts_with("agent:"))
        );
        assert!(
            denied
                .owner_agent_id()
                .is_some_and(|id| id.starts_with("agent:"))
        );
        assert!(!json.contains("alice"));
        assert!(!json.contains("bob"));
        assert!(!json.contains("C123"));
    }

    #[test]
    fn agent_mail_reservation_request_uses_redacted_chat_thread_key() {
        let key = key_for(connector("slack:chat:1.0.0"));
        let claimant = agent("alice");
        let request = AgentMailThreadReservationRequest::new(
            key.clone(),
            claimant.clone(),
            Duration::from_secs(120),
        );
        let expected_key = format!(
            "{CHAT_THREAD_RESERVATION_PREFIX}z:work/slack:chat:1.0.0/{}/{}",
            key.channel_id().redacted(),
            key.thread_id().redacted()
        );

        assert_eq!(request.reservation_key(), expected_key);
        assert_eq!(request.claim_key(), &key);
        assert_eq!(request.claimant_agent_id(), &claimant);
        assert_eq!(request.ttl(), Duration::from_secs(120));
        assert!(!request.reservation_key().contains("C123"));
        assert!(!request.reservation_key().contains("1700000000.000100"));

        let debug = format!("{request:?}");
        assert!(debug.contains("agent:"));
        assert!(debug.contains("channel:"));
        assert!(debug.contains("thread:"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("C123"));
        assert!(!debug.contains("1700000000.000100"));
    }

    #[test]
    fn agent_mail_checker_maps_granted_and_conflict_responses() {
        let key = key_for(connector("slack:chat:1.0.0"));
        let claimant = agent("alice");
        let granted_checker = AgentMailThreadOwnershipChecker::with_ttl(
            ScriptedAgentMailReservationClient::new([AgentMailThreadReservationOutcome::Granted]),
            Duration::from_secs(90),
        );

        let granted = run_agent_mail_claim(&granted_checker, key.clone(), claimant.clone());
        assert_eq!(granted, ClaimOutcome::Granted(claimant.clone()));
        let requests = granted_checker.client().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].ttl(), Duration::from_secs(90));
        assert_eq!(requests[0].claimant_agent_id(), &claimant);

        let owner = agent("bob");
        let conflict_checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::conflict(owner.clone()),
            ]));
        let conflict = run_agent_mail_claim(&conflict_checker, key, claimant);
        assert_eq!(conflict, ClaimOutcome::AlreadyOwned(owner));
        assert_eq!(conflict_checker.client().requests().len(), 1);
    }

    #[test]
    fn agent_mail_checker_retries_once_then_returns_unavailable() {
        let checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::unavailable("socket_closed"),
                AgentMailThreadReservationOutcome::unavailable("still_down"),
            ]));
        let key = key_for(connector("slack:chat:1.0.0"));
        let outcome = run_agent_mail_claim(&checker, key, agent("alice"));

        assert_eq!(
            outcome,
            ClaimOutcome::Indeterminate(AGENT_MAIL_UNAVAILABLE_REASON.to_owned())
        );
        assert_eq!(checker.retry_attempts(), AGENT_MAIL_CLAIM_RETRY_ATTEMPTS);
        assert_eq!(checker.client().requests().len(), 2);
    }

    #[test]
    fn cancelled_agent_mail_claim_does_not_touch_backend_and_fails_closed() {
        let checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::Granted,
            ]));

        let decision = fcp_async_core::runtime::block_on_sync(async {
            let cx = current_test_cx();
            cx.cancel_fast(asupersync::types::CancelKind::User);
            ChatCoordinationConfig::new()
                .with_fail_open(true)
                .claim_before_send(
                    &cx,
                    &checker,
                    ChatCoordinationSendRequest::new(
                        ZoneId::work(),
                        connector("slack:chat:1.0.0"),
                        ChannelId::new("C123"),
                        Some(ThreadId::new("1700000000.000100")),
                        agent("alice"),
                    ),
                )
                .await
        })
        .expect("test runtime starts");

        assert_eq!(checker.client().requests().len(), 0);
        assert_eq!(
            decision.claim_outcome(),
            Some(&ClaimOutcome::Indeterminate(
                THREAD_OWNERSHIP_CANCELLED_REASON.to_owned()
            ))
        );
        assert!(!decision.should_send());
        assert!(matches!(
            decision.denial_error(),
            Some(FcpError::ConnectorUnavailable {
                code: THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE,
                message,
            }) if message == "thread_ownership_indeterminate:request_cancelled"
        ));
        assert!(
            decision
                .send_executed_audit_record(ChatCoordinationBackend::AgentMail, &agent("alice"))
                .is_none()
        );
        let denied = decision
            .send_denied_audit_record(ChatCoordinationBackend::AgentMail, &agent("alice"))
            .expect("cancelled claim emits denial audit");
        assert_eq!(denied.reason(), Some(THREAD_OWNERSHIP_CANCELLED_REASON));
    }

    #[test]
    fn claim_before_send_granted_path_returns_ordered_audit_records() {
        let checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::Granted,
            ]));
        let claimant = agent("alice");
        let decision = run_claim_before_send(
            &ChatCoordinationConfig::new(),
            &checker,
            "C123",
            Some("1700000000.000100"),
            claimant.as_str(),
        );

        assert!(decision.should_send());
        assert!(matches!(decision.decision(), ChatClaimDecision::Proceed));
        assert_eq!(
            decision.claim_outcome(),
            Some(&ClaimOutcome::Granted(claimant.clone()))
        );
        assert_eq!(
            decision
                .audit_records()
                .iter()
                .map(ChatCoordinationAuditRecord::event)
                .collect::<Vec<_>>(),
            vec![
                ChatCoordinationAuditEvent::ClaimAttempt,
                ChatCoordinationAuditEvent::ClaimOutcome,
            ]
        );
        assert_eq!(decision.audit_records()[1].outcome(), Some("granted"));
        let executed = decision
            .send_executed_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
            .expect("claim path can emit send execution audit");
        assert_eq!(executed.event(), ChatCoordinationAuditEvent::SendExecuted);
        assert_eq!(executed.reason(), None);
        assert!(
            decision
                .send_denied_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
                .is_none()
        );
    }

    #[test]
    fn claim_before_send_conflict_denies_and_exposes_owner() {
        let owner = agent("bob");
        let claimant = agent("alice");
        let checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::conflict(owner.clone()),
            ]));
        let decision = run_claim_before_send(
            &ChatCoordinationConfig::new(),
            &checker,
            "C123",
            Some("1700000000.000100"),
            claimant.as_str(),
        );

        assert!(!decision.should_send());
        assert_eq!(
            decision.claim_outcome(),
            Some(&ClaimOutcome::AlreadyOwned(owner.clone()))
        );
        assert_eq!(decision.owner_agent_id(), Some(&owner));
        assert!(matches!(
            decision.denial_error(),
            Some(FcpError::Unauthorized {
                code: THREAD_OWNED_BY_PEER_ERROR_CODE,
                message,
            }) if message == "thread_owned_by_peer:bob"
        ));
        let denied = decision
            .send_denied_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
            .expect("denied claim can emit send denial audit");
        assert_eq!(denied.event(), ChatCoordinationAuditEvent::SendDenied);
        assert_eq!(denied.error_code(), Some(THREAD_OWNED_BY_PEER_ERROR_CODE));
        assert!(denied.owner_agent_id().is_some());
    }

    #[test]
    fn claim_before_send_unavailable_respects_fail_open_and_fail_closed() {
        let claimant = agent("alice");
        let fail_open_checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::unavailable("socket_closed"),
                AgentMailThreadReservationOutcome::unavailable("still_down"),
            ]));
        let fail_open = run_claim_before_send(
            &ChatCoordinationConfig::new().with_fail_open(true),
            &fail_open_checker,
            "C123",
            Some("1700000000.000100"),
            claimant.as_str(),
        );
        assert!(fail_open.should_send());
        assert!(matches!(
            fail_open.decision(),
            ChatClaimDecision::DegradedProceed { reason }
                if reason == AGENT_MAIL_UNAVAILABLE_REASON
        ));
        assert_eq!(
            fail_open.indeterminate_reason(),
            Some(AGENT_MAIL_UNAVAILABLE_REASON)
        );
        let executed = fail_open
            .send_executed_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
            .expect("degraded claim can emit execution audit");
        assert_eq!(executed.reason(), Some(AGENT_MAIL_UNAVAILABLE_REASON));

        let fail_closed_checker =
            AgentMailThreadOwnershipChecker::new(ScriptedAgentMailReservationClient::new([
                AgentMailThreadReservationOutcome::unavailable("socket_closed"),
                AgentMailThreadReservationOutcome::unavailable("still_down"),
            ]));
        let fail_closed = run_claim_before_send(
            &ChatCoordinationConfig::new().with_fail_open(false),
            &fail_closed_checker,
            "C123",
            Some("1700000000.000100"),
            claimant.as_str(),
        );
        assert!(!fail_closed.should_send());
        assert!(matches!(
            fail_closed.denial_error(),
            Some(FcpError::ConnectorUnavailable {
                code: THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE,
                message,
            }) if message == "thread_ownership_indeterminate:agent_mail_unavailable"
        ));
        let denied = fail_closed
            .send_denied_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
            .expect("fail-closed claim can emit denial audit");
        assert_eq!(
            denied.error_code(),
            Some(THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE)
        );
        assert_eq!(denied.reason(), Some(AGENT_MAIL_UNAVAILABLE_REASON));
    }

    #[test]
    fn slack_channel_normalization_strips_prefixes_and_uppercases() {
        assert_eq!(
            normalize_slack_channel_id("slack:c123").map(|id| id.as_str().to_owned()),
            Some("C123".to_owned())
        );
        assert_eq!(
            normalize_slack_channel_id("channel:gabc123").map(|id| id.as_str().to_owned()),
            Some("GABC123".to_owned())
        );
        assert_eq!(
            normalize_slack_channel_id(" D999 ").map(|id| id.as_str().to_owned()),
            Some("D999".to_owned())
        );
        assert!(normalize_slack_channel_id("x123").is_none());
        assert!(normalize_slack_channel_id("C12-3").is_none());
    }

    #[test]
    fn literal_mentions_require_ascii_boundaries() {
        assert!(literal_at_mention_matches(
            "please ask @AgentName now",
            "agentname"
        ));
        assert!(literal_at_mention_matches("(@AgentName)", "AgentName"));
        assert!(!literal_at_mention_matches(
            "name@AgentName.test should not count",
            "AgentName"
        ));
        assert!(!literal_at_mention_matches("@AgentNameExtra", "AgentName"));
        assert!(!literal_at_mention_matches("@", "AgentName"));
    }

    #[test]
    fn slack_text_mentions_user_tokens_or_literal_names() {
        assert!(slack_text_mentions_agent(
            "hello <@U12345>",
            "U12345",
            "AgentName"
        ));
        assert!(slack_text_mentions_agent(
            "hello <@U12345|agent>",
            "U12345",
            "AgentName"
        ));
        assert!(slack_text_mentions_agent(
            "hello @agentname",
            "U99999",
            "AgentName"
        ));
        assert!(!slack_text_mentions_agent(
            "hello <@U99999>",
            "U12345",
            "AgentName"
        ));
    }

    #[test]
    fn discord_text_mentions_users_legacy_users_and_owned_roles() {
        let roles = vec!["R1".to_owned(), "R2".to_owned()];

        assert!(discord_text_mentions_agent("hello <@123>", "123", &roles));
        assert!(discord_text_mentions_agent("hello <@!123>", "123", &roles));
        assert!(discord_text_mentions_agent("hello <@&R2>", "999", &roles));
        assert!(!discord_text_mentions_agent("hello <@&R3>", "999", &roles));
        assert!(!discord_text_mentions_agent("hello <@456>", "123", &roles));
    }

    #[test]
    fn telegram_entities_match_username_or_text_mention_user_id() {
        let entities = vec![
            TelegramMentionEntity::mention("@SupportBot"),
            TelegramMentionEntity::text_mention("42"),
        ];

        assert!(telegram_entities_mention_agent(&entities, "supportbot", ""));
        assert!(telegram_entities_mention_agent(&entities, "other", "42"));
        assert!(!telegram_entities_mention_agent(&entities, "other", "43"));
    }

    #[test]
    fn matrix_and_teams_use_structured_user_id_mentions() {
        let matrix_mentions = vec![
            "@alice:example.org".to_owned(),
            "@bot:example.org".to_owned(),
        ];
        let teams_mentions = vec!["teams-user-1".to_owned(), "teams-bot".to_owned()];

        assert!(matrix_mentions_agent(&matrix_mentions, "@bot:example.org"));
        assert!(!matrix_mentions_agent(
            &matrix_mentions,
            "@other:example.org"
        ));
        assert!(teams_mentions_agent(&teams_mentions, "teams-bot"));
        assert!(!structured_user_mentions_agent(&teams_mentions, ""));
    }

    #[test]
    fn mattermost_props_mentions_parse_json_arrays_only() {
        assert!(mattermost_props_mentions_agent(
            r#"["user-a","bot-user"]"#,
            "bot-user"
        ));
        assert!(!mattermost_props_mentions_agent(
            r#"["user-a","bot-user"]"#,
            "other"
        ));
        assert!(!mattermost_props_mentions_agent(
            r#"{"mentions":["bot-user"]}"#,
            "bot-user"
        ));
        assert!(!mattermost_props_mentions_agent("not-json", "bot-user"));
    }

    #[test]
    fn mention_tracker_records_and_expires_lazily() {
        let tracker = MentionTracker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let alice = agent("alice");
        let now = Instant::now();

        tracker.stamp(key.clone(), alice.clone(), now);
        assert_eq!(
            tracker
                .record_for(&key, &alice, now)
                .map(|record| record.agent_id().clone()),
            Some(alice.clone())
        );
        assert_eq!(tracker.active_len(now), 1);
        assert_eq!(tracker.active_len(now + Duration::from_secs(5)), 0);
        assert!(
            tracker
                .record_for(&key, &alice, now + Duration::from_secs(5))
                .is_none()
        );
    }

    #[test]
    fn mention_tracker_isolates_zones_and_connectors() {
        let tracker = MentionTracker::new();
        let slack_key = key_for(connector("slack:chat:1.0.0"));
        let discord_key = key_for(connector("discord:chat:1.0.0"));
        let private_key = ClaimKey::new(
            ZoneId::private(),
            connector("slack:chat:1.0.0"),
            ChannelId::new("C123"),
            ThreadId::new("1700000000.000100"),
        );
        let alice = agent("alice");
        let now = Instant::now();

        tracker.stamp(slack_key.clone(), alice.clone(), now);

        assert!(tracker.record_for(&slack_key, &alice, now).is_some());
        assert!(tracker.record_for(&discord_key, &alice, now).is_none());
        assert!(tracker.record_for(&private_key, &alice, now).is_none());
    }

    #[test]
    fn mention_tracker_keeps_multi_mentions_for_race_to_claim() {
        let tracker = MentionTracker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        tracker.stamp(key.clone(), agent("alice"), now);
        tracker.stamp(key.clone(), agent("bob"), now);

        assert_eq!(
            tracker.mentioned_agents(&key, now),
            vec![agent("alice"), agent("bob")]
        );
    }

    #[test]
    fn dm_mode_controls_threadless_claim_key_creation() {
        let channel = ChannelId::new("signal-dm-42");
        let skipped = ClaimKey::for_chat_message(
            ZoneId::work(),
            connector("signal:chat:1.0.0"),
            channel.clone(),
            None,
            DmMode::Skip,
        );
        assert!(skipped.is_none());

        let treated = ClaimKey::for_chat_message(
            ZoneId::work(),
            connector("signal:chat:1.0.0"),
            channel.clone(),
            None,
            DmMode::TreatAsThread,
        );
        assert_eq!(treated.as_ref().map(ClaimKey::channel_id), Some(&channel));
        assert_eq!(
            treated.as_ref().map(|key| key.thread_id().as_str()),
            Some(channel.as_str())
        );
    }

    #[test]
    fn first_claim_wins_and_second_agent_is_denied() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert_eq!(
            checker.claim_now(key.clone(), agent("alice"), now),
            ClaimOutcome::Granted(agent("alice"))
        );
        assert_eq!(
            checker.claim_now(key, agent("bob"), now),
            ClaimOutcome::AlreadyOwned(agent("alice"))
        );
    }

    #[test]
    fn same_owner_renews_claim() {
        let checker = InMemoryThreadOwnershipChecker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        let renewed_at = now + Duration::from_secs(2);

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), renewed_at)
                .is_granted()
        );

        let record = checker.record_for(&key, renewed_at);
        assert_eq!(record.as_ref().map(OwnershipRecord::claimed_at), Some(now));
        assert_eq!(
            record.as_ref().map(OwnershipRecord::renewed_at),
            Some(renewed_at)
        );
        assert_eq!(
            record.as_ref().map(OwnershipRecord::expires_at),
            Some(renewed_at + Duration::from_secs(5))
        );
    }

    #[test]
    fn stale_claim_can_be_recovered_by_peer() {
        let checker = InMemoryThreadOwnershipChecker::with_ttl(Duration::from_secs(5));
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert_eq!(checker.active_len(now + Duration::from_secs(5)), 0);
        assert_eq!(
            checker.claim_now(key, agent("bob"), now + Duration::from_secs(6)),
            ClaimOutcome::Granted(agent("bob"))
        );
    }

    #[test]
    fn owner_release_allows_handoff() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(key.clone(), agent("alice"), now)
                .is_granted()
        );
        assert!(checker.release(&key, &agent("alice"), now));
        assert!(!checker.release(&key, &agent("alice"), now));
        assert_eq!(
            checker.claim_now(key, agent("bob"), now),
            ClaimOutcome::Granted(agent("bob"))
        );
    }

    #[test]
    fn connector_namespace_keeps_claims_independent() {
        let checker = InMemoryThreadOwnershipChecker::new();
        let slack_key = key_for(connector("slack:chat:1.0.0"));
        let discord_key = key_for(connector("discord:chat:1.0.0"));
        let now = Instant::now();

        assert!(
            checker
                .claim_now(slack_key, agent("alice"), now)
                .is_granted()
        );
        assert!(
            checker
                .claim_now(discord_key, agent("bob"), now)
                .is_granted()
        );
    }

    #[test]
    fn mention_preference_blocks_unmentioned_agent() {
        let tracker = MentionTracker::new();
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        tracker.stamp(key.clone(), agent("alice"), now);

        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key.clone(), agent("bob"), now),
            ClaimOutcome::AlreadyOwned(agent("alice"))
        );
        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key, agent("alice"), now),
            ClaimOutcome::Granted(agent("alice"))
        );
    }

    #[test]
    fn multi_mentioned_agents_still_use_first_claim_wins() {
        let tracker = MentionTracker::new();
        let checker = InMemoryThreadOwnershipChecker::new();
        let key = key_for(connector("slack:chat:1.0.0"));
        let now = Instant::now();
        tracker.stamp(key.clone(), agent("alice"), now);
        tracker.stamp(key.clone(), agent("bob"), now);

        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key.clone(), agent("bob"), now),
            ClaimOutcome::Granted(agent("bob"))
        );
        assert_eq!(
            checker.claim_with_mentions_now(&tracker, key, agent("alice"), now),
            ClaimOutcome::AlreadyOwned(agent("bob"))
        );
    }

    #[test]
    fn thread_owned_error_uses_standard_unauthorized_code() {
        let err = thread_owned_by_peer_error(&agent("alice"));
        let unauthorized = match err {
            FcpError::Unauthorized { code, message } => Some((code, message)),
            _ => None,
        };
        assert_eq!(
            unauthorized,
            Some((
                THREAD_OWNED_BY_PEER_ERROR_CODE,
                "thread_owned_by_peer:alice".to_owned()
            ))
        );
    }

    #[test]
    fn redacted_ids_are_deterministic_and_hide_raw_values() {
        let agent_id = agent("alice@example.test");
        let key = key_for(connector("slack:chat:1.0.0"));

        assert_eq!(agent_id.redacted(), agent_id.redacted());
        assert!(!agent_id.redacted().contains("alice"));
        assert!(!key.redacted().contains("1700000000"));
    }
}
