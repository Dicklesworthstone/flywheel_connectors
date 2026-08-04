//! Host-side credential pooling primitives.
//!
//! This module models provider/zone pools, selection strategies, active leases,
//! cooldowns, audit events, and redacted public views. Host admin routes wire
//! these primitives in `bin/fcp-host.rs`; connector-facing transport remains a
//! separate integration layer.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use fcp_prelude::{CredentialId, ZoneId};
use fcp_provider_auth::{AuthMethod, AuthProfile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const DEFAULT_MAX_CONCURRENT_PER_CREDENTIAL: u32 = 5;
const DEFAULT_RATE_LIMIT_COOLDOWN_SECS: i64 = 60;
const DEFAULT_QUOTA_COOLDOWN_SECS: i64 = 600;

/// Upper bound on any credential cooldown window (7 days).
///
/// A provider `Retry-After` (or a direct caller-supplied duration) is clamped
/// to this. Real providers never ask for more (Stripe's webhook retry horizon
/// tops out around 3 days), and an unbounded value is a live panic vector:
/// `chrono::Duration::from_std` accepts durations up to ~292 million years, but
/// `DateTime<Utc> + Duration` panics (`checked_add_signed(..).expect(..)`) once
/// the result exceeds `DateTime`'s ~year-262143 range, so a hostile
/// `Retry-After` in that window would crash the host. Clamping keeps every
/// cooldown deadline comfortably in range.
const MAX_CREDENTIAL_COOLDOWN_SECS: i64 = 7 * 24 * 60 * 60;

/// Provider identifier for a credential pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderKey(String);

impl ProviderKey {
    /// Construct a canonical provider key.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::InvalidProviderKey`] when the key is
    /// empty after trimming whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialPoolError> {
        let value = value.into().trim().to_ascii_lowercase();
        if value.is_empty() {
            return Err(CredentialPoolError::InvalidProviderKey);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical provider key string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ProviderKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProviderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Registry identity for one provider pool inside one zone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialPoolKey {
    /// Provider namespace, for example `openai` or `anthropic`.
    pub provider: ProviderKey,
    /// Zone that owns the credential pool.
    pub zone_id: ZoneId,
}

impl CredentialPoolKey {
    /// Construct a provider+zone pool key.
    #[must_use]
    pub const fn new(provider: ProviderKey, zone_id: ZoneId) -> Self {
        Self { provider, zone_id }
    }
}

impl fmt::Display for CredentialPoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "provider {} in zone {}",
            self.provider,
            self.zone_id.as_str()
        )
    }
}

/// Source label for a credential inside a pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Operator entered the credential manually.
    Manual,
    /// Credential was seeded from an environment variable.
    Env,
    /// Credential was seeded from host configuration.
    Config,
    /// Credential came from a named custom pool source.
    CustomPool(String),
}

impl CredentialSource {
    /// Redaction-safe source label.
    #[must_use]
    pub fn as_label(&self) -> String {
        match self {
            Self::Manual => "manual".to_owned(),
            Self::Env => "env".to_owned(),
            Self::Config => "config".to_owned(),
            Self::CustomPool(name) => format!("custom-pool:{name}"),
        }
    }
}

/// Selection strategy for a credential pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPoolStrategy {
    /// Cycle across all currently available credentials.
    RoundRobin,
    /// Continue using the current credential until it becomes unavailable.
    Sticky,
    /// Always choose the lowest-priority-number available credential.
    Priority,
    /// Choose the available credential that has gone unused the longest.
    LeastRecentlyUsed,
}

/// Sticky-strategy controls for a credential pool.
///
/// Defaults preserve the original sticky behavior: once a fallback credential
/// is selected, the pool keeps that fallback until it becomes unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StickyCredentialPolicy {
    /// Return to a displaced sticky credential once it becomes selectable again.
    #[serde(default)]
    pub restick_on_recovery: bool,
    /// Maximum lease selections to keep on one sticky credential before rotating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses_per_stick: Option<u32>,
}

impl StickyCredentialPolicy {
    /// Validate operator-supplied sticky policy values.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::InvalidStickyMaxUses`] when
    /// `max_uses_per_stick` is zero.
    pub fn validate(self) -> Result<(), CredentialPoolError> {
        if self.max_uses_per_stick == Some(0) {
            return Err(CredentialPoolError::InvalidStickyMaxUses { max: 0 });
        }
        Ok(())
    }
}

/// Behavior when every credential is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolExhaustedBehavior {
    /// Return an explicit exhausted error immediately.
    FailFast,
    /// Return deterministic wait advice when the next available credential is known.
    Wait,
}

/// Cooldown status for a pooled credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialCooldown {
    /// Credential is unavailable until this timestamp.
    Until { until: DateTime<Utc> },
    /// Credential is unavailable until an operator clears it.
    Permanent,
}

impl CredentialCooldown {
    fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self {
            Self::Until { until } => now < *until,
            Self::Permanent => true,
        }
    }

    fn available_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Until { until } if now < *until => Some(*until),
            Self::Until { .. } | Self::Permanent => None,
        }
    }
}

/// Policy error reported against a leased credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorKind {
    /// Provider returned a rate-limit response.
    RateLimited,
    /// Provider reported exhausted quota.
    QuotaExhausted,
    /// Provider rejected authentication.
    AuthFailed,
    /// Provider returned another retryable credential-scoped failure.
    RetryableProviderError,
}

/// Redaction-safe classifier for a leased credential payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPayloadKind {
    /// Legacy raw JSON payload accepted by the host admin API.
    RawJson,
    /// Provider-auth profile that can build outbound request auth.
    AuthProfile,
}

/// Secret-bearing payload carried by a pooled credential lease.
///
/// Intentionally not serializable: operator/admin surfaces expose only
/// [`CredentialPayloadKind`] and redacted labels, never credential material.
#[derive(Clone)]
pub enum CredentialPayload {
    /// Legacy JSON credential material accepted by existing admin routes.
    RawJson(Value),
    /// Provider-auth profile selected from the pool.
    AuthProfile {
        /// Provider-auth profile selected from the pool.
        profile: Box<AuthProfile>,
        /// Destination hosts that may receive material from this profile.
        host_allow: Vec<String>,
    },
}

impl CredentialPayload {
    /// Construct a raw JSON payload.
    #[must_use]
    pub const fn raw_json(payload: Value) -> Self {
        Self::RawJson(payload)
    }

    /// Construct an auth-profile payload.
    #[must_use]
    pub fn auth_profile(profile: AuthProfile) -> Self {
        Self::AuthProfile {
            profile: Box::new(profile),
            host_allow: Vec::new(),
        }
    }

    /// Construct an auth-profile payload with destination host bindings.
    #[must_use]
    pub fn auth_profile_with_allowed_hosts<I, S>(profile: AuthProfile, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::AuthProfile {
            profile: Box::new(profile),
            host_allow: hosts.into_iter().map(Into::into).collect(),
        }
    }

    /// Return the redaction-safe payload class.
    #[must_use]
    pub const fn kind(&self) -> CredentialPayloadKind {
        match self {
            Self::RawJson(_) => CredentialPayloadKind::RawJson,
            Self::AuthProfile { .. } => CredentialPayloadKind::AuthProfile,
        }
    }

    /// Borrow raw JSON material, if this lease uses the legacy payload form.
    #[must_use]
    pub const fn as_raw_json(&self) -> Option<&Value> {
        match self {
            Self::RawJson(payload) => Some(payload),
            Self::AuthProfile { .. } => None,
        }
    }

    /// Borrow the provider-auth profile, if this lease carries one.
    #[must_use]
    pub fn as_auth_profile(&self) -> Option<&AuthProfile> {
        match self {
            Self::RawJson(_) => None,
            Self::AuthProfile { profile, .. } => Some(profile.as_ref()),
        }
    }

    /// Borrow destination host bindings for an auth-profile payload.
    #[must_use]
    pub const fn auth_profile_host_allow(&self) -> Option<&[String]> {
        match self {
            Self::RawJson(_) => None,
            Self::AuthProfile { host_allow, .. } => Some(host_allow.as_slice()),
        }
    }

    /// Consume the payload and return the provider-auth profile, if present.
    #[must_use]
    pub fn into_auth_profile(self) -> Option<AuthProfile> {
        match self {
            Self::RawJson(_) => None,
            Self::AuthProfile { profile, .. } => Some(*profile),
        }
    }
}

impl From<Value> for CredentialPayload {
    fn from(payload: Value) -> Self {
        Self::RawJson(payload)
    }
}

impl fmt::Debug for CredentialPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawJson(_) => f.write_str("CredentialPayload::RawJson([redacted])"),
            Self::AuthProfile {
                profile,
                host_allow,
            } => f
                .debug_struct("CredentialPayload::AuthProfile")
                .field("provider", &profile.provider)
                .field("profile_id", &profile.id)
                .field("method", &profile.method.id())
                .field("label", &profile.label)
                .field("host_allow_count", &host_allow.len())
                .finish(),
        }
    }
}

/// Secret material plus routing metadata for one pooled credential.
///
/// Intentionally not serializable: public/operator surfaces must use
/// [`PooledCredentialView`] so secret payloads stay behind an explicit
/// redaction boundary.
#[derive(Debug, Clone)]
pub struct PooledCredential {
    /// Stable credential identifier.
    pub credential_id: CredentialId,
    /// Source class used for redacted operator views.
    pub source: CredentialSource,
    /// Lower values are preferred by [`CredentialPoolStrategy::Priority`].
    pub priority: u32,
    /// Redaction-safe human label.
    pub label: String,
    /// Credential payload. This must never appear in public views or errors.
    pub payload: CredentialPayload,
    /// Current cooldown, if any.
    pub cooldown: Option<CredentialCooldown>,
    /// Last successful or attempted selection timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Number of credential-scoped errors reported.
    pub error_count: u32,
}

impl PooledCredential {
    /// Construct a pooled credential entry.
    #[must_use]
    pub fn new(
        credential_id: CredentialId,
        source: CredentialSource,
        priority: u32,
        label: impl Into<String>,
        payload: impl Into<CredentialPayload>,
    ) -> Self {
        Self {
            credential_id,
            source,
            priority,
            label: label.into(),
            payload: payload.into(),
            cooldown: None,
            last_used_at: None,
            error_count: 0,
        }
    }

    fn is_available(&self, now: DateTime<Utc>) -> bool {
        self.cooldown
            .as_ref()
            .is_none_or(|cooldown| !cooldown.is_active(now))
    }
}

/// Secret-bearing input shape for adding or updating one pool entry.
///
/// Intentionally not serializable: route handlers may deserialize this request
/// shape, but operator responses must use [`PooledCredentialView`].
#[derive(Debug, Clone, Deserialize)]
pub struct PooledCredentialInput {
    /// Stable credential identifier.
    pub credential_id: CredentialId,
    /// Source class used for redacted operator views.
    pub source: CredentialSource,
    /// Lower values are preferred by [`CredentialPoolStrategy::Priority`].
    pub priority: u32,
    /// Redaction-safe human label.
    pub label: String,
    /// Credential payload. This must never appear in public views or errors.
    pub payload: Value,
}

impl PooledCredentialInput {
    /// Construct a secret-bearing pool-entry request.
    #[must_use]
    pub fn new(
        credential_id: CredentialId,
        source: CredentialSource,
        priority: u32,
        label: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            credential_id,
            source,
            priority,
            label: label.into(),
            payload,
        }
    }

    /// Convert the input into the internal pool entry.
    #[must_use]
    pub fn into_credential(self) -> PooledCredential {
        PooledCredential::new(
            self.credential_id,
            self.source,
            self.priority,
            self.label,
            self.payload,
        )
    }
}

/// Duplicate handling policy for adding a credential to a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialUpsertMode {
    /// Reject an existing credential id.
    RejectExisting,
    /// Replace an existing credential entry with the supplied metadata/payload.
    ReplaceExisting,
}

/// Result of a credential entry mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMutationOutcome {
    /// A new entry was inserted.
    Added,
    /// An existing entry was replaced.
    Replaced,
    /// An entry was removed.
    Removed,
}

/// Stable event type for credential-pool mutation audit records.
pub const CREDENTIAL_POOL_AUDIT_EVENT_TYPE: &str = "credential_pool.admin_mutation";

/// Redaction-safe credential-pool mutation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPoolAuditOperation {
    /// A credential entry was added or replaced.
    CredentialUpsert,
    /// A credential entry was removed.
    CredentialRemove,
    /// The pool selection strategy changed.
    StrategySet,
    /// The per-credential active lease ceiling changed.
    MaxConcurrentSet,
    /// Sticky strategy policy changed.
    StickyPolicySet,
    /// The all-pool-exhausted behavior changed.
    ExhaustedBehaviorSet,
    /// A credential cooldown was manually set or cleared.
    CooldownSet,
}

/// Redaction-safe cooldown state carried in audit records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CredentialCooldownAuditState {
    /// Cooldown was cleared.
    Cleared,
    /// Credential is unavailable until this timestamp.
    Until {
        /// Cooldown expiry timestamp.
        until: DateTime<Utc>,
    },
    /// Credential is unavailable until an operator clears it.
    Permanent,
}

impl From<Option<CredentialCooldown>> for CredentialCooldownAuditState {
    fn from(cooldown: Option<CredentialCooldown>) -> Self {
        match cooldown {
            Some(CredentialCooldown::Until { until }) => Self::Until { until },
            Some(CredentialCooldown::Permanent) => Self::Permanent,
            None => Self::Cleared,
        }
    }
}

/// Redaction-safe credential-pool mutation audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPoolAuditEvent {
    /// Stable audit event namespace.
    pub event_type: String,
    /// Wall-clock event timestamp.
    pub occurred_at: DateTime<Utc>,
    /// Mutation class.
    pub operation: CredentialPoolAuditOperation,
    /// Provider+zone pool identity.
    pub pool_key: CredentialPoolKey,
    /// Credential touched by the mutation, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<CredentialId>,
    /// Add/remove outcome, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<CredentialMutationOutcome>,
    /// New strategy, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<CredentialPoolStrategy>,
    /// New active lease ceiling, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_per_credential: Option<u32>,
    /// New sticky policy, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sticky_policy: Option<StickyCredentialPolicy>,
    /// New all-pool-exhausted behavior, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exhausted_behavior: Option<PoolExhaustedBehavior>,
    /// New cooldown state, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown: Option<CredentialCooldownAuditState>,
}

impl CredentialPoolAuditEvent {
    fn credential_upsert(
        pool_key: CredentialPoolKey,
        credential_id: CredentialId,
        outcome: CredentialMutationOutcome,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::CredentialUpsert,
            pool_key,
            credential_id: Some(credential_id),
            outcome: Some(outcome),
            strategy: None,
            max_concurrent_per_credential: None,
            sticky_policy: None,
            exhausted_behavior: None,
            cooldown: None,
        }
    }

    fn credential_remove(
        pool_key: CredentialPoolKey,
        credential_id: CredentialId,
        outcome: CredentialMutationOutcome,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::CredentialRemove,
            pool_key,
            credential_id: Some(credential_id),
            outcome: Some(outcome),
            strategy: None,
            max_concurrent_per_credential: None,
            sticky_policy: None,
            exhausted_behavior: None,
            cooldown: None,
        }
    }

    fn strategy_set(
        pool_key: CredentialPoolKey,
        strategy: CredentialPoolStrategy,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::StrategySet,
            pool_key,
            credential_id: None,
            outcome: None,
            strategy: Some(strategy),
            max_concurrent_per_credential: None,
            sticky_policy: None,
            exhausted_behavior: None,
            cooldown: None,
        }
    }

    fn max_concurrent_set(
        pool_key: CredentialPoolKey,
        max_concurrent_per_credential: u32,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::MaxConcurrentSet,
            pool_key,
            credential_id: None,
            outcome: None,
            strategy: None,
            max_concurrent_per_credential: Some(max_concurrent_per_credential),
            sticky_policy: None,
            exhausted_behavior: None,
            cooldown: None,
        }
    }

    fn sticky_policy_set(
        pool_key: CredentialPoolKey,
        sticky_policy: StickyCredentialPolicy,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::StickyPolicySet,
            pool_key,
            credential_id: None,
            outcome: None,
            strategy: None,
            max_concurrent_per_credential: None,
            sticky_policy: Some(sticky_policy),
            exhausted_behavior: None,
            cooldown: None,
        }
    }

    fn exhausted_behavior_set(
        pool_key: CredentialPoolKey,
        exhausted_behavior: PoolExhaustedBehavior,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::ExhaustedBehaviorSet,
            pool_key,
            credential_id: None,
            outcome: None,
            strategy: None,
            max_concurrent_per_credential: None,
            sticky_policy: None,
            exhausted_behavior: Some(exhausted_behavior),
            cooldown: None,
        }
    }

    fn cooldown_set(
        pool_key: CredentialPoolKey,
        credential_id: CredentialId,
        cooldown: Option<CredentialCooldown>,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            event_type: CREDENTIAL_POOL_AUDIT_EVENT_TYPE.to_owned(),
            occurred_at,
            operation: CredentialPoolAuditOperation::CooldownSet,
            pool_key,
            credential_id: Some(credential_id),
            outcome: None,
            strategy: None,
            max_concurrent_per_credential: None,
            sticky_policy: None,
            exhausted_behavior: None,
            cooldown: Some(CredentialCooldownAuditState::from(cooldown)),
        }
    }
}

/// Active credential lease returned by a pool.
#[derive(Clone)]
pub struct CredentialLease {
    /// Opaque lease token used to release or report errors.
    pub token: CredentialLeaseToken,
    /// Credential selected for this lease.
    pub credential_id: CredentialId,
    /// Secret-bearing credential payload selected for this lease.
    pub payload: CredentialPayload,
    /// Provider+zone pool that issued the lease.
    pub pool_key: CredentialPoolKey,
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialLease")
            .field("token", &self.token)
            .field("credential_id", &self.credential_id)
            .field("payload_kind", &self.payload.kind())
            .field("payload", &"[redacted]")
            .field("pool_key", &self.pool_key)
            .finish()
    }
}

/// Opaque credential lease token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialLeaseToken(u64);

impl CredentialLeaseToken {
    /// Raw numeric lease token, safe for diagnostics.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CredentialLeaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_u64())
    }
}

/// Redaction-safe view of one pooled credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PooledCredentialView {
    /// Stable credential identifier.
    pub credential_id: CredentialId,
    /// Redaction-safe source label.
    pub source: String,
    /// Lower values are preferred by priority strategy.
    pub priority: u32,
    /// Redaction-safe human label.
    pub label: String,
    /// Redaction-safe payload class.
    pub payload_kind: CredentialPayloadKind,
    /// Current active leases for this credential.
    pub active_leases: u32,
    /// Current cooldown, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown: Option<CredentialCooldown>,
    /// Last selection timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Number of credential-scoped errors reported.
    pub error_count: u32,
    /// Whether this credential can be selected at the supplied snapshot time.
    pub available: bool,
}

/// Redaction-safe view of a credential pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPoolView {
    /// Provider+zone pool identity.
    pub key: CredentialPoolKey,
    /// Selection strategy.
    pub strategy: CredentialPoolStrategy,
    /// Sticky-strategy controls.
    pub sticky_policy: StickyCredentialPolicy,
    /// Maximum active leases per credential.
    pub max_concurrent_per_credential: u32,
    /// Exhaustion behavior.
    pub exhausted_behavior: PoolExhaustedBehavior,
    /// Redacted credential entries.
    pub entries: Vec<PooledCredentialView>,
}

/// Host-side credential pool with deterministic selection and lease tracking.
#[derive(Debug, Clone)]
pub struct CredentialPool {
    key: CredentialPoolKey,
    strategy: CredentialPoolStrategy,
    sticky_policy: StickyCredentialPolicy,
    exhausted_behavior: PoolExhaustedBehavior,
    max_concurrent_per_credential: u32,
    entries: Vec<PooledCredential>,
    active_leases: HashMap<CredentialId, u32>,
    lease_index: HashMap<CredentialLeaseToken, CredentialId>,
    round_robin_cursor: usize,
    sticky_current: Option<CredentialId>,
    sticky_restick_target: Option<CredentialId>,
    sticky_current_uses: u32,
    next_lease_serial: u64,
}

impl CredentialPool {
    /// Create a pool and sort credentials by priority for stable selection.
    #[must_use]
    pub fn new(
        key: CredentialPoolKey,
        strategy: CredentialPoolStrategy,
        mut entries: Vec<PooledCredential>,
    ) -> Self {
        sort_entries(&mut entries);

        Self {
            key,
            strategy,
            sticky_policy: StickyCredentialPolicy::default(),
            exhausted_behavior: PoolExhaustedBehavior::FailFast,
            max_concurrent_per_credential: DEFAULT_MAX_CONCURRENT_PER_CREDENTIAL,
            entries,
            active_leases: HashMap::new(),
            lease_index: HashMap::new(),
            round_robin_cursor: 0,
            sticky_current: None,
            sticky_restick_target: None,
            sticky_current_uses: 0,
            next_lease_serial: 1,
        }
    }

    /// Set the per-credential active lease ceiling.
    #[must_use]
    pub const fn with_max_concurrent_per_credential(mut self, max: u32) -> Self {
        self.max_concurrent_per_credential = max;
        self
    }

    /// Set the all-pool-exhausted behavior.
    #[must_use]
    pub const fn with_exhausted_behavior(mut self, behavior: PoolExhaustedBehavior) -> Self {
        self.exhausted_behavior = behavior;
        self
    }

    /// Borrow the provider+zone pool key.
    #[must_use]
    pub const fn key(&self) -> &CredentialPoolKey {
        &self.key
    }

    /// Current selection strategy.
    #[must_use]
    pub const fn strategy(&self) -> CredentialPoolStrategy {
        self.strategy
    }

    /// Current sticky-strategy controls.
    #[must_use]
    pub const fn sticky_policy(&self) -> StickyCredentialPolicy {
        self.sticky_policy
    }

    /// Current all-pool-exhausted behavior.
    #[must_use]
    pub const fn exhausted_behavior(&self) -> PoolExhaustedBehavior {
        self.exhausted_behavior
    }

    /// Current per-credential active lease ceiling.
    #[must_use]
    pub const fn max_concurrent_per_credential(&self) -> u32 {
        self.max_concurrent_per_credential
    }

    /// Number of credentials in the pool.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool has no credentials.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add or replace one credential entry in this pool.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::DuplicateCredential`] when the entry
    /// already exists and `mode` is [`CredentialUpsertMode::RejectExisting`].
    pub fn add_credential(
        &mut self,
        credential: PooledCredential,
        mode: CredentialUpsertMode,
    ) -> Result<CredentialMutationOutcome, CredentialPoolError> {
        if let Some(index) = self.index_of(credential.credential_id) {
            if mode == CredentialUpsertMode::RejectExisting {
                return Err(CredentialPoolError::DuplicateCredential {
                    credential_id: credential.credential_id,
                });
            }
            let Some(entry) = self.entries.get_mut(index) else {
                return Err(CredentialPoolError::SelectionIndexInvalid {
                    key: self.key.clone(),
                    index,
                });
            };
            *entry = credential;
            sort_entries(&mut self.entries);
            self.round_robin_cursor = self.round_robin_cursor.min(self.entries.len());
            return Ok(CredentialMutationOutcome::Replaced);
        }

        self.entries.push(credential);
        sort_entries(&mut self.entries);
        if !self.entries.is_empty() {
            self.round_robin_cursor %= self.entries.len();
        }
        Ok(CredentialMutationOutcome::Added)
    }

    /// Replace the payload for an existing credential without changing its
    /// routing metadata or active lease bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is not part of this pool.
    pub fn replace_payload(
        &mut self,
        credential_id: CredentialId,
        payload: CredentialPayload,
    ) -> Result<(), CredentialPoolError> {
        let Some(entry) = self.entry_mut(credential_id) else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };
        entry.payload = payload;
        Ok(())
    }

    /// Remove a credential entry and any active lease bookkeeping for it.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is not part of this pool.
    pub fn remove_credential(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PooledCredential, CredentialPoolError> {
        let Some(index) = self.index_of(credential_id) else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };
        let removed = self.entries.remove(index);
        self.active_leases.remove(&credential_id);
        self.lease_index
            .retain(|_, leased_credential_id| *leased_credential_id != credential_id);
        if self.sticky_current == Some(credential_id) {
            self.sticky_current = None;
            self.sticky_current_uses = 0;
        }
        if self.sticky_restick_target == Some(credential_id) {
            self.sticky_restick_target = None;
        }
        if self.entries.is_empty() {
            self.round_robin_cursor = 0;
        } else {
            self.round_robin_cursor %= self.entries.len();
        }
        Ok(removed)
    }

    /// Change the pool selection strategy.
    pub const fn set_strategy(&mut self, strategy: CredentialPoolStrategy) {
        self.strategy = strategy;
        self.sticky_current = None;
        self.sticky_restick_target = None;
        self.sticky_current_uses = 0;
    }

    /// Set sticky-strategy controls.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::InvalidStickyMaxUses`] when
    /// `max_uses_per_stick` is zero.
    pub fn set_sticky_policy(
        &mut self,
        policy: StickyCredentialPolicy,
    ) -> Result<(), CredentialPoolError> {
        policy.validate()?;
        self.sticky_policy = policy;
        if !policy.restick_on_recovery {
            self.sticky_restick_target = None;
        }
        Ok(())
    }

    /// Set the per-credential active lease ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::InvalidMaxConcurrentPerCredential`] when
    /// `max` is zero.
    pub const fn set_max_concurrent_per_credential(
        &mut self,
        max: u32,
    ) -> Result<(), CredentialPoolError> {
        if max == 0 {
            return Err(CredentialPoolError::InvalidMaxConcurrentPerCredential { max });
        }
        self.max_concurrent_per_credential = max;
        Ok(())
    }

    /// Set the all-pool-exhausted behavior.
    pub const fn set_exhausted_behavior(&mut self, behavior: PoolExhaustedBehavior) {
        self.exhausted_behavior = behavior;
    }

    /// Acquire a credential lease using the configured strategy.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolExhausted`] if no credential is
    /// currently available with no known wait deadline, or
    /// [`CredentialPoolError::PoolWaitRequired`] when wait mode can report the
    /// earliest cooldown expiry.
    pub fn acquire(&mut self, now: DateTime<Utc>) -> Result<CredentialLease, CredentialPoolError> {
        let Some(index) = self.select_index(now) else {
            return match self.exhausted_behavior {
                PoolExhaustedBehavior::FailFast => Err(CredentialPoolError::PoolExhausted {
                    key: self.key.clone(),
                }),
                PoolExhaustedBehavior::Wait => self.wait_required_or_exhausted(now),
            };
        };

        let Some(entry) = self.entries.get_mut(index) else {
            return Err(CredentialPoolError::SelectionIndexInvalid {
                key: self.key.clone(),
                index,
            });
        };
        let credential_id = entry.credential_id;
        let payload = entry.payload.clone();
        entry.last_used_at = Some(now);
        if self.strategy == CredentialPoolStrategy::Sticky {
            self.record_sticky_selection(credential_id);
        }

        let lease_id = CredentialLeaseToken(self.next_lease_serial);
        self.next_lease_serial = self.next_lease_serial.saturating_add(1);
        *self.active_leases.entry(credential_id).or_default() += 1;
        self.lease_index.insert(lease_id, credential_id);

        Ok(CredentialLease {
            token: lease_id,
            credential_id,
            payload,
            pool_key: self.key.clone(),
        })
    }

    /// Acquire a lease for a specific credential in this pool.
    ///
    /// Host-mediated egress uses explicit credential ids from a verified
    /// capability token. It must not silently substitute a different pooled
    /// credential via the pool selection strategy.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is absent, [`CredentialPoolError::PoolWaitRequired`] when a cooldown has
    /// a known expiry and the pool is in wait mode, or
    /// [`CredentialPoolError::PoolExhausted`] when the credential is currently
    /// unavailable.
    pub fn acquire_specific(
        &mut self,
        credential_id: CredentialId,
        now: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialPoolError> {
        let Some(index) = self.index_of(credential_id) else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };
        if !self.can_select(index, now) {
            return match self.exhausted_behavior {
                PoolExhaustedBehavior::FailFast => Err(CredentialPoolError::PoolExhausted {
                    key: self.key.clone(),
                }),
                PoolExhaustedBehavior::Wait => self.wait_required_or_exhausted(now),
            };
        }

        let Some(entry) = self.entries.get_mut(index) else {
            return Err(CredentialPoolError::SelectionIndexInvalid {
                key: self.key.clone(),
                index,
            });
        };
        let payload = entry.payload.clone();
        entry.last_used_at = Some(now);
        if self.strategy == CredentialPoolStrategy::Sticky {
            self.record_sticky_selection(credential_id);
        }

        let lease_id = CredentialLeaseToken(self.next_lease_serial);
        self.next_lease_serial = self.next_lease_serial.saturating_add(1);
        *self.active_leases.entry(credential_id).or_default() += 1;
        self.lease_index.insert(lease_id, credential_id);

        Ok(CredentialLease {
            token: lease_id,
            credential_id,
            payload,
            pool_key: self.key.clone(),
        })
    }

    /// Release a previously acquired lease.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::UnknownLease`] if the token was not
    /// issued by this pool or was already released.
    pub fn release(
        &mut self,
        token: CredentialLeaseToken,
    ) -> Result<CredentialId, CredentialPoolError> {
        let Some(credential_id) = self.lease_index.remove(&token) else {
            return Err(CredentialPoolError::UnknownLease { token });
        };
        self.decrement_active_lease(credential_id);
        Ok(credential_id)
    }

    /// Report a credential-scoped error for an active lease, then release it.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::UnknownLease`] if the token is unknown.
    pub fn report_error(
        &mut self,
        token: CredentialLeaseToken,
        kind: CredentialErrorKind,
        retry_after: Option<StdDuration>,
        now: DateTime<Utc>,
    ) -> Result<CredentialId, CredentialPoolError> {
        let credential_id = self.release(token)?;
        self.mark_error(credential_id, kind, retry_after, now)?;
        Ok(credential_id)
    }

    /// Mark a credential error without requiring an active lease.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is not part of this pool.
    pub fn mark_error(
        &mut self,
        credential_id: CredentialId,
        kind: CredentialErrorKind,
        retry_after: Option<StdDuration>,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialPoolError> {
        let Some(entry) = self.entry_mut(credential_id) else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };
        entry.error_count = entry.error_count.saturating_add(1);
        entry.cooldown = cooldown_for_error(kind, retry_after, now);
        self.displace_sticky_current(credential_id);
        Ok(())
    }

    /// Clear cooldown state for a credential.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is not part of this pool.
    pub fn clear_cooldown(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<(), CredentialPoolError> {
        self.set_cooldown(credential_id, None)
    }

    /// Set or clear cooldown state for a credential.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when the credential
    /// is not part of this pool.
    pub fn set_cooldown(
        &mut self,
        credential_id: CredentialId,
        cooldown: Option<CredentialCooldown>,
    ) -> Result<(), CredentialPoolError> {
        let Some(entry) = self.entry_mut(credential_id) else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };
        let displace_sticky = cooldown.is_some();
        entry.cooldown = cooldown;
        if displace_sticky {
            self.displace_sticky_current(credential_id);
        }
        Ok(())
    }

    /// Build a redaction-safe snapshot of the pool.
    #[must_use]
    pub fn redacted_view(&self, now: DateTime<Utc>) -> CredentialPoolView {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                let active_leases = self.active_count(entry.credential_id);
                PooledCredentialView {
                    credential_id: entry.credential_id,
                    source: entry.source.as_label(),
                    priority: entry.priority,
                    label: entry.label.clone(),
                    payload_kind: entry.payload.kind(),
                    active_leases,
                    cooldown: entry.cooldown.clone(),
                    last_used_at: entry.last_used_at,
                    error_count: entry.error_count,
                    available: entry.is_available(now)
                        && active_leases < self.max_concurrent_per_credential,
                }
            })
            .collect();

        CredentialPoolView {
            key: self.key.clone(),
            strategy: self.strategy,
            sticky_policy: self.sticky_policy,
            max_concurrent_per_credential: self.max_concurrent_per_credential,
            exhausted_behavior: self.exhausted_behavior,
            entries,
        }
    }

    fn select_index(&mut self, now: DateTime<Utc>) -> Option<usize> {
        match self.strategy {
            CredentialPoolStrategy::RoundRobin => self.select_round_robin(now),
            CredentialPoolStrategy::Sticky => self.select_sticky(now),
            CredentialPoolStrategy::Priority => self.select_priority(now),
            CredentialPoolStrategy::LeastRecentlyUsed => self.select_least_recently_used(now),
        }
    }

    fn select_round_robin(&mut self, now: DateTime<Utc>) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }

        for offset in 0..self.entries.len() {
            let index = (self.round_robin_cursor + offset) % self.entries.len();
            if self.can_select(index, now) {
                self.round_robin_cursor = (index + 1) % self.entries.len();
                return Some(index);
            }
        }
        None
    }

    fn select_sticky(&mut self, now: DateTime<Utc>) -> Option<usize> {
        if let Some(restick_target) = self.sticky_restick_target
            && self.sticky_policy.restick_on_recovery
            && let Some(index) = self.index_of(restick_target)
            && self.can_select(index, now)
        {
            self.prepare_sticky_selection(restick_target);
            return Some(index);
        }

        if let Some(current) = self.sticky_current
            && let Some(index) = self.index_of(current)
            && self.can_select(index, now)
        {
            if self.sticky_use_limit_reached()
                && let Some(selected) = self.select_priority_excluding(now, current)
            {
                let credential_id = self.entries.get(selected)?.credential_id;
                self.prepare_sticky_selection(credential_id);
                return Some(selected);
            }
            return Some(index);
        }

        if let Some(current) = self.sticky_current {
            self.displace_sticky_current(current);
        }

        let selected = self.select_priority(now)?;
        self.prepare_sticky_selection(self.entries.get(selected)?.credential_id);
        Some(selected)
    }

    fn select_priority(&self, now: DateTime<Utc>) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find_map(|(index, _)| self.can_select(index, now).then_some(index))
    }

    fn select_priority_excluding(
        &self,
        now: DateTime<Utc>,
        excluded: CredentialId,
    ) -> Option<usize> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            (entry.credential_id != excluded && self.can_select(index, now)).then_some(index)
        })
    }

    fn select_least_recently_used(&self, now: DateTime<Utc>) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, _)| self.can_select(*index, now))
            .min_by(|(_, left), (_, right)| compare_lru_entries(left, right))
            .map(|(index, _)| index)
    }

    fn can_select(&self, index: usize, now: DateTime<Utc>) -> bool {
        let Some(entry) = self.entries.get(index) else {
            return false;
        };
        entry.is_available(now)
            && self.active_count(entry.credential_id) < self.max_concurrent_per_credential
    }

    fn active_count(&self, credential_id: CredentialId) -> u32 {
        self.active_leases
            .get(&credential_id)
            .copied()
            .unwrap_or_default()
    }

    fn sticky_use_limit_reached(&self) -> bool {
        self.sticky_policy
            .max_uses_per_stick
            .is_some_and(|max_uses| self.sticky_current_uses >= max_uses)
    }

    fn prepare_sticky_selection(&mut self, credential_id: CredentialId) {
        if self.sticky_current != Some(credential_id) {
            self.sticky_current = Some(credential_id);
            self.sticky_current_uses = 0;
        }
        if self.sticky_restick_target == Some(credential_id) {
            self.sticky_restick_target = None;
        }
    }

    fn record_sticky_selection(&mut self, credential_id: CredentialId) {
        if self.sticky_current == Some(credential_id) {
            self.sticky_current_uses = self.sticky_current_uses.saturating_add(1);
        } else {
            self.sticky_current = Some(credential_id);
            self.sticky_current_uses = 1;
        }
        if self.sticky_restick_target == Some(credential_id) {
            self.sticky_restick_target = None;
        }
    }

    fn displace_sticky_current(&mut self, credential_id: CredentialId) {
        if self.sticky_current != Some(credential_id) {
            return;
        }
        if self.sticky_policy.restick_on_recovery
            && self.sticky_restick_target.is_none()
            && self.contains_credential(credential_id)
        {
            self.sticky_restick_target = Some(credential_id);
        }
        self.sticky_current = None;
        self.sticky_current_uses = 0;
    }

    fn wait_required_or_exhausted<T>(&self, now: DateTime<Utc>) -> Result<T, CredentialPoolError> {
        if let Some(available_at) = self.next_available_at(now) {
            return Err(CredentialPoolError::PoolWaitRequired {
                key: self.key.clone(),
                available_at,
            });
        }

        Err(CredentialPoolError::PoolExhausted {
            key: self.key.clone(),
        })
    }

    fn next_available_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.entries
            .iter()
            .filter(|entry| {
                self.active_count(entry.credential_id) < self.max_concurrent_per_credential
            })
            .filter_map(|entry| {
                entry
                    .cooldown
                    .as_ref()
                    .and_then(|cooldown| cooldown.available_at(now))
            })
            .min()
    }

    fn decrement_active_lease(&mut self, credential_id: CredentialId) {
        if let Some(count) = self.active_leases.get_mut(&credential_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.active_leases.remove(&credential_id);
            }
        }
    }

    fn index_of(&self, credential_id: CredentialId) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.credential_id == credential_id)
    }

    fn contains_credential(&self, credential_id: CredentialId) -> bool {
        self.index_of(credential_id).is_some()
    }

    fn entry_mut(&mut self, credential_id: CredentialId) -> Option<&mut PooledCredential> {
        self.entries
            .iter_mut()
            .find(|entry| entry.credential_id == credential_id)
    }
}

/// In-memory registry keyed by provider and zone.
#[derive(Debug, Clone, Default)]
pub struct CredentialPoolRegistry {
    pools: HashMap<CredentialPoolKey, CredentialPool>,
    audit_events: Vec<CredentialPoolAuditEvent>,
}

impl CredentialPoolRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a pool.
    pub fn upsert(&mut self, pool: CredentialPool) -> Option<CredentialPool> {
        self.pools.insert(pool.key.clone(), pool)
    }

    /// Add or replace one credential entry, creating the pool when needed.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::DuplicateCredential`] when the entry
    /// already exists and `mode` is [`CredentialUpsertMode::RejectExisting`].
    pub fn add_credential(
        &mut self,
        key: CredentialPoolKey,
        strategy_for_new_pool: CredentialPoolStrategy,
        credential: PooledCredential,
        mode: CredentialUpsertMode,
    ) -> Result<CredentialMutationOutcome, CredentialPoolError> {
        let credential_id = credential.credential_id;
        let outcome = if let Some(pool) = self.pools.get_mut(&key) {
            pool.add_credential(credential, mode)?
        } else {
            let mut pool = CredentialPool::new(key.clone(), strategy_for_new_pool, Vec::new());
            let outcome = pool.add_credential(credential, mode)?;
            self.pools.insert(key.clone(), pool);
            outcome
        };

        self.record_audit(CredentialPoolAuditEvent::credential_upsert(
            key,
            credential_id,
            outcome,
            Utc::now(),
        ));
        Ok(outcome)
    }

    /// Remove one credential entry from a pool.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or [`CredentialPoolError::CredentialNotFound`] when the credential is
    /// not part of the pool.
    pub fn remove_credential(
        &mut self,
        key: &CredentialPoolKey,
        credential_id: CredentialId,
    ) -> Result<CredentialMutationOutcome, CredentialPoolError> {
        let pool = self.pool_mut_or_err(key)?;
        pool.remove_credential(credential_id)?;
        let outcome = CredentialMutationOutcome::Removed;
        self.record_audit(CredentialPoolAuditEvent::credential_remove(
            key.clone(),
            credential_id,
            outcome,
            Utc::now(),
        ));
        Ok(outcome)
    }

    /// Change a pool selection strategy.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent.
    pub fn set_strategy(
        &mut self,
        key: &CredentialPoolKey,
        strategy: CredentialPoolStrategy,
    ) -> Result<(), CredentialPoolError> {
        self.pool_mut_or_err(key)?.set_strategy(strategy);
        self.record_audit(CredentialPoolAuditEvent::strategy_set(
            key.clone(),
            strategy,
            Utc::now(),
        ));
        Ok(())
    }

    /// Set a pool's active lease ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or [`CredentialPoolError::InvalidMaxConcurrentPerCredential`] when
    /// `max` is zero.
    pub fn set_max_concurrent_per_credential(
        &mut self,
        key: &CredentialPoolKey,
        max: u32,
    ) -> Result<(), CredentialPoolError> {
        self.pool_mut_or_err(key)?
            .set_max_concurrent_per_credential(max)?;
        self.record_audit(CredentialPoolAuditEvent::max_concurrent_set(
            key.clone(),
            max,
            Utc::now(),
        ));
        Ok(())
    }

    /// Set a pool's sticky-strategy controls.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or [`CredentialPoolError::InvalidStickyMaxUses`] when
    /// `max_uses_per_stick` is zero.
    pub fn set_sticky_policy(
        &mut self,
        key: &CredentialPoolKey,
        policy: StickyCredentialPolicy,
    ) -> Result<(), CredentialPoolError> {
        self.pool_mut_or_err(key)?.set_sticky_policy(policy)?;
        self.record_audit(CredentialPoolAuditEvent::sticky_policy_set(
            key.clone(),
            policy,
            Utc::now(),
        ));
        Ok(())
    }

    /// Set a pool's all-pool-exhausted behavior.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent.
    pub fn set_exhausted_behavior(
        &mut self,
        key: &CredentialPoolKey,
        behavior: PoolExhaustedBehavior,
    ) -> Result<(), CredentialPoolError> {
        self.pool_mut_or_err(key)?.set_exhausted_behavior(behavior);
        self.record_audit(CredentialPoolAuditEvent::exhausted_behavior_set(
            key.clone(),
            behavior,
            Utc::now(),
        ));
        Ok(())
    }

    /// Manually set or clear cooldown state for a credential.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or [`CredentialPoolError::CredentialNotFound`] when the credential is
    /// not part of the pool.
    pub fn set_cooldown(
        &mut self,
        key: &CredentialPoolKey,
        credential_id: CredentialId,
        cooldown: Option<CredentialCooldown>,
    ) -> Result<(), CredentialPoolError> {
        let audit_cooldown = cooldown.clone();
        self.pool_mut_or_err(key)?
            .set_cooldown(credential_id, cooldown)?;
        self.record_audit(CredentialPoolAuditEvent::cooldown_set(
            key.clone(),
            credential_id,
            audit_cooldown,
            Utc::now(),
        ));
        Ok(())
    }

    /// Acquire a credential lease from a registered pool.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or the underlying acquisition error from [`CredentialPool::acquire`].
    pub fn acquire(
        &mut self,
        key: &CredentialPoolKey,
        now: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialPoolError> {
        self.pool_mut_or_err(key)?.acquire(now)
    }

    /// Acquire a lease for an explicit credential id within a zone.
    ///
    /// The lookup is deterministic across providers and does not expose secret
    /// payloads unless a lease is successfully created.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when no pool in the
    /// zone contains the credential, or the underlying pool acquisition error.
    pub fn acquire_specific_in_zone(
        &mut self,
        zone_id: &ZoneId,
        credential_id: CredentialId,
        now: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialPoolError> {
        let mut matching_keys = self
            .pools
            .iter()
            .filter(|(key, pool)| {
                key.zone_id == *zone_id && pool.contains_credential(credential_id)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        matching_keys.sort_by(|left, right| {
            left.provider
                .as_str()
                .cmp(right.provider.as_str())
                .then_with(|| left.zone_id.as_str().cmp(right.zone_id.as_str()))
        });
        let Some(key) = matching_keys.into_iter().next() else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };

        self.pool_mut_or_err(&key)?
            .acquire_specific(credential_id, now)
    }

    /// Replace payload material for an explicit credential id within a zone.
    ///
    /// The lookup is deterministic across providers and records a redacted
    /// mutation audit event.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::CredentialNotFound`] when no pool in the
    /// zone contains the credential, or the underlying replacement error.
    pub fn replace_payload_in_zone(
        &mut self,
        zone_id: &ZoneId,
        credential_id: CredentialId,
        payload: CredentialPayload,
    ) -> Result<(), CredentialPoolError> {
        let mut matching_keys = self
            .pools
            .iter()
            .filter(|(key, pool)| {
                key.zone_id == *zone_id && pool.contains_credential(credential_id)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        matching_keys.sort_by(|left, right| {
            left.provider
                .as_str()
                .cmp(right.provider.as_str())
                .then_with(|| left.zone_id.as_str().cmp(right.zone_id.as_str()))
        });
        let Some(key) = matching_keys.into_iter().next() else {
            return Err(CredentialPoolError::CredentialNotFound { credential_id });
        };

        self.pool_mut_or_err(&key)?
            .replace_payload(credential_id, payload)?;
        self.record_audit(CredentialPoolAuditEvent::credential_upsert(
            key,
            credential_id,
            CredentialMutationOutcome::Replaced,
            Utc::now(),
        ));
        Ok(())
    }

    /// Release a previously acquired registry lease.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or [`CredentialPoolError::UnknownLease`] when the token is unknown.
    pub fn release(
        &mut self,
        key: &CredentialPoolKey,
        token: CredentialLeaseToken,
    ) -> Result<CredentialId, CredentialPoolError> {
        self.pool_mut_or_err(key)?.release(token)
    }

    /// Report a credential-scoped error for an active registry lease.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent,
    /// or the underlying report error from [`CredentialPool::report_error`].
    pub fn report_error(
        &mut self,
        key: &CredentialPoolKey,
        token: CredentialLeaseToken,
        kind: CredentialErrorKind,
        retry_after: Option<StdDuration>,
        now: DateTime<Utc>,
    ) -> Result<CredentialId, CredentialPoolError> {
        self.pool_mut_or_err(key)?
            .report_error(token, kind, retry_after, now)
    }

    /// Build a redaction-safe snapshot for one pool.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialPoolError::PoolNotFound`] when the pool is absent.
    pub fn redacted_view(
        &self,
        key: &CredentialPoolKey,
        now: DateTime<Utc>,
    ) -> Result<CredentialPoolView, CredentialPoolError> {
        self.pools
            .get(key)
            .map(|pool| pool.redacted_view(now))
            .ok_or_else(|| CredentialPoolError::PoolNotFound { key: key.clone() })
    }

    /// Build redaction-safe snapshots for every pool in deterministic order.
    #[must_use]
    pub fn redacted_views(&self, now: DateTime<Utc>) -> Vec<CredentialPoolView> {
        let mut views: Vec<_> = self
            .pools
            .values()
            .map(|pool| pool.redacted_view(now))
            .collect();
        views.sort_by(|left, right| {
            left.key
                .provider
                .as_str()
                .cmp(right.key.provider.as_str())
                .then_with(|| left.key.zone_id.as_str().cmp(right.key.zone_id.as_str()))
        });
        views
    }

    /// Return redaction-safe mutation audit events in append order.
    #[must_use]
    pub fn audit_events(&self) -> &[CredentialPoolAuditEvent] {
        &self.audit_events
    }

    /// Borrow a pool by key.
    #[must_use]
    pub fn get(&self, key: &CredentialPoolKey) -> Option<&CredentialPool> {
        self.pools.get(key)
    }

    /// Mutably borrow a pool by key.
    pub fn get_mut(&mut self, key: &CredentialPoolKey) -> Option<&mut CredentialPool> {
        self.pools.get_mut(key)
    }

    /// Number of pools in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// Whether the registry has no pools.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    fn pool_mut_or_err(
        &mut self,
        key: &CredentialPoolKey,
    ) -> Result<&mut CredentialPool, CredentialPoolError> {
        self.pools
            .get_mut(key)
            .ok_or_else(|| CredentialPoolError::PoolNotFound { key: key.clone() })
    }

    fn record_audit(&mut self, event: CredentialPoolAuditEvent) {
        let credential_id = event.credential_id.map(|id| id.to_string());
        tracing::info!(
            audit_event_type = event.event_type.as_str(),
            operation = ?event.operation,
            provider = %event.pool_key.provider,
            zone_id = %event.pool_key.zone_id.as_str(),
            credential_id = credential_id.as_deref(),
            outcome = ?event.outcome,
            "credential_pool_admin_mutation_audit_event"
        );
        self.audit_events.push(event);
    }
}

/// Credential-pool operation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialPoolError {
    /// Provider keys must not be empty.
    #[error("credential pool provider key must not be empty")]
    InvalidProviderKey,
    /// Pool key is absent from the registry.
    #[error("credential pool not found for {key}")]
    PoolNotFound {
        /// Provider+zone pool key.
        key: CredentialPoolKey,
    },
    /// Credential already exists in the target pool.
    #[error("credential {credential_id} already exists in the pool")]
    DuplicateCredential {
        /// Duplicate credential.
        credential_id: CredentialId,
    },
    /// Per-credential lease ceiling must be non-zero.
    #[error("max concurrent per credential must be greater than zero, got {max}")]
    InvalidMaxConcurrentPerCredential {
        /// Invalid value.
        max: u32,
    },
    /// Sticky max-use bound must be non-zero when configured.
    #[error("sticky max uses per stick must be greater than zero, got {max}")]
    InvalidStickyMaxUses {
        /// Invalid value.
        max: u32,
    },
    /// No credential is currently available.
    #[error("credential pool exhausted for {key}")]
    PoolExhausted {
        /// Provider+zone pool key.
        key: CredentialPoolKey,
    },
    /// Pool is configured to wait and has a known future availability deadline.
    #[error("credential pool wait required for {key}; next credential available at {available_at}")]
    PoolWaitRequired {
        /// Provider+zone pool key.
        key: CredentialPoolKey,
        /// Earliest known cooldown expiry.
        available_at: DateTime<Utc>,
    },
    /// Lease token is unknown or already released.
    #[error("unknown credential lease token {token}")]
    UnknownLease {
        /// Unknown token.
        token: CredentialLeaseToken,
    },
    /// Credential ID is not part of the pool.
    #[error("credential {credential_id} is not part of the pool")]
    CredentialNotFound {
        /// Missing credential.
        credential_id: CredentialId,
    },
    /// Internal strategy state returned an index outside the entry list.
    #[error("credential pool selection returned invalid index {index} for {key}")]
    SelectionIndexInvalid {
        /// Provider+zone pool key.
        key: CredentialPoolKey,
        /// Invalid entry index.
        index: usize,
    },
}

fn sort_entries(entries: &mut [PooledCredential]) {
    entries.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| {
                left.credential_id
                    .to_string()
                    .cmp(&right.credential_id.to_string())
            })
    });
}

fn compare_lru_entries(left: &PooledCredential, right: &PooledCredential) -> Ordering {
    match (left.last_used_at, right.last_used_at) {
        (None, None) => compare_priority_then_id(left, right),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left_used), Some(right_used)) => left_used
            .cmp(&right_used)
            .then_with(|| compare_priority_then_id(left, right)),
    }
}

fn compare_priority_then_id(left: &PooledCredential, right: &PooledCredential) -> Ordering {
    left.priority.cmp(&right.priority).then_with(|| {
        left.credential_id
            .to_string()
            .cmp(&right.credential_id.to_string())
    })
}

fn cooldown_for_error(
    kind: CredentialErrorKind,
    retry_after: Option<StdDuration>,
    now: DateTime<Utc>,
) -> Option<CredentialCooldown> {
    match kind {
        CredentialErrorKind::AuthFailed => Some(CredentialCooldown::Permanent),
        CredentialErrorKind::RateLimited => Some(CredentialCooldown::Until {
            until: cooldown_until(now, retry_after, DEFAULT_RATE_LIMIT_COOLDOWN_SECS),
        }),
        CredentialErrorKind::QuotaExhausted => Some(CredentialCooldown::Until {
            until: cooldown_until(now, retry_after, DEFAULT_QUOTA_COOLDOWN_SECS),
        }),
        CredentialErrorKind::RetryableProviderError => {
            retry_after.map(|retry_after| CredentialCooldown::Until {
                until: cooldown_until(now, Some(retry_after), 0),
            })
        }
    }
}

/// Compute a cooldown deadline `now + clamped(retry_after | default)`.
///
/// The delta is clamped to `[0, MAX_CREDENTIAL_COOLDOWN_SECS]` so that
/// `DateTime + Duration` (which panics on overflow) can never be handed a
/// value that exceeds `DateTime`'s range. The `checked_add_signed` fallback is
/// belt-and-suspenders for the pathological case where `now` itself is already
/// within the clamp window of `DateTime::MAX`.
fn cooldown_until(
    now: DateTime<Utc>,
    retry_after: Option<StdDuration>,
    default_secs: i64,
) -> DateTime<Utc> {
    let secs = retry_after.map_or(default_secs, |retry_after| {
        i64::try_from(retry_after.as_secs()).unwrap_or(MAX_CREDENTIAL_COOLDOWN_SECS)
    });
    let delta = Duration::seconds(secs.clamp(0, MAX_CREDENTIAL_COOLDOWN_SECS));
    now.checked_add_signed(delta).unwrap_or(now)
}

/// Parse an HTTP Retry-After value as seconds or an HTTP-date.
#[must_use]
pub fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<StdDuration> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Cap the parsed value: a `Retry-After` beyond the max cooldown window is
    // hostile or buggy, and an uncapped value feeds the `DateTime + Duration`
    // panic path downstream. `MAX_CREDENTIAL_COOLDOWN_SECS` is non-negative.
    #[allow(clippy::cast_sign_loss)]
    let max_secs = MAX_CREDENTIAL_COOLDOWN_SECS as u64;

    if let Ok(seconds) = trimmed.parse::<u64>() {
        return Some(StdDuration::from_secs(seconds.min(max_secs)));
    }

    let parsed = DateTime::parse_from_rfc2822(trimmed)
        .ok()
        .map(|value| value.with_timezone(&Utc))?;
    if parsed <= now {
        return Some(StdDuration::ZERO);
    }
    (parsed - now)
        .to_std()
        .ok()
        .map(|delta| delta.min(StdDuration::from_secs(max_secs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_provider_auth::{AuthRequest, providers};

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-06T20:00:00Z")
            .expect("fixed test timestamp")
            .with_timezone(&Utc)
    }

    fn cred(byte: u8) -> CredentialId {
        let raw = format!(
            "{byte:02x}{byte:02x}{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}-{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}"
        );
        CredentialId::parse(&raw).expect("fixed credential id")
    }

    fn key(provider: &str) -> CredentialPoolKey {
        CredentialPoolKey::new(
            ProviderKey::new(provider).expect("provider key"),
            ZoneId::work(),
        )
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        fcp_async_core::runtime::block_on_sync(future).expect("test future should run")
    }

    // asupersync 0.3.2 gates `Cx::for_testing` out of non-test builds
    // (cap-mask bypass hardening). `compatibility_cx()` reads the ambient
    // runtime context, so it must be evaluated *inside* the future that
    // `run`/`block_on_sync` drives — never as an eagerly-evaluated argument.
    fn cx() -> fcp_async_core::Cx {
        fcp_async_core::compatibility_cx()
    }

    fn entry(byte: u8, priority: u32, label: &str) -> PooledCredential {
        PooledCredential::new(
            cred(byte),
            CredentialSource::Manual,
            priority,
            label,
            serde_json::json!({"api_key": format!("secret-{byte}")}),
        )
    }

    fn input(byte: u8, priority: u32, label: &str) -> PooledCredentialInput {
        PooledCredentialInput::new(
            cred(byte),
            CredentialSource::Manual,
            priority,
            label,
            serde_json::json!({"api_key": format!("updated-secret-{byte}")}),
        )
    }

    fn three_entry_pool(strategy: CredentialPoolStrategy) -> CredentialPool {
        CredentialPool::new(
            key("OpenAI"),
            strategy,
            vec![
                entry(0x03, 30, "third"),
                entry(0x01, 10, "first"),
                entry(0x02, 20, "second"),
            ],
        )
    }

    #[test]
    fn provider_key_canonicalizes_and_rejects_empty() {
        let provider = ProviderKey::new(" OpenAI ").expect("provider");
        assert_eq!(provider.as_str(), "openai");
        assert_eq!(
            ProviderKey::new("   ").expect_err("empty provider"),
            CredentialPoolError::InvalidProviderKey
        );
    }

    #[test]
    fn pool_init_sorts_by_priority() {
        let pool = three_entry_pool(CredentialPoolStrategy::Priority);
        let view = pool.redacted_view(now());
        let ids: Vec<_> = view
            .entries
            .iter()
            .map(|entry| entry.credential_id)
            .collect();
        assert_eq!(ids, vec![cred(0x01), cred(0x02), cred(0x03)]);
    }

    #[test]
    fn round_robin_cycles_available_entries() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::RoundRobin);
        let first = pool.acquire(now()).expect("first lease");
        pool.release(first.token).expect("release first");
        let second = pool.acquire(now()).expect("second lease");
        pool.release(second.token).expect("release second");
        let third = pool.acquire(now()).expect("third lease");

        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x02));
        assert_eq!(third.credential_id, cred(0x03));
    }

    #[test]
    fn round_robin_skips_cooldown_entries() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::RoundRobin);
        pool.mark_error(
            cred(0x01),
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_mins(2)),
            now(),
        )
        .expect("mark cooldown");

        let lease = pool.acquire(now()).expect("lease skips first");
        assert_eq!(lease.credential_id, cred(0x02));
    }

    #[test]
    fn priority_selects_lowest_priority_available() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        let first = pool.acquire(now()).expect("first lease");
        pool.release(first.token).expect("release first");
        let second = pool.acquire(now()).expect("second lease");

        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x01));
    }

    #[test]
    fn least_recently_used_prefers_never_used_then_oldest_used() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::LeastRecentlyUsed);
        let current_time = now();

        let first = pool.acquire(current_time).expect("first lru lease");
        pool.release(first.token).expect("release first");
        let second = pool
            .acquire(current_time + Duration::seconds(1))
            .expect("second lru lease");
        pool.release(second.token).expect("release second");
        let third = pool
            .acquire(current_time + Duration::seconds(2))
            .expect("third lru lease");
        pool.release(third.token).expect("release third");
        let oldest = pool
            .acquire(current_time + Duration::seconds(3))
            .expect("oldest-used lease");

        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x02));
        assert_eq!(third.credential_id, cred(0x03));
        assert_eq!(oldest.credential_id, cred(0x01));
    }

    #[test]
    fn least_recently_used_ties_by_priority_then_credential_id() {
        let mut priority_pool = CredentialPool::new(
            key("openai"),
            CredentialPoolStrategy::LeastRecentlyUsed,
            vec![
                entry(0x01, 30, "alpha"),
                entry(0x02, 10, "middle"),
                entry(0x03, 20, "zulu"),
            ],
        );
        let priority_first = priority_pool
            .acquire(now())
            .expect("priority tie-broken lru lease");
        assert_eq!(priority_first.credential_id, cred(0x02));

        let mut id_pool = CredentialPool::new(
            key("openai"),
            CredentialPoolStrategy::LeastRecentlyUsed,
            vec![
                entry(0x03, 10, "alpha"),
                entry(0x01, 10, "zulu"),
                entry(0x02, 10, "middle"),
            ],
        );
        let id_first = id_pool.acquire(now()).expect("id tie-broken lru lease");
        assert_eq!(id_first.credential_id, cred(0x01));
    }

    #[test]
    fn least_recently_used_skips_cooldown_and_active_lease_entries() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::LeastRecentlyUsed)
            .with_max_concurrent_per_credential(1);
        pool.set_cooldown(
            cred(0x01),
            Some(CredentialCooldown::Until {
                until: now() + Duration::seconds(30),
            }),
        )
        .expect("cool down first");

        let first_available = pool.acquire(now()).expect("skip cooldown");
        let second_available = pool.acquire(now()).expect("skip active lease");

        assert_eq!(first_available.credential_id, cred(0x02));
        assert_eq!(second_available.credential_id, cred(0x03));
    }

    #[test]
    fn least_recently_used_serializes_for_admin_strategy_requests() {
        let encoded =
            serde_json::to_string(&CredentialPoolStrategy::LeastRecentlyUsed).expect("serialize");
        assert_eq!(encoded, "\"least_recently_used\"");
        assert_eq!(
            serde_json::from_str::<CredentialPoolStrategy>("\"least_recently_used\"")
                .expect("deserialize"),
            CredentialPoolStrategy::LeastRecentlyUsed
        );
    }

    #[test]
    fn sticky_keeps_current_until_unavailable() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        let first = pool.acquire(now()).expect("first lease");
        pool.release(first.token).expect("release first");
        let second = pool.acquire(now()).expect("second lease");

        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x01));

        pool.report_error(
            second.token,
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_mins(2)),
            now(),
        )
        .expect("rate limit sticky credential");
        let third = pool.acquire(now()).expect("fallback lease");
        assert_eq!(third.credential_id, cred(0x02));
    }

    #[test]
    fn sticky_default_does_not_restick_after_cooldown_recovery() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        let first = pool.acquire(now()).expect("first lease");
        pool.report_error(
            first.token,
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_secs(30)),
            now(),
        )
        .expect("rate limit first");

        let fallback = pool.acquire(now()).expect("fallback lease");
        assert_eq!(fallback.credential_id, cred(0x02));
        pool.release(fallback.token).expect("release fallback");

        let after_recovery = pool
            .acquire(now() + Duration::seconds(31))
            .expect("sticky fallback persists");
        assert_eq!(after_recovery.credential_id, cred(0x02));
    }

    #[test]
    fn sticky_restick_on_recovery_returns_to_cooldown_credential() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        pool.set_sticky_policy(StickyCredentialPolicy {
            restick_on_recovery: true,
            max_uses_per_stick: None,
        })
        .expect("set sticky policy");
        let first = pool.acquire(now()).expect("first lease");
        pool.report_error(
            first.token,
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_secs(30)),
            now(),
        )
        .expect("rate limit first");

        let fallback = pool.acquire(now()).expect("fallback lease");
        assert_eq!(fallback.credential_id, cred(0x02));
        pool.release(fallback.token).expect("release fallback");

        let recovered = pool
            .acquire(now() + Duration::seconds(31))
            .expect("restick to recovered credential");
        assert_eq!(recovered.credential_id, cred(0x01));
    }

    #[test]
    fn sticky_restick_on_recovery_returns_after_active_lease_exhaustion() {
        let mut pool =
            three_entry_pool(CredentialPoolStrategy::Sticky).with_max_concurrent_per_credential(1);
        pool.set_sticky_policy(StickyCredentialPolicy {
            restick_on_recovery: true,
            max_uses_per_stick: None,
        })
        .expect("set sticky policy");

        let first = pool.acquire(now()).expect("first active lease");
        let fallback = pool.acquire(now()).expect("fallback while first active");
        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(fallback.credential_id, cred(0x02));

        pool.release(first.token).expect("release first");
        let restuck = pool.acquire(now()).expect("restick after active release");
        assert_eq!(restuck.credential_id, cred(0x01));
    }

    #[test]
    fn sticky_restick_on_recovery_returns_after_auth_error_clear() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        pool.set_sticky_policy(StickyCredentialPolicy {
            restick_on_recovery: true,
            max_uses_per_stick: None,
        })
        .expect("set sticky policy");
        let first = pool.acquire(now()).expect("first lease");
        pool.report_error(first.token, CredentialErrorKind::AuthFailed, None, now())
            .expect("auth failure");

        let fallback = pool.acquire(now()).expect("fallback after auth failure");
        assert_eq!(fallback.credential_id, cred(0x02));
        pool.release(fallback.token).expect("release fallback");

        pool.clear_cooldown(cred(0x01)).expect("manual clear");
        let restuck = pool.acquire(now()).expect("restick after auth clear");
        assert_eq!(restuck.credential_id, cred(0x01));
    }

    #[test]
    fn sticky_max_uses_per_stick_rotates_deterministically() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        pool.set_sticky_policy(StickyCredentialPolicy {
            restick_on_recovery: false,
            max_uses_per_stick: Some(2),
        })
        .expect("set sticky policy");

        let first = pool.acquire(now()).expect("first lease");
        pool.release(first.token).expect("release first");
        let second = pool.acquire(now()).expect("second lease");
        pool.release(second.token).expect("release second");
        let third = pool.acquire(now()).expect("third lease");
        pool.release(third.token).expect("release third");
        let fourth = pool.acquire(now()).expect("fourth lease");
        pool.release(fourth.token).expect("release fourth");
        let fifth = pool.acquire(now()).expect("fifth lease");

        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x01));
        assert_eq!(third.credential_id, cred(0x02));
        assert_eq!(fourth.credential_id, cred(0x02));
        assert_eq!(fifth.credential_id, cred(0x01));
    }

    #[test]
    fn sticky_policy_rejects_zero_max_uses_and_serializes_for_admin_views() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Sticky);
        let err = pool
            .set_sticky_policy(StickyCredentialPolicy {
                restick_on_recovery: true,
                max_uses_per_stick: Some(0),
            })
            .expect_err("zero max uses rejected");
        assert_eq!(err, CredentialPoolError::InvalidStickyMaxUses { max: 0 });

        pool.set_sticky_policy(StickyCredentialPolicy {
            restick_on_recovery: true,
            max_uses_per_stick: Some(3),
        })
        .expect("set sticky policy");
        let view = pool.redacted_view(now());
        assert_eq!(
            view.sticky_policy,
            StickyCredentialPolicy {
                restick_on_recovery: true,
                max_uses_per_stick: Some(3),
            }
        );

        let rendered = serde_json::to_string(&view).expect("serialize view");
        assert!(rendered.contains("restick_on_recovery"));
        assert!(rendered.contains("max_uses_per_stick"));
        assert!(!rendered.contains("secret-"));
        assert!(!rendered.contains("api_key"));
    }

    #[test]
    fn active_leases_enforce_max_concurrent_and_release() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority)
            .with_max_concurrent_per_credential(1);

        let first = pool.acquire(now()).expect("first lease");
        let second = pool.acquire(now()).expect("second lease");
        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x02));

        pool.release(first.token).expect("release first");
        let third = pool.acquire(now()).expect("first available again");
        assert_eq!(third.credential_id, cred(0x01));
    }

    #[test]
    fn rate_limit_cooldown_recovers_after_retry_after() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.mark_error(
            cred(0x01),
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_secs(30)),
            now(),
        )
        .expect("mark rate limit");

        let during = pool.acquire(now()).expect("fallback during cooldown");
        assert_eq!(during.credential_id, cred(0x02));
        pool.release(during.token).expect("release fallback");

        let after = pool
            .acquire(now() + Duration::seconds(31))
            .expect("primary recovered");
        assert_eq!(after.credential_id, cred(0x01));
    }

    #[test]
    fn quota_cooldown_uses_default_recovery_window() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.mark_error(cred(0x01), CredentialErrorKind::QuotaExhausted, None, now())
            .expect("quota failure");

        let during = pool.acquire(now()).expect("fallback during quota cooldown");
        assert_eq!(during.credential_id, cred(0x02));
        pool.release(during.token).expect("release fallback");

        let before_default = pool
            .acquire(now() + Duration::seconds(DEFAULT_QUOTA_COOLDOWN_SECS - 1))
            .expect("primary still cooling down");
        assert_eq!(before_default.credential_id, cred(0x02));
        pool.release(before_default.token)
            .expect("release second fallback");

        let after_default = pool
            .acquire(now() + Duration::seconds(DEFAULT_QUOTA_COOLDOWN_SECS + 1))
            .expect("primary recovered after quota cooldown");
        assert_eq!(after_default.credential_id, cred(0x01));
    }

    #[test]
    fn auth_error_is_permanent_until_manual_clear() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.mark_error(cred(0x01), CredentialErrorKind::AuthFailed, None, now())
            .expect("auth failure");

        let much_later = now() + Duration::days(365);
        let fallback = pool.acquire(much_later).expect("fallback");
        assert_eq!(fallback.credential_id, cred(0x02));
        pool.release(fallback.token).expect("release fallback");

        pool.clear_cooldown(cred(0x01)).expect("manual clear");
        let primary = pool.acquire(much_later).expect("primary restored");
        assert_eq!(primary.credential_id, cred(0x01));
    }

    #[test]
    fn exhausted_pool_fails_fast() {
        let mut pool = CredentialPool::new(
            key("openai"),
            CredentialPoolStrategy::Priority,
            vec![entry(0x01, 10, "first")],
        )
        .with_max_concurrent_per_credential(1);
        let _lease = pool.acquire(now()).expect("only lease");

        let err = pool.acquire(now()).expect_err("pool exhausted");
        assert!(matches!(err, CredentialPoolError::PoolExhausted { .. }));
    }

    #[test]
    fn unknown_lease_release_is_rejected() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        let err = pool
            .release(CredentialLeaseToken(42))
            .expect_err("unknown lease rejected");
        assert_eq!(
            err,
            CredentialPoolError::UnknownLease {
                token: CredentialLeaseToken(42)
            }
        );
    }

    #[test]
    fn redacted_view_never_contains_payload_or_error_body() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.mark_error(cred(0x01), CredentialErrorKind::AuthFailed, None, now())
            .expect("auth failure");
        let view = pool.redacted_view(now());
        let rendered = serde_json::to_string(&view).expect("serialize view");

        assert!(rendered.contains("first"));
        assert!(!rendered.contains("secret-"));
        assert!(!rendered.contains("api_key"));
        assert!(!rendered.contains("provider said key sk-live failed"));
    }

    #[test]
    fn retry_after_seconds_parse() {
        assert_eq!(
            parse_retry_after("42", now()),
            Some(StdDuration::from_secs(42))
        );
    }

    #[test]
    fn retry_after_http_date_parse() {
        assert_eq!(
            parse_retry_after("Wed, 06 May 2026 20:00:30 GMT", now()),
            Some(StdDuration::from_secs(30))
        );
    }

    #[test]
    fn retry_after_past_http_date_is_zero() {
        assert_eq!(
            parse_retry_after("Wed, 06 May 2026 19:59:30 GMT", now()),
            Some(StdDuration::ZERO)
        );
    }

    #[test]
    fn registry_is_keyed_by_provider_and_zone() {
        let mut registry = CredentialPoolRegistry::new();
        let openai_key = key("openai");
        let anthropic_key = key("anthropic");
        registry.upsert(CredentialPool::new(
            openai_key.clone(),
            CredentialPoolStrategy::RoundRobin,
            vec![entry(0x01, 10, "openai")],
        ));
        registry.upsert(CredentialPool::new(
            anthropic_key.clone(),
            CredentialPoolStrategy::Priority,
            vec![entry(0x02, 10, "anthropic")],
        ));

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get(&openai_key).expect("openai").len(), 1);
        assert_eq!(registry.get(&anthropic_key).expect("anthropic").len(), 1);
    }

    #[test]
    fn registry_add_credential_creates_and_updates_pool() {
        let mut registry = CredentialPoolRegistry::new();
        let pool_key = key("OpenAI");

        let added = registry
            .add_credential(
                pool_key.clone(),
                CredentialPoolStrategy::RoundRobin,
                input(0x01, 20, "primary").into_credential(),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("add credential");
        assert_eq!(added, CredentialMutationOutcome::Added);
        assert_eq!(
            registry.get(&pool_key).expect("created pool").strategy(),
            CredentialPoolStrategy::RoundRobin
        );

        let replaced = registry
            .add_credential(
                pool_key.clone(),
                CredentialPoolStrategy::Priority,
                input(0x01, 5, "renamed primary").into_credential(),
                CredentialUpsertMode::ReplaceExisting,
            )
            .expect("replace credential");
        assert_eq!(replaced, CredentialMutationOutcome::Replaced);

        let view = registry.redacted_view(&pool_key, now()).expect("view");
        assert_eq!(view.strategy, CredentialPoolStrategy::RoundRobin);
        assert_eq!(view.entries[0].priority, 5);
        assert_eq!(view.entries[0].label, "renamed primary");
        let rendered = serde_json::to_string(&view).expect("serialize view");
        assert!(!rendered.contains("updated-secret"));
        assert!(!rendered.contains("api_key"));
    }

    #[test]
    fn registry_mutation_audit_events_are_redacted_and_ordered() {
        let mut registry = CredentialPoolRegistry::new();
        let pool_key = key("OpenAI");

        registry
            .add_credential(
                pool_key.clone(),
                CredentialPoolStrategy::RoundRobin,
                input(0x01, 20, "primary").into_credential(),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("add credential");
        let duplicate = registry
            .add_credential(
                pool_key.clone(),
                CredentialPoolStrategy::RoundRobin,
                input(0x01, 20, "duplicate").into_credential(),
                CredentialUpsertMode::RejectExisting,
            )
            .expect_err("duplicate should not be audited");
        assert!(matches!(
            duplicate,
            CredentialPoolError::DuplicateCredential { .. }
        ));
        registry
            .add_credential(
                pool_key.clone(),
                CredentialPoolStrategy::Priority,
                input(0x01, 5, "renamed primary").into_credential(),
                CredentialUpsertMode::ReplaceExisting,
            )
            .expect("replace credential");
        registry
            .set_strategy(&pool_key, CredentialPoolStrategy::Sticky)
            .expect("set strategy");
        registry
            .set_max_concurrent_per_credential(&pool_key, 1)
            .expect("set max concurrent");
        registry
            .set_sticky_policy(
                &pool_key,
                StickyCredentialPolicy {
                    restick_on_recovery: true,
                    max_uses_per_stick: Some(5),
                },
            )
            .expect("set sticky policy");
        registry
            .set_exhausted_behavior(&pool_key, PoolExhaustedBehavior::Wait)
            .expect("set exhausted behavior");
        registry
            .set_cooldown(&pool_key, cred(0x01), Some(CredentialCooldown::Permanent))
            .expect("set cooldown");
        registry
            .remove_credential(&pool_key, cred(0x01))
            .expect("remove credential");

        let operations: Vec<_> = registry
            .audit_events()
            .iter()
            .map(|event| event.operation)
            .collect();
        assert_eq!(
            operations,
            vec![
                CredentialPoolAuditOperation::CredentialUpsert,
                CredentialPoolAuditOperation::CredentialUpsert,
                CredentialPoolAuditOperation::StrategySet,
                CredentialPoolAuditOperation::MaxConcurrentSet,
                CredentialPoolAuditOperation::StickyPolicySet,
                CredentialPoolAuditOperation::ExhaustedBehaviorSet,
                CredentialPoolAuditOperation::CooldownSet,
                CredentialPoolAuditOperation::CredentialRemove,
            ]
        );
        assert_eq!(
            registry.audit_events()[0].outcome,
            Some(CredentialMutationOutcome::Added)
        );
        assert_eq!(
            registry.audit_events()[1].outcome,
            Some(CredentialMutationOutcome::Replaced)
        );
        assert_eq!(
            registry.audit_events()[4].sticky_policy,
            Some(StickyCredentialPolicy {
                restick_on_recovery: true,
                max_uses_per_stick: Some(5),
            })
        );

        let rendered =
            serde_json::to_string(registry.audit_events()).expect("serialize audit events");
        assert!(rendered.contains(CREDENTIAL_POOL_AUDIT_EVENT_TYPE));
        assert!(rendered.contains("openai"));
        assert!(rendered.contains("credential_upsert"));
        assert!(rendered.contains("sticky_policy_set"));
        assert!(rendered.contains("cooldown_set"));
        assert!(!rendered.contains("\"payload\":"));
        assert!(!rendered.contains("api_key"));
        assert!(!rendered.contains("secret-"));
        assert!(!rendered.contains("updated-secret"));
    }

    #[test]
    fn duplicate_add_with_reject_mode_errors() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);

        let err = pool
            .add_credential(
                entry(0x01, 1, "duplicate"),
                CredentialUpsertMode::RejectExisting,
            )
            .expect_err("duplicate rejected");
        assert_eq!(
            err,
            CredentialPoolError::DuplicateCredential {
                credential_id: cred(0x01)
            }
        );
    }

    #[test]
    fn remove_credential_clears_active_leases_and_sticky_current() {
        let mut pool =
            three_entry_pool(CredentialPoolStrategy::Sticky).with_max_concurrent_per_credential(1);
        let first = pool.acquire(now()).expect("sticky lease");
        assert_eq!(first.credential_id, cred(0x01));

        let removed = pool
            .remove_credential(cred(0x01))
            .expect("remove active sticky credential");
        assert_eq!(removed.credential_id, cred(0x01));

        let release_err = pool
            .release(first.token)
            .expect_err("removed active lease token");
        assert_eq!(
            release_err,
            CredentialPoolError::UnknownLease { token: first.token }
        );

        let next = pool.acquire(now()).expect("next sticky lease");
        assert_eq!(next.credential_id, cred(0x02));
    }

    #[test]
    fn removing_unknown_credential_errors() {
        let mut registry = CredentialPoolRegistry::new();
        let pool_key = key("openai");
        registry.upsert(three_entry_pool(CredentialPoolStrategy::Priority));

        let err = registry
            .remove_credential(&pool_key, cred(0x99))
            .expect_err("unknown credential");
        assert_eq!(
            err,
            CredentialPoolError::CredentialNotFound {
                credential_id: cred(0x99)
            }
        );

        let absent_key = key("anthropic");
        let absent_err = registry
            .remove_credential(&absent_key, cred(0x01))
            .expect_err("unknown pool");
        assert_eq!(
            absent_err,
            CredentialPoolError::PoolNotFound { key: absent_key }
        );
    }

    #[test]
    fn lease_payload_is_available_but_debug_redacted() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        let lease = pool.acquire(now()).expect("credential lease");

        assert_eq!(lease.credential_id, cred(0x01));
        assert_eq!(
            lease.payload.as_raw_json().expect("raw json payload")["api_key"],
            "secret-1"
        );

        let rendered = format!("{lease:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("api_key"));
        assert!(!rendered.contains("secret-1"));
    }

    #[test]
    fn auth_profile_payload_lease_builds_request_auth_and_redacts_views() {
        let profile = providers::openai_codex::api_key_profile(
            "codex-work",
            "Codex Work",
            0,
            "fixture-openai-key",
        )
        .expect("provider profile");
        let mut pool = CredentialPool::new(
            key("openai"),
            CredentialPoolStrategy::Priority,
            vec![PooledCredential::new(
                cred(0x04),
                CredentialSource::Config,
                0,
                "codex profile",
                CredentialPayload::auth_profile(profile),
            )],
        );

        let view = pool.redacted_view(now());
        assert_eq!(
            view.entries[0].payload_kind,
            CredentialPayloadKind::AuthProfile
        );
        let view_json = serde_json::to_string(&view).expect("serialize view");
        assert!(view_json.contains("auth_profile"));
        assert!(view_json.contains("codex profile"));
        assert!(!view_json.contains("fixture-openai-key"));

        let lease = pool.acquire(now()).expect("auth profile lease");
        let profile = lease
            .payload
            .as_auth_profile()
            .expect("auth profile payload");
        assert_eq!(profile.provider, providers::openai_codex::PROVIDER_ID);
        assert_eq!(profile.id, "codex-work");

        let mut request = AuthRequest::new();
        run(async { profile.method.build_request_auth(&cx(), &mut request).await })
            .expect("request auth");
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-openai-key")
        );

        let rendered = format!("{lease:?}");
        assert!(rendered.contains("AuthProfile"));
        assert!(!rendered.contains("fixture-openai-key"));
    }

    #[test]
    fn registry_lease_bridge_acquires_releases_and_reports_errors() {
        let mut registry = CredentialPoolRegistry::new();
        let pool_key = key("openai");
        registry.upsert(three_entry_pool(CredentialPoolStrategy::Priority));

        let first = registry.acquire(&pool_key, now()).expect("first lease");
        assert_eq!(first.pool_key, pool_key);
        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(
            first.payload.as_raw_json().expect("raw json payload")["api_key"],
            "secret-1"
        );
        assert_eq!(
            registry
                .release(&pool_key, first.token)
                .expect("release first"),
            cred(0x01)
        );

        let second = registry.acquire(&pool_key, now()).expect("second lease");
        assert_eq!(second.credential_id, cred(0x01));
        assert_eq!(
            registry
                .report_error(
                    &pool_key,
                    second.token,
                    CredentialErrorKind::RateLimited,
                    Some(StdDuration::from_secs(30)),
                    now(),
                )
                .expect("report rate limit"),
            cred(0x01)
        );

        let fallback = registry
            .acquire(&pool_key, now())
            .expect("fallback during cooldown");
        assert_eq!(fallback.credential_id, cred(0x02));

        let missing_key = key("anthropic");
        assert_eq!(
            registry
                .acquire(&missing_key, now())
                .expect_err("missing pool"),
            CredentialPoolError::PoolNotFound {
                key: missing_key.clone()
            }
        );
        assert_eq!(
            registry
                .release(&missing_key, fallback.token)
                .expect_err("missing pool on release"),
            CredentialPoolError::PoolNotFound { key: missing_key }
        );

        registry
            .release(&pool_key, fallback.token)
            .expect("release fallback");
    }

    #[test]
    fn set_strategy_changes_selection_behavior() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::RoundRobin);
        let first = pool.acquire(now()).expect("first round robin");
        pool.release(first.token).expect("release first");
        let second = pool.acquire(now()).expect("second round robin");
        pool.release(second.token).expect("release second");
        assert_eq!(second.credential_id, cred(0x02));

        pool.set_strategy(CredentialPoolStrategy::Priority);
        let priority_first = pool.acquire(now()).expect("priority lease");
        pool.release(priority_first.token)
            .expect("release priority first");
        let priority_second = pool.acquire(now()).expect("priority second");

        assert_eq!(priority_first.credential_id, cred(0x01));
        assert_eq!(priority_second.credential_id, cred(0x01));
    }

    #[test]
    fn set_max_concurrent_rejects_zero_and_affects_acquisition() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        let err = pool
            .set_max_concurrent_per_credential(0)
            .expect_err("zero max rejected");
        assert_eq!(
            err,
            CredentialPoolError::InvalidMaxConcurrentPerCredential { max: 0 }
        );

        pool.set_max_concurrent_per_credential(1)
            .expect("set valid max");
        let first = pool.acquire(now()).expect("first active");
        let second = pool.acquire(now()).expect("second active");
        assert_eq!(first.credential_id, cred(0x01));
        assert_eq!(second.credential_id, cred(0x02));
        assert_eq!(pool.max_concurrent_per_credential(), 1);
    }

    #[test]
    fn set_exhausted_behavior_records_wait_and_fail_fast() {
        let mut pool = CredentialPool::new(
            key("openai"),
            CredentialPoolStrategy::Priority,
            vec![entry(0x01, 10, "first")],
        )
        .with_max_concurrent_per_credential(1);
        let _lease = pool.acquire(now()).expect("only lease");

        pool.set_exhausted_behavior(PoolExhaustedBehavior::Wait);
        assert_eq!(pool.exhausted_behavior(), PoolExhaustedBehavior::Wait);
        assert!(matches!(
            pool.acquire(now())
                .expect_err("active lease has no wait deadline"),
            CredentialPoolError::PoolExhausted { .. }
        ));

        pool.set_exhausted_behavior(PoolExhaustedBehavior::FailFast);
        assert!(matches!(
            pool.acquire(now()).expect_err("fail fast exhausted"),
            CredentialPoolError::PoolExhausted { .. }
        ));
    }

    #[test]
    fn wait_exhausted_behavior_reports_earliest_cooldown_deadline() {
        let current_time = now();
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.set_exhausted_behavior(PoolExhaustedBehavior::Wait);

        pool.set_cooldown(
            cred(0x01),
            Some(CredentialCooldown::Until {
                until: current_time + Duration::seconds(30),
            }),
        )
        .expect("cool down first");
        pool.set_cooldown(
            cred(0x02),
            Some(CredentialCooldown::Until {
                until: current_time + Duration::seconds(10),
            }),
        )
        .expect("cool down second");
        pool.set_cooldown(cred(0x03), Some(CredentialCooldown::Permanent))
            .expect("permanent cooldown third");

        let err = pool
            .acquire(current_time)
            .expect_err("all credentials unavailable");

        assert!(matches!(
            err,
            CredentialPoolError::PoolWaitRequired {
                available_at,
                ..
            } if available_at == current_time + Duration::seconds(10)
        ));
    }

    #[test]
    fn manual_cooldown_set_and_clear_controls_availability() {
        let mut pool = three_entry_pool(CredentialPoolStrategy::Priority);
        pool.set_cooldown(
            cred(0x01),
            Some(CredentialCooldown::Until {
                until: now() + Duration::seconds(30),
            }),
        )
        .expect("manual cooldown");

        let fallback = pool.acquire(now()).expect("fallback during cooldown");
        assert_eq!(fallback.credential_id, cred(0x02));
        pool.release(fallback.token).expect("release fallback");

        pool.clear_cooldown(cred(0x01)).expect("manual clear");
        let primary = pool.acquire(now()).expect("primary restored");
        assert_eq!(primary.credential_id, cred(0x01));
    }

    #[test]
    fn hostile_retry_after_is_clamped_and_never_panics() {
        let now = now();

        // A gigantic Retry-After seconds value fits in chrono::Duration but
        // would overflow `DateTime + Duration` (panic). It must be clamped at
        // parse time to at most the max cooldown window.
        let parsed = parse_retry_after("100000000000000", now).expect("huge value parses");
        assert!(
            parsed <= StdDuration::from_secs(MAX_CREDENTIAL_COOLDOWN_SECS as u64),
            "parse_retry_after must clamp hostile values, got {parsed:?}"
        );

        // Even if a direct caller bypasses parsing and hands cooldown_for_error
        // an absurd duration, computing the deadline must not panic and must
        // land within the clamp window.
        let absurd = StdDuration::from_secs(u64::MAX);
        for kind in [
            CredentialErrorKind::RateLimited,
            CredentialErrorKind::QuotaExhausted,
            CredentialErrorKind::RetryableProviderError,
        ] {
            let cooldown = cooldown_for_error(kind, Some(absurd), now)
                .expect("timed error kinds yield a cooldown");
            let CredentialCooldown::Until { until } = cooldown else {
                panic!("expected a bounded Until cooldown for {kind:?}");
            };
            let max_until = now + Duration::seconds(MAX_CREDENTIAL_COOLDOWN_SECS);
            assert!(
                until <= max_until && until >= now,
                "cooldown for {kind:?} must be clamped in [now, now+max], got {until}"
            );
        }
    }

    #[test]
    fn registry_lists_redacted_all_pool_state_without_payloads() {
        let mut registry = CredentialPoolRegistry::new();
        registry
            .add_credential(
                key("openai"),
                CredentialPoolStrategy::Priority,
                input(0x01, 10, "openai primary").into_credential(),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("add openai");
        registry
            .add_credential(
                key("anthropic"),
                CredentialPoolStrategy::Sticky,
                input(0x02, 10, "anthropic primary").into_credential(),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("add anthropic");

        let views = registry.redacted_views(now());
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].key.provider.as_str(), "anthropic");
        assert_eq!(views[1].key.provider.as_str(), "openai");

        let rendered = serde_json::to_string(&views).expect("serialize views");
        assert!(rendered.contains("openai primary"));
        assert!(rendered.contains("anthropic primary"));
        assert!(!rendered.contains("updated-secret"));
        assert!(!rendered.contains("api_key"));
    }
}
