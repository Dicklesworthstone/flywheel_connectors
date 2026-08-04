//! Connector process supervisor with restart policies and health monitoring.
//!
//! Implements the supervisor model from the oip0 bead:
//! - Configurable restart policies (`Always`, `OnFailure`, `OnCrash`, `Never`)
//! - Exponential backoff with jitter for restart timing
//! - Restart window tracking (max N restarts within a time window)
//! - Process state machine (Starting → Running → Stopping → Stopped/Failed)
//! - Health check scheduling with configurable intervals and timeouts
//! - Graceful shutdown with SIGTERM → timeout → SIGKILL sequencing

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::resilience::{
    BackpressureAction, BackpressureCalibration, BackpressureController,
    BackpressureControllerConfig, BackpressureControllerInput, BackpressureDecision,
    BackpressureTelemetry, RequestPriority,
};

// ─────────────────────────────────────────────────────────────────────────────
// Restart Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy governing when a connector process should be restarted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RestartPolicy {
    /// Always restart, regardless of exit status.
    Always,
    /// Restart only on failure (non-zero exit or signal).
    #[default]
    OnFailure,
    /// Restart only on crash (signal-terminated, not clean non-zero exit).
    OnCrash,
    /// Never restart automatically.
    Never,
}

impl RestartPolicy {
    /// Determine whether a restart should be attempted for the given exit.
    #[must_use]
    pub fn should_restart(&self, exit: &ProcessExit) -> bool {
        match self {
            Self::Always => true,
            Self::OnFailure => !exit.is_clean(),
            Self::OnCrash => exit.is_signal_terminated(),
            Self::Never => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process Exit
// ─────────────────────────────────────────────────────────────────────────────

/// How a connector process exited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessExit {
    /// Exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Signal number, if the process was terminated by a signal.
    pub signal: Option<i32>,
}

impl ProcessExit {
    /// Clean exit (code 0).
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            code: Some(0),
            signal: None,
        }
    }

    /// Exit with a specific code.
    #[must_use]
    pub const fn with_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// Terminated by a signal.
    #[must_use]
    pub const fn with_signal(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
        }
    }

    /// Whether this was a clean exit (code 0).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.code == Some(0) && self.signal.is_none()
    }

    /// Whether the process was terminated by a signal.
    #[must_use]
    pub const fn is_signal_terminated(&self) -> bool {
        self.signal.is_some()
    }
}

impl std::fmt::Display for ProcessExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.code, self.signal) {
            (Some(code), None) => write!(f, "exit code {code}"),
            (None, Some(sig)) => write!(f, "signal {sig}"),
            (Some(code), Some(sig)) => write!(f, "exit code {code}, signal {sig}"),
            (None, None) => write!(f, "unknown exit"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process State
// ─────────────────────────────────────────────────────────────────────────────

/// Current state of a supervised connector process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is starting up.
    Starting {
        /// When the start was initiated.
        since: Instant,
    },
    /// Process is running normally.
    Running {
        /// Process ID.
        pid: u32,
        /// When the process started.
        started_at: Instant,
    },
    /// Process is being stopped gracefully.
    Stopping {
        /// Why the process is being stopped.
        reason: StopReason,
        /// When the stop was initiated.
        since: Instant,
    },
    /// Process has stopped.
    Stopped {
        /// How the process exited.
        exit: ProcessExit,
        /// When the process stopped.
        stopped_at: Instant,
    },
    /// Process has failed and won't be restarted.
    Failed {
        /// Error description.
        error: String,
        /// When the failure was recorded.
        failed_at: Instant,
    },
}

impl ProcessState {
    /// Whether the process is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Whether the process is in a terminal state (Stopped or Failed).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped { .. } | Self::Failed { .. })
    }

    /// Human-readable label for the current state.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Starting { .. } => "starting",
            Self::Running { .. } => "running",
            Self::Stopping { .. } => "stopping",
            Self::Stopped { .. } => "stopped",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Reason for stopping a connector process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Operator requested shutdown.
    Requested,
    /// Host is shutting down.
    HostShutdown,
    /// Health check failed too many times.
    HealthCheckFailed,
    /// Resource limits exceeded.
    ResourceLimitExceeded,
    /// Being replaced by a new version.
    Upgrade,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::HostShutdown => write!(f, "host shutdown"),
            Self::HealthCheckFailed => write!(f, "health check failed"),
            Self::ResourceLimitExceeded => write!(f, "resource limit exceeded"),
            Self::Upgrade => write!(f, "upgrade"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Supervisor Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the connector process supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorConfig {
    /// Policy for automatic restarts.
    pub restart_policy: RestartPolicy,
    /// Maximum number of restarts allowed within the restart window.
    pub max_restarts: u32,
    /// Time window for counting restarts.
    pub restart_window: Duration,
    /// How often to check connector health.
    pub health_check_interval: Duration,
    /// Timeout for individual health checks.
    pub health_check_timeout: Duration,
    /// How long to wait for graceful shutdown before SIGKILL.
    pub graceful_shutdown_timeout: Duration,
    /// Initial backoff delay for restart attempts.
    pub initial_backoff: Duration,
    /// Maximum backoff delay.
    pub max_backoff: Duration,
    /// Backoff multiplier (typically 2.0).
    pub backoff_multiplier: f64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            restart_policy: RestartPolicy::default(),
            max_restarts: 5,
            restart_window: Duration::from_mins(5),
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_mins(1),
            backoff_multiplier: 2.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Prewarm Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Startup strategy for supervised connector processes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmStrategy {
    /// Spawn connectors only when the live inventory requires them.
    #[default]
    OnDemand,
    /// Keep bounded, already-started connector processes eligible for checkout.
    WarmPool,
    /// Reuse a fork/zygote-style parent process.
    ///
    /// This is intentionally rejected until there is a separate security proof:
    /// credential isolation, zone binding, sandbox limits, and manifest freshness
    /// are harder to prove across forked process state than across a fresh warm
    /// process.
    Zygote,
}

/// Explicit prewarm pool configuration for connector startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorPrewarmConfig {
    /// Which startup strategy to use.
    pub strategy: PrewarmStrategy,
    /// Minimum idle warm entries to keep for a connector.
    pub min_idle: u32,
    /// Maximum idle warm entries allowed for a connector.
    pub max_idle: u32,
    /// Maximum age for a warm entry before checkout falls back to on-demand.
    pub max_age: Duration,
    /// Maximum wait while checking out a warm entry.
    pub checkout_timeout: Duration,
}

impl Default for ConnectorPrewarmConfig {
    fn default() -> Self {
        Self {
            strategy: PrewarmStrategy::OnDemand,
            min_idle: 0,
            max_idle: 0,
            max_age: Duration::ZERO,
            checkout_timeout: Duration::ZERO,
        }
    }
}

impl ConnectorPrewarmConfig {
    /// Build a warm-pool configuration.
    #[must_use]
    pub const fn warm_pool(
        min_idle: u32,
        max_idle: u32,
        max_age: Duration,
        checkout_timeout: Duration,
    ) -> Self {
        Self {
            strategy: PrewarmStrategy::WarmPool,
            min_idle,
            max_idle,
            max_age,
            checkout_timeout,
        }
    }

    /// Validate the prewarm configuration before it can influence startup.
    ///
    /// # Errors
    ///
    /// Returns a [`PrewarmConfigError`] when the requested strategy would be
    /// unsafe or internally inconsistent.
    pub const fn validate(&self) -> Result<(), PrewarmConfigError> {
        match self.strategy {
            PrewarmStrategy::OnDemand => Ok(()),
            PrewarmStrategy::Zygote => Err(PrewarmConfigError::ZygoteRequiresSecurityProof),
            PrewarmStrategy::WarmPool => {
                if self.max_idle == 0 {
                    return Err(PrewarmConfigError::MaxIdleZero);
                }
                if self.min_idle > self.max_idle {
                    return Err(PrewarmConfigError::MinIdleExceedsMaxIdle);
                }
                if self.max_age.is_zero() {
                    return Err(PrewarmConfigError::MaxAgeZero);
                }
                if self.checkout_timeout.is_zero() {
                    return Err(PrewarmConfigError::CheckoutTimeoutZero);
                }
                Ok(())
            }
        }
    }

    /// Decide whether a warm entry can be checked out for an invocation.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn decide_checkout(
        &self,
        observation: &PrewarmCheckoutObservation,
    ) -> PrewarmCheckoutDecision {
        if let Err(error) = self.validate() {
            return match error {
                PrewarmConfigError::ZygoteRequiresSecurityProof => {
                    PrewarmCheckoutDecision::RejectUnsafe {
                        reason: PrewarmUnsafeReason::ZygoteWithoutSecurityProof,
                    }
                }
                PrewarmConfigError::MaxIdleZero
                | PrewarmConfigError::MinIdleExceedsMaxIdle
                | PrewarmConfigError::MaxAgeZero
                | PrewarmConfigError::CheckoutTimeoutZero => {
                    PrewarmCheckoutDecision::FallbackOnDemand {
                        reason: PrewarmFallbackReason::InvalidConfig,
                    }
                }
            };
        }

        if self.strategy == PrewarmStrategy::OnDemand {
            return PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::NotConfigured,
            };
        }

        match observation.pool_state {
            PrewarmPoolState::WarmHit => {}
            PrewarmPoolState::Disabled => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::NotConfigured,
                };
            }
            PrewarmPoolState::Empty => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::EmptyPool,
                };
            }
            PrewarmPoolState::Stale => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::WarmEntryStale,
                };
            }
            PrewarmPoolState::CrashBeforeCheckout => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::CrashBeforeCheckout,
                };
            }
            PrewarmPoolState::Rejected => {
                return PrewarmCheckoutDecision::RejectUnsafe {
                    reason: PrewarmUnsafeReason::WarmEntryRejected,
                };
            }
        }

        match observation.manifest {
            PrewarmManifestState::Current => {}
            PrewarmManifestState::Missing => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::MissingManifestHash,
                };
            }
            PrewarmManifestState::Stale => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::StaleManifest,
                };
            }
        }

        if observation.zone_binding == PrewarmZoneBinding::Missing {
            return PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::MissingZoneBinding,
            };
        }

        if observation.sandbox == PrewarmSandboxState::LimitsUnavailable {
            return PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::SandboxLimitsUnavailable,
            };
        }

        if observation.credential == PrewarmCredentialState::MaterialLoaded {
            return PrewarmCheckoutDecision::RejectUnsafe {
                reason: PrewarmUnsafeReason::CredentialMaterialLoaded,
            };
        }

        match observation.health {
            PrewarmHealthState::Ready => {}
            PrewarmHealthState::Starting => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::WarmEntryStillStarting,
                };
            }
            PrewarmHealthState::Failed => {
                return PrewarmCheckoutDecision::FallbackOnDemand {
                    reason: PrewarmFallbackReason::WarmEntryFailedHealth,
                };
            }
        }

        if observation.entry_age > self.max_age {
            return PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::WarmEntryStale,
            };
        }

        if let Some(exit) = &observation.previous_exit
            && !exit.is_clean()
        {
            return PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::CrashBeforeCheckout,
            };
        }

        PrewarmCheckoutDecision::AdmitWarm {
            pool_state: PrewarmPoolState::WarmHit,
        }
    }
}

/// Why a prewarm configuration is invalid.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmConfigError {
    /// Fork/zygote style startup lacks the required security proof.
    ZygoteRequiresSecurityProof,
    /// Warm-pool mode needs at least one possible idle entry.
    MaxIdleZero,
    /// The requested floor is higher than the cap.
    MinIdleExceedsMaxIdle,
    /// Warm entries need a bounded lifetime.
    MaxAgeZero,
    /// Warm checkout needs a bounded wait.
    CheckoutTimeoutZero,
}

impl std::fmt::Display for PrewarmConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZygoteRequiresSecurityProof => {
                f.write_str("zygote prewarm requires a security proof")
            }
            Self::MaxIdleZero => f.write_str("warm-pool max_idle must be greater than zero"),
            Self::MinIdleExceedsMaxIdle => {
                f.write_str("warm-pool min_idle must not exceed max_idle")
            }
            Self::MaxAgeZero => f.write_str("warm-pool max_age must be greater than zero"),
            Self::CheckoutTimeoutZero => {
                f.write_str("warm-pool checkout_timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for PrewarmConfigError {}

/// Manifest freshness observed for a warm entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmManifestState {
    /// Warm entry was created from the current manifest hash.
    Current,
    /// No manifest hash was captured.
    Missing,
    /// Warm entry was created from an older manifest hash.
    Stale,
}

/// Zone binding observed for a warm entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmZoneBinding {
    /// Warm entry is already bound to the requested zone.
    Bound,
    /// Warm entry has no usable zone binding.
    Missing,
}

/// Sandbox state observed for a warm entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmSandboxState {
    /// Required sandbox limits are active.
    LimitsActive,
    /// Required sandbox limits are unavailable or unverified.
    LimitsUnavailable,
}

/// Credential state observed for a warm entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmCredentialState {
    /// Warm entry has not loaded secret credential material.
    Deferred,
    /// Warm entry already loaded credential material and must not be reused.
    MaterialLoaded,
}

/// Health state observed for a warm entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmHealthState {
    /// Warm entry passed readiness checks.
    Ready,
    /// Warm entry is still starting.
    Starting,
    /// Warm entry failed readiness checks.
    Failed,
}

/// Pool state recorded in prewarm checkout evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmPoolState {
    /// No prewarm pool was configured.
    Disabled,
    /// No eligible warm process was available.
    Empty,
    /// A safe warm entry was admitted.
    WarmHit,
    /// A warm entry existed but was too old.
    Stale,
    /// A warm entry crashed or failed before checkout.
    CrashBeforeCheckout,
    /// A warm entry was rejected as unsafe.
    Rejected,
}

/// Live observation used to decide whether a warm entry is safe to checkout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrewarmCheckoutObservation {
    /// Current pool state for the candidate checkout.
    pub pool_state: PrewarmPoolState,
    /// Manifest freshness for the candidate warm entry.
    pub manifest: PrewarmManifestState,
    /// Zone binding state for the candidate warm entry.
    pub zone_binding: PrewarmZoneBinding,
    /// Sandbox limit state for the candidate warm entry.
    pub sandbox: PrewarmSandboxState,
    /// Credential loading state for the candidate warm entry.
    pub credential: PrewarmCredentialState,
    /// Readiness state for the candidate warm entry.
    pub health: PrewarmHealthState,
    /// Age of the candidate warm entry.
    pub entry_age: Duration,
    /// Exit observed before checkout, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_exit: Option<ProcessExit>,
}

/// Decision produced for a warm-entry checkout attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PrewarmCheckoutDecision {
    /// Admit the warm entry.
    AdmitWarm {
        /// Pool state to record in structured evidence.
        pool_state: PrewarmPoolState,
    },
    /// Fall back to conservative on-demand startup.
    FallbackOnDemand {
        /// Why prewarm was not used.
        reason: PrewarmFallbackReason,
    },
    /// Reject the warm entry because it would violate a security invariant.
    RejectUnsafe {
        /// Why the warm entry is unsafe.
        reason: PrewarmUnsafeReason,
    },
}

impl PrewarmCheckoutDecision {
    /// Whether this decision admits a warm process.
    #[must_use]
    pub const fn admits_warm_entry(&self) -> bool {
        matches!(self, Self::AdmitWarm { .. })
    }
}

/// Conservative fallback reason for an on-demand connector startup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmFallbackReason {
    /// Prewarm is disabled.
    NotConfigured,
    /// Configuration is invalid.
    InvalidConfig,
    /// No warm entry is available.
    EmptyPool,
    /// The warm entry did not capture a manifest hash.
    MissingManifestHash,
    /// The warm entry manifest hash does not match the current manifest.
    StaleManifest,
    /// The warm entry is not bound to the target zone.
    MissingZoneBinding,
    /// Sandbox limits are unavailable or unverified.
    SandboxLimitsUnavailable,
    /// The warm entry is still starting.
    WarmEntryStillStarting,
    /// The warm entry failed readiness checks.
    WarmEntryFailedHealth,
    /// The warm entry exceeded the configured maximum age.
    WarmEntryStale,
    /// The warm entry crashed before checkout.
    CrashBeforeCheckout,
}

/// Unsafe prewarm rejection reason.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrewarmUnsafeReason {
    /// Zygote startup was requested without a security proof.
    ZygoteWithoutSecurityProof,
    /// Pool metadata marked the warm entry as rejected before checkout.
    WarmEntryRejected,
    /// The warm entry already loaded credential material.
    CredentialMaterialLoaded,
}

/// Structured prewarm checkout evidence suitable for JSONL proof logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrewarmCheckoutEvidence {
    /// Connector identifier.
    pub connector_id: String,
    /// Host boundary that made the checkout decision.
    pub host_boundary: String,
    /// Manifest hash used by the candidate warm entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    /// Zone requested by checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Pool state recorded for the checkout.
    pub pool_state: PrewarmPoolState,
    /// Configured warm pool capacity represented by this checkout.
    pub pool_size: u32,
    /// Coarse checkout decision label for JSONL logs.
    pub admission_decision: String,
    /// Whether the decision admits a warm entry.
    pub warm_checkout: bool,
    /// Activation latency in milliseconds, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_latency_ms: Option<u64>,
    /// Sandbox layer reported for the warm entry.
    pub sandbox_layer: String,
    /// Sandbox profile requested by the connector fixture.
    pub sandbox_profile: String,
    /// Sandbox boundary represented by this checkout.
    pub sandbox_boundary: String,
    /// Credential handling mode, redacted to a coarse class.
    pub credential_state: PrewarmCredentialState,
    /// Resident set size observed for the connector sandbox, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    /// Process count observed for the connector sandbox.
    pub process_count: u32,
    /// Operator-facing error mapping class for fallback or rejection paths.
    pub error_mapping: String,
    /// Cleanup result recorded for the warm entry or fallback path.
    pub cleanup_result: String,
    /// Final checkout decision.
    pub decision: PrewarmCheckoutDecision,
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive Warm-Pool Retention
// ─────────────────────────────────────────────────────────────────────────────

/// Stable event name emitted for adaptive warm-pool retention evidence.
pub const WARM_POOL_EVIDENCE_EVENT: &str = "fcp.host.warm_pool";
/// Owning bead for adaptive warm-pool controller evidence.
pub const ADAPTIVE_WARM_POOL_BEAD: &str = "flywheel_connectors-ql87d.2";

/// Isolation key for a warm connector process.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WarmPoolKey {
    /// Connector package or binary identity.
    pub connector_id: String,
    /// Manifest hash captured when the warm process was configured.
    pub manifest_hash: String,
    /// Sandbox profile active for the warm process.
    pub sandbox_profile: String,
    /// Single zone the warm process is bound to.
    pub zone: String,
    /// Coarse credential profile class; never secret material.
    pub credential_profile_class: String,
}

impl WarmPoolKey {
    /// Build a key that prevents reuse across incompatible warm-entry domains.
    #[must_use]
    pub fn new(
        connector_id: impl Into<String>,
        manifest_hash: impl Into<String>,
        sandbox_profile: impl Into<String>,
        zone: impl Into<String>,
        credential_profile_class: impl Into<String>,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            manifest_hash: manifest_hash.into(),
            sandbox_profile: sandbox_profile.into(),
            zone: zone.into(),
            credential_profile_class: credential_profile_class.into(),
        }
    }
}

/// Snapshot of one warm process considered for retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmPoolEntrySnapshot {
    /// Isolation key for this warm entry.
    pub key: WarmPoolKey,
    /// Milliseconds since this entry was last used.
    pub idle_ms: u64,
    /// Milliseconds since this entry was created/configured.
    pub age_ms: u64,
    /// Resident set size attributed to this warm entry.
    pub rss_bytes: u64,
    /// Manifest freshness for this entry.
    pub manifest: PrewarmManifestState,
    /// Sandbox enforcement status.
    pub sandbox: PrewarmSandboxState,
    /// Credential loading status.
    pub credential: PrewarmCredentialState,
    /// Readiness health.
    pub health: PrewarmHealthState,
    /// Exit observed before reuse, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_exit: Option<ProcessExit>,
    /// Whether request-local state leaked into the warm entry.
    pub retained_request_context: bool,
    /// Whether a prior capability token leaked into the warm entry.
    pub retained_capability_token: bool,
}

impl WarmPoolEntrySnapshot {
    /// Build a ready, secret-free warm entry for tests and fixtures.
    #[must_use]
    pub const fn ready(key: WarmPoolKey, idle_ms: u64, rss_bytes: u64) -> Self {
        Self {
            key,
            idle_ms,
            age_ms: idle_ms,
            rss_bytes,
            manifest: PrewarmManifestState::Current,
            sandbox: PrewarmSandboxState::LimitsActive,
            credential: PrewarmCredentialState::Deferred,
            health: PrewarmHealthState::Ready,
            previous_exit: None,
            retained_request_context: false,
            retained_capability_token: false,
        }
    }

    fn invariant_eviction_reason(&self) -> Option<WarmPoolEvictionReason> {
        if self.retained_request_context || self.retained_capability_token {
            return Some(WarmPoolEvictionReason::BookkeepingInconsistent);
        }
        if self.manifest != PrewarmManifestState::Current {
            return Some(WarmPoolEvictionReason::StaleManifest);
        }
        if self.sandbox != PrewarmSandboxState::LimitsActive {
            return Some(WarmPoolEvictionReason::SandboxLimitsUnavailable);
        }
        if self.credential == PrewarmCredentialState::MaterialLoaded {
            return Some(WarmPoolEvictionReason::CredentialMaterialLoaded);
        }
        if self.health != PrewarmHealthState::Ready {
            return Some(WarmPoolEvictionReason::DegradedHealth);
        }
        if let Some(exit) = &self.previous_exit
            && !exit.is_clean()
        {
            return Some(WarmPoolEvictionReason::CrashBeforeCheckout);
        }
        None
    }
}

/// Pressure inputs for adaptive warm-pool retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum WarmPoolPressureSnapshot {
    /// Replayable pressure input is present and calibrated.
    Available {
        /// Current host pressure telemetry.
        telemetry: BackpressureTelemetry,
        /// Calibration envelope for adaptive decisions.
        calibration: BackpressureCalibration,
    },
    /// Required pressure inputs are unavailable.
    Unavailable {
        /// Redaction-safe reason.
        reason: String,
    },
}

impl WarmPoolPressureSnapshot {
    /// Build a valid low-pressure snapshot.
    #[must_use]
    pub const fn low_pressure() -> Self {
        Self::Available {
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(100),
                cpu_pressure_per_mille: Some(100),
                memory_pressure_per_mille: Some(100),
                downstream_retry_after_ms: None,
                retry_amplification_per_mille: None,
                useful_work_per_mille: Some(900),
            },
            calibration: BackpressureCalibration::valid(),
        }
    }
}

/// Configuration for adaptive warm-pool retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveWarmPoolConfig {
    /// Maximum idle warm entries retained for one connector id.
    pub per_connector_max_idle: usize,
    /// Global resident-set cap for all retained warm entries.
    pub global_rss_cap_bytes: u64,
}

impl AdaptiveWarmPoolConfig {
    /// Build a bounded adaptive warm-pool retention config.
    #[must_use]
    pub const fn new(per_connector_max_idle: usize, global_rss_cap_bytes: u64) -> Self {
        Self {
            per_connector_max_idle,
            global_rss_cap_bytes,
        }
    }
}

impl Default for AdaptiveWarmPoolConfig {
    fn default() -> Self {
        Self {
            per_connector_max_idle: 1,
            global_rss_cap_bytes: 0,
        }
    }
}

/// Why a warm entry was evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmPoolEvictionReason {
    /// Health is not ready.
    DegradedHealth,
    /// Manifest hash is missing or stale relative to the current manifest.
    StaleManifest,
    /// Sandbox limits are unavailable or unverified.
    SandboxLimitsUnavailable,
    /// The warm entry already loaded credential material.
    CredentialMaterialLoaded,
    /// The warm entry crashed before checkout.
    CrashBeforeCheckout,
    /// Request context or capability state leaked into the warm entry.
    BookkeepingInconsistent,
    /// Retention would exceed the per-connector idle cap.
    PerConnectorCap,
    /// Retention would exceed the global resident-set cap.
    GlobalRssCap,
    /// Host pressure asked low-priority work to back off.
    PressureBackoff,
    /// Host pressure asked low-priority work to be shed or cancelled.
    PressureShed,
    /// Pressure input, calibration, or replay evidence is unavailable.
    PressureUnavailable,
}

impl WarmPoolEvictionReason {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DegradedHealth => "degraded_health",
            Self::StaleManifest => "stale_manifest",
            Self::SandboxLimitsUnavailable => "sandbox_limits_unavailable",
            Self::CredentialMaterialLoaded => "credential_material_loaded",
            Self::CrashBeforeCheckout => "crash_before_checkout",
            Self::BookkeepingInconsistent => "bookkeeping_inconsistent",
            Self::PerConnectorCap => "per_connector_cap",
            Self::GlobalRssCap => "global_rss_cap",
            Self::PressureBackoff => "pressure_backoff",
            Self::PressureShed => "pressure_shed",
            Self::PressureUnavailable => "pressure_unavailable",
        }
    }
}

/// Deterministic eviction selected by the warm-pool controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmPoolEviction {
    /// Evicted warm-entry key.
    pub key: WarmPoolKey,
    /// Explicit reason code.
    pub reason: WarmPoolEvictionReason,
    /// Idle age at eviction.
    pub idle_ms: u64,
    /// RSS attributed to this entry.
    pub rss_bytes: u64,
}

impl WarmPoolEviction {
    fn new(entry: &WarmPoolEntrySnapshot, reason: WarmPoolEvictionReason) -> Self {
        Self {
            key: entry.key.clone(),
            reason,
            idle_ms: entry.idle_ms,
            rss_bytes: entry.rss_bytes,
        }
    }
}

/// Redaction-safe JSONL-ready warm-pool evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmPoolEvidenceRecord {
    /// Stable event name: `fcp.host.warm_pool`.
    pub event: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Connector id, safe for operator logs.
    pub connector_id: String,
    /// Manifest hash captured by the warm entry.
    pub manifest_hash: String,
    /// Sandbox profile class.
    pub sandbox_profile: String,
    /// Redacted zone id hash.
    pub zone_hash: String,
    /// Redacted credential profile class hash.
    pub credential_profile_class_hash: String,
    /// Eviction reason.
    pub reason: WarmPoolEvictionReason,
    /// Stable reason label for JSONL consumers.
    pub reason_code: String,
    /// Idle age at eviction.
    pub idle_ms: u64,
    /// RSS attributed to this entry.
    pub rss_bytes: u64,
    /// Backpressure state, when a replayable decision was available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_state: Option<String>,
    /// Backpressure action, when a replayable decision was available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_action: Option<String>,
    /// Whether embedded pressure replay reproduced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_replay_matches: Option<bool>,
}

impl WarmPoolEvidenceRecord {
    fn new(
        entry: &WarmPoolEntrySnapshot,
        reason: WarmPoolEvictionReason,
        pressure_decision: Option<&BackpressureDecision>,
    ) -> Self {
        Self {
            event: WARM_POOL_EVIDENCE_EVENT.to_string(),
            bead_id: ADAPTIVE_WARM_POOL_BEAD.to_string(),
            connector_id: entry.key.connector_id.clone(),
            manifest_hash: entry.key.manifest_hash.clone(),
            sandbox_profile: entry.key.sandbox_profile.clone(),
            zone_hash: redacted_warm_pool_label("zone", &entry.key.zone),
            credential_profile_class_hash: redacted_warm_pool_label(
                "credential_profile",
                &entry.key.credential_profile_class,
            ),
            reason,
            reason_code: reason.as_str().to_string(),
            idle_ms: entry.idle_ms,
            rss_bytes: entry.rss_bytes,
            pressure_state: pressure_decision.map(|decision| decision.state.as_str().to_string()),
            pressure_action: pressure_decision.map(|decision| decision.action.as_str().to_string()),
            pressure_replay_matches: pressure_decision.map(BackpressureDecision::replay_matches),
        }
    }
}

/// Retention plan produced by the adaptive warm-pool controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmPoolRetentionPlan {
    /// Stable event name: `fcp.host.warm_pool`.
    pub event: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Whether warm pooling should be disabled for this cycle.
    pub disabled: bool,
    /// Why retention was globally disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<WarmPoolEvictionReason>,
    /// Backpressure state, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_state: Option<String>,
    /// Backpressure action, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_action: Option<String>,
    /// Whether embedded backpressure replay reproduced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_replay_matches: Option<bool>,
    /// Warm-entry keys retained for future checkout.
    pub retained: Vec<WarmPoolKey>,
    /// Indices (into the planned snapshot slice) of the entries retained for
    /// future checkout. Unlike [`Self::retained`], which collapses to class
    /// keys, these preserve entry identity — the caller MUST apply eviction by
    /// these indices, because several live entries can share one `WarmPoolKey`
    /// (same connector/zone/manifest/credential class) and a key-membership
    /// filter would then retain every same-key entry, silently dropping the
    /// planned eviction.
    #[serde(skip)]
    pub retained_indices: Vec<usize>,
    /// Deterministic evictions selected by the controller.
    pub evictions: Vec<WarmPoolEviction>,
    /// Redaction-safe evidence records for the evictions.
    pub evidence: Vec<WarmPoolEvidenceRecord>,
}

impl WarmPoolRetentionPlan {
    fn empty(
        disabled: bool,
        disabled_reason: Option<WarmPoolEvictionReason>,
        pressure_decision: Option<&BackpressureDecision>,
    ) -> Self {
        Self {
            event: WARM_POOL_EVIDENCE_EVENT.to_string(),
            bead_id: ADAPTIVE_WARM_POOL_BEAD.to_string(),
            disabled,
            disabled_reason,
            pressure_state: pressure_decision.map(|decision| decision.state.as_str().to_string()),
            pressure_action: pressure_decision.map(|decision| decision.action.as_str().to_string()),
            pressure_replay_matches: pressure_decision.map(BackpressureDecision::replay_matches),
            retained: Vec::new(),
            retained_indices: Vec::new(),
            evictions: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// Adaptive controller for bounded warm-pool retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveWarmPoolController {
    /// Retention caps.
    pub config: AdaptiveWarmPoolConfig,
    /// Existing host backpressure model used for admission/eviction.
    pub backpressure: BackpressureController,
}

impl AdaptiveWarmPoolController {
    /// Build a controller with explicit retention bounds.
    #[must_use]
    pub fn new(config: AdaptiveWarmPoolConfig) -> Self {
        Self {
            config,
            backpressure: BackpressureController::new(BackpressureControllerConfig::default()),
        }
    }

    /// Plan deterministic retention for a warm-pool snapshot.
    #[must_use]
    pub fn plan_retention(
        &self,
        entries: &[WarmPoolEntrySnapshot],
        pressure: &WarmPoolPressureSnapshot,
    ) -> WarmPoolRetentionPlan {
        let pressure_decision = match pressure {
            WarmPoolPressureSnapshot::Available {
                telemetry,
                calibration,
            } => Some(self.backpressure.decide(BackpressureControllerInput::new(
                "fcp.host.warm_pool/retention",
                RequestPriority::Low,
                *telemetry,
                *calibration,
            ))),
            WarmPoolPressureSnapshot::Unavailable { .. } => None,
        };

        if let Some(reason) = pressure_decision
            .as_ref()
            .and_then(|decision| pressure_eviction_reason(decision.action))
            .or_else(|| {
                pressure_decision
                    .is_none()
                    .then_some(WarmPoolEvictionReason::PressureUnavailable)
            })
        {
            return Self::evict_all(entries, reason, pressure_decision.as_ref());
        }

        let Some(decision) = pressure_decision.as_ref() else {
            return Self::evict_all(entries, WarmPoolEvictionReason::PressureUnavailable, None);
        };
        let mut plan = WarmPoolRetentionPlan::empty(false, None, Some(decision));
        let mut retained_indices = Vec::new();
        let mut evicted_indices = BTreeSet::new();

        for (index, entry) in entries.iter().enumerate() {
            if let Some(reason) = entry.invariant_eviction_reason() {
                evict_entry(&mut plan, entry, reason, Some(decision));
                evicted_indices.insert(index);
            } else {
                retained_indices.push(index);
            }
        }

        self.apply_per_connector_cap(
            entries,
            &retained_indices,
            &mut evicted_indices,
            &mut plan,
            decision,
        );
        self.apply_global_rss_cap(
            entries,
            &retained_indices,
            &mut evicted_indices,
            &mut plan,
            decision,
        );

        let final_indices: Vec<usize> = retained_indices
            .into_iter()
            .filter(|index| !evicted_indices.contains(index))
            .collect();
        plan.retained = final_indices
            .iter()
            .map(|&index| entries[index].key.clone())
            .collect();
        plan.retained_indices = final_indices;
        plan
    }

    fn evict_all(
        entries: &[WarmPoolEntrySnapshot],
        reason: WarmPoolEvictionReason,
        pressure_decision: Option<&BackpressureDecision>,
    ) -> WarmPoolRetentionPlan {
        let mut plan = WarmPoolRetentionPlan::empty(true, Some(reason), pressure_decision);
        for entry in entries {
            evict_entry(&mut plan, entry, reason, pressure_decision);
        }
        plan
    }

    fn apply_per_connector_cap(
        &self,
        entries: &[WarmPoolEntrySnapshot],
        retained_indices: &[usize],
        evicted_indices: &mut BTreeSet<usize>,
        plan: &mut WarmPoolRetentionPlan,
        pressure_decision: &BackpressureDecision,
    ) {
        let mut by_connector: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for index in retained_indices {
            by_connector
                .entry(entries[*index].key.connector_id.clone())
                .or_default()
                .push(*index);
        }

        for mut connector_indices in by_connector.into_values() {
            connector_indices.sort_by(|left, right| {
                entries[*right]
                    .idle_ms
                    .cmp(&entries[*left].idle_ms)
                    .then_with(|| entries[*left].key.cmp(&entries[*right].key))
            });

            let overflow = connector_indices
                .len()
                .saturating_sub(self.config.per_connector_max_idle);
            for index in connector_indices.into_iter().take(overflow) {
                if evicted_indices.insert(index) {
                    evict_entry(
                        plan,
                        &entries[index],
                        WarmPoolEvictionReason::PerConnectorCap,
                        Some(pressure_decision),
                    );
                }
            }
        }
    }

    fn apply_global_rss_cap(
        &self,
        entries: &[WarmPoolEntrySnapshot],
        retained_indices: &[usize],
        evicted_indices: &mut BTreeSet<usize>,
        plan: &mut WarmPoolRetentionPlan,
        pressure_decision: &BackpressureDecision,
    ) {
        let mut total_rss = retained_indices
            .iter()
            .filter(|index| !evicted_indices.contains(index))
            .map(|index| entries[*index].rss_bytes)
            .sum::<u64>();
        let mut candidates = retained_indices
            .iter()
            .copied()
            .filter(|index| !evicted_indices.contains(index))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            entries[*right]
                .idle_ms
                .cmp(&entries[*left].idle_ms)
                .then_with(|| entries[*right].rss_bytes.cmp(&entries[*left].rss_bytes))
                .then_with(|| entries[*left].key.cmp(&entries[*right].key))
        });

        for index in candidates {
            if total_rss <= self.config.global_rss_cap_bytes {
                break;
            }
            if evicted_indices.insert(index) {
                total_rss = total_rss.saturating_sub(entries[index].rss_bytes);
                evict_entry(
                    plan,
                    &entries[index],
                    WarmPoolEvictionReason::GlobalRssCap,
                    Some(pressure_decision),
                );
            }
        }
    }
}

impl Default for AdaptiveWarmPoolController {
    fn default() -> Self {
        Self::new(AdaptiveWarmPoolConfig::default())
    }
}

fn evict_entry(
    plan: &mut WarmPoolRetentionPlan,
    entry: &WarmPoolEntrySnapshot,
    reason: WarmPoolEvictionReason,
    pressure_decision: Option<&BackpressureDecision>,
) {
    plan.evictions.push(WarmPoolEviction::new(entry, reason));
    plan.evidence.push(WarmPoolEvidenceRecord::new(
        entry,
        reason,
        pressure_decision,
    ));
}

const fn pressure_eviction_reason(action: BackpressureAction) -> Option<WarmPoolEvictionReason> {
    match action {
        BackpressureAction::Admit | BackpressureAction::AdmitWithWarning => None,
        BackpressureAction::Delay => Some(WarmPoolEvictionReason::PressureBackoff),
        BackpressureAction::Shed | BackpressureAction::CancelLowPriority => {
            Some(WarmPoolEvictionReason::PressureShed)
        }
        BackpressureAction::FallbackStaticPolicy => {
            Some(WarmPoolEvictionReason::PressureUnavailable)
        }
    }
}

fn redacted_warm_pool_label(prefix: &str, raw: &str) -> String {
    let digest = blake3::hash(raw.as_bytes()).to_hex().to_string();
    format!("{prefix}:blake3:{}", &digest[..16])
}

// ─────────────────────────────────────────────────────────────────────────────
// Capacity-Aware Local Placement
// ─────────────────────────────────────────────────────────────────────────────

/// Stable event name emitted for local placement evidence.
pub const PLACEMENT_EVIDENCE_EVENT: &str = "fcp.host.placement";
/// Owning bead for local connector placement evidence.
pub const LOCAL_PLACEMENT_BEAD: &str = "flywheel_connectors-ql87d.4";

/// Coarse operation class used by local placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementOperationClass {
    /// Lifecycle, revocation, audit, and other safety-critical host work.
    LifecycleCritical,
    /// Interactive request-response work with user-visible latency.
    LatencySensitive,
    /// Long-lived stream work.
    StreamingLongLived,
    /// High-volume throughput or batch work.
    Throughput,
    /// Work whose primary risk is resident memory pressure.
    MemoryHeavy,
    /// Work dominated by signing, verification, encryption, or hashing.
    CryptoHeavy,
    /// Best-effort warm-pool or bulk prewarm work.
    BulkPrewarm,
}

impl PlacementOperationClass {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LifecycleCritical => "lifecycle_critical",
            Self::LatencySensitive => "latency_sensitive",
            Self::StreamingLongLived => "streaming_long_lived",
            Self::Throughput => "throughput",
            Self::MemoryHeavy => "memory_heavy",
            Self::CryptoHeavy => "crypto_heavy",
            Self::BulkPrewarm => "bulk_prewarm",
        }
    }

    /// Priority used when asking the host backpressure model for pressure.
    #[must_use]
    pub const fn request_priority(self) -> RequestPriority {
        match self {
            Self::LifecycleCritical => RequestPriority::Critical,
            Self::LatencySensitive | Self::StreamingLongLived | Self::CryptoHeavy => {
                RequestPriority::High
            }
            Self::MemoryHeavy | Self::Throughput => RequestPriority::Normal,
            Self::BulkPrewarm => RequestPriority::Low,
        }
    }

    const fn is_bulk_like(self) -> bool {
        matches!(self, Self::BulkPrewarm | Self::Throughput)
    }
}

/// Operator-visible hint class selected from manifest/config metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementHintClass {
    /// Lifecycle-critical work takes the critical lane regardless of connector labels.
    LifecycleCritical,
    /// Interactive latency-sensitive connector.
    LatencySensitive,
    /// Long-lived streaming connector.
    StreamingLongLived,
    /// Memory-heavy connector.
    MemoryHeavy,
    /// Crypto-heavy connector.
    CryptoHeavy,
    /// Throughput-oriented connector.
    Throughput,
    /// Strict sandbox constraints dominate the hint.
    SandboxStrict,
    /// Default low-specificity hint.
    Bulk,
}

impl PlacementHintClass {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LifecycleCritical => "lifecycle_critical",
            Self::LatencySensitive => "latency_sensitive",
            Self::StreamingLongLived => "streaming_long_lived",
            Self::MemoryHeavy => "memory_heavy",
            Self::CryptoHeavy => "crypto_heavy",
            Self::Throughput => "throughput",
            Self::SandboxStrict => "sandbox_strict",
            Self::Bulk => "bulk",
        }
    }
}

/// Local execution lane selected for a connector launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementLane {
    /// Critical lifecycle lane.
    Critical,
    /// Latency lane.
    Latency,
    /// Streaming lane.
    Streaming,
    /// Memory-constrained lane.
    MemoryConstrained,
    /// Crypto lane.
    Crypto,
    /// Throughput lane.
    Throughput,
    /// Bulk lane.
    Bulk,
}

impl PlacementLane {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Latency => "latency",
            Self::Streaming => "streaming",
            Self::MemoryConstrained => "memory_constrained",
            Self::Crypto => "crypto",
            Self::Throughput => "throughput",
            Self::Bulk => "bulk",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::Latency => 1,
            Self::Streaming => 2,
            Self::Crypto => 3,
            Self::MemoryConstrained => 4,
            Self::Throughput => 5,
            Self::Bulk => 6,
        }
    }
}

/// Backpressure verdict used by local placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementPressureVerdict {
    /// Admit normally.
    Green,
    /// Admit critical/latency work, but add backoff for low-value work.
    Yellow,
    /// Preserve critical work and refuse bulk/prewarm launches.
    Red,
    /// Pressure input was unavailable; preserve critical work only.
    Unavailable,
}

impl PlacementPressureVerdict {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
            Self::Unavailable => "unavailable",
        }
    }

    const fn from_action(action: BackpressureAction) -> Self {
        match action {
            BackpressureAction::Admit => Self::Green,
            BackpressureAction::AdmitWithWarning | BackpressureAction::Delay => Self::Yellow,
            BackpressureAction::Shed
            | BackpressureAction::CancelLowPriority
            | BackpressureAction::FallbackStaticPolicy => Self::Red,
        }
    }
}

/// Why placement affinity was recorded as a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementAffinityNoOpReason {
    /// No CPU-set hint was requested.
    NotRequested,
    /// CPU-set hint was syntactically empty.
    EmptyPreferredCpuSet,
    /// The host has no supported affinity application path for this launch.
    UnsupportedPlatform,
}

impl PlacementAffinityNoOpReason {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::EmptyPreferredCpuSet => "empty_preferred_cpu_set",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

/// Placement hints derived from host-owned connector metadata.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementHint {
    /// Whether the connector should prefer latency lanes.
    pub latency_sensitive: bool,
    /// Whether the connector should prefer throughput lanes.
    pub throughput: bool,
    /// Whether the connector is expected to hold long-lived streams.
    pub streaming_long_lived: bool,
    /// Whether the connector should be treated as memory-heavy.
    pub memory_heavy: bool,
    /// Whether the connector should be treated as crypto-heavy.
    pub crypto_heavy: bool,
    /// Whether strict sandbox constraints are part of launch planning.
    pub sandbox_strict: bool,
    /// Optional CPU-set affinity hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_cpu_set: Option<Vec<u16>>,
    /// Optional resident-set budget hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rss_bytes: Option<u64>,
}

impl PlacementHint {
    /// Classify this hint for stable evidence.
    #[must_use]
    pub const fn class(&self, operation_class: PlacementOperationClass) -> PlacementHintClass {
        if matches!(operation_class, PlacementOperationClass::LifecycleCritical) {
            return PlacementHintClass::LifecycleCritical;
        }
        if self.streaming_long_lived {
            return PlacementHintClass::StreamingLongLived;
        }
        if self.latency_sensitive {
            return PlacementHintClass::LatencySensitive;
        }
        if self.memory_heavy {
            return PlacementHintClass::MemoryHeavy;
        }
        if self.crypto_heavy {
            return PlacementHintClass::CryptoHeavy;
        }
        if self.throughput {
            return PlacementHintClass::Throughput;
        }
        if self.sandbox_strict {
            return PlacementHintClass::SandboxStrict;
        }
        PlacementHintClass::Bulk
    }

    /// Select the local lane for this hint and operation class.
    #[must_use]
    pub const fn lane(&self, operation_class: PlacementOperationClass) -> PlacementLane {
        match operation_class {
            PlacementOperationClass::LifecycleCritical => PlacementLane::Critical,
            PlacementOperationClass::LatencySensitive => PlacementLane::Latency,
            PlacementOperationClass::StreamingLongLived => PlacementLane::Streaming,
            PlacementOperationClass::Throughput => PlacementLane::Throughput,
            PlacementOperationClass::MemoryHeavy => PlacementLane::MemoryConstrained,
            PlacementOperationClass::CryptoHeavy => PlacementLane::Crypto,
            PlacementOperationClass::BulkPrewarm => PlacementLane::Bulk,
        }
    }
}

/// Host metadata used to derive a default placement hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementHintDerivationInput {
    /// Connector id used only for deterministic tie-breaking evidence.
    pub connector_id: String,
    /// Manifest archetypes or inventory category labels.
    pub manifest_archetypes: Vec<String>,
    /// Operation ids from manifest/admin operation metadata.
    pub operation_ids: Vec<String>,
    /// Whether the runtime path claims strict sandbox/network enforcement.
    pub sandbox_strict: bool,
    /// Configured startup prewarm strategy.
    pub prewarm_strategy: PrewarmStrategy,
    /// Optional operator CPU-set preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_cpu_set: Option<Vec<u16>>,
    /// Optional operator resident-set budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rss_bytes: Option<u64>,
}

impl PlacementHintDerivationInput {
    /// Build derivation input for a connector id.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            manifest_archetypes: Vec::new(),
            operation_ids: Vec::new(),
            sandbox_strict: false,
            prewarm_strategy: PrewarmStrategy::OnDemand,
            preferred_cpu_set: None,
            max_rss_bytes: None,
        }
    }

    /// Derive a default placement hint from host-owned metadata.
    #[must_use]
    pub fn derive_hint(&self) -> PlacementHint {
        let labels = self
            .manifest_archetypes
            .iter()
            .chain(self.operation_ids.iter())
            .map(|label| normalize_placement_label(label))
            .collect::<Vec<_>>();
        let has = |needles: &[&str]| labels.iter().any(|label| label_has_any(label, needles));

        PlacementHint {
            latency_sensitive: self.prewarm_strategy == PrewarmStrategy::WarmPool
                || has(&[
                    "requestresponse",
                    "rest",
                    "graphql",
                    "grpc",
                    "chat",
                    "webhook",
                    "browser",
                    "interactive",
                    "search",
                ]),
            throughput: has(&[
                "batch", "queue", "pubsub", "database", "blob", "file", "storage", "export", "sync",
            ]),
            streaming_long_lived: has(&["stream", "websocket", "sse", "tail", "subscribe"]),
            memory_heavy: self
                .max_rss_bytes
                .is_some_and(|bytes| bytes >= 256 * 1024 * 1024)
                || has(&[
                    "video",
                    "audio",
                    "speech",
                    "vision",
                    "embedding",
                    "ml",
                    "comfyui",
                ]),
            crypto_heavy: has(&[
                "crypto",
                "sign",
                "signature",
                "verify",
                "verification",
                "sigstore",
                "tuf",
                "cose",
                "hpke",
            ]),
            sandbox_strict: self.sandbox_strict,
            preferred_cpu_set: self.preferred_cpu_set.clone(),
            max_rss_bytes: self.max_rss_bytes,
        }
    }
}

/// Launch request consumed by local placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPlacementRequest {
    /// Connector id.
    pub connector_id: String,
    /// Coarse operation class.
    pub operation_class: PlacementOperationClass,
    /// Derived placement hint.
    pub hint: PlacementHint,
    /// Already-observed queue wait, in milliseconds.
    pub queue_wait_ms: u64,
}

impl LocalPlacementRequest {
    /// Build a launch request.
    #[must_use]
    pub fn new(
        connector_id: impl Into<String>,
        operation_class: PlacementOperationClass,
        hint: PlacementHint,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            operation_class,
            hint,
            queue_wait_ms: 0,
        }
    }
}

/// Pressure inputs for local placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum LocalPlacementPressureSnapshot {
    /// Replayable decision is already present from the host resilience layer.
    Decision {
        /// Current host backpressure decision.
        decision: Box<BackpressureDecision>,
    },
    /// Replayable pressure input is present and calibrated.
    Available {
        /// Current host pressure telemetry.
        telemetry: BackpressureTelemetry,
        /// Calibration envelope for adaptive decisions.
        calibration: BackpressureCalibration,
    },
    /// Required pressure inputs are unavailable.
    Unavailable {
        /// Redaction-safe reason.
        reason: String,
    },
}

impl LocalPlacementPressureSnapshot {
    /// Build a valid low-pressure snapshot.
    #[must_use]
    pub const fn low_pressure() -> Self {
        Self::Available {
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(100),
                cpu_pressure_per_mille: Some(100),
                memory_pressure_per_mille: Some(100),
                downstream_retry_after_ms: None,
                retry_amplification_per_mille: None,
                useful_work_per_mille: Some(900),
            },
            calibration: BackpressureCalibration::valid(),
        }
    }

    /// Wrap an already-computed host backpressure decision.
    #[must_use]
    pub fn from_decision(decision: BackpressureDecision) -> Self {
        Self::Decision {
            decision: Box::new(decision),
        }
    }
}

/// Redaction-safe placement evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPlacementPlan {
    /// Stable event name: `fcp.host.placement`.
    pub event: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Connector id.
    pub connector_id: String,
    /// Coarse operation class.
    pub operation_class: PlacementOperationClass,
    /// Derived hint class.
    pub hint_class: PlacementHintClass,
    /// Selected local lane.
    pub selected_lane: PlacementLane,
    /// Whether launch work is admitted.
    pub admitted: bool,
    /// Whether CPU affinity was actually applied.
    pub affinity_applied: bool,
    /// Explicit affinity no-op reason.
    pub no_op_reason: PlacementAffinityNoOpReason,
    /// Green/yellow/red pressure verdict.
    pub pressure_verdict: PlacementPressureVerdict,
    /// Backpressure state, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_state: Option<String>,
    /// Backpressure action, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_action: Option<String>,
    /// Whether embedded pressure replay reproduced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_replay_matches: Option<bool>,
    /// Queue wait, in milliseconds.
    pub queue_wait_ms: u64,
    /// Optional CPU-set affinity hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_cpu_set: Option<Vec<u16>>,
    /// Optional resident-set budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rss_bytes: Option<u64>,
    /// Placement must never participate in capability, zone, or sandbox authorization.
    pub security_influence: bool,
}

impl LocalPlacementPlan {
    /// Serialize this plan as one JSONL line.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the plan cannot be serialized.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Controller for capacity-aware local connector placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPlacementController {
    /// Existing host backpressure model used for red/yellow admission.
    pub backpressure: BackpressureController,
}

impl LocalPlacementController {
    /// Build a controller with the default host backpressure model.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backpressure: BackpressureController::new(BackpressureControllerConfig::default()),
        }
    }

    /// Plan a single connector launch.
    #[must_use]
    pub fn plan_launch(
        &self,
        request: &LocalPlacementRequest,
        pressure: &LocalPlacementPressureSnapshot,
    ) -> LocalPlacementPlan {
        let pressure_decision = self.pressure_decision(request, pressure);
        let pressure_verdict = pressure_decision
            .as_ref()
            .map_or(PlacementPressureVerdict::Unavailable, |decision| {
                PlacementPressureVerdict::from_action(decision.action)
            });
        let selected_lane = request.hint.lane(request.operation_class);
        let mut queue_wait_ms = request.queue_wait_ms;
        if pressure_verdict == PlacementPressureVerdict::Yellow
            && request.operation_class.is_bulk_like()
        {
            queue_wait_ms = queue_wait_ms.max(5);
        }
        let admitted = placement_admits(request.operation_class, pressure_verdict);
        let no_op_reason = affinity_no_op_reason(&request.hint);

        LocalPlacementPlan {
            event: PLACEMENT_EVIDENCE_EVENT.to_string(),
            bead_id: LOCAL_PLACEMENT_BEAD.to_string(),
            connector_id: request.connector_id.clone(),
            operation_class: request.operation_class,
            hint_class: request.hint.class(request.operation_class),
            selected_lane,
            admitted,
            affinity_applied: false,
            no_op_reason,
            pressure_verdict,
            pressure_state: pressure_decision
                .as_ref()
                .map(|decision| decision.state.as_str().to_string()),
            pressure_action: pressure_decision
                .as_ref()
                .map(|decision| decision.action.as_str().to_string()),
            pressure_replay_matches: pressure_decision
                .as_ref()
                .map(BackpressureDecision::replay_matches),
            queue_wait_ms,
            preferred_cpu_set: request.hint.preferred_cpu_set.clone(),
            max_rss_bytes: request.hint.max_rss_bytes,
            security_influence: false,
        }
    }

    /// Plan a deterministic batch, ordered by lane priority and connector id.
    #[must_use]
    pub fn plan_batch(
        &self,
        requests: &[LocalPlacementRequest],
        pressure: &LocalPlacementPressureSnapshot,
        immediate_slots: usize,
    ) -> Vec<LocalPlacementPlan> {
        let mut ordered = requests.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.hint
                .lane(left.operation_class)
                .rank()
                .cmp(&right.hint.lane(right.operation_class).rank())
                .then_with(|| left.connector_id.cmp(&right.connector_id))
        });

        ordered
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let mut plan = self.plan_launch(request, pressure);
                if plan.admitted && index >= immediate_slots {
                    let queued_slots = index.saturating_sub(immediate_slots).saturating_add(1);
                    let queued_wait_ms = u64::try_from(queued_slots)
                        .unwrap_or(u64::MAX / 5)
                        .saturating_mul(5);
                    plan.queue_wait_ms = plan.queue_wait_ms.max(queued_wait_ms);
                }
                plan
            })
            .collect()
    }

    fn pressure_decision(
        &self,
        request: &LocalPlacementRequest,
        pressure: &LocalPlacementPressureSnapshot,
    ) -> Option<BackpressureDecision> {
        match pressure {
            LocalPlacementPressureSnapshot::Decision { decision } => Some((**decision).clone()),
            LocalPlacementPressureSnapshot::Available {
                telemetry,
                calibration,
            } => Some(self.backpressure.decide(BackpressureControllerInput::new(
                format!("fcp.host.placement/{}", request.connector_id),
                request.operation_class.request_priority(),
                *telemetry,
                *calibration,
            ))),
            LocalPlacementPressureSnapshot::Unavailable { .. } => None,
        }
    }
}

impl Default for LocalPlacementController {
    fn default() -> Self {
        Self::new()
    }
}

const fn placement_admits(
    operation_class: PlacementOperationClass,
    verdict: PlacementPressureVerdict,
) -> bool {
    match verdict {
        PlacementPressureVerdict::Green | PlacementPressureVerdict::Yellow => true,
        PlacementPressureVerdict::Red | PlacementPressureVerdict::Unavailable => {
            matches!(operation_class, PlacementOperationClass::LifecycleCritical)
        }
    }
}

const fn affinity_no_op_reason(hint: &PlacementHint) -> PlacementAffinityNoOpReason {
    match &hint.preferred_cpu_set {
        None => PlacementAffinityNoOpReason::NotRequested,
        Some(cpu_set) if cpu_set.is_empty() => PlacementAffinityNoOpReason::EmptyPreferredCpuSet,
        Some(_) => PlacementAffinityNoOpReason::UnsupportedPlatform,
    }
}

fn normalize_placement_label(label: &str) -> String {
    label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn label_has_any(label: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| label.contains(needle))
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Snapshot/Resume Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Stable JSONL schema for connector sandbox snapshot/resume spike evidence.
pub const SNAPSHOT_RESUME_SCHEMA_VERSION: &str = "sandbox-snapshot-resume/v1";
/// Owning bead for snapshot/resume spike evidence.
pub const SNAPSHOT_RESUME_BEAD: &str = "flywheel_connectors-k3zfl.12";

/// Snapshot/resume startup strategy requested for a connector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotResumeStrategy {
    /// Do not use persisted sandbox snapshots.
    #[default]
    Disabled,
    /// Restore a WASI/runtime snapshot after rechecking host-side bindings.
    WasmtimeSnapshot,
    /// Reuse copy-on-write pages from a fork/zygote parent.
    CowFork,
}

/// Explicit snapshot/resume configuration for connector startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorSnapshotResumeConfig {
    /// Which snapshot strategy to use.
    pub strategy: SnapshotResumeStrategy,
    /// Maximum age for a candidate snapshot before on-demand fallback.
    pub max_age: Duration,
    /// Maximum wait while checking out a snapshot.
    pub checkout_timeout: Duration,
}

impl Default for ConnectorSnapshotResumeConfig {
    fn default() -> Self {
        Self {
            strategy: SnapshotResumeStrategy::Disabled,
            max_age: Duration::ZERO,
            checkout_timeout: Duration::ZERO,
        }
    }
}

impl ConnectorSnapshotResumeConfig {
    /// Build a WASI/runtime snapshot configuration.
    #[must_use]
    pub const fn wasmtime_snapshot(max_age: Duration, checkout_timeout: Duration) -> Self {
        Self {
            strategy: SnapshotResumeStrategy::WasmtimeSnapshot,
            max_age,
            checkout_timeout,
        }
    }

    /// Build a copy-on-write fork configuration.
    #[must_use]
    pub const fn cow_fork(max_age: Duration, checkout_timeout: Duration) -> Self {
        Self {
            strategy: SnapshotResumeStrategy::CowFork,
            max_age,
            checkout_timeout,
        }
    }

    /// Validate the snapshot configuration before it can influence startup.
    ///
    /// # Errors
    ///
    /// Returns a [`SnapshotResumeConfigError`] when the requested strategy would
    /// be unsafe or internally inconsistent.
    pub const fn validate(&self) -> Result<(), SnapshotResumeConfigError> {
        match self.strategy {
            SnapshotResumeStrategy::Disabled => Ok(()),
            SnapshotResumeStrategy::CowFork => {
                Err(SnapshotResumeConfigError::CowForkRequiresSecurityProof)
            }
            SnapshotResumeStrategy::WasmtimeSnapshot => {
                if self.max_age.is_zero() {
                    return Err(SnapshotResumeConfigError::MaxAgeZero);
                }
                if self.checkout_timeout.is_zero() {
                    return Err(SnapshotResumeConfigError::CheckoutTimeoutZero);
                }
                Ok(())
            }
        }
    }

    /// Decide whether a snapshot can be resumed for an invocation.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn decide_resume(&self, observation: &SnapshotResumeObservation) -> SnapshotResumeDecision {
        if let Err(error) = self.validate() {
            return match error {
                SnapshotResumeConfigError::CowForkRequiresSecurityProof => {
                    SnapshotResumeDecision::RejectUnsafe {
                        reason: SnapshotUnsafeReason::CowForkWithoutSecurityProof,
                    }
                }
                SnapshotResumeConfigError::MaxAgeZero
                | SnapshotResumeConfigError::CheckoutTimeoutZero => {
                    SnapshotResumeDecision::FallbackOnDemand {
                        reason: SnapshotFallbackReason::InvalidConfig,
                    }
                }
            };
        }

        if self.strategy == SnapshotResumeStrategy::Disabled {
            return SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::NotConfigured,
            };
        }

        if observation.platform == SnapshotPlatformState::Unsupported {
            return SnapshotResumeDecision::SkipUnsupported {
                reason: SnapshotSkipReason::PlatformUnsupported,
            };
        }

        match observation.snapshot_state {
            SnapshotResumeState::Disabled => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::NotConfigured,
                };
            }
            SnapshotResumeState::EmptySnapshotStore => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::EmptySnapshotStore,
                };
            }
            SnapshotResumeState::WarmCandidate | SnapshotResumeState::Restored => {}
            SnapshotResumeState::StaleManifest => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::StaleManifest,
                };
            }
            SnapshotResumeState::RevokedCapability => {
                return SnapshotResumeDecision::RejectUnsafe {
                    reason: SnapshotUnsafeReason::RevokedCapability,
                };
            }
            SnapshotResumeState::CrashBeforeCheckout => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::CrashBeforeCheckout,
                };
            }
            SnapshotResumeState::ConcurrentStartup => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::ConcurrentStartup,
                };
            }
            SnapshotResumeState::UnsupportedPlatform => {
                return SnapshotResumeDecision::SkipUnsupported {
                    reason: SnapshotSkipReason::PlatformUnsupported,
                };
            }
            SnapshotResumeState::Rejected => {
                return SnapshotResumeDecision::RejectUnsafe {
                    reason: SnapshotUnsafeReason::SnapshotMarkedRejected,
                };
            }
        }

        match observation.manifest {
            PrewarmManifestState::Current => {}
            PrewarmManifestState::Missing => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::MissingManifestHash,
                };
            }
            PrewarmManifestState::Stale => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::StaleManifest,
                };
            }
        }

        if observation.zone_binding == PrewarmZoneBinding::Missing {
            return SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::MissingZoneBinding,
            };
        }

        match observation.capability {
            SnapshotCapabilityState::Bound => {}
            SnapshotCapabilityState::Missing => {
                return SnapshotResumeDecision::FallbackOnDemand {
                    reason: SnapshotFallbackReason::MissingCapabilityBinding,
                };
            }
            SnapshotCapabilityState::Revoked => {
                return SnapshotResumeDecision::RejectUnsafe {
                    reason: SnapshotUnsafeReason::RevokedCapability,
                };
            }
        }

        if observation.sandbox == PrewarmSandboxState::LimitsUnavailable {
            return SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::SandboxLimitsUnavailable,
            };
        }

        if observation.credential == PrewarmCredentialState::MaterialLoaded {
            return SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::CredentialMaterialLoaded,
            };
        }

        if observation.snapshot_age > self.max_age {
            return SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::SnapshotTooOld,
            };
        }

        if let Some(exit) = &observation.previous_exit
            && !exit.is_clean()
        {
            return SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::CrashBeforeCheckout,
            };
        }

        if observation.proof == SnapshotSecurityProofState::Absent {
            return SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::SnapshotResumeProofUnavailable,
            };
        }

        SnapshotResumeDecision::AdmitSnapshot {
            snapshot_state: SnapshotResumeState::Restored,
        }
    }
}

/// Why a snapshot/resume configuration is invalid.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotResumeConfigError {
    /// Copy-on-write fork reuse lacks the required security proof.
    CowForkRequiresSecurityProof,
    /// Snapshot candidates need a bounded lifetime.
    MaxAgeZero,
    /// Snapshot checkout needs a bounded wait.
    CheckoutTimeoutZero,
}

impl std::fmt::Display for SnapshotResumeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CowForkRequiresSecurityProof => {
                f.write_str("copy-on-write snapshot resume requires a security proof")
            }
            Self::MaxAgeZero => f.write_str("snapshot max_age must be greater than zero"),
            Self::CheckoutTimeoutZero => {
                f.write_str("snapshot checkout_timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for SnapshotResumeConfigError {}

/// Snapshot store or checkout state recorded in snapshot/resume evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotResumeState {
    /// Snapshot/resume is disabled.
    Disabled,
    /// Snapshot store had no eligible candidate.
    EmptySnapshotStore,
    /// Snapshot store had a warm candidate.
    WarmCandidate,
    /// Snapshot candidate was restored after all safety gates passed.
    Restored,
    /// Snapshot manifest hash did not match the current connector manifest.
    StaleManifest,
    /// Snapshot capability binding was revoked.
    RevokedCapability,
    /// Snapshot checkout observed a prior crash marker.
    CrashBeforeCheckout,
    /// Concurrent swarm startup contended for the same snapshot.
    ConcurrentStartup,
    /// Platform cannot support the configured snapshot mode.
    UnsupportedPlatform,
    /// Snapshot metadata was explicitly rejected.
    Rejected,
}

/// Capability binding state observed for a snapshot candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCapabilityState {
    /// Snapshot has a current capability binding proof.
    Bound,
    /// Snapshot lacks a usable capability binding proof.
    Missing,
    /// Snapshot capability binding has been revoked.
    Revoked,
}

/// Runtime/platform support state observed for snapshot checkout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPlatformState {
    /// Platform/runtime reports snapshot support.
    Supported,
    /// Platform/runtime does not support snapshot restore.
    Unsupported,
}

/// Security proof state for a snapshot candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSecurityProofState {
    /// The host has not verified a snapshot/resume security proof.
    Absent,
    /// The host verified manifest, zone, capability, sandbox, and credential gates.
    Present,
}

/// Credential mode recorded in snapshot/resume evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCredentialMode {
    /// Credential access remains deferred until after host admission.
    Deferred,
    /// Credential material was observed and is represented only as redacted state.
    RedactedMaterialPresent,
}

/// Live observation used to decide whether a snapshot is safe to resume.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotResumeObservation {
    /// Snapshot store or checkout state.
    pub snapshot_state: SnapshotResumeState,
    /// Manifest freshness for the candidate snapshot.
    pub manifest: PrewarmManifestState,
    /// Zone binding state for the candidate snapshot.
    pub zone_binding: PrewarmZoneBinding,
    /// Capability binding state for the candidate snapshot.
    pub capability: SnapshotCapabilityState,
    /// Sandbox limit state for the candidate snapshot.
    pub sandbox: PrewarmSandboxState,
    /// Credential loading state for the candidate snapshot.
    pub credential: PrewarmCredentialState,
    /// Runtime/platform support state.
    pub platform: SnapshotPlatformState,
    /// Snapshot/resume security proof state.
    pub proof: SnapshotSecurityProofState,
    /// Age of the candidate snapshot.
    pub snapshot_age: Duration,
    /// Dirty copy-on-write pages reported by the runtime, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cow_dirty_pages: Option<u64>,
    /// Exit observed before checkout, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_exit: Option<ProcessExit>,
}

/// Decision produced for a snapshot/resume checkout attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SnapshotResumeDecision {
    /// Admit and restore the snapshot.
    AdmitSnapshot {
        /// Snapshot state to record in structured evidence.
        snapshot_state: SnapshotResumeState,
    },
    /// Fall back to conservative on-demand startup.
    FallbackOnDemand {
        /// Why snapshot/resume was not used.
        reason: SnapshotFallbackReason,
    },
    /// Reject the snapshot because it would violate a security invariant.
    RejectUnsafe {
        /// Why the snapshot is unsafe.
        reason: SnapshotUnsafeReason,
    },
    /// Skip the scenario because the current platform cannot provide support.
    SkipUnsupported {
        /// Why the scenario was skipped.
        reason: SnapshotSkipReason,
    },
}

impl SnapshotResumeDecision {
    /// Whether this decision admits a snapshot restore.
    #[must_use]
    pub const fn admits_resume(&self) -> bool {
        matches!(self, Self::AdmitSnapshot { .. })
    }

    /// Coarse action label for JSONL evidence.
    #[must_use]
    pub const fn action_label(&self) -> &'static str {
        match self {
            Self::AdmitSnapshot { .. } => "admit_snapshot",
            Self::FallbackOnDemand { .. } => "fallback_on_demand",
            Self::RejectUnsafe { .. } => "reject_unsafe",
            Self::SkipUnsupported { .. } => "skip_unsupported",
        }
    }

    /// Conservative fallback reason label, when any.
    #[must_use]
    pub const fn fallback_reason_label(&self) -> Option<&'static str> {
        match self {
            Self::FallbackOnDemand { reason } => Some(reason.as_str()),
            Self::AdmitSnapshot { .. }
            | Self::RejectUnsafe { .. }
            | Self::SkipUnsupported { .. } => None,
        }
    }

    /// Unsafe rejection reason label, when any.
    #[must_use]
    pub const fn rejection_reason_label(&self) -> Option<&'static str> {
        match self {
            Self::RejectUnsafe { reason } => Some(reason.as_str()),
            Self::AdmitSnapshot { .. }
            | Self::FallbackOnDemand { .. }
            | Self::SkipUnsupported { .. } => None,
        }
    }

    /// Unsupported-platform skip reason label, when any.
    #[must_use]
    pub const fn skip_reason_label(&self) -> Option<&'static str> {
        match self {
            Self::SkipUnsupported { reason } => Some(reason.as_str()),
            Self::AdmitSnapshot { .. }
            | Self::FallbackOnDemand { .. }
            | Self::RejectUnsafe { .. } => None,
        }
    }
}

/// Conservative fallback reason for an on-demand connector startup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotFallbackReason {
    /// Snapshot/resume is disabled.
    NotConfigured,
    /// Configuration is invalid.
    InvalidConfig,
    /// No snapshot candidate is available.
    EmptySnapshotStore,
    /// The snapshot did not capture a manifest hash.
    MissingManifestHash,
    /// The snapshot manifest hash does not match the current manifest.
    StaleManifest,
    /// The snapshot is not bound to the target zone.
    MissingZoneBinding,
    /// The snapshot lacks a current capability binding.
    MissingCapabilityBinding,
    /// Sandbox limits are unavailable or unverified.
    SandboxLimitsUnavailable,
    /// The snapshot exceeded the configured maximum age.
    SnapshotTooOld,
    /// The snapshot crashed before checkout.
    CrashBeforeCheckout,
    /// Concurrent startup contention required on-demand activation.
    ConcurrentStartup,
}

impl SnapshotFallbackReason {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::InvalidConfig => "invalid_config",
            Self::EmptySnapshotStore => "empty_snapshot_store",
            Self::MissingManifestHash => "missing_manifest_hash",
            Self::StaleManifest => "stale_manifest",
            Self::MissingZoneBinding => "missing_zone_binding",
            Self::MissingCapabilityBinding => "missing_capability_binding",
            Self::SandboxLimitsUnavailable => "sandbox_limits_unavailable",
            Self::SnapshotTooOld => "snapshot_too_old",
            Self::CrashBeforeCheckout => "crash_before_checkout",
            Self::ConcurrentStartup => "concurrent_startup",
        }
    }
}

/// Unsafe snapshot rejection reason.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotUnsafeReason {
    /// Copy-on-write fork reuse was requested without a security proof.
    CowForkWithoutSecurityProof,
    /// Snapshot restore was requested without a complete security proof.
    SnapshotResumeProofUnavailable,
    /// Snapshot metadata marked the entry as rejected before checkout.
    SnapshotMarkedRejected,
    /// The snapshot already loaded credential material.
    CredentialMaterialLoaded,
    /// The snapshot capability binding has been revoked.
    RevokedCapability,
}

impl SnapshotUnsafeReason {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::CowForkWithoutSecurityProof => "cow_fork_without_security_proof",
            Self::SnapshotResumeProofUnavailable => "snapshot_resume_proof_unavailable",
            Self::SnapshotMarkedRejected => "snapshot_marked_rejected",
            Self::CredentialMaterialLoaded => "credential_material_loaded",
            Self::RevokedCapability => "revoked_capability",
        }
    }
}

/// Unsupported-platform snapshot skip reason.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSkipReason {
    /// Runtime/platform cannot support snapshot restore.
    PlatformUnsupported,
}

impl SnapshotSkipReason {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformUnsupported => "platform_unsupported",
        }
    }
}

/// Input object for [`SnapshotResumeEvidence::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotResumeEvidenceInput {
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Connector identifier.
    pub connector_id: String,
    /// Manifest hash associated with the snapshot candidate.
    pub manifest_hash: Option<String>,
    /// Zone requested by checkout.
    pub zone: String,
    /// Snapshot state recorded for the checkout.
    pub snapshot_state: SnapshotResumeState,
    /// Dirty copy-on-write pages, when reported by the runtime.
    pub cow_dirty_pages: Option<u64>,
    /// Activation latency in milliseconds, when measured.
    pub activation_latency_ms: Option<u64>,
    /// Resident set size observed for the connector sandbox, when measured.
    pub memory_rss_bytes: Option<u64>,
    /// Sandbox profile requested by the connector fixture.
    pub sandbox_profile: String,
    /// Credential handling mode, redacted to a coarse class.
    pub credential_mode: SnapshotCredentialMode,
    /// Cleanup result recorded for the snapshot or fallback path.
    pub cleanup_result: String,
    /// Final snapshot/resume decision.
    pub decision: SnapshotResumeDecision,
}

/// Structured snapshot/resume evidence suitable for JSONL proof logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotResumeEvidence {
    /// Stable schema version.
    pub schema_version: String,
    /// Bead that owns this evidence contract.
    pub bead_id: String,
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Connector identifier.
    pub connector_id: String,
    /// Host boundary that made the resume decision.
    pub host_boundary: String,
    /// Manifest hash associated with the snapshot candidate.
    pub manifest_hash: Option<String>,
    /// Zone requested by checkout.
    pub zone: String,
    /// Snapshot state recorded for the checkout.
    pub snapshot_state: SnapshotResumeState,
    /// Coarse checkout decision label for JSONL logs.
    pub admission_decision: String,
    /// Whether the decision admits a snapshot restore.
    pub resume_checkout: bool,
    /// Dirty copy-on-write pages, when reported by the runtime.
    pub cow_dirty_pages: Option<u64>,
    /// Activation latency in milliseconds, when measured.
    pub activation_latency_ms: Option<u64>,
    /// Resident set size observed for the connector sandbox, when measured.
    pub memory_rss_bytes: Option<u64>,
    /// Sandbox profile requested by the connector fixture.
    pub sandbox_profile: String,
    /// Credential handling mode, redacted to a coarse class.
    pub credential_mode: SnapshotCredentialMode,
    /// Conservative fallback reason, when any.
    pub fallback_reason: Option<String>,
    /// Unsafe rejection reason, when any.
    pub rejection_reason: Option<String>,
    /// Unsupported-platform skip reason, when any.
    pub skip_reason: Option<String>,
    /// Cleanup result recorded for the snapshot or fallback path.
    pub cleanup_result: String,
    /// Operator-facing guidance for the decision.
    pub operator_guidance: String,
    /// Final snapshot/resume decision.
    pub decision: SnapshotResumeDecision,
}

impl SnapshotResumeEvidence {
    /// Build redaction-safe snapshot/resume evidence.
    #[must_use]
    pub fn new(input: SnapshotResumeEvidenceInput) -> Self {
        Self {
            schema_version: SNAPSHOT_RESUME_SCHEMA_VERSION.to_string(),
            bead_id: SNAPSHOT_RESUME_BEAD.to_string(),
            scenario_id: input.scenario_id,
            connector_id: input.connector_id,
            host_boundary: "fcp-host::supervisor::ConnectorSnapshotResumeConfig::decide_resume"
                .to_string(),
            manifest_hash: input.manifest_hash,
            zone: input.zone,
            snapshot_state: input.snapshot_state,
            admission_decision: input.decision.action_label().to_string(),
            resume_checkout: input.decision.admits_resume(),
            cow_dirty_pages: input.cow_dirty_pages,
            activation_latency_ms: input.activation_latency_ms,
            memory_rss_bytes: input.memory_rss_bytes,
            sandbox_profile: input.sandbox_profile,
            credential_mode: input.credential_mode,
            fallback_reason: input.decision.fallback_reason_label().map(str::to_string),
            rejection_reason: input.decision.rejection_reason_label().map(str::to_string),
            skip_reason: input.decision.skip_reason_label().map(str::to_string),
            cleanup_result: redact_snapshot_evidence_text(&input.cleanup_result),
            operator_guidance: snapshot_operator_guidance(&input.decision),
            decision: input.decision,
        }
    }

    /// Serialize this proof record as one JSONL line.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if serde cannot encode the record.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

fn snapshot_operator_guidance(decision: &SnapshotResumeDecision) -> String {
    match decision {
        SnapshotResumeDecision::AdmitSnapshot { .. } => {
            "snapshot restore admitted only after manifest, zone, capability, sandbox, and credential rebinding proofs passed".to_string()
        }
        SnapshotResumeDecision::FallbackOnDemand { reason } => format!(
            "snapshot resume fell back to on-demand activation because {}; keep connector startup on the normal enforcement path",
            reason.as_str()
        ),
        SnapshotResumeDecision::RejectUnsafe { reason } => format!(
            "snapshot resume was rejected because {}; do not enable snapshot reuse until the missing proof is available",
            reason.as_str()
        ),
        SnapshotResumeDecision::SkipUnsupported { reason } => format!(
            "snapshot resume scenario skipped because {}; use on-demand activation on this platform",
            reason.as_str()
        ),
    }
}

fn redact_snapshot_evidence_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if ["token", "secret", "password", "bearer", "private_key"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart Event
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a restart event.
#[derive(Debug, Clone)]
pub struct RestartEvent {
    /// When the restart occurred.
    pub timestamp: Instant,
    /// How the previous process exited.
    pub previous_exit: ProcessExit,
    /// Which restart attempt this is (1-based).
    pub attempt: u32,
    /// Backoff delay applied before this restart.
    pub backoff_delay: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// Exponential Backoff
// ─────────────────────────────────────────────────────────────────────────────

/// Exponential backoff calculator with configurable parameters.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    multiplier: f64,
    attempt: u32,
}

impl ExponentialBackoff {
    /// Create a new backoff calculator.
    #[must_use]
    pub fn new(initial: Duration, max: Duration, multiplier: f64) -> Self {
        let initial = initial.min(max);
        Self {
            initial,
            max,
            multiplier: if multiplier < 1.0 { 2.0 } else { multiplier },
            attempt: 0,
        }
    }

    /// Create from a supervisor config.
    #[must_use]
    pub fn from_config(config: &SupervisorConfig) -> Self {
        Self::new(
            config.initial_backoff,
            config.max_backoff,
            config.backoff_multiplier,
        )
    }

    /// Get the next backoff duration, advancing the attempt counter.
    #[must_use]
    pub fn next_backoff(&mut self) -> Duration {
        let delay = self.current_delay();
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    /// Get the current delay without advancing.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn current_delay(&self) -> Duration {
        if self.attempt == 0 || self.initial.is_zero() {
            return self.initial;
        }
        let factor = self
            .multiplier
            .powi(i32::try_from(self.attempt).unwrap_or(i32::MAX));
        let initial_ms = self.initial.as_millis() as f64;
        let max_ms = self.max.as_millis() as f64;
        let delay_ms = (initial_ms * factor).min(max_ms).max(0.0);

        if delay_ms.is_nan() || delay_ms.is_infinite() {
            return self.max;
        }

        let capped = Duration::from_millis(delay_ms as u64);
        capped.min(self.max)
    }

    /// Reset the backoff counter.
    pub const fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Current attempt count.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempt
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks restart events within a sliding window to enforce limits.
#[derive(Debug, Clone)]
pub struct RestartTracker {
    config: SupervisorConfig,
    history: VecDeque<RestartEvent>,
    backoff: ExponentialBackoff,
    total_restarts: usize,
}

impl RestartTracker {
    /// Create a new tracker with the given configuration.
    #[must_use]
    pub fn new(config: SupervisorConfig) -> Self {
        let backoff = ExponentialBackoff::from_config(&config);
        Self {
            config,
            history: VecDeque::new(),
            backoff,
            total_restarts: 0,
        }
    }

    /// Evaluate whether a restart should be attempted for the given exit.
    ///
    /// Returns `Ok(delay)` if a restart should be attempted after the given delay,
    /// or `Err(reason)` if the process should not be restarted.
    ///
    /// # Errors
    ///
    /// Returns `RestartDenied::PolicyDenied` if the restart policy does not allow
    /// restart for this exit type, or `RestartDenied::MaxRestartsExceeded` if the
    /// maximum number of restarts within the window has been reached.
    pub fn evaluate_restart(
        &mut self,
        exit: &ProcessExit,
        now: Instant,
    ) -> Result<Duration, RestartDenied> {
        // Check policy first.
        if !self.config.restart_policy.should_restart(exit) {
            return Err(RestartDenied::PolicyDenied);
        }

        // Prune events outside the window.
        if let Some(window_start) = now.checked_sub(self.config.restart_window) {
            while self
                .history
                .front()
                .is_some_and(|event| event.timestamp < window_start)
            {
                self.history.pop_front();
            }
        }

        // Check restart count within window.
        let restarts_in_window = u32::try_from(self.history.len()).unwrap_or(u32::MAX);
        if restarts_in_window >= self.config.max_restarts {
            return Err(RestartDenied::MaxRestartsExceeded {
                count: restarts_in_window,
                window: self.config.restart_window,
            });
        }

        // Calculate backoff delay.
        let delay = self.backoff.next_backoff();
        let attempt = restarts_in_window + 1;

        // Record the restart event.
        self.history.push_back(RestartEvent {
            timestamp: now,
            previous_exit: exit.clone(),
            attempt,
            backoff_delay: delay,
        });
        self.total_restarts = self.total_restarts.saturating_add(1);

        Ok(delay)
    }

    /// Record a successful start, resetting the backoff.
    pub const fn record_successful_start(&mut self) {
        self.backoff.reset();
    }

    /// Total number of restarts ever recorded, including events pruned from history.
    #[must_use]
    pub const fn total_restarts(&self) -> usize {
        self.total_restarts
    }

    /// Restarts within the current window.
    #[must_use]
    pub fn restarts_in_window(&self, now: Instant) -> u32 {
        let window_start = now.checked_sub(self.config.restart_window);
        u32::try_from(
            self.history
                .iter()
                .filter(|event| window_start.is_none_or(|start| event.timestamp >= start))
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Get the restart history.
    #[must_use]
    pub const fn history(&self) -> &VecDeque<RestartEvent> {
        &self.history
    }

    /// Get the supervisor configuration.
    #[must_use]
    pub const fn config(&self) -> &SupervisorConfig {
        &self.config
    }
}

/// Reason why a restart was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDenied {
    /// Restart policy does not allow restart for this exit type.
    PolicyDenied,
    /// Maximum restarts within the window have been exceeded.
    MaxRestartsExceeded {
        /// Number of restarts in the window.
        count: u32,
        /// The window duration.
        window: Duration,
    },
}

impl std::fmt::Display for RestartDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyDenied => write!(f, "restart policy denied"),
            Self::MaxRestartsExceeded { count, window } => {
                write!(
                    f,
                    "max restarts exceeded: {count} restarts in {}s window",
                    window.as_secs()
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown Coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the graceful shutdown sequence for a process.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    /// Timeout for graceful shutdown before escalating to SIGKILL.
    graceful_timeout: Duration,
    /// Current phase of shutdown.
    phase: ShutdownPhase,
}

/// Phase of the shutdown sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Not shutting down.
    NotStarted,
    /// SIGTERM sent, waiting for graceful exit.
    GracefulWait { sent_at: Instant },
    /// Graceful timeout expired, SIGKILL should be sent.
    ForceKill { escalated_at: Instant },
    /// Process has exited.
    Complete { exit: ProcessExit },
}

impl ShutdownCoordinator {
    /// Create a new coordinator with the given graceful timeout.
    #[must_use]
    pub const fn new(graceful_timeout: Duration) -> Self {
        Self {
            graceful_timeout,
            phase: ShutdownPhase::NotStarted,
        }
    }

    /// Start the graceful shutdown sequence.
    pub fn start_graceful(&mut self, now: Instant) {
        if self.phase == ShutdownPhase::NotStarted {
            self.phase = ShutdownPhase::GracefulWait { sent_at: now };
        }
    }

    /// Check whether it's time to escalate to SIGKILL.
    #[must_use]
    pub fn should_force_kill(&self, now: Instant) -> bool {
        match self.phase {
            ShutdownPhase::GracefulWait { sent_at } => {
                now.saturating_duration_since(sent_at) >= self.graceful_timeout
            }
            _ => false,
        }
    }

    /// Record that force kill has been sent.
    pub const fn record_force_kill(&mut self, now: Instant) {
        if matches!(self.phase, ShutdownPhase::GracefulWait { .. }) {
            self.phase = ShutdownPhase::ForceKill { escalated_at: now };
        }
    }

    /// Record that the process has exited.
    pub const fn record_exit(&mut self, exit: ProcessExit) {
        self.phase = ShutdownPhase::Complete { exit };
    }

    /// Current shutdown phase.
    #[must_use]
    pub const fn phase(&self) -> &ShutdownPhase {
        &self.phase
    }

    /// Whether shutdown is in progress.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        matches!(
            self.phase,
            ShutdownPhase::GracefulWait { .. } | ShutdownPhase::ForceKill { .. }
        )
    }

    /// Whether shutdown is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, ShutdownPhase::Complete { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check Scheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Schedules periodic health checks for a connector.
#[derive(Debug, Clone)]
pub struct HealthCheckScheduler {
    interval: Duration,
    timeout: Duration,
    last_check: Option<Instant>,
    consecutive_failures: u32,
    max_consecutive_failures: u32,
}

impl HealthCheckScheduler {
    /// Create a new scheduler from supervisor config.
    #[must_use]
    pub const fn new(interval: Duration, timeout: Duration) -> Self {
        Self {
            interval,
            timeout,
            last_check: None,
            consecutive_failures: 0,
            max_consecutive_failures: 3,
        }
    }

    /// Create with a custom failure threshold.
    #[must_use]
    pub const fn with_max_failures(mut self, max: u32) -> Self {
        self.max_consecutive_failures = max;
        self
    }

    /// Whether a health check is due now.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        self.last_check
            .is_none_or(|last| now.saturating_duration_since(last) >= self.interval)
    }

    /// Record a successful health check.
    pub const fn record_success(&mut self, now: Instant) {
        self.last_check = Some(now);
        self.consecutive_failures = 0;
    }

    /// Record a failed health check.
    pub const fn record_failure(&mut self, now: Instant) {
        self.last_check = Some(now);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Whether the connector should be considered unhealthy.
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        self.consecutive_failures >= self.max_consecutive_failures
    }

    /// Current consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Health check timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Time until next health check is due.
    #[must_use]
    pub fn time_until_next(&self, now: Instant) -> Duration {
        self.last_check.map_or(Duration::ZERO, |last| {
            self.interval
                .saturating_sub(now.saturating_duration_since(last))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Limits
// ─────────────────────────────────────────────────────────────────────────────

/// Resource limits for a supervised connector process.
///
/// These map to OS-level resource constraints (e.g. `setrlimit` on Unix).
/// All limits are optional — `None` means unlimited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum resident memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum CPU time in seconds (cumulative).
    pub cpu_seconds: Option<u64>,
    /// Maximum number of open file descriptors.
    pub max_fds: Option<u64>,
    /// Maximum number of child processes.
    pub max_processes: Option<u64>,
    /// Maximum file size in bytes that the process can create.
    pub max_file_size_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            cpu_seconds: None,
            max_fds: Some(1024),
            max_processes: Some(64),
            max_file_size_bytes: None,
        }
    }
}

impl ResourceLimits {
    /// Create unlimited resource limits (no constraints).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            memory_bytes: None,
            cpu_seconds: None,
            max_fds: None,
            max_processes: None,
            max_file_size_bytes: None,
        }
    }

    /// Whether any limits are set.
    #[must_use]
    pub const fn has_any_limits(&self) -> bool {
        self.memory_bytes.is_some()
            || self.cpu_seconds.is_some()
            || self.max_fds.is_some()
            || self.max_processes.is_some()
            || self.max_file_size_bytes.is_some()
    }

    /// Count how many limits are set.
    #[must_use]
    pub const fn active_limit_count(&self) -> u32 {
        let mut count = 0;
        if self.memory_bytes.is_some() {
            count += 1;
        }
        if self.cpu_seconds.is_some() {
            count += 1;
        }
        if self.max_fds.is_some() {
            count += 1;
        }
        if self.max_processes.is_some() {
            count += 1;
        }
        if self.max_file_size_bytes.is_some() {
            count += 1;
        }
        count
    }

    /// Merge with another set of limits, taking the stricter (lower) value for each.
    #[must_use]
    pub fn merge_strict(&self, other: &Self) -> Self {
        Self {
            memory_bytes: merge_option_min(self.memory_bytes, other.memory_bytes),
            cpu_seconds: merge_option_min(self.cpu_seconds, other.cpu_seconds),
            max_fds: merge_option_min(self.max_fds, other.max_fds),
            max_processes: merge_option_min(self.max_processes, other.max_processes),
            max_file_size_bytes: merge_option_min(
                self.max_file_size_bytes,
                other.max_file_size_bytes,
            ),
        }
    }
}

/// Merge two optional limits, taking the stricter (lower) value.
fn merge_option_min(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Snapshot of current resource usage for a process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// Current resident memory in bytes.
    pub memory_bytes: u64,
    /// Cumulative CPU time in milliseconds.
    pub cpu_millis: u64,
    /// Current open file descriptors.
    pub open_fds: u64,
    /// Current child process count.
    pub process_count: u64,
    /// Size in bytes of the largest file the process has created or is writing.
    pub file_size_bytes: u64,
}

impl ResourceUsage {
    /// Check which resource limits are violated, if any.
    #[must_use]
    pub fn violations(&self, limits: &ResourceLimits) -> Vec<ResourceViolation> {
        let mut violations = Vec::new();

        if let Some(limit) = limits.memory_bytes
            && self.memory_bytes > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::Memory,
                current: self.memory_bytes,
                limit,
            });
        }

        if let Some(limit) = limits.cpu_seconds {
            let cpu_limit_millis = limit.saturating_mul(1000);
            if self.cpu_millis > cpu_limit_millis {
                violations.push(ResourceViolation {
                    resource: ResourceKind::CpuTime,
                    current: self.cpu_millis.div_ceil(1000),
                    limit,
                });
            }
        }

        if let Some(limit) = limits.max_fds
            && self.open_fds > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::FileDescriptors,
                current: self.open_fds,
                limit,
            });
        }

        if let Some(limit) = limits.max_processes
            && self.process_count > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::Processes,
                current: self.process_count,
                limit,
            });
        }

        if let Some(limit) = limits.max_file_size_bytes
            && self.file_size_bytes > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::FileSize,
                current: self.file_size_bytes,
                limit,
            });
        }

        violations
    }

    /// Whether all resource usage is within the given limits.
    #[must_use]
    pub fn within_limits(&self, limits: &ResourceLimits) -> bool {
        self.violations(limits).is_empty()
    }

    /// Percentage of each limit consumed (0.0–1.0+). Returns None for unlimited.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self, limits: &ResourceLimits) -> ResourceUtilization {
        ResourceUtilization {
            memory: limits.memory_bytes.map(|l| {
                if l == 0 {
                    0.0
                } else {
                    self.memory_bytes as f64 / l as f64
                }
            }),
            cpu: limits.cpu_seconds.map(|l| {
                if l == 0 {
                    0.0
                } else {
                    (self.cpu_millis as f64 / 1000.0) / l as f64
                }
            }),
            fds: limits.max_fds.map(|l| {
                if l == 0 {
                    0.0
                } else {
                    self.open_fds as f64 / l as f64
                }
            }),
            processes: limits.max_processes.map(|l| {
                if l == 0 {
                    0.0
                } else {
                    self.process_count as f64 / l as f64
                }
            }),
            file_size: limits.max_file_size_bytes.map(|l| {
                if l == 0 {
                    0.0
                } else {
                    self.file_size_bytes as f64 / l as f64
                }
            }),
        }
    }
}

/// A specific resource limit violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceViolation {
    /// Which resource is violated.
    pub resource: ResourceKind,
    /// Current usage.
    pub current: u64,
    /// The limit that was exceeded.
    pub limit: u64,
}

impl std::fmt::Display for ResourceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} limit exceeded: {} > {} (limit)",
            self.resource, self.current, self.limit
        )
    }
}

/// Kind of resource being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Resident memory.
    Memory,
    /// Cumulative CPU time.
    CpuTime,
    /// Open file descriptors.
    FileDescriptors,
    /// Child processes.
    Processes,
    /// File size.
    FileSize,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::CpuTime => write!(f, "cpu_time"),
            Self::FileDescriptors => write!(f, "file_descriptors"),
            Self::Processes => write!(f, "processes"),
            Self::FileSize => write!(f, "file_size"),
        }
    }
}

/// Utilization percentages for each resource type.
#[derive(Debug, Clone)]
pub struct ResourceUtilization {
    /// Memory utilization (0.0–1.0+), None if unlimited.
    pub memory: Option<f64>,
    /// CPU utilization (0.0–1.0+), None if unlimited.
    pub cpu: Option<f64>,
    /// FD utilization (0.0–1.0+), None if unlimited.
    pub fds: Option<f64>,
    /// Process utilization (0.0–1.0+), None if unlimited.
    pub processes: Option<f64>,
    /// File size utilization (0.0–1.0+), None if unlimited.
    pub file_size: Option<f64>,
}

impl ResourceUtilization {
    /// The highest utilization across all tracked resources.
    #[must_use]
    pub fn max_utilization(&self) -> Option<f64> {
        [
            self.memory,
            self.cpu,
            self.fds,
            self.processes,
            self.file_size,
        ]
        .into_iter()
        .flatten()
        .reduce(f64::max)
    }

    /// Whether any resource is at or above the given threshold (e.g. 0.9 for 90%).
    #[must_use]
    pub fn any_above_threshold(&self, threshold: f64) -> bool {
        self.max_utilization().is_some_and(|max| max >= threshold)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks active connections for graceful shutdown draining.
///
/// During normal operation, connections are counted. When shutdown is initiated,
/// new connections are rejected and the system waits for in-flight connections
/// to complete before fully stopping.
#[derive(Debug)]
pub struct ConnectionTracker {
    active: std::sync::atomic::AtomicU32,
    draining: std::sync::atomic::AtomicBool,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    /// Create a new connection tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicU32::new(0),
            draining: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Try to acquire a connection slot. Returns `None` if draining.
    #[must_use]
    pub fn try_acquire(&self) -> Option<ConnectionGuard<'_>> {
        if self.draining.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        // Double-check after incrementing (avoid race with start_drain).
        if self.draining.load(std::sync::atomic::Ordering::Acquire) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return None;
        }
        Some(ConnectionGuard { tracker: self })
    }

    /// Current number of active connections.
    #[must_use]
    pub fn active_count(&self) -> u32 {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the tracker is in drain mode (rejecting new connections).
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Start draining — no new connections will be accepted.
    pub fn start_drain(&self) {
        self.draining
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether all connections have drained (draining + zero active).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.is_draining() && self.active_count() == 0
    }
}

/// RAII guard that decrements the active connection count on drop.
#[derive(Debug)]
pub struct ConnectionGuard<'a> {
    tracker: &'a ConnectionTracker,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.tracker
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::redundant_clone,
        reason = "clone-focused tests intentionally exercise Clone impls"
    )]

    use super::*;

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RestartPolicyGoldenVector {
        policy: RestartPolicyGoldenPolicy,
        crashes: Vec<RestartPolicyGoldenCrash>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RestartPolicyGoldenPolicy {
        max_restarts: u32,
        backoff_base_ms: u64,
        backoff_max_ms: u64,
        backoff_multiplier: f64,
        window_seconds: u64,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RestartPolicyGoldenCrash {
        at_ms: u64,
        restart: bool,
        delay_ms: Option<u64>,
        reason: Option<String>,
    }

    // ── ProcessExit ──

    #[test]
    fn clean_exit_is_clean() {
        let exit = ProcessExit::clean();
        assert!(exit.is_clean());
        assert!(!exit.is_signal_terminated());
    }

    #[test]
    fn exit_code_nonzero_is_not_clean() {
        let exit = ProcessExit::with_code(1);
        assert!(!exit.is_clean());
        assert!(!exit.is_signal_terminated());
    }

    #[test]
    fn signal_exit_is_signal_terminated() {
        let exit = ProcessExit::with_signal(9);
        assert!(!exit.is_clean());
        assert!(exit.is_signal_terminated());
    }

    #[test]
    fn exit_display_code() {
        assert_eq!(ProcessExit::with_code(42).to_string(), "exit code 42");
    }

    #[test]
    fn exit_display_signal() {
        assert_eq!(ProcessExit::with_signal(15).to_string(), "signal 15");
    }

    #[test]
    fn exit_display_both() {
        let exit = ProcessExit {
            code: Some(1),
            signal: Some(11),
        };
        assert_eq!(exit.to_string(), "exit code 1, signal 11");
    }

    #[test]
    fn exit_display_unknown() {
        let exit = ProcessExit {
            code: None,
            signal: None,
        };
        assert_eq!(exit.to_string(), "unknown exit");
    }

    // ── RestartPolicy ──

    #[test]
    fn always_restarts_on_clean_exit() {
        assert!(RestartPolicy::Always.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn always_restarts_on_crash() {
        assert!(RestartPolicy::Always.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn on_failure_does_not_restart_clean_exit() {
        assert!(!RestartPolicy::OnFailure.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn on_failure_restarts_nonzero_exit() {
        assert!(RestartPolicy::OnFailure.should_restart(&ProcessExit::with_code(1)));
    }

    #[test]
    fn on_failure_restarts_signal() {
        assert!(RestartPolicy::OnFailure.should_restart(&ProcessExit::with_signal(15)));
    }

    #[test]
    fn on_crash_does_not_restart_clean_exit() {
        assert!(!RestartPolicy::OnCrash.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn on_crash_does_not_restart_nonzero_exit() {
        assert!(!RestartPolicy::OnCrash.should_restart(&ProcessExit::with_code(1)));
    }

    #[test]
    fn on_crash_restarts_signal() {
        assert!(RestartPolicy::OnCrash.should_restart(&ProcessExit::with_signal(11)));
    }

    #[test]
    fn never_does_not_restart_anything() {
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::clean()));
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::with_code(1)));
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn default_policy_is_on_failure() {
        assert_eq!(RestartPolicy::default(), RestartPolicy::OnFailure);
    }

    // ── ProcessState ──

    #[test]
    fn starting_is_not_running_or_terminal() {
        let state = ProcessState::Starting {
            since: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "starting");
    }

    #[test]
    fn running_is_running_not_terminal() {
        let state = ProcessState::Running {
            pid: 1234,
            started_at: Instant::now(),
        };
        assert!(state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "running");
    }

    #[test]
    fn stopping_is_not_running_or_terminal() {
        let state = ProcessState::Stopping {
            reason: StopReason::Requested,
            since: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "stopping");
    }

    #[test]
    fn stopped_is_terminal() {
        let state = ProcessState::Stopped {
            exit: ProcessExit::clean(),
            stopped_at: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(state.is_terminal());
        assert_eq!(state.label(), "stopped");
    }

    #[test]
    fn failed_is_terminal() {
        let state = ProcessState::Failed {
            error: "boom".into(),
            failed_at: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(state.is_terminal());
        assert_eq!(state.label(), "failed");
    }

    // ── StopReason ──

    #[test]
    fn stop_reason_display() {
        assert_eq!(StopReason::Requested.to_string(), "requested");
        assert_eq!(StopReason::HostShutdown.to_string(), "host shutdown");
        assert_eq!(
            StopReason::HealthCheckFailed.to_string(),
            "health check failed"
        );
        assert_eq!(
            StopReason::ResourceLimitExceeded.to_string(),
            "resource limit exceeded"
        );
        assert_eq!(StopReason::Upgrade.to_string(), "upgrade");
    }

    // ── ExponentialBackoff ──

    #[test]
    fn backoff_starts_at_initial() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
    }

    #[test]
    fn backoff_doubles_each_attempt() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(200));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(400));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(800));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(2), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(500));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
    }

    #[test]
    fn backoff_reset_restarts_from_initial() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        let _ = backoff.next_backoff();
        let _ = backoff.next_backoff();
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
    }

    #[test]
    fn backoff_from_config() {
        let config = SupervisorConfig::default();
        let backoff = ExponentialBackoff::from_config(&config);
        assert_eq!(backoff.current_delay(), config.initial_backoff);
    }

    #[test]
    fn backoff_negative_multiplier_defaults_to_two() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), -1.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(200));
    }

    #[test]
    fn backoff_triple_multiplier() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 3.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(300));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(900));
    }

    // ── SupervisorConfig ──

    #[test]
    fn supervisor_config_default_values() {
        let config = SupervisorConfig::default();
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_mins(5));
        assert_eq!(config.health_check_interval, Duration::from_secs(30));
        assert_eq!(config.health_check_timeout, Duration::from_secs(10));
        assert_eq!(config.graceful_shutdown_timeout, Duration::from_secs(30));
        assert_eq!(config.initial_backoff, Duration::from_millis(500));
        assert_eq!(config.max_backoff, Duration::from_mins(1));
    }

    // ── ConnectorPrewarmConfig ──

    fn safe_prewarm_observation() -> PrewarmCheckoutObservation {
        PrewarmCheckoutObservation {
            pool_state: PrewarmPoolState::WarmHit,
            manifest: PrewarmManifestState::Current,
            zone_binding: PrewarmZoneBinding::Bound,
            sandbox: PrewarmSandboxState::LimitsActive,
            credential: PrewarmCredentialState::Deferred,
            health: PrewarmHealthState::Ready,
            entry_age: Duration::from_secs(5),
            previous_exit: None,
        }
    }

    #[test]
    fn prewarm_default_preserves_on_demand_startup() {
        let config = ConnectorPrewarmConfig::default();
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            config.decide_checkout(&safe_prewarm_observation()),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::NotConfigured
            }
        );
    }

    #[test]
    fn prewarm_rejects_zygote_without_security_proof() {
        let config = ConnectorPrewarmConfig {
            strategy: PrewarmStrategy::Zygote,
            min_idle: 1,
            max_idle: 1,
            max_age: Duration::from_secs(30),
            checkout_timeout: Duration::from_millis(50),
        };
        assert_eq!(
            config.validate(),
            Err(PrewarmConfigError::ZygoteRequiresSecurityProof)
        );
        assert_eq!(
            config.decide_checkout(&safe_prewarm_observation()),
            PrewarmCheckoutDecision::RejectUnsafe {
                reason: PrewarmUnsafeReason::ZygoteWithoutSecurityProof
            }
        );
    }

    #[test]
    fn prewarm_validates_pool_bounds() {
        assert_eq!(
            ConnectorPrewarmConfig::warm_pool(
                2,
                1,
                Duration::from_secs(30),
                Duration::from_secs(1)
            )
            .validate(),
            Err(PrewarmConfigError::MinIdleExceedsMaxIdle)
        );
        assert_eq!(
            ConnectorPrewarmConfig::warm_pool(
                0,
                0,
                Duration::from_secs(30),
                Duration::from_secs(1)
            )
            .validate(),
            Err(PrewarmConfigError::MaxIdleZero)
        );
        assert_eq!(
            ConnectorPrewarmConfig::warm_pool(0, 1, Duration::ZERO, Duration::from_secs(1))
                .validate(),
            Err(PrewarmConfigError::MaxAgeZero)
        );
        assert_eq!(
            ConnectorPrewarmConfig::warm_pool(0, 1, Duration::from_secs(30), Duration::ZERO)
                .validate(),
            Err(PrewarmConfigError::CheckoutTimeoutZero)
        );
    }

    #[test]
    fn prewarm_admits_only_safe_warm_entry() {
        let config = ConnectorPrewarmConfig::warm_pool(
            1,
            4,
            Duration::from_secs(30),
            Duration::from_secs(1),
        );
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            config.decide_checkout(&safe_prewarm_observation()),
            PrewarmCheckoutDecision::AdmitWarm {
                pool_state: PrewarmPoolState::WarmHit
            }
        );
        assert!(
            config
                .decide_checkout(&safe_prewarm_observation())
                .admits_warm_entry()
        );
    }

    #[test]
    fn prewarm_falls_back_when_pool_has_no_candidate() {
        let config = ConnectorPrewarmConfig::warm_pool(
            1,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
        );
        let mut observation = safe_prewarm_observation();
        observation.pool_state = PrewarmPoolState::Empty;
        assert_eq!(
            config.decide_checkout(&observation),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::EmptyPool
            }
        );
    }

    #[test]
    fn prewarm_falls_back_on_manifest_zone_and_sandbox_gaps() {
        let config = ConnectorPrewarmConfig::warm_pool(
            1,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
        );

        let mut missing_manifest = safe_prewarm_observation();
        missing_manifest.manifest = PrewarmManifestState::Missing;
        assert_eq!(
            config.decide_checkout(&missing_manifest),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::MissingManifestHash
            }
        );

        let mut stale_manifest = safe_prewarm_observation();
        stale_manifest.manifest = PrewarmManifestState::Stale;
        assert_eq!(
            config.decide_checkout(&stale_manifest),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::StaleManifest
            }
        );

        let mut missing_zone = safe_prewarm_observation();
        missing_zone.zone_binding = PrewarmZoneBinding::Missing;
        assert_eq!(
            config.decide_checkout(&missing_zone),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::MissingZoneBinding
            }
        );

        let mut sandbox_gap = safe_prewarm_observation();
        sandbox_gap.sandbox = PrewarmSandboxState::LimitsUnavailable;
        assert_eq!(
            config.decide_checkout(&sandbox_gap),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::SandboxLimitsUnavailable
            }
        );
    }

    #[test]
    fn prewarm_rejects_loaded_credential_material() {
        let config = ConnectorPrewarmConfig::warm_pool(
            1,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
        );
        let mut observation = safe_prewarm_observation();
        observation.credential = PrewarmCredentialState::MaterialLoaded;
        assert_eq!(
            config.decide_checkout(&observation),
            PrewarmCheckoutDecision::RejectUnsafe {
                reason: PrewarmUnsafeReason::CredentialMaterialLoaded
            }
        );
    }

    #[test]
    fn prewarm_falls_back_on_readiness_age_and_crash_history() {
        let config = ConnectorPrewarmConfig::warm_pool(
            1,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
        );

        let mut starting = safe_prewarm_observation();
        starting.health = PrewarmHealthState::Starting;
        assert_eq!(
            config.decide_checkout(&starting),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::WarmEntryStillStarting
            }
        );

        let mut failed = safe_prewarm_observation();
        failed.health = PrewarmHealthState::Failed;
        assert_eq!(
            config.decide_checkout(&failed),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::WarmEntryFailedHealth
            }
        );

        let mut stale = safe_prewarm_observation();
        stale.entry_age = Duration::from_secs(31);
        assert_eq!(
            config.decide_checkout(&stale),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::WarmEntryStale
            }
        );

        let mut crashed = safe_prewarm_observation();
        crashed.previous_exit = Some(ProcessExit::with_code(1));
        assert_eq!(
            config.decide_checkout(&crashed),
            PrewarmCheckoutDecision::FallbackOnDemand {
                reason: PrewarmFallbackReason::CrashBeforeCheckout
            }
        );
    }

    #[test]
    fn prewarm_config_serde_roundtrip() -> serde_json::Result<()> {
        let config =
            ConnectorPrewarmConfig::warm_pool(2, 8, Duration::from_mins(1), Duration::from_secs(2));
        let json = serde_json::to_string(&config)?;
        assert!(json.contains("\"strategy\":\"warm_pool\""));
        let parsed: ConnectorPrewarmConfig = serde_json::from_str(&json)?;
        assert_eq!(parsed, config);
        Ok(())
    }

    #[test]
    fn prewarm_checkout_evidence_serializes_redacted_operational_fields() -> serde_json::Result<()>
    {
        let evidence = PrewarmCheckoutEvidence {
            connector_id: "fcp.github:utility:1.0.0".to_string(),
            host_boundary: "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout"
                .to_string(),
            manifest_hash: Some("blake3:abc123".to_string()),
            zone: Some("z:project:alpha".to_string()),
            pool_state: PrewarmPoolState::WarmHit,
            pool_size: 4,
            admission_decision: "admit_warm".to_string(),
            warm_checkout: true,
            activation_latency_ms: Some(17),
            sandbox_layer: "wasi".to_string(),
            sandbox_profile: "strict".to_string(),
            sandbox_boundary: "fcp-sandbox::strict-profile-limits".to_string(),
            credential_state: PrewarmCredentialState::Deferred,
            rss_bytes: Some(96 * 1024 * 1024),
            process_count: 1,
            error_mapping: "ok".to_string(),
            cleanup_result: "verified".to_string(),
            decision: PrewarmCheckoutDecision::AdmitWarm {
                pool_state: PrewarmPoolState::WarmHit,
            },
        };
        let value = serde_json::to_value(&evidence)?;
        assert_eq!(
            value["host_boundary"],
            "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout"
        );
        assert_eq!(value["credential_state"], "deferred");
        assert_eq!(value["pool_size"], 4);
        assert_eq!(value["admission_decision"], "admit_warm");
        assert_eq!(value["warm_checkout"], true);
        assert_eq!(value["activation_latency_ms"], 17);
        assert_eq!(value["sandbox_profile"], "strict");
        assert_eq!(
            value["sandbox_boundary"],
            "fcp-sandbox::strict-profile-limits"
        );
        assert_eq!(value["rss_bytes"], 96 * 1024 * 1024);
        assert_eq!(value["error_mapping"], "ok");
        assert_eq!(value["cleanup_result"], "verified");
        assert!(!value.to_string().contains("secret"));
        Ok(())
    }

    // ── AdaptiveWarmPoolController ──

    fn adaptive_warm_pool_key(
        connector_id: &str,
        manifest_hash: &str,
        sandbox_profile: &str,
        zone: &str,
        credential_profile_class: &str,
    ) -> WarmPoolKey {
        WarmPoolKey::new(
            connector_id,
            manifest_hash,
            sandbox_profile,
            zone,
            credential_profile_class,
        )
    }

    fn adaptive_warm_pool_entry(
        connector_id: &str,
        idle_ms: u64,
        rss_bytes: u64,
    ) -> WarmPoolEntrySnapshot {
        WarmPoolEntrySnapshot::ready(
            adaptive_warm_pool_key(
                connector_id,
                "blake3:manifest-current",
                "strict",
                "z:project:alpha",
                "profile-prod-secret",
            ),
            idle_ms,
            rss_bytes,
        )
    }

    fn adaptive_warm_pool_normal_controller() -> AdaptiveWarmPoolController {
        AdaptiveWarmPoolController::new(AdaptiveWarmPoolConfig::new(4, 512 * 1024 * 1024))
    }

    #[test]
    fn adaptive_warm_pool_key_separates_manifest_sandbox_zone_and_credentials() {
        let base = adaptive_warm_pool_key(
            "fcp.github:utility:1.0.0",
            "blake3:manifest-a",
            "strict",
            "z:project:alpha",
            "credential-profile-a",
        );

        for variant in [
            adaptive_warm_pool_key(
                "fcp.github:utility:1.0.0",
                "blake3:manifest-b",
                "strict",
                "z:project:alpha",
                "credential-profile-a",
            ),
            adaptive_warm_pool_key(
                "fcp.github:utility:1.0.0",
                "blake3:manifest-a",
                "relaxed",
                "z:project:alpha",
                "credential-profile-a",
            ),
            adaptive_warm_pool_key(
                "fcp.github:utility:1.0.0",
                "blake3:manifest-a",
                "strict",
                "z:project:beta",
                "credential-profile-a",
            ),
            adaptive_warm_pool_key(
                "fcp.github:utility:1.0.0",
                "blake3:manifest-a",
                "strict",
                "z:project:alpha",
                "credential-profile-b",
            ),
        ] {
            assert_ne!(base, variant);
        }
    }

    #[test]
    fn adaptive_warm_pool_retains_only_current_ready_secret_free_entries() {
        let controller = adaptive_warm_pool_normal_controller();
        let ready = adaptive_warm_pool_entry("fcp.github:utility:1.0.0", 10, 8 * 1024);
        let mut failed_health = adaptive_warm_pool_entry("fcp.slack:utility:1.0.0", 20, 8 * 1024);
        failed_health.health = PrewarmHealthState::Failed;
        let mut stale_manifest = adaptive_warm_pool_entry("fcp.gmail:utility:1.0.0", 30, 8 * 1024);
        stale_manifest.manifest = PrewarmManifestState::Stale;
        let mut loaded_credential =
            adaptive_warm_pool_entry("fcp.discord:utility:1.0.0", 40, 8 * 1024);
        loaded_credential.credential = PrewarmCredentialState::MaterialLoaded;
        let mut leaked_context =
            adaptive_warm_pool_entry("fcp.telegram:utility:1.0.0", 50, 8 * 1024);
        leaked_context.retained_capability_token = true;

        let plan = controller.plan_retention(
            &[
                ready.clone(),
                failed_health,
                stale_manifest,
                loaded_credential,
                leaked_context,
            ],
            &WarmPoolPressureSnapshot::low_pressure(),
        );

        assert!(!plan.disabled);
        assert_eq!(plan.retained, vec![ready.key]);
        let reasons = plan
            .evictions
            .iter()
            .map(|eviction| eviction.reason)
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            vec![
                WarmPoolEvictionReason::DegradedHealth,
                WarmPoolEvictionReason::StaleManifest,
                WarmPoolEvictionReason::CredentialMaterialLoaded,
                WarmPoolEvictionReason::BookkeepingInconsistent,
            ]
        );
    }

    #[test]
    fn adaptive_warm_pool_disables_on_missing_pressure_model_with_redacted_evidence()
    -> serde_json::Result<()> {
        let controller = adaptive_warm_pool_normal_controller();
        let entry = adaptive_warm_pool_entry("fcp.github:utility:1.0.0", 10, 8 * 1024);
        let plan = controller.plan_retention(
            std::slice::from_ref(&entry),
            &WarmPoolPressureSnapshot::Unavailable {
                reason: "swarm pressure evidence unavailable".to_string(),
            },
        );

        assert!(plan.disabled);
        assert_eq!(
            plan.disabled_reason,
            Some(WarmPoolEvictionReason::PressureUnavailable)
        );
        assert!(plan.retained.is_empty());
        assert_eq!(
            plan.evictions[0].reason,
            WarmPoolEvictionReason::PressureUnavailable
        );

        let json = serde_json::to_string(&plan.evidence[0])?;
        assert!(json.contains(WARM_POOL_EVIDENCE_EVENT));
        assert!(json.contains("\"reason_code\":\"pressure_unavailable\""));
        assert!(!json.contains("z:project:alpha"));
        assert!(!json.contains("profile-prod-secret"));
        assert!(json.contains("zone:blake3:"));
        assert!(json.contains("credential_profile:blake3:"));
        Ok(())
    }

    #[test]
    fn adaptive_warm_pool_uses_backpressure_memory_pressure_to_shed_low_priority_entries() {
        let controller = adaptive_warm_pool_normal_controller();
        let plan = controller.plan_retention(
            &[adaptive_warm_pool_entry(
                "fcp.github:utility:1.0.0",
                10,
                8 * 1024,
            )],
            &WarmPoolPressureSnapshot::Available {
                telemetry: BackpressureTelemetry {
                    queue_pressure_per_mille: Some(200),
                    cpu_pressure_per_mille: Some(300),
                    memory_pressure_per_mille: Some(970),
                    useful_work_per_mille: Some(300),
                    ..BackpressureTelemetry::default()
                },
                calibration: BackpressureCalibration::valid(),
            },
        );

        assert!(plan.disabled);
        assert_eq!(
            plan.disabled_reason,
            Some(WarmPoolEvictionReason::PressureShed)
        );
        assert_eq!(plan.pressure_state.as_deref(), Some("memory_pressure"));
        assert_eq!(plan.pressure_action.as_deref(), Some("cancel_low_priority"));
        assert_eq!(plan.pressure_replay_matches, Some(true));
        assert_eq!(
            plan.evictions[0].reason,
            WarmPoolEvictionReason::PressureShed
        );
    }

    #[test]
    fn adaptive_warm_pool_applies_lru_per_connector_and_global_rss_caps() {
        let controller = AdaptiveWarmPoolController::new(AdaptiveWarmPoolConfig::new(2, 100));
        let newest = adaptive_warm_pool_entry("fcp.github:utility:1.0.0", 10, 40);
        let middle = adaptive_warm_pool_entry("fcp.github:utility:1.0.0", 20, 40);
        let oldest_same_connector = adaptive_warm_pool_entry("fcp.github:utility:1.0.0", 30, 40);
        let oldest_global = adaptive_warm_pool_entry("fcp.slack:utility:1.0.0", 50, 80);

        let plan = controller.plan_retention(
            &[
                newest.clone(),
                middle.clone(),
                oldest_same_connector.clone(),
                oldest_global.clone(),
            ],
            &WarmPoolPressureSnapshot::low_pressure(),
        );

        assert_eq!(plan.retained, vec![newest.key, middle.key]);
        // `newest`/`middle`/`oldest_same_connector` all share one `WarmPoolKey`,
        // so `retained` (keys) cannot distinguish which same-key entries survive
        // — the caller must apply eviction by `retained_indices`. Index 2
        // (oldest_same_connector, PerConnectorCap) and index 3 (oldest_global,
        // GlobalRssCap) are evicted; only indices 0 and 1 are retained.
        assert_eq!(plan.retained_indices, vec![0, 1]);
        assert!(plan.evictions.iter().any(|eviction| {
            eviction.key == oldest_same_connector.key
                && eviction.reason == WarmPoolEvictionReason::PerConnectorCap
        }));
        assert!(plan.evictions.iter().any(|eviction| {
            eviction.key == oldest_global.key
                && eviction.reason == WarmPoolEvictionReason::GlobalRssCap
        }));
    }

    // ── LocalPlacementController ──

    fn local_placement_request(
        connector_id: &str,
        operation_class: PlacementOperationClass,
        labels: &[&str],
    ) -> LocalPlacementRequest {
        let mut input = PlacementHintDerivationInput::new(connector_id);
        input.manifest_archetypes = labels.iter().map(|label| (*label).to_string()).collect();
        LocalPlacementRequest::new(connector_id, operation_class, input.derive_hint())
    }

    fn red_memory_pressure() -> LocalPlacementPressureSnapshot {
        LocalPlacementPressureSnapshot::Available {
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(200),
                cpu_pressure_per_mille: Some(300),
                memory_pressure_per_mille: Some(970),
                useful_work_per_mille: Some(300),
                ..BackpressureTelemetry::default()
            },
            calibration: BackpressureCalibration::valid(),
        }
    }

    #[test]
    fn local_placement_hint_derives_from_manifest_operations_sandbox_and_budgets() {
        let mut input = PlacementHintDerivationInput::new("fcp.fixture.hybrid:utility:1.0.0");
        input.manifest_archetypes = vec![
            "Request-Response".to_string(),
            "WebSocket".to_string(),
            "Sigstore".to_string(),
        ];
        input.operation_ids = vec![
            "messages.stream".to_string(),
            "artifact.verify_signature".to_string(),
        ];
        input.sandbox_strict = true;
        input.prewarm_strategy = PrewarmStrategy::WarmPool;
        input.preferred_cpu_set = Some(vec![0, 2]);
        input.max_rss_bytes = Some(512 * 1024 * 1024);

        let hint = input.derive_hint();

        assert!(hint.latency_sensitive);
        assert!(hint.streaming_long_lived);
        assert!(hint.crypto_heavy);
        assert!(hint.memory_heavy);
        assert!(hint.sandbox_strict);
        assert_eq!(hint.preferred_cpu_set, Some(vec![0, 2]));
        assert_eq!(
            hint.class(PlacementOperationClass::LatencySensitive),
            PlacementHintClass::StreamingLongLived
        );
    }

    #[test]
    fn local_placement_scheduler_does_not_queue_latency_behind_bulk() {
        let controller = LocalPlacementController::default();
        let bulk = local_placement_request(
            "fcp.fixture.bulk:utility:1.0.0",
            PlacementOperationClass::BulkPrewarm,
            &["batch", "export"],
        );
        let latency = local_placement_request(
            "fcp.fixture.latency:utility:1.0.0",
            PlacementOperationClass::LatencySensitive,
            &["request-response", "chat"],
        );

        let plans = controller.plan_batch(
            &[bulk, latency],
            &LocalPlacementPressureSnapshot::low_pressure(),
            1,
        );

        assert_eq!(plans[0].connector_id, "fcp.fixture.latency:utility:1.0.0");
        assert_eq!(plans[0].selected_lane, PlacementLane::Latency);
        assert_eq!(plans[0].queue_wait_ms, 0);
        assert_eq!(plans[1].connector_id, "fcp.fixture.bulk:utility:1.0.0");
        assert!(plans[1].queue_wait_ms > 0);
    }

    #[test]
    fn local_placement_red_pressure_refuses_bulk_but_preserves_critical_launches() {
        let controller = LocalPlacementController::default();
        let critical = local_placement_request(
            "fcp.fixture.audit:utility:1.0.0",
            PlacementOperationClass::LifecycleCritical,
            &["audit"],
        );
        let bulk = local_placement_request(
            "fcp.fixture.prewarm:utility:1.0.0",
            PlacementOperationClass::BulkPrewarm,
            &["batch"],
        );

        let plans = controller.plan_batch(&[bulk, critical], &red_memory_pressure(), 2);
        let critical_plan = plans
            .iter()
            .find(|plan| plan.connector_id == "fcp.fixture.audit:utility:1.0.0")
            .expect("critical plan");
        let bulk_plan = plans
            .iter()
            .find(|plan| plan.connector_id == "fcp.fixture.prewarm:utility:1.0.0")
            .expect("bulk plan");

        assert!(critical_plan.admitted);
        assert_eq!(critical_plan.selected_lane, PlacementLane::Critical);
        assert!(!bulk_plan.admitted);
        assert_eq!(bulk_plan.pressure_verdict, PlacementPressureVerdict::Red);
        assert_eq!(
            bulk_plan.pressure_action.as_deref(),
            Some("cancel_low_priority")
        );
    }

    #[test]
    fn local_placement_affinity_unsupported_is_explicit_noop_evidence() {
        let controller = LocalPlacementController::default();
        let hint = PlacementHint {
            latency_sensitive: true,
            preferred_cpu_set: Some(vec![1, 3]),
            ..PlacementHint::default()
        };
        let request = LocalPlacementRequest::new(
            "fcp.fixture.affinity:utility:1.0.0",
            PlacementOperationClass::LatencySensitive,
            hint,
        );

        let plan =
            controller.plan_launch(&request, &LocalPlacementPressureSnapshot::low_pressure());

        assert!(plan.admitted);
        assert!(!plan.affinity_applied);
        assert_eq!(
            plan.no_op_reason,
            PlacementAffinityNoOpReason::UnsupportedPlatform
        );
        assert_eq!(plan.preferred_cpu_set, Some(vec![1, 3]));
    }

    #[test]
    fn local_placement_evidence_does_not_participate_in_security_decisions() {
        let controller = LocalPlacementController::default();
        let hint = PlacementHint {
            sandbox_strict: true,
            latency_sensitive: true,
            ..PlacementHint::default()
        };
        let request = LocalPlacementRequest::new(
            "fcp.fixture.security:utility:1.0.0",
            PlacementOperationClass::LatencySensitive,
            hint,
        );

        let plan =
            controller.plan_launch(&request, &LocalPlacementPressureSnapshot::low_pressure());
        let evidence = serde_json::to_value(&plan).expect("placement evidence serializes");

        assert!(!plan.security_influence);
        assert!(evidence.get("security_influence").is_some());
        assert!(evidence.get("zone").is_none());
        assert!(evidence.get("capability").is_none());
        assert!(evidence.get("sandbox_profile").is_none());
    }

    #[test]
    fn local_placement_fixture_is_deterministic_across_sixteen_connectors() {
        let controller = LocalPlacementController::default();
        let mut requests = local_placement_fixture_requests();
        requests.reverse();

        let render = || {
            controller
                .plan_batch(
                    &requests,
                    &LocalPlacementPressureSnapshot::low_pressure(),
                    4,
                )
                .into_iter()
                .map(|plan| plan.to_jsonl_line().expect("placement JSONL line"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let first = render();
        let second = render();
        let lines = first.lines().collect::<Vec<_>>();

        assert_eq!(first, second);
        assert_eq!(lines.len(), 16);
        assert!(lines[0].contains("\"selected_lane\":\"critical\""));
        assert!(lines[1].contains("\"selected_lane\":\"latency\""));
        assert!(lines[15].contains("\"selected_lane\":\"bulk\""));
        assert!(
            lines
                .iter()
                .all(|line| line.contains(PLACEMENT_EVIDENCE_EVENT))
        );
        assert!(lines.iter().all(|line| line.contains(LOCAL_PLACEMENT_BEAD)));
    }

    fn local_placement_fixture_requests() -> Vec<LocalPlacementRequest> {
        [
            (
                "fcp.fixture.00-critical:utility:1.0.0",
                PlacementOperationClass::LifecycleCritical,
                &["audit"][..],
            ),
            (
                "fcp.fixture.01-chat:utility:1.0.0",
                PlacementOperationClass::LatencySensitive,
                &["chat"],
            ),
            (
                "fcp.fixture.02-browser:utility:1.0.0",
                PlacementOperationClass::LatencySensitive,
                &["browser"],
            ),
            (
                "fcp.fixture.03-webhook:utility:1.0.0",
                PlacementOperationClass::LatencySensitive,
                &["webhook"],
            ),
            (
                "fcp.fixture.04-stream:utility:1.0.0",
                PlacementOperationClass::StreamingLongLived,
                &["websocket"],
            ),
            (
                "fcp.fixture.05-sse:utility:1.0.0",
                PlacementOperationClass::StreamingLongLived,
                &["sse"],
            ),
            (
                "fcp.fixture.06-crypto:utility:1.0.0",
                PlacementOperationClass::CryptoHeavy,
                &["sigstore"],
            ),
            (
                "fcp.fixture.07-tuf:utility:1.0.0",
                PlacementOperationClass::CryptoHeavy,
                &["tuf"],
            ),
            (
                "fcp.fixture.08-video:utility:1.0.0",
                PlacementOperationClass::MemoryHeavy,
                &["video"],
            ),
            (
                "fcp.fixture.09-ml:utility:1.0.0",
                PlacementOperationClass::MemoryHeavy,
                &["ml"],
            ),
            (
                "fcp.fixture.10-db:utility:1.0.0",
                PlacementOperationClass::Throughput,
                &["database"],
            ),
            (
                "fcp.fixture.11-blob:utility:1.0.0",
                PlacementOperationClass::Throughput,
                &["blob"],
            ),
            (
                "fcp.fixture.12-batch:utility:1.0.0",
                PlacementOperationClass::BulkPrewarm,
                &["batch"],
            ),
            (
                "fcp.fixture.13-export:utility:1.0.0",
                PlacementOperationClass::BulkPrewarm,
                &["export"],
            ),
            (
                "fcp.fixture.14-storage:utility:1.0.0",
                PlacementOperationClass::Throughput,
                &["storage"],
            ),
            (
                "fcp.fixture.15-search:utility:1.0.0",
                PlacementOperationClass::LatencySensitive,
                &["search"],
            ),
        ]
        .into_iter()
        .map(|(connector_id, operation_class, labels)| {
            local_placement_request(connector_id, operation_class, labels)
        })
        .collect()
    }

    // ── ConnectorSnapshotResumeConfig ──

    fn safe_snapshot_observation() -> SnapshotResumeObservation {
        SnapshotResumeObservation {
            snapshot_state: SnapshotResumeState::WarmCandidate,
            manifest: PrewarmManifestState::Current,
            zone_binding: PrewarmZoneBinding::Bound,
            capability: SnapshotCapabilityState::Bound,
            sandbox: PrewarmSandboxState::LimitsActive,
            credential: PrewarmCredentialState::Deferred,
            platform: SnapshotPlatformState::Supported,
            proof: SnapshotSecurityProofState::Present,
            snapshot_age: Duration::from_secs(5),
            cow_dirty_pages: None,
            previous_exit: None,
        }
    }

    #[test]
    fn snapshot_default_preserves_on_demand_startup() {
        let config = ConnectorSnapshotResumeConfig::default();
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            config.decide_resume(&safe_snapshot_observation()),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::NotConfigured
            }
        );
    }

    #[test]
    fn snapshot_rejects_cow_fork_without_security_proof() {
        let config = ConnectorSnapshotResumeConfig::cow_fork(
            Duration::from_secs(30),
            Duration::from_millis(50),
        );
        assert_eq!(
            config.validate(),
            Err(SnapshotResumeConfigError::CowForkRequiresSecurityProof)
        );
        assert_eq!(
            config.decide_resume(&safe_snapshot_observation()),
            SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::CowForkWithoutSecurityProof
            }
        );
    }

    #[test]
    fn snapshot_validates_bounds() {
        assert_eq!(
            ConnectorSnapshotResumeConfig::wasmtime_snapshot(
                Duration::ZERO,
                Duration::from_secs(1)
            )
            .validate(),
            Err(SnapshotResumeConfigError::MaxAgeZero)
        );
        assert_eq!(
            ConnectorSnapshotResumeConfig::wasmtime_snapshot(
                Duration::from_secs(30),
                Duration::ZERO
            )
            .validate(),
            Err(SnapshotResumeConfigError::CheckoutTimeoutZero)
        );
    }

    #[test]
    fn snapshot_admits_only_after_all_rebinding_proofs_pass() {
        let config = ConnectorSnapshotResumeConfig::wasmtime_snapshot(
            Duration::from_secs(30),
            Duration::from_millis(50),
        );
        let decision = config.decide_resume(&safe_snapshot_observation());

        assert_eq!(
            decision,
            SnapshotResumeDecision::AdmitSnapshot {
                snapshot_state: SnapshotResumeState::Restored
            }
        );
        assert!(decision.admits_resume());
    }

    #[test]
    fn snapshot_falls_back_on_empty_store_manifest_zone_capability_and_sandbox_gaps() {
        let config = ConnectorSnapshotResumeConfig::wasmtime_snapshot(
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let mut empty_store = safe_snapshot_observation();
        empty_store.snapshot_state = SnapshotResumeState::EmptySnapshotStore;
        assert_eq!(
            config.decide_resume(&empty_store),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::EmptySnapshotStore
            }
        );

        let mut stale_manifest = safe_snapshot_observation();
        stale_manifest.manifest = PrewarmManifestState::Stale;
        assert_eq!(
            config.decide_resume(&stale_manifest),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::StaleManifest
            }
        );

        let mut missing_zone = safe_snapshot_observation();
        missing_zone.zone_binding = PrewarmZoneBinding::Missing;
        assert_eq!(
            config.decide_resume(&missing_zone),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::MissingZoneBinding
            }
        );

        let mut missing_capability = safe_snapshot_observation();
        missing_capability.capability = SnapshotCapabilityState::Missing;
        assert_eq!(
            config.decide_resume(&missing_capability),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::MissingCapabilityBinding
            }
        );

        let mut sandbox_gap = safe_snapshot_observation();
        sandbox_gap.sandbox = PrewarmSandboxState::LimitsUnavailable;
        assert_eq!(
            config.decide_resume(&sandbox_gap),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::SandboxLimitsUnavailable
            }
        );
    }

    #[test]
    fn snapshot_rejects_revoked_capability_loaded_credentials_and_missing_resume_proof() {
        let config = ConnectorSnapshotResumeConfig::wasmtime_snapshot(
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let mut revoked = safe_snapshot_observation();
        revoked.capability = SnapshotCapabilityState::Revoked;
        assert_eq!(
            config.decide_resume(&revoked),
            SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::RevokedCapability
            }
        );

        let mut loaded_credential = safe_snapshot_observation();
        loaded_credential.credential = PrewarmCredentialState::MaterialLoaded;
        assert_eq!(
            config.decide_resume(&loaded_credential),
            SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::CredentialMaterialLoaded
            }
        );

        let mut missing_proof = safe_snapshot_observation();
        missing_proof.proof = SnapshotSecurityProofState::Absent;
        assert_eq!(
            config.decide_resume(&missing_proof),
            SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::SnapshotResumeProofUnavailable
            }
        );
    }

    #[test]
    fn snapshot_skips_or_falls_back_for_platform_crash_age_and_concurrency() {
        let config = ConnectorSnapshotResumeConfig::wasmtime_snapshot(
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let mut unsupported = safe_snapshot_observation();
        unsupported.platform = SnapshotPlatformState::Unsupported;
        assert_eq!(
            config.decide_resume(&unsupported),
            SnapshotResumeDecision::SkipUnsupported {
                reason: SnapshotSkipReason::PlatformUnsupported
            }
        );

        let mut crashed = safe_snapshot_observation();
        crashed.previous_exit = Some(ProcessExit::with_code(1));
        assert_eq!(
            config.decide_resume(&crashed),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::CrashBeforeCheckout
            }
        );

        let mut stale = safe_snapshot_observation();
        stale.snapshot_age = Duration::from_secs(31);
        assert_eq!(
            config.decide_resume(&stale),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::SnapshotTooOld
            }
        );

        let mut concurrent = safe_snapshot_observation();
        concurrent.snapshot_state = SnapshotResumeState::ConcurrentStartup;
        assert_eq!(
            config.decide_resume(&concurrent),
            SnapshotResumeDecision::FallbackOnDemand {
                reason: SnapshotFallbackReason::ConcurrentStartup
            }
        );
    }

    #[test]
    fn snapshot_resume_evidence_serializes_required_fail_closed_fields() -> serde_json::Result<()> {
        let evidence = SnapshotResumeEvidence::new(SnapshotResumeEvidenceInput {
            scenario_id: "warm_resume".to_string(),
            connector_id: "fcp.github:utility:1.0.0".to_string(),
            manifest_hash: Some("blake3:abc123".to_string()),
            zone: "z:project:alpha".to_string(),
            snapshot_state: SnapshotResumeState::WarmCandidate,
            cow_dirty_pages: Some(0),
            activation_latency_ms: Some(42),
            memory_rss_bytes: Some(64 * 1024 * 1024),
            sandbox_profile: "strict".to_string(),
            credential_mode: SnapshotCredentialMode::Deferred,
            cleanup_result: "secret token cleanup detail".to_string(),
            decision: SnapshotResumeDecision::RejectUnsafe {
                reason: SnapshotUnsafeReason::SnapshotResumeProofUnavailable,
            },
        });
        let value = serde_json::to_value(&evidence)?;

        assert_eq!(value["schema_version"], SNAPSHOT_RESUME_SCHEMA_VERSION);
        assert_eq!(value["bead_id"], SNAPSHOT_RESUME_BEAD);
        assert_eq!(
            value["host_boundary"],
            "fcp-host::supervisor::ConnectorSnapshotResumeConfig::decide_resume"
        );
        assert_eq!(value["snapshot_state"], "warm_candidate");
        assert_eq!(value["admission_decision"], "reject_unsafe");
        assert_eq!(value["resume_checkout"], false);
        assert_eq!(value["cow_dirty_pages"], 0);
        assert_eq!(value["activation_latency_ms"], 42);
        assert_eq!(value["memory_rss_bytes"], 64 * 1024 * 1024);
        assert_eq!(value["sandbox_profile"], "strict");
        assert_eq!(value["credential_mode"], "deferred");
        assert_eq!(
            value["rejection_reason"],
            "snapshot_resume_proof_unavailable"
        );
        assert_eq!(value["cleanup_result"], "[REDACTED]");
        assert!(!value.to_string().contains("secret token"));
        assert!(
            value["operator_guidance"]
                .as_str()
                .unwrap()
                .contains("rejected")
        );
        Ok(())
    }

    // ── RestartTracker ──

    #[test]
    fn tracker_allows_restart_on_failure() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let result = tracker.evaluate_restart(&exit, Instant::now());
        assert!(result.is_ok());
    }

    #[test]
    fn tracker_denies_restart_on_clean_exit_with_default_policy() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::clean();
        let result = tracker.evaluate_restart(&exit, Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    #[test]
    fn tracker_enforces_max_restarts() {
        let config = SupervisorConfig {
            max_restarts: 2,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        // First two restarts should succeed.
        assert!(tracker.evaluate_restart(&exit, now).is_ok());
        assert!(tracker.evaluate_restart(&exit, now).is_ok());

        // Third restart should be denied.
        let result = tracker.evaluate_restart(&exit, now);
        assert!(matches!(
            result,
            Err(RestartDenied::MaxRestartsExceeded { count: 2, .. })
        ));
    }

    #[test]
    fn tracker_window_expiry_allows_new_restarts() {
        let config = SupervisorConfig {
            max_restarts: 2,
            restart_window: Duration::from_secs(1),
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let start = Instant::now();

        // Fill up the window.
        assert!(tracker.evaluate_restart(&exit, start).is_ok());
        assert!(tracker.evaluate_restart(&exit, start).is_ok());
        assert!(tracker.evaluate_restart(&exit, start).is_err());

        // After the window expires, restarts should be allowed again.
        let later = start + Duration::from_secs(2);
        assert!(tracker.evaluate_restart(&exit, later).is_ok());
    }

    #[test]
    fn tracker_backoff_increases() {
        let config = SupervisorConfig {
            max_restarts: 10,
            initial_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        let delay1 = tracker.evaluate_restart(&exit, now).unwrap();
        let delay2 = tracker.evaluate_restart(&exit, now).unwrap();
        let delay3 = tracker.evaluate_restart(&exit, now).unwrap();

        assert_eq!(delay1, Duration::from_millis(100));
        assert_eq!(delay2, Duration::from_millis(200));
        assert_eq!(delay3, Duration::from_millis(400));
    }

    #[test]
    fn tracker_successful_start_resets_backoff() {
        let config = SupervisorConfig {
            max_restarts: 10,
            initial_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        // Build up backoff.
        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();

        // Successful start resets backoff.
        tracker.record_successful_start();
        let delay = tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn tracker_restarts_in_window_counts_correctly() {
        let config = SupervisorConfig {
            max_restarts: 10,
            restart_window: Duration::from_secs(10),
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(tracker.restarts_in_window(now), 2);
        assert_eq!(tracker.total_restarts(), 2);
    }

    #[test]
    fn tracker_history_records_events() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(tracker.history().len(), 1);
        assert_eq!(tracker.history()[0].attempt, 1);
    }

    #[test]
    fn restart_denied_display() {
        let denied = RestartDenied::PolicyDenied;
        assert_eq!(denied.to_string(), "restart policy denied");

        let denied = RestartDenied::MaxRestartsExceeded {
            count: 5,
            window: Duration::from_mins(5),
        };
        assert!(denied.to_string().contains("5 restarts"));
        assert!(denied.to_string().contains("300s"));
    }

    #[test]
    fn tracker_always_policy_restarts_clean_exit() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::Always,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        assert!(
            tracker
                .evaluate_restart(&ProcessExit::clean(), Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn tracker_never_policy_denies_crash() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::Never,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let result = tracker.evaluate_restart(&ProcessExit::with_signal(9), Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    // ── ShutdownCoordinator ──

    #[test]
    fn shutdown_not_started_initially() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        assert!(!coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
        assert_eq!(*coordinator.phase(), ShutdownPhase::NotStarted);
    }

    #[test]
    fn shutdown_graceful_transitions_to_waiting() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        assert!(coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
        assert!(matches!(
            coordinator.phase(),
            ShutdownPhase::GracefulWait { .. }
        ));
    }

    #[test]
    fn shutdown_should_not_force_kill_before_timeout() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        assert!(!coordinator.should_force_kill(now));
    }

    #[test]
    fn shutdown_should_force_kill_after_timeout() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(2);
        assert!(coordinator.should_force_kill(later));
    }

    #[test]
    fn shutdown_stale_now_does_not_panic_or_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let earlier = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!coordinator.should_force_kill(earlier));
    }

    #[test]
    fn shutdown_record_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(2);
        coordinator.record_force_kill(later);
        assert!(matches!(
            coordinator.phase(),
            ShutdownPhase::ForceKill { .. }
        ));
        assert!(coordinator.is_shutting_down());
    }

    #[test]
    fn shutdown_record_exit_completes() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        coordinator.start_graceful(Instant::now());
        coordinator.record_exit(ProcessExit::clean());
        assert!(coordinator.is_complete());
        assert!(!coordinator.is_shutting_down());
    }

    #[test]
    fn shutdown_double_start_is_idempotent() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(5);
        coordinator.start_graceful(later);
        // Should still have the original start time.
        assert_eq!(
            coordinator.phase(),
            &ShutdownPhase::GracefulWait { sent_at: now }
        );
    }

    #[test]
    fn shutdown_not_started_does_not_force_kill() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        assert!(!coordinator.should_force_kill(Instant::now()));
    }

    // ── HealthCheckScheduler ──

    #[test]
    fn health_check_due_initially() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        assert!(scheduler.is_due(Instant::now()));
    }

    #[test]
    fn health_check_not_due_after_recent_check() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        assert!(!scheduler.is_due(now));
    }

    #[test]
    fn health_check_stale_now_is_not_due() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let earlier = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!scheduler.is_due(earlier));
    }

    #[test]
    fn health_check_due_after_interval() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(1), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let later = now + Duration::from_secs(2);
        assert!(scheduler.is_due(later));
    }

    #[test]
    fn health_check_consecutive_failures_tracked() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(scheduler.consecutive_failures(), 0);
        scheduler.record_failure(now);
        assert_eq!(scheduler.consecutive_failures(), 1);
        scheduler.record_failure(now);
        assert_eq!(scheduler.consecutive_failures(), 2);
    }

    #[test]
    fn health_check_success_resets_failures() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_failure(now);
        scheduler.record_failure(now);
        scheduler.record_success(now);
        assert_eq!(scheduler.consecutive_failures(), 0);
    }

    #[test]
    fn health_check_unhealthy_after_threshold() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10))
                .with_max_failures(2);
        let now = Instant::now();
        assert!(!scheduler.is_unhealthy());
        scheduler.record_failure(now);
        assert!(!scheduler.is_unhealthy());
        scheduler.record_failure(now);
        assert!(scheduler.is_unhealthy());
    }

    #[test]
    fn health_check_time_until_next() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(scheduler.time_until_next(now), Duration::ZERO);
        scheduler.record_success(now);
        let remaining = scheduler.time_until_next(now + Duration::from_secs(10));
        assert_eq!(remaining, Duration::from_secs(20));
    }

    #[test]
    fn health_check_time_until_next_saturates_for_stale_now() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let earlier = now.checked_sub(Duration::from_secs(5)).unwrap();
        assert_eq!(scheduler.time_until_next(earlier), Duration::from_secs(30));
    }

    #[test]
    fn health_check_timeout_accessor() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(5));
        assert_eq!(scheduler.timeout(), Duration::from_secs(5));
    }

    // ── JSON serialization roundtrips ──

    #[test]
    fn restart_policy_json_roundtrip() {
        for policy in [
            RestartPolicy::Always,
            RestartPolicy::OnFailure,
            RestartPolicy::OnCrash,
            RestartPolicy::Never,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: RestartPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    #[test]
    fn process_exit_json_roundtrip() {
        for exit in [
            ProcessExit::clean(),
            ProcessExit::with_code(42),
            ProcessExit::with_signal(15),
            ProcessExit {
                code: Some(1),
                signal: Some(11),
            },
        ] {
            let json = serde_json::to_string(&exit).unwrap();
            let parsed: ProcessExit = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, exit);
        }
    }

    #[test]
    fn supervisor_config_json_roundtrip() {
        let config = SupervisorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_restarts, config.max_restarts);
        assert_eq!(parsed.restart_window, config.restart_window);
    }

    #[test]
    fn stop_reason_equality() {
        assert_eq!(StopReason::Requested, StopReason::Requested);
        assert_ne!(StopReason::Requested, StopReason::HostShutdown);
    }

    #[test]
    fn backoff_zero_initial_stays_zero() {
        let mut backoff = ExponentialBackoff::new(Duration::ZERO, Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
    }

    #[test]
    fn tracker_on_crash_denies_nonzero_exit() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::OnCrash,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let result = tracker.evaluate_restart(&ProcessExit::with_code(1), Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    #[test]
    fn tracker_on_crash_allows_signal() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::OnCrash,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        assert!(
            tracker
                .evaluate_restart(&ProcessExit::with_signal(11), Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn backoff_saturates_attempt_counter() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(1), Duration::from_secs(1), 2.0);
        for _ in 0..1000 {
            let _ = backoff.next_backoff();
        }
        // Should cap at max, never panic.
        assert!(backoff.current_delay() <= Duration::from_secs(1));
    }

    #[test]
    fn health_scheduler_custom_max_failures() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10))
            .with_max_failures(5);
        assert!(!scheduler.is_unhealthy());
    }

    #[test]
    fn shutdown_force_kill_not_from_not_started() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        // record_force_kill should be a no-op when not in GracefulWait.
        coordinator.record_force_kill(Instant::now());
        assert_eq!(*coordinator.phase(), ShutdownPhase::NotStarted);
    }

    #[test]
    fn shutdown_complete_after_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        coordinator.record_force_kill(now + Duration::from_secs(2));
        coordinator.record_exit(ProcessExit::with_signal(9));
        assert!(coordinator.is_complete());
    }

    #[test]
    fn tracker_config_accessor() {
        let config = SupervisorConfig {
            max_restarts: 42,
            ..Default::default()
        };
        let tracker = RestartTracker::new(config);
        assert_eq!(tracker.config().max_restarts, 42);
    }

    // ── ResourceLimits ──

    #[test]
    fn resource_limits_default_has_memory_and_fds() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.max_fds, Some(1024));
        assert_eq!(limits.max_processes, Some(64));
        assert!(limits.cpu_seconds.is_none());
        assert!(limits.max_file_size_bytes.is_none());
    }

    #[test]
    fn resource_limits_unlimited_has_no_limits() {
        let limits = ResourceLimits::unlimited();
        assert!(!limits.has_any_limits());
        assert_eq!(limits.active_limit_count(), 0);
    }

    #[test]
    fn resource_limits_default_has_three_active() {
        let limits = ResourceLimits::default();
        assert!(limits.has_any_limits());
        assert_eq!(limits.active_limit_count(), 3);
    }

    #[test]
    fn resource_limits_all_set_counts_five() {
        let limits = ResourceLimits {
            memory_bytes: Some(1),
            cpu_seconds: Some(1),
            max_fds: Some(1),
            max_processes: Some(1),
            max_file_size_bytes: Some(1),
        };
        assert_eq!(limits.active_limit_count(), 5);
    }

    #[test]
    fn resource_limits_merge_strict_takes_lower() {
        let a = ResourceLimits {
            memory_bytes: Some(1000),
            max_fds: Some(100),
            ..ResourceLimits::unlimited()
        };
        let b = ResourceLimits {
            memory_bytes: Some(500),
            max_fds: Some(200),
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let merged = a.merge_strict(&b);
        assert_eq!(merged.memory_bytes, Some(500));
        assert_eq!(merged.max_fds, Some(100));
        assert_eq!(merged.cpu_seconds, Some(60));
    }

    #[test]
    fn resource_limits_merge_strict_with_unlimited() {
        let limited = ResourceLimits::default();
        let unlimited = ResourceLimits::unlimited();
        let merged = limited.merge_strict(&unlimited);
        assert_eq!(merged.memory_bytes, limited.memory_bytes);
        assert_eq!(merged.max_fds, limited.max_fds);
    }

    #[test]
    fn resource_limits_merge_strict_both_unlimited() {
        let a = ResourceLimits::unlimited();
        let b = ResourceLimits::unlimited();
        assert!(!a.merge_strict(&b).has_any_limits());
    }

    #[test]
    fn resource_limits_json_roundtrip() {
        let limits = ResourceLimits::default();
        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, limits);
    }

    #[test]
    fn resource_limits_unlimited_json_roundtrip() {
        let limits = ResourceLimits::unlimited();
        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, limits);
    }

    // ── ResourceUsage ──

    #[test]
    fn resource_usage_within_limits() {
        let usage = ResourceUsage {
            memory_bytes: 100 * 1024 * 1024,
            cpu_millis: 5000,
            open_fds: 50,
            process_count: 10,
            file_size_bytes: 0,
        };
        let limits = ResourceLimits::default();
        assert!(usage.within_limits(&limits));
        assert!(usage.violations(&limits).is_empty());
    }

    #[test]
    fn resource_usage_memory_violation() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024, // 1 GiB
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            ..ResourceLimits::unlimited()
        };
        assert!(!usage.within_limits(&limits));
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::Memory);
        assert_eq!(violations[0].current, 1024 * 1024 * 1024);
        assert_eq!(violations[0].limit, 512 * 1024 * 1024);
    }

    #[test]
    fn resource_usage_fds_violation() {
        let usage = ResourceUsage {
            open_fds: 2048,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_fds: Some(1024),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::FileDescriptors);
    }

    #[test]
    fn resource_usage_cpu_violation() {
        let usage = ResourceUsage {
            cpu_millis: 120_000, // 120 seconds
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::CpuTime);
        assert_eq!(violations[0].current, 120);
        assert_eq!(violations[0].limit, 60);
    }

    #[test]
    fn resource_usage_process_violation() {
        let usage = ResourceUsage {
            process_count: 100,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_processes: Some(64),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::Processes);
    }

    #[test]
    fn resource_usage_multiple_violations() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024,
            open_fds: 2048,
            process_count: 100,
            cpu_millis: 0,
            file_size_bytes: 0,
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1024),
            max_processes: Some(50),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn resource_usage_no_violations_unlimited() {
        let usage = ResourceUsage {
            memory_bytes: u64::MAX,
            cpu_millis: u64::MAX,
            open_fds: u64::MAX,
            process_count: u64::MAX,
            file_size_bytes: u64::MAX,
        };
        let limits = ResourceLimits::unlimited();
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_at_exact_limit_is_ok() {
        let usage = ResourceUsage {
            memory_bytes: 512 * 1024 * 1024,
            open_fds: 1024,
            process_count: 64,
            cpu_millis: 60_000,
            file_size_bytes: 0,
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1024),
            max_processes: Some(64),
            cpu_seconds: Some(60),
            max_file_size_bytes: None,
        };
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_one_over_limit_violates() {
        let usage = ResourceUsage {
            memory_bytes: 512 * 1024 * 1024 + 1,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        assert!(!usage.within_limits(&limits));
    }

    // ── ResourceViolation ──

    #[test]
    fn resource_violation_display() {
        let v = ResourceViolation {
            resource: ResourceKind::Memory,
            current: 1024,
            limit: 512,
        };
        let msg = v.to_string();
        assert!(msg.contains("memory"));
        assert!(msg.contains("1024"));
        assert!(msg.contains("512"));
    }

    // ── ResourceKind ──

    #[test]
    fn resource_kind_display_all_variants() {
        assert_eq!(ResourceKind::Memory.to_string(), "memory");
        assert_eq!(ResourceKind::CpuTime.to_string(), "cpu_time");
        assert_eq!(
            ResourceKind::FileDescriptors.to_string(),
            "file_descriptors"
        );
        assert_eq!(ResourceKind::Processes.to_string(), "processes");
        assert_eq!(ResourceKind::FileSize.to_string(), "file_size");
    }

    #[test]
    fn resource_kind_json_roundtrip() {
        for kind in [
            ResourceKind::Memory,
            ResourceKind::CpuTime,
            ResourceKind::FileDescriptors,
            ResourceKind::Processes,
            ResourceKind::FileSize,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: ResourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    // ── ResourceUtilization ──

    #[test]
    fn utilization_50_percent_memory() {
        let usage = ResourceUsage {
            memory_bytes: 256 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!((util.memory.unwrap() - 0.5).abs() < f64::EPSILON);
        assert!(util.cpu.is_none());
        assert!(util.fds.is_none());
        assert!(util.processes.is_none());
        assert!(util.file_size.is_none());
    }

    #[test]
    fn utilization_over_100_percent() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!(util.memory.unwrap() > 1.0);
    }

    #[test]
    fn utilization_max_returns_highest() {
        let usage = ResourceUsage {
            memory_bytes: 400 * 1024 * 1024,
            open_fds: 900,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1000),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        let max = util.max_utilization().unwrap();
        // FDs: 900/1000 = 0.9, Memory: 400/512 ≈ 0.78
        assert!((max - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn resource_usage_file_size_violation() {
        let usage = ResourceUsage {
            file_size_bytes: 4097,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_file_size_bytes: Some(4096),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::FileSize);
        assert_eq!(violations[0].current, 4097);
        assert_eq!(violations[0].limit, 4096);
    }

    #[test]
    fn utilization_file_size_is_computed() {
        let usage = ResourceUsage {
            file_size_bytes: 512,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_file_size_bytes: Some(1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!((util.file_size.unwrap() - 0.5).abs() < f64::EPSILON);
        assert!((util.max_utilization().unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn utilization_all_unlimited_returns_none() {
        let usage = ResourceUsage::default();
        let limits = ResourceLimits::unlimited();
        let util = usage.utilization(&limits);
        assert!(util.max_utilization().is_none());
    }

    #[test]
    fn utilization_above_threshold() {
        let usage = ResourceUsage {
            memory_bytes: 480 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!(util.any_above_threshold(0.9));
        assert!(!util.any_above_threshold(0.95));
    }

    #[test]
    fn utilization_not_above_threshold_when_unlimited() {
        let usage = ResourceUsage::default();
        let limits = ResourceLimits::unlimited();
        let util = usage.utilization(&limits);
        assert!(!util.any_above_threshold(0.0));
    }

    // ── merge_option_min ──

    #[test]
    fn merge_option_min_both_some() {
        assert_eq!(merge_option_min(Some(10), Some(5)), Some(5));
        assert_eq!(merge_option_min(Some(5), Some(10)), Some(5));
    }

    #[test]
    fn merge_option_min_one_none() {
        assert_eq!(merge_option_min(Some(10), None), Some(10));
        assert_eq!(merge_option_min(None, Some(10)), Some(10));
    }

    #[test]
    fn merge_option_min_both_none() {
        assert_eq!(merge_option_min(None, None), None);
    }

    // ── ConnectionTracker ──

    #[test]
    fn connection_tracker_starts_at_zero() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.active_count(), 0);
        assert!(!tracker.is_draining());
        assert!(!tracker.is_drained()); // Not drained because not draining.
    }

    #[test]
    fn connection_tracker_default_same_as_new() {
        let tracker = ConnectionTracker::default();
        assert_eq!(tracker.active_count(), 0);
        assert!(!tracker.is_draining());
    }

    #[test]
    fn connection_tracker_acquire_increments() {
        let tracker = ConnectionTracker::new();
        let _g1 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        let _g2 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn connection_tracker_drop_decrements() {
        let tracker = ConnectionTracker::new();
        let g1 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        drop(g1);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_tracker_drain_rejects_new() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(tracker.try_acquire().is_none());
    }

    #[test]
    fn connection_tracker_existing_during_drain() {
        let tracker = ConnectionTracker::new();
        let _g = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(!tracker.is_drained()); // Still has active connection.
        assert!(tracker.try_acquire().is_none()); // New connections rejected.
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn connection_tracker_drained_after_all_drop() {
        let tracker = ConnectionTracker::new();
        let g1 = tracker.try_acquire().unwrap();
        let g2 = tracker.try_acquire().unwrap();
        tracker.start_drain();
        assert!(!tracker.is_drained());
        drop(g1);
        assert!(!tracker.is_drained());
        drop(g2);
        assert!(tracker.is_drained());
    }

    #[test]
    fn connection_tracker_multiple_drains_idempotent() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(tracker.is_drained());
    }

    #[test]
    fn connection_tracker_many_connections() {
        let tracker = ConnectionTracker::new();
        let guards: Vec<_> = (0..100).map(|_| tracker.try_acquire().unwrap()).collect();
        assert_eq!(tracker.active_count(), 100);
        drop(guards);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_guard_debug_format() {
        let tracker = ConnectionTracker::new();
        let guard = tracker.try_acquire().unwrap();
        let debug = format!("{guard:?}");
        assert!(debug.contains("ConnectionGuard"));
    }

    // ── Additional ProcessExit tests ──

    #[test]
    fn exit_clean_has_code_zero_no_signal() {
        let exit = ProcessExit::clean();
        assert_eq!(exit.code, Some(0));
        assert!(exit.signal.is_none());
    }

    #[test]
    fn exit_with_code_stores_code() {
        let exit = ProcessExit::with_code(127);
        assert_eq!(exit.code, Some(127));
        assert!(exit.signal.is_none());
    }

    #[test]
    fn exit_with_signal_stores_signal() {
        let exit = ProcessExit::with_signal(11);
        assert!(exit.code.is_none());
        assert_eq!(exit.signal, Some(11));
    }

    #[test]
    fn exit_with_code_zero_is_clean() {
        let exit = ProcessExit::with_code(0);
        // code == 0 but signal == None, so is_clean() is true.
        assert!(exit.is_clean());
    }

    #[test]
    fn exit_with_code_and_signal_not_clean_but_signal_terminated() {
        let exit = ProcessExit {
            code: Some(1),
            signal: Some(15),
        };
        assert!(!exit.is_clean()); // signal present → not clean
        assert!(exit.is_signal_terminated());
    }

    #[test]
    fn exit_none_none_not_clean_not_signal() {
        let exit = ProcessExit {
            code: None,
            signal: None,
        };
        assert!(!exit.is_clean());
        assert!(!exit.is_signal_terminated());
    }

    #[test]
    fn exit_equality_clean_same() {
        assert_eq!(ProcessExit::clean(), ProcessExit::clean());
    }

    #[test]
    fn exit_equality_code_differs() {
        assert_ne!(ProcessExit::with_code(0), ProcessExit::with_code(1));
    }

    #[test]
    fn exit_clone_preserves_fields() {
        let exit = ProcessExit {
            code: Some(2),
            signal: Some(9),
        };
        let cloned = exit.clone();
        assert_eq!(exit, cloned);
    }

    // ── Additional RestartPolicy tests ──

    #[test]
    fn restart_policy_always_restarts_signal() {
        assert!(RestartPolicy::Always.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn restart_policy_on_failure_restarts_signal() {
        // Signal exit is not clean, so OnFailure should restart.
        assert!(RestartPolicy::OnFailure.should_restart(&ProcessExit::with_signal(15)));
    }

    #[test]
    fn restart_policy_on_failure_does_not_restart_clean() {
        assert!(!RestartPolicy::OnFailure.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn restart_policy_on_crash_restarts_sigkill() {
        assert!(RestartPolicy::OnCrash.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn restart_policy_on_crash_does_not_restart_code_2() {
        // non-zero exit code without signal is NOT a crash.
        assert!(!RestartPolicy::OnCrash.should_restart(&ProcessExit::with_code(2)));
    }

    #[test]
    fn restart_policy_never_does_not_restart_signal() {
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::with_signal(11)));
    }

    #[test]
    fn restart_policy_default_is_on_failure_serde() {
        let policy = RestartPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("on_failure"));
    }

    #[test]
    fn restart_policy_clone() {
        let policy = RestartPolicy::OnCrash;
        let cloned = policy.clone();
        assert_eq!(policy, cloned);
        assert_eq!(cloned, RestartPolicy::OnCrash);
    }

    // ── Additional ProcessState tests ──

    #[test]
    fn process_state_starting_label() {
        let state = ProcessState::Starting {
            since: Instant::now(),
        };
        assert_eq!(state.label(), "starting");
        assert!(!state.is_running());
        assert!(!state.is_terminal());
    }

    #[test]
    fn process_state_running_label() {
        let state = ProcessState::Running {
            pid: 9999,
            started_at: Instant::now(),
        };
        assert_eq!(state.label(), "running");
        assert!(state.is_running());
        assert!(!state.is_terminal());
    }

    #[test]
    fn process_state_stopping_all_stop_reasons() {
        for reason in [
            StopReason::Requested,
            StopReason::HostShutdown,
            StopReason::HealthCheckFailed,
            StopReason::ResourceLimitExceeded,
            StopReason::Upgrade,
        ] {
            let state = ProcessState::Stopping {
                reason,
                since: Instant::now(),
            };
            assert_eq!(state.label(), "stopping");
            assert!(!state.is_running());
            assert!(!state.is_terminal());
        }
    }

    #[test]
    fn process_state_stopped_with_signal_exit() {
        let state = ProcessState::Stopped {
            exit: ProcessExit::with_signal(9),
            stopped_at: Instant::now(),
        };
        assert_eq!(state.label(), "stopped");
        assert!(!state.is_running());
        assert!(state.is_terminal());
    }

    #[test]
    fn process_state_failed_with_empty_error() {
        let state = ProcessState::Failed {
            error: String::new(),
            failed_at: Instant::now(),
        };
        assert_eq!(state.label(), "failed");
        assert!(!state.is_running());
        assert!(state.is_terminal());
    }

    // ── Additional StopReason tests ──

    #[test]
    fn stop_reason_serde_roundtrip() {
        for reason in [
            StopReason::Requested,
            StopReason::HostShutdown,
            StopReason::HealthCheckFailed,
            StopReason::ResourceLimitExceeded,
            StopReason::Upgrade,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let parsed: StopReason = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, reason);
        }
    }

    #[test]
    fn stop_reason_clone() {
        let r = StopReason::Upgrade;
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(cloned, StopReason::Upgrade);
    }

    // ── Additional ExponentialBackoff tests ──

    #[test]
    fn backoff_current_delay_advances_with_next() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(200), Duration::from_secs(10), 2.0);
        let first = backoff.current_delay();
        assert_eq!(first, Duration::from_millis(200));
        let _ = backoff.next_backoff();
        let second = backoff.current_delay();
        assert_eq!(second, Duration::from_millis(400));
    }

    #[test]
    fn backoff_attempts_increments() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        assert_eq!(backoff.attempts(), 0);
        let _ = backoff.next_backoff();
        assert_eq!(backoff.attempts(), 1);
        let _ = backoff.next_backoff();
        assert_eq!(backoff.attempts(), 2);
    }

    #[test]
    fn backoff_reset_brings_attempts_to_zero() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        for _ in 0..5 {
            let _ = backoff.next_backoff();
        }
        assert_eq!(backoff.attempts(), 5);
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.current_delay(), Duration::from_millis(100));
    }

    #[test]
    fn backoff_multiplier_below_one_clamps_to_two() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(2), 0.5);
        // multiplier < 1 → reset to 2.0
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(200));
    }

    #[test]
    fn backoff_zero_max_clamps_all_delays_to_zero() {
        let mut backoff = ExponentialBackoff::new(Duration::from_millis(100), Duration::ZERO, 2.0);
        assert_eq!(backoff.current_delay(), Duration::ZERO);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
    }

    #[test]
    fn backoff_initial_eq_max_stays_constant() {
        let fixed = Duration::from_millis(500);
        let mut backoff = ExponentialBackoff::new(fixed, fixed, 2.0);
        for _ in 0..5 {
            assert_eq!(backoff.next_backoff(), fixed);
        }
    }

    #[test]
    fn backoff_initial_above_max_clamps_immediately() {
        let max = Duration::from_millis(250);
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), max, 2.0);
        assert_eq!(backoff.current_delay(), max);
        assert_eq!(backoff.next_backoff(), max);
        assert_eq!(backoff.next_backoff(), max);
    }

    // ── Additional SupervisorConfig tests ──

    #[test]
    fn supervisor_config_custom_values() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::Always,
            max_restarts: 10,
            restart_window: Duration::from_mins(1),
            health_check_interval: Duration::from_secs(5),
            health_check_timeout: Duration::from_secs(2),
            graceful_shutdown_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 1.5,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_restarts, config.max_restarts);
        assert!((parsed.backoff_multiplier - config.backoff_multiplier).abs() < f64::EPSILON);
        assert_eq!(parsed.restart_policy, RestartPolicy::Always);
    }

    #[test]
    fn supervisor_config_clone() {
        let config = SupervisorConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.max_restarts, config.max_restarts);
        assert_eq!(cloned.restart_policy, config.restart_policy);
    }

    // ── Additional RestartTracker tests ──

    #[test]
    fn tracker_empty_history_restarts_in_window_zero() {
        let config = SupervisorConfig::default();
        let tracker = RestartTracker::new(config);
        assert_eq!(tracker.restarts_in_window(Instant::now()), 0);
        assert_eq!(tracker.total_restarts(), 0);
    }

    #[test]
    fn tracker_history_attempt_numbers_sequential() {
        let config = SupervisorConfig {
            max_restarts: 10,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();
        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();
        let hist = tracker.history();
        assert_eq!(hist[0].attempt, 1);
        assert_eq!(hist[1].attempt, 2);
        assert_eq!(hist[2].attempt, 3);
    }

    #[test]
    fn tracker_history_records_previous_exit() {
        let config = SupervisorConfig {
            max_restarts: 5,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_signal(11);
        tracker.evaluate_restart(&exit, Instant::now()).unwrap();
        assert_eq!(tracker.history()[0].previous_exit, exit);
    }

    #[test]
    fn tracker_max_restarts_zero_always_denied() {
        let config = SupervisorConfig {
            max_restarts: 0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let result = tracker.evaluate_restart(&ProcessExit::with_code(1), Instant::now());
        assert!(matches!(
            result,
            Err(RestartDenied::MaxRestartsExceeded { count: 0, .. })
        ));
    }

    #[test]
    fn tracker_window_boundary_exact_expired() {
        let window = Duration::from_secs(5);
        let config = SupervisorConfig {
            max_restarts: 1,
            restart_window: window,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let start = Instant::now();

        // Use up the one allowed restart.
        tracker.evaluate_restart(&exit, start).unwrap();

        // Exactly at boundary (start + window): event at start is at boundary.
        // window_start = now - window = start + window - window = start
        // event.timestamp == start >= window_start, so still in window → denied.
        let at_boundary = start + window;
        let result = tracker.evaluate_restart(&exit, at_boundary);
        assert!(result.is_err());

        // One tick past the boundary → event expires.
        let past_boundary = start + window + Duration::from_nanos(1);
        let result2 = tracker.evaluate_restart(&exit, past_boundary);
        assert!(result2.is_ok());
    }

    #[test]
    fn tracker_total_restarts_includes_pruned_history() {
        let config = SupervisorConfig {
            max_restarts: 10,
            restart_window: Duration::from_secs(5),
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let start = Instant::now();

        tracker.evaluate_restart(&exit, start).unwrap();
        tracker
            .evaluate_restart(&exit, start + Duration::from_secs(1))
            .unwrap();

        let later = start + Duration::from_secs(10);
        tracker.evaluate_restart(&exit, later).unwrap();

        assert_eq!(tracker.restarts_in_window(later), 1);
        assert_eq!(tracker.history().len(), 1);
        assert_eq!(tracker.total_restarts(), 3);
    }

    #[test]
    fn tracker_record_successful_start_resets_backoff_after_multiple() {
        let config = SupervisorConfig {
            max_restarts: 20,
            initial_backoff: Duration::from_millis(50),
            backoff_multiplier: 2.0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        // Five restarts — backoff builds up.
        for _ in 0..5 {
            tracker.evaluate_restart(&exit, now).unwrap();
        }
        // Reset via successful start.
        tracker.record_successful_start();
        // Next restart should use initial backoff.
        let delay = tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(delay, Duration::from_millis(50));
    }

    #[test]
    fn tracker_matches_supervisor_restart_policy_golden_vector() {
        let vector: RestartPolicyGoldenVector = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/host/supervisor_restart_policy.json"
        )))
        .unwrap();

        let config = SupervisorConfig {
            restart_policy: RestartPolicy::OnCrash,
            max_restarts: vector.policy.max_restarts,
            restart_window: Duration::from_secs(vector.policy.window_seconds),
            initial_backoff: Duration::from_millis(vector.policy.backoff_base_ms),
            max_backoff: Duration::from_millis(vector.policy.backoff_max_ms),
            backoff_multiplier: vector.policy.backoff_multiplier,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let start = Instant::now();

        for (index, crash) in vector.crashes.iter().enumerate() {
            let now = start + Duration::from_millis(crash.at_ms);
            let result = tracker.evaluate_restart(&ProcessExit::with_signal(11), now);

            match result {
                Ok(delay) => {
                    assert!(
                        crash.restart,
                        "golden vector step {index} expected restart denial but restart was allowed"
                    );
                    assert_eq!(
                        Some(delay.as_millis()),
                        crash.delay_ms.map(u128::from),
                        "golden vector step {index} produced unexpected restart delay"
                    );
                    assert_eq!(
                        tracker.history().back().map(|event| event.timestamp),
                        Some(now),
                        "golden vector step {index} did not record the expected restart instant"
                    );
                }
                Err(denied) => {
                    assert!(
                        !crash.restart,
                        "golden vector step {index} expected restart but supervisor denied it: {denied}"
                    );
                    assert_eq!(
                        crash.reason.as_deref(),
                        Some(match denied {
                            RestartDenied::PolicyDenied => "policy_denied",
                            RestartDenied::MaxRestartsExceeded { .. } => {
                                "max_restarts_exceeded"
                            }
                        }),
                        "golden vector step {index} produced an unexpected denial reason"
                    );
                }
            }
        }

        let allowed_restarts = vector.crashes.iter().filter(|crash| crash.restart).count();
        assert_eq!(tracker.total_restarts(), allowed_restarts);
    }

    #[test]
    fn restart_denied_display_policy() {
        let denied = RestartDenied::PolicyDenied;
        assert!(denied.to_string().contains("policy"));
    }

    #[test]
    fn restart_denied_display_max_exceeded() {
        let denied = RestartDenied::MaxRestartsExceeded {
            count: 3,
            window: Duration::from_secs(10),
        };
        let s = denied.to_string();
        assert!(s.contains('3'));
        assert!(s.contains("10"));
    }

    // ── Additional ShutdownCoordinator tests ──

    #[test]
    fn shutdown_coordinator_zero_timeout_immediately_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::ZERO);
        let now = Instant::now();
        coordinator.start_graceful(now);
        // With zero timeout, should_force_kill at same instant.
        assert!(coordinator.should_force_kill(now));
    }

    #[test]
    fn shutdown_not_shutting_down_when_not_started() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        assert!(!coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
    }

    #[test]
    fn shutdown_force_kill_phase_not_shutting_down_as_bool() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        coordinator.record_force_kill(now + Duration::from_secs(2));
        // ForceKill phase IS considered shutting down.
        assert!(coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
    }

    #[test]
    fn shutdown_complete_not_shutting_down() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        coordinator.start_graceful(Instant::now());
        coordinator.record_exit(ProcessExit::with_code(0));
        assert!(!coordinator.is_shutting_down());
        assert!(coordinator.is_complete());
    }

    #[test]
    fn shutdown_record_exit_from_not_started() {
        // Can record exit directly without going through graceful.
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        coordinator.record_exit(ProcessExit::with_signal(9));
        assert!(coordinator.is_complete());
        assert!(!coordinator.is_shutting_down());
    }

    #[test]
    fn shutdown_force_kill_from_complete_is_noop() {
        // record_force_kill only applies when in GracefulWait.
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        coordinator.record_exit(ProcessExit::clean());
        coordinator.record_force_kill(Instant::now());
        // Still complete.
        assert!(coordinator.is_complete());
    }

    #[test]
    fn shutdown_start_graceful_after_force_kill_is_noop() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        coordinator.record_force_kill(now + Duration::from_secs(2));
        let later = now + Duration::from_secs(3);
        coordinator.start_graceful(later); // Should be no-op.
        // Still in ForceKill, not GracefulWait.
        assert!(matches!(
            coordinator.phase(),
            ShutdownPhase::ForceKill { .. }
        ));
    }

    // ── Additional HealthCheckScheduler tests ──

    #[test]
    fn health_scheduler_max_failures_zero_always_unhealthy_after_one() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(5))
                .with_max_failures(0);
        // zero threshold — already at limit with no failures.
        assert!(scheduler.is_unhealthy());
        // After one failure, still unhealthy.
        scheduler.record_failure(Instant::now());
        assert!(scheduler.is_unhealthy());
    }

    #[test]
    fn health_scheduler_one_success_clears_all_failures() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(5))
                .with_max_failures(2);
        let now = Instant::now();
        scheduler.record_failure(now);
        scheduler.record_failure(now);
        assert!(scheduler.is_unhealthy());
        scheduler.record_success(now);
        assert!(!scheduler.is_unhealthy());
        assert_eq!(scheduler.consecutive_failures(), 0);
    }

    #[test]
    fn health_scheduler_time_until_next_zero_when_no_check() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(5));
        assert_eq!(scheduler.time_until_next(Instant::now()), Duration::ZERO);
    }

    #[test]
    fn health_scheduler_consecutive_failures_saturate_at_max() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(1), Duration::from_secs(1))
                .with_max_failures(3);
        let now = Instant::now();
        // Record 10 failures — saturating_add should prevent overflow.
        for _ in 0..10 {
            scheduler.record_failure(now);
        }
        assert_eq!(scheduler.consecutive_failures(), 10);
        assert!(scheduler.is_unhealthy());
    }

    #[test]
    fn health_scheduler_is_due_after_interval_passed() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(10), Duration::from_secs(5));
        let now = Instant::now();
        scheduler.record_success(now);
        // Not due immediately after.
        assert!(!scheduler.is_due(now));
        // Due after interval.
        let later = now + Duration::from_secs(11);
        assert!(scheduler.is_due(later));
    }

    #[test]
    fn health_scheduler_timeout_unchanged_by_record_calls() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(7));
        let now = Instant::now();
        scheduler.record_failure(now);
        scheduler.record_success(now);
        assert_eq!(scheduler.timeout(), Duration::from_secs(7));
    }

    // ── Additional ResourceLimits tests ──

    #[test]
    fn resource_limits_one_active_count() {
        let limits = ResourceLimits {
            memory_bytes: Some(100),
            cpu_seconds: None,
            max_fds: None,
            max_processes: None,
            max_file_size_bytes: None,
        };
        assert_eq!(limits.active_limit_count(), 1);
    }

    #[test]
    fn resource_limits_merge_strict_file_size() {
        let a = ResourceLimits {
            max_file_size_bytes: Some(1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let b = ResourceLimits {
            max_file_size_bytes: Some(512 * 1024),
            ..ResourceLimits::unlimited()
        };
        let merged = a.merge_strict(&b);
        assert_eq!(merged.max_file_size_bytes, Some(512 * 1024));
    }

    #[test]
    fn resource_limits_cpu_active_count() {
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        assert_eq!(limits.active_limit_count(), 1);
    }

    #[test]
    fn resource_limits_has_any_after_merge_unlimited_unlimited() {
        let a = ResourceLimits::unlimited();
        let b = ResourceLimits::unlimited();
        let merged = a.merge_strict(&b);
        assert!(!merged.has_any_limits());
    }

    // ── Additional ResourceUsage tests ──

    #[test]
    fn resource_usage_default_all_zero() {
        let usage = ResourceUsage::default();
        assert_eq!(usage.memory_bytes, 0);
        assert_eq!(usage.cpu_millis, 0);
        assert_eq!(usage.open_fds, 0);
        assert_eq!(usage.process_count, 0);
        assert_eq!(usage.file_size_bytes, 0);
    }

    #[test]
    fn resource_usage_cpu_not_violated_below_threshold() {
        // 59 seconds out of 60 limit — no violation.
        let usage = ResourceUsage {
            cpu_millis: 59_000,
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        assert!(usage.within_limits(&limits));
        assert!(usage.violations(&limits).is_empty());
    }

    #[test]
    fn resource_usage_cpu_not_violated_at_threshold() {
        let usage = ResourceUsage {
            cpu_millis: 60_000,
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        assert!(usage.within_limits(&limits));
        assert!(usage.violations(&limits).is_empty());
    }

    #[test]
    fn resource_usage_cpu_violation_subsecond_overflow() {
        let usage = ResourceUsage {
            cpu_millis: 1_500,
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(1),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::CpuTime);
        assert_eq!(violations[0].current, 2);
        assert_eq!(violations[0].limit, 1);
    }

    #[test]
    fn resource_usage_cpu_violation_display() {
        let usage = ResourceUsage {
            cpu_millis: 90_000,
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        let msg = violations[0].to_string();
        assert!(msg.contains("cpu_time"));
    }

    #[test]
    fn resource_usage_process_count_at_limit_no_violation() {
        let usage = ResourceUsage {
            process_count: 64,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_processes: Some(64),
            ..ResourceLimits::unlimited()
        };
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_fds_at_limit_no_violation() {
        let usage = ResourceUsage {
            open_fds: 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_fds: Some(1024),
            ..ResourceLimits::unlimited()
        };
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_utilization_cpu_computed() {
        let usage = ResourceUsage {
            cpu_millis: 30_000, // 30 seconds
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        let cpu = util.cpu.unwrap();
        assert!((cpu - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn resource_usage_utilization_processes_computed() {
        let usage = ResourceUsage {
            process_count: 32,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_processes: Some(64),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        let processes = util.processes.unwrap();
        assert!((processes - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn resource_usage_utilization_any_above_zero_threshold() {
        let usage = ResourceUsage {
            memory_bytes: 1, // tiny non-zero usage
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        // 1/1024 < 0.001, so not above 0.001 threshold.
        assert!(!util.any_above_threshold(0.001));
        // But above 0.0 threshold.
        assert!(util.any_above_threshold(0.0));
    }

    #[test]
    fn resource_violation_clone() {
        let v = ResourceViolation {
            resource: ResourceKind::Processes,
            current: 100,
            limit: 50,
        };
        let cloned = v.clone();
        assert_eq!(cloned.resource, ResourceKind::Processes);
        assert_eq!(cloned.current, 100);
        assert_eq!(v.limit, cloned.limit);
    }

    // ── ConnectionTracker edge cases ──

    #[test]
    fn connection_tracker_acquire_returns_none_when_draining() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        let guard = tracker.try_acquire();
        assert!(guard.is_none());
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_tracker_not_drained_without_start_drain() {
        let tracker = ConnectionTracker::new();
        // active == 0 but draining == false → not drained.
        assert!(!tracker.is_drained());
    }

    #[test]
    fn connection_tracker_single_acquire_then_drain_then_drop() {
        let tracker = ConnectionTracker::new();
        let g = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        tracker.start_drain();
        assert!(!tracker.is_drained());
        drop(g);
        assert_eq!(tracker.active_count(), 0);
        assert!(tracker.is_drained());
    }

    #[test]
    fn connection_tracker_acquire_fails_after_drain_even_with_zero_active() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        assert_eq!(tracker.active_count(), 0);
        assert!(tracker.try_acquire().is_none());
        // Still counts as drained.
        assert!(tracker.is_drained());
    }
}
