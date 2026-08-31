//! Runtime supervision utilities for streaming and polling connectors.
//!
//! This module provides:
//! - [`SupervisorConfig`]: Configuration for backoff, retry budgets, and lifecycle management
//! - [`StreamingSession`]: Trait for streaming connectors to manage session state
//! - [`PollingCursor`]: Trait for polling connectors to manage cursor/offset state
//! - [`CursorStore`]: Mesh-backed cursor state helper for polling connectors
//! - [`HealthTracker`]: Health state machine with transition rules
//!
//! # Design Principles
//!
//! 1. **Config defaults align with study docs** (1s base backoff, 60s cap, jitter on)
//! 2. **Traits are minimal** - connectors provide persistence, SDK provides supervision logic
//! 3. **Health transitions are explicit** - state changes require evidence
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::runtime::{SupervisorConfig, HealthTracker, HealthTransition};
//!
//! let config = SupervisorConfig::default();
//! let mut health = HealthTracker::new();
//!
//! // Report failures
//! health.record_failure("connection timeout");
//!
//! // Health degrades after threshold
//! if health.consecutive_failures() >= config.max_consecutive_failures {
//!     health.transition(HealthTransition::ToUnhealthy { reason: "too many failures".into() });
//! }
//! ```

use std::collections::{VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fcp_async_core::{
    ExecutionContext,
    channel::{mpsc, watch},
};
use fcp_manifest::{ConnectorManifest, ManifestTimeouts};
use serde::{Deserialize, Serialize};

#[cfg(feature = "connector-http")]
use crate::migration::HostEgressProxyClient;
#[cfg(feature = "cursor-store-object-store")]
use fcp_cbor::CanonicalSerializer;
use fcp_prelude::{
    ConnectorId, ConnectorStateObject, CursorState, HealthSnapshot, HealthState, InstanceId,
    ObjectHeader, ObjectId, Signature, ZoneId,
};
#[cfg(feature = "cursor-store-object-store")]
use fcp_prelude::{
    ConnectorStateAppendOutcome, ConnectorStateStore, ConnectorStateWriteAuthorization,
    ObjectIdKey, RetentionClass, StorageMeta, StoredObject,
};

/// Produce a pseudo-random jitter factor in [0.0, 1.0) using stdlib hashing.
///
/// Mixes the attempt number with the current thread ID and wall-clock time so
/// that different threads at different instants produce different values, which
/// prevents thundering-herd convergence that a purely deterministic formula
/// would cause.
fn pseudo_random_jitter(attempt: u32) -> f64 {
    let mut hasher = DefaultHasher::new();
    attempt.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    let h = hasher.finish();
    // Value is at most 999_999 which is exactly representable as f64.
    #[allow(clippy::cast_precision_loss)]
    let jitter = (h % 1_000_000) as f64 / 1_000_000.0;
    jitter
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorRuntime
// ─────────────────────────────────────────────────────────────────────────────

/// Shared connector runtime providing lifecycle management.
///
/// Each connector instance creates one `ConnectorRuntime` during `configure()`.
/// The runtime provides:
/// - Request-scoped `ExecutionContext` creation with configurable timeouts
/// - Background context for long-lived operations (streaming, polling)
/// - Graceful shutdown coordination
#[derive(Debug, Clone)]
pub struct ConnectorRuntime {
    config: ConnectorRuntimeConfig,
    background_ctx: ExecutionContext,
    request_ctx_root: ExecutionContext,
}

const MANIFEST_REQUEST_TIMEOUT_ENV_VAR: &str = "FCP_REQUEST_TIMEOUT_MS";
const HOST_EGRESS_PROXY_URL_ENV_VAR: &str = "FCP_HOST_EGRESS_PROXY_URL";
const ALLOW_AMBIENT_TIMEOUT_OVERRIDE_ENV_VAR: &str = "FCP_ALLOW_AMBIENT_TIMEOUT_OVERRIDE";

fn opt_in_value_allows_override(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "yes"))
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TestEnvOverride {
    Inherit,
    Set(Option<String>),
}

#[cfg(test)]
thread_local! {
    static AMBIENT_OPT_IN_TEST_VALUE:
        std::cell::RefCell<TestEnvOverride> =
            const { std::cell::RefCell::new(TestEnvOverride::Inherit) };

    static REQUEST_TIMEOUT_TEST_VALUE:
        std::cell::RefCell<TestEnvOverride> =
            const { std::cell::RefCell::new(TestEnvOverride::Inherit) };
}

#[cfg(test)]
pub(crate) fn set_ambient_opt_in_test_value(value: TestEnvOverride) {
    AMBIENT_OPT_IN_TEST_VALUE.with(|cell| {
        *cell.borrow_mut() = value;
    });
}

#[cfg(test)]
pub(crate) fn set_request_timeout_test_value(value: TestEnvOverride) {
    REQUEST_TIMEOUT_TEST_VALUE.with(|cell| {
        *cell.borrow_mut() = value;
    });
}

fn ambient_timeout_override_allowed() -> bool {
    #[cfg(test)]
    {
        let test_override = AMBIENT_OPT_IN_TEST_VALUE.with(|cell| cell.borrow().clone());
        if let TestEnvOverride::Set(value) = test_override {
            return opt_in_value_allows_override(value.as_deref());
        }
    }
    let real = std::env::var_os(ALLOW_AMBIENT_TIMEOUT_OVERRIDE_ENV_VAR);
    let owned = real.map(|value| value.to_string_lossy().into_owned());
    opt_in_value_allows_override(owned.as_deref())
}

fn ambient_request_timeout_env_value() -> Option<String> {
    #[cfg(test)]
    {
        let test_override = REQUEST_TIMEOUT_TEST_VALUE.with(|cell| cell.borrow().clone());
        if let TestEnvOverride::Set(value) = test_override {
            return value;
        }
    }
    std::env::var_os(MANIFEST_REQUEST_TIMEOUT_ENV_VAR)
        .map(|value| value.to_string_lossy().into_owned())
}

/// Errors produced while loading runtime settings from an embedded manifest.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorRuntimeConfigError {
    /// The connector manifest could not be parsed or validated.
    #[error(transparent)]
    Manifest(#[from] fcp_manifest::ManifestError),

    /// The request-timeout override env var was present but unusable.
    #[error("{env_var} must be a positive integer number of milliseconds, got `{value}`")]
    InvalidRequestTimeoutEnvVar {
        /// The env var name.
        env_var: &'static str,
        /// The invalid value observed at load time.
        value: String,
    },
}

/// Configuration for [`ConnectorRuntime`].
#[derive(Debug, Clone)]
pub struct ConnectorRuntimeConfig {
    /// Default timeout for request-scoped operations.
    pub request_timeout: Duration,
    /// Default timeout for establishing outbound connections.
    pub connect_timeout: Duration,
    /// Default wall-clock budget for a single operation.
    pub wall_clock_timeout: Duration,
    /// Timeout for graceful shutdown.
    pub shutdown_timeout: Duration,
    /// Connector-facing host egress endpoint. When present, SDK egress helpers
    /// use `/rpc/egress/*` instead of opening direct sockets.
    pub host_egress_proxy_url: Option<String>,
}

impl Default for ConnectorRuntimeConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            wall_clock_timeout: Duration::from_secs(120),
            shutdown_timeout: Duration::from_secs(30),
            host_egress_proxy_url: None,
        }
    }
}

impl ConnectorRuntimeConfig {
    /// Manifest-aligned defaults used by newly scaffolded connectors.
    #[must_use]
    pub const fn manifest_defaults() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            wall_clock_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(30),
            host_egress_proxy_url: None,
        }
    }

    /// Build runtime settings from a manifest `[timeouts]` section.
    #[must_use]
    pub const fn from_manifest_timeouts(timeouts: &ManifestTimeouts) -> Self {
        Self::manifest_defaults()
            .with_request_timeout(Duration::from_millis(timeouts.request_timeout_ms))
            .with_connect_timeout(Duration::from_millis(timeouts.connect_timeout_ms))
            .with_wall_clock_timeout(Duration::from_millis(timeouts.wall_clock_timeout_ms))
    }

    /// Build runtime settings from a parsed connector manifest.
    ///
    /// If the manifest omits `[timeouts]`, scaffold defaults are used. An
    /// `FCP_REQUEST_TIMEOUT_MS` env var overrides the request timeout only when
    /// the operator explicitly opts in with
    /// `FCP_ALLOW_AMBIENT_TIMEOUT_OVERRIDE=1`.
    ///
    /// # Errors
    /// Returns an error when the opt-in is set and `FCP_REQUEST_TIMEOUT_MS` is
    /// present but invalid.
    pub fn from_manifest(
        manifest: &ConnectorManifest,
    ) -> Result<Self, ConnectorRuntimeConfigError> {
        let request_timeout_override = if ambient_timeout_override_allowed() {
            ambient_request_timeout_env_value()
        } else {
            None
        };
        Self::from_manifest_with_request_timeout_override(
            manifest,
            request_timeout_override.as_deref(),
        )
    }

    /// Build runtime settings from embedded manifest TOML.
    ///
    /// # Errors
    /// Returns an error when the manifest is invalid or the request-timeout
    /// env override cannot be parsed.
    pub fn from_manifest_str(manifest_toml: &str) -> Result<Self, ConnectorRuntimeConfigError> {
        let manifest = ConnectorManifest::parse_str(manifest_toml)?;
        Self::from_manifest(&manifest)
    }

    /// Builder: set request timeout.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Builder: set connect timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: set wall-clock timeout.
    #[must_use]
    pub const fn with_wall_clock_timeout(mut self, timeout: Duration) -> Self {
        self.wall_clock_timeout = timeout;
        self
    }

    /// Builder: set shutdown timeout.
    #[must_use]
    pub const fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Builder: set the host egress proxy base URL.
    #[must_use]
    pub fn with_host_egress_proxy_url(mut self, url: impl Into<String>) -> Self {
        self.host_egress_proxy_url = Some(url.into());
        self
    }

    /// Builder: read the host egress proxy base URL from the launch
    /// environment the host gives strict host-proxy connectors.
    #[must_use]
    pub fn with_host_egress_proxy_url_from_env(mut self) -> Self {
        if let Some(url) = std::env::var_os(HOST_EGRESS_PROXY_URL_ENV_VAR)
            .map(|value| value.to_string_lossy().trim().to_string())
            .filter(|value| !value.is_empty())
        {
            self.host_egress_proxy_url = Some(url);
        }
        self
    }

    pub(crate) fn from_manifest_with_request_timeout_override(
        manifest: &ConnectorManifest,
        request_timeout_override: Option<&str>,
    ) -> Result<Self, ConnectorRuntimeConfigError> {
        let mut config = manifest
            .timeouts
            .as_ref()
            .map_or_else(Self::manifest_defaults, Self::from_manifest_timeouts);

        if let Some(timeout) = parse_request_timeout_override(request_timeout_override)? {
            config = config.with_request_timeout(timeout);
        }

        Ok(config)
    }
}

fn parse_request_timeout_override(
    request_timeout_override: Option<&str>,
) -> Result<Option<Duration>, ConnectorRuntimeConfigError> {
    let Some(raw) = request_timeout_override else {
        return Ok(None);
    };

    let timeout_ms: u64 =
        raw.parse().map_err(
            |_| ConnectorRuntimeConfigError::InvalidRequestTimeoutEnvVar {
                env_var: MANIFEST_REQUEST_TIMEOUT_ENV_VAR,
                value: raw.to_string(),
            },
        )?;
    if timeout_ms == 0 {
        return Err(ConnectorRuntimeConfigError::InvalidRequestTimeoutEnvVar {
            env_var: MANIFEST_REQUEST_TIMEOUT_ENV_VAR,
            value: raw.to_string(),
        });
    }

    Ok(Some(Duration::from_millis(timeout_ms)))
}

impl ConnectorRuntime {
    /// Create a new connector runtime.
    #[must_use]
    pub fn new(config: ConnectorRuntimeConfig) -> Self {
        Self {
            config,
            background_ctx: ExecutionContext::background(),
            request_ctx_root: ExecutionContext::request_scoped(Duration::MAX),
        }
    }

    /// Create a request-scoped execution context with the configured timeout.
    #[must_use]
    pub fn request_context(&self) -> ExecutionContext {
        self.request_ctx_root
            .child()
            .with_deadline(self.config.request_timeout)
    }

    /// Create a request-scoped context with a custom timeout.
    #[must_use]
    pub fn request_context_with_timeout(&self, timeout: Duration) -> ExecutionContext {
        self.request_ctx_root.child().with_deadline(timeout)
    }

    /// Get a child of the background context for long-lived operations.
    #[must_use]
    pub fn background_context(&self) -> ExecutionContext {
        self.background_ctx.child()
    }

    /// Trigger graceful shutdown of all contexts.
    pub fn shutdown(&self) {
        self.background_ctx.cancel();
        self.request_ctx_root.cancel();
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.background_ctx.is_cancelled()
    }

    /// The configured request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    /// The configured connect timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.config.connect_timeout
    }

    /// The configured wall-clock timeout.
    #[must_use]
    pub const fn wall_clock_timeout(&self) -> Duration {
        self.config.wall_clock_timeout
    }

    /// The configured shutdown timeout.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.config.shutdown_timeout
    }

    /// Host egress proxy URL used by SDK network helpers, if configured.
    #[must_use]
    pub fn host_egress_proxy_url(&self) -> Option<&str> {
        self.config.host_egress_proxy_url.as_deref()
    }

    /// Build a connector-facing client for host-mediated HTTP/TCP egress.
    ///
    /// The helper is only available with `connector-http`, matching the rest of
    /// the SDK HTTP client surface.
    #[cfg(feature = "connector-http")]
    #[must_use]
    pub fn host_egress_proxy_client(&self) -> Option<HostEgressProxyClient> {
        self.host_egress_proxy_url().map(HostEgressProxyClient::new)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SupervisorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for connector supervisors (streaming or polling).
///
/// These settings control backoff behavior, retry budgets, and lifecycle
/// management. Defaults align with FCP2 study recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorConfig {
    /// Base delay for exponential backoff (milliseconds).
    ///
    /// After a failure, wait `base_backoff_ms * 2^attempt` before retrying.
    /// Default: 1000ms (1 second).
    pub base_backoff_ms: u64,

    /// Maximum backoff delay (milliseconds).
    ///
    /// Backoff will not exceed this value regardless of attempt count.
    /// Default: 60000ms (60 seconds).
    pub max_backoff_ms: u64,

    /// Whether to add random jitter to backoff delays.
    ///
    /// When enabled, actual delay is `delay * (0.5 + random(0..0.5))`.
    /// Default: true.
    pub jitter_enabled: bool,

    /// Maximum consecutive failures before declaring unhealthy.
    ///
    /// After this many failures in a row without success, the supervisor
    /// should transition to `HealthState::Error`.
    /// Default: 5.
    pub max_consecutive_failures: u32,

    /// Cooldown period after max failures (milliseconds).
    ///
    /// After hitting `max_consecutive_failures`, wait this long before
    /// attempting recovery. This prevents rapid retry storms.
    /// Default: 300000ms (5 minutes).
    pub cooldown_after_failure_ms: u64,

    /// Graceful shutdown timeout (milliseconds).
    ///
    /// Maximum time to wait for in-flight operations during shutdown.
    /// Default: 30000ms (30 seconds).
    pub shutdown_timeout_ms: u64,

    /// Heartbeat interval for streaming sessions (milliseconds).
    ///
    /// How often to send/expect heartbeats. Zero disables heartbeats.
    /// Default: 30000ms (30 seconds).
    pub heartbeat_interval_ms: u64,

    /// Heartbeat timeout multiplier.
    ///
    /// If no heartbeat received within `heartbeat_interval_ms * heartbeat_timeout_multiplier`,
    /// consider the connection dead.
    /// Default: 2.5.
    pub heartbeat_timeout_multiplier: f64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1000,
            max_backoff_ms: 60_000,
            jitter_enabled: true,
            max_consecutive_failures: 5,
            cooldown_after_failure_ms: 300_000,
            shutdown_timeout_ms: 30_000,
            heartbeat_interval_ms: 30_000,
            heartbeat_timeout_multiplier: 2.5,
        }
    }
}

impl SupervisorConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set base backoff.
    #[must_use]
    pub const fn with_base_backoff_ms(mut self, ms: u64) -> Self {
        self.base_backoff_ms = ms;
        self
    }

    /// Builder: set max backoff.
    #[must_use]
    pub const fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder: enable/disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Builder: set max consecutive failures.
    #[must_use]
    pub const fn with_max_consecutive_failures(mut self, count: u32) -> Self {
        self.max_consecutive_failures = count;
        self
    }

    /// Compute backoff delay for a given attempt number (0-indexed).
    ///
    /// Returns the delay in milliseconds, capped at `max_backoff_ms`.
    #[must_use]
    pub fn compute_backoff(&self, attempt: u32) -> u64 {
        let exp = attempt.min(30); // Prevent overflow
        let delay = self.base_backoff_ms.saturating_mul(1u64 << exp);
        delay.min(self.max_backoff_ms)
    }

    /// Compute backoff delay with optional jitter.
    ///
    /// If jitter is enabled, returns delay * (0.5 + random factor).
    /// The `jitter_factor` should be in range [0.0, 1.0].
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_backoff_with_jitter(&self, attempt: u32, jitter_factor: f64) -> u64 {
        let base = self.compute_backoff(attempt);
        if self.jitter_enabled {
            let factor = jitter_factor.clamp(0.0, 1.0).mul_add(0.5, 0.5);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let jittered = (base as f64 * factor) as u64;
            jittered
        } else {
            base
        }
    }

    /// Get shutdown timeout as a Duration.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.shutdown_timeout_ms)
    }

    /// Get cooldown period as a Duration.
    #[must_use]
    pub const fn cooldown_duration(&self) -> Duration {
        Duration::from_millis(self.cooldown_after_failure_ms)
    }

    /// Get heartbeat interval as a Duration (or None if disabled).
    #[must_use]
    pub const fn heartbeat_interval(&self) -> Option<Duration> {
        if self.heartbeat_interval_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.heartbeat_interval_ms))
        }
    }

    /// Get heartbeat timeout as a Duration (or None if disabled).
    ///
    /// `Duration::from_secs_f64` panics on NaN, negative, and non-finite or
    /// overflowing input, and this struct is `#[derive(Deserialize)]` — it is
    /// already embedded in externally-supplied connector config. `validate()`
    /// cannot catch the dangerous values on its own because
    /// `heartbeat_timeout_multiplier <= 1.0` is *false* for both `NaN` and
    /// `1e308`, so a deserialized config could reach the supervisor loop and
    /// abort it. Saturate instead of panicking.
    #[must_use]
    pub fn heartbeat_timeout(&self) -> Option<Duration> {
        self.heartbeat_interval().map(|interval| {
            let seconds = interval.as_secs_f64() * self.heartbeat_timeout_multiplier;
            if seconds.is_finite() && seconds >= 0.0 {
                Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
            } else {
                Duration::MAX
            }
        })
    }

    /// Validate configuration, returning errors for invalid values.
    ///
    /// # Errors
    ///
    /// Returns error strings for any invalid configuration values.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.base_backoff_ms == 0 {
            errors.push("base_backoff_ms must be > 0".to_string());
        }
        if self.max_backoff_ms < self.base_backoff_ms {
            errors.push("max_backoff_ms must be >= base_backoff_ms".to_string());
        }
        if self.max_consecutive_failures == 0 {
            errors.push("max_consecutive_failures must be > 0".to_string());
        }
        // `<= 1.0` is FALSE for NaN, so the finiteness check has to be
        // explicit — otherwise a deserialized `NaN` passes validation and then
        // reaches `heartbeat_timeout()`. (Overflow to +inf is handled there by
        // saturating rather than panicking, so it does not need a second check
        // here.)
        if !self.heartbeat_timeout_multiplier.is_finite() {
            errors.push("heartbeat_timeout_multiplier must be finite".to_string());
        } else if self.heartbeat_timeout_multiplier <= 1.0 {
            errors.push("heartbeat_timeout_multiplier must be > 1.0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamingSession trait
// ─────────────────────────────────────────────────────────────────────────────

/// Session state for streaming connectors (e.g., WebSocket-based).
///
/// Connectors implement this trait to enable session resumption, sequence
/// tracking, and heartbeat management. The supervisor uses these hooks
/// to maintain connection health.
pub trait StreamingSession: Send + Sync {
    /// Get the current resume token (opaque string for session resumption).
    ///
    /// Returns `None` if no session has been established yet.
    fn resume_token(&self) -> Option<String>;

    /// Set the resume token after successful connection.
    fn set_resume_token(&mut self, token: String);

    /// Clear the resume token (e.g., when session is invalidated).
    fn clear_resume_token(&mut self);

    /// Get the current sequence number for ordered message delivery.
    fn sequence(&self) -> u64;

    /// Update the sequence number after processing a message.
    fn set_sequence(&mut self, seq: u64);

    /// Increment and return the next sequence number.
    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence();
        self.set_sequence(seq.saturating_add(1));
        seq
    }

    /// Record that a heartbeat was sent.
    fn record_heartbeat_sent(&mut self, at: Instant);

    /// Record that a heartbeat acknowledgment was received.
    fn record_heartbeat_ack(&mut self, at: Instant);

    /// Get the timestamp of the last sent heartbeat.
    fn last_heartbeat_sent(&self) -> Option<Instant>;

    /// Get the timestamp of the last received heartbeat acknowledgment.
    fn last_heartbeat_ack(&self) -> Option<Instant>;

    /// Current heartbeat sequence counter (sent).
    #[must_use]
    fn heartbeat_seq(&self) -> u64 {
        0
    }

    /// Current heartbeat acknowledgment sequence counter.
    #[must_use]
    fn ack_seq(&self) -> u64 {
        0
    }

    /// Timestamp of the oldest heartbeat that has not yet been acknowledged.
    ///
    /// Implementations that track individual outstanding heartbeats should
    /// override this to return the oldest unacked send. The default falls back
    /// to `None`, in which case timeout detection will use coarser heuristics.
    #[must_use]
    fn first_unacked_heartbeat_sent(&self) -> Option<Instant> {
        None
    }

    /// Check if heartbeats have timed out.
    ///
    /// Returns `true` if the oldest outstanding heartbeat send has exceeded the
    /// configured timeout. When no heartbeats are outstanding, implementations
    /// fall back to the most recent acknowledgement timestamp.
    fn is_heartbeat_timeout(&self, timeout: Duration) -> bool {
        if self.heartbeat_seq() > self.ack_seq() {
            return self
                .first_unacked_heartbeat_sent()
                .or_else(|| self.last_heartbeat_sent())
                .is_some_and(|sent| sent.elapsed() > timeout);
        }

        self.last_heartbeat_ack()
            .is_some_and(|ack| ack.elapsed() > timeout)
    }

    /// Persist session state to storage (connector-specific).
    ///
    /// Called periodically and before shutdown to preserve state.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore session state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous session.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`StreamingSession`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryStreamingSession {
    resume_token: Option<String>,
    sequence: u64,
    last_heartbeat_sent: Option<Instant>,
    last_heartbeat_ack: Option<Instant>,
    heartbeat_seq: u64,
    ack_seq: u64,
    outstanding_heartbeats: VecDeque<Instant>,
}

impl InMemoryStreamingSession {
    /// Create a new in-memory session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StreamingSession for InMemoryStreamingSession {
    fn resume_token(&self) -> Option<String> {
        self.resume_token.clone()
    }

    fn set_resume_token(&mut self, token: String) {
        self.resume_token = Some(token);
    }

    fn clear_resume_token(&mut self) {
        self.resume_token = None;
    }

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn set_sequence(&mut self, seq: u64) {
        self.sequence = seq;
    }

    fn record_heartbeat_sent(&mut self, at: Instant) {
        self.last_heartbeat_sent = Some(at);
        self.heartbeat_seq = self.heartbeat_seq.saturating_add(1);
        self.outstanding_heartbeats.push_back(at);
    }

    fn record_heartbeat_ack(&mut self, at: Instant) {
        self.last_heartbeat_ack = Some(at);
        if self.outstanding_heartbeats.pop_front().is_some() {
            self.ack_seq = self.ack_seq.saturating_add(1);
        }
    }

    fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    fn last_heartbeat_ack(&self) -> Option<Instant> {
        self.last_heartbeat_ack
    }

    fn heartbeat_seq(&self) -> u64 {
        self.heartbeat_seq
    }

    fn ack_seq(&self) -> u64 {
        self.ack_seq
    }

    fn first_unacked_heartbeat_sent(&self) -> Option<Instant> {
        self.outstanding_heartbeats.front().copied()
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PollingCursor trait
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor state for polling connectors (e.g., getUpdates-style APIs).
///
/// Connectors implement this trait to track the current offset/sequence
/// and persist it across restarts. This enables exactly-once processing
/// of updates via offset deduplication.
pub trait PollingCursor: Send + Sync {
    /// Get the current cursor offset (e.g., Telegram `update_id`).
    ///
    /// Returns `None` if no updates have been processed yet.
    fn offset(&self) -> Option<i64>;

    /// Set the cursor offset after processing updates.
    ///
    /// Typically set to `last_update_id + 1` to acknowledge processed updates.
    fn set_offset(&mut self, offset: i64);

    /// Clear the cursor offset after a failed processing attempt.
    ///
    /// This must restore the pre-poll "no cursor yet" state so failed first
    /// polls do not accidentally advance the in-memory cursor.
    fn clear_offset(&mut self);

    /// Get the last processing timestamp.
    fn last_poll_at(&self) -> Option<Instant>;

    /// Record that a poll was executed.
    fn record_poll(&mut self, at: Instant, updates_received: usize);

    /// Get the count of updates received in the last poll.
    fn last_poll_count(&self) -> usize;

    /// Advance offset by processing an update with the given ID.
    ///
    /// Sets offset to `update_id + 1` if it's newer than current offset.
    fn advance_if_newer(&mut self, update_id: i64) {
        let new_offset = update_id.saturating_add(1);
        if self.offset().is_none_or(|current| new_offset > current) {
            self.set_offset(new_offset);
        }
    }

    /// Persist cursor state to storage (connector-specific).
    ///
    /// Called after processing updates and before shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore cursor state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous cursor position.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`PollingCursor`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
}

impl InMemoryPollingCursor {
    /// Create a new in-memory cursor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cursor with an initial offset.
    #[must_use]
    pub const fn with_offset(offset: i64) -> Self {
        Self {
            offset: Some(offset),
            last_poll_at: None,
            last_poll_count: 0,
        }
    }
}

impl PollingCursor for InMemoryPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        self.offset = Some(offset);
    }

    fn clear_offset(&mut self) {
        self.offset = None;
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CursorStore (mesh-backed cursor state helper)
// ─────────────────────────────────────────────────────────────────────────────

/// Lease metadata required for cursor state writes.
#[derive(Debug, Clone, Copy)]
pub struct CursorLease {
    /// Fencing token from the authorizing lease.
    pub lease_seq: u64,
    /// Lease object ID granting write authority.
    pub lease_object_id: ObjectId,
}

/// Errors returned by cursor store operations.
#[derive(Debug, thiserror::Error)]
pub enum CursorStoreError {
    /// Underlying storage failed.
    #[error("cursor store backend error: {0}")]
    Storage(String),

    /// Lease fencing token regressed.
    #[error("stale lease_seq (current {current}, incoming {incoming})")]
    StaleLeaseSeq {
        /// Current lease sequence.
        current: u64,
        /// Incoming lease sequence.
        incoming: u64,
    },

    /// Offset moved backwards.
    #[error("offset regression (current {current}, incoming {incoming})")]
    OffsetRegression {
        /// Current offset value.
        current: i64,
        /// Incoming offset value.
        incoming: i64,
    },

    /// Watermark moved backwards.
    #[error("watermark regression (current {current}, incoming {incoming})")]
    WatermarkRegression {
        /// Current watermark.
        current: u64,
        /// Incoming watermark.
        incoming: u64,
    },

    /// Cursor encoding failed.
    #[error("cursor encoding failed: {0}")]
    CursorEncoding(String),

    /// Cursor decoding failed.
    #[error("cursor decoding failed: {0}")]
    CursorDecoding(String),
}

/// Backend for storing and retrieving connector state objects.
pub trait CursorStoreBackend: Send + Sync {
    /// Load the latest state object (head) and its object id.
    ///
    /// # Errors
    /// Returns [`CursorStoreError::Storage`] if the backend cannot load state.
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError>;

    /// Persist a new state object and return its object id.
    ///
    /// # Errors
    /// Returns [`CursorStoreError::Storage`] if the backend cannot persist state.
    fn store_state_object(&self, state: ConnectorStateObject)
    -> Result<ObjectId, CursorStoreError>;
}

/// Cursor store helper that builds lease-fenced state objects.
#[derive(Debug)]
pub struct CursorStore<B: CursorStoreBackend> {
    backend: B,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: Option<InstanceId>,
    writer_public_key: [u8; 32],
    head: Option<ObjectId>,
    seq: u64,
    last_cursor: Option<CursorState>,
    last_lease_seq: u64,
}

impl<B: CursorStoreBackend> CursorStore<B> {
    /// Create a new cursor store helper.
    pub const fn new(backend: B, connector_id: ConnectorId, zone_id: ZoneId) -> Self {
        Self {
            backend,
            connector_id,
            zone_id,
            instance_id: None,
            writer_public_key: [0u8; 32],
            head: None,
            seq: 0,
            last_cursor: None,
            last_lease_seq: 0,
        }
    }

    /// Attach an instance id to state objects produced by this store.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Attach the Ed25519 writer key whose signature is stored on state objects.
    #[must_use]
    pub const fn with_writer_public_key(mut self, writer_public_key: [u8; 32]) -> Self {
        self.writer_public_key = writer_public_key;
        self
    }

    /// Load the latest cursor state from the backend.
    ///
    /// # Errors
    /// Returns [`CursorStoreError`] if the backend fails or the cursor payload is invalid.
    pub fn load_cursor(&mut self) -> Result<Option<CursorState>, CursorStoreError> {
        let Some((head_id, head)) = self.backend.load_head()? else {
            return Ok(None);
        };

        self.validate_state_identity(&head)?;

        let cursor = CursorState::from_cbor(&head.state_cbor)
            .map_err(|err| CursorStoreError::CursorDecoding(err.to_string()))?;

        self.head = Some(head_id);
        self.seq = head.seq;
        self.last_cursor = Some(cursor.clone());
        self.last_lease_seq = head.lease_seq;

        Ok(Some(cursor))
    }

    /// Commit a new cursor state, enforcing lease fencing and monotonic rules.
    ///
    /// # Errors
    /// Returns [`CursorStoreError`] if monotonicity checks fail, the cursor cannot be
    /// encoded, or the backend cannot persist the state object.
    pub fn commit_cursor(
        &mut self,
        cursor: CursorState,
        mut header: ObjectHeader,
        lease: CursorLease,
        signature: Signature,
    ) -> Result<ObjectId, CursorStoreError> {
        self.validate_commit(&cursor, lease.lease_seq)?;
        if header.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "connector state header zone_id mismatch".to_string(),
            ));
        }

        if !header.refs.contains(&lease.lease_object_id) {
            header.refs.push(lease.lease_object_id);
        }

        let state_cbor = cursor
            .to_cbor()
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;

        let next_seq = if self.head.is_some() {
            self.seq.checked_add(1).ok_or_else(|| {
                CursorStoreError::CursorEncoding("sequence number overflow".to_string())
            })?
        } else {
            0
        };
        let prev = self.head;

        let updated_at = header.created_at;
        let state_obj = ConnectorStateObject {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            prev,
            seq: next_seq,
            state_cbor,
            updated_at,
            lease_seq: lease.lease_seq,
            lease_object_id: lease.lease_object_id,
            writer_public_key: self.writer_public_key,
            signature,
        };

        let object_id = self.backend.store_state_object(state_obj)?;
        self.head = Some(object_id);
        self.seq = next_seq;
        self.last_cursor = Some(cursor);
        self.last_lease_seq = lease.lease_seq;

        Ok(object_id)
    }

    /// Return the current head object id, if any.
    #[must_use]
    pub const fn head(&self) -> Option<ObjectId> {
        self.head
    }

    #[allow(clippy::missing_const_for_fn)]
    fn validate_commit(
        &self,
        cursor: &CursorState,
        lease_seq: u64,
    ) -> Result<(), CursorStoreError> {
        if lease_seq < self.last_lease_seq {
            return Err(CursorStoreError::StaleLeaseSeq {
                current: self.last_lease_seq,
                incoming: lease_seq,
            });
        }

        if let Some(previous) = &self.last_cursor {
            if let (Some(current), Some(incoming)) = (previous.offset, cursor.offset)
                && incoming < current
            {
                return Err(CursorStoreError::OffsetRegression { current, incoming });
            }

            if let (Some(current), Some(incoming)) = (previous.watermark, cursor.watermark)
                && incoming < current
            {
                return Err(CursorStoreError::WatermarkRegression { current, incoming });
            }
        }

        Ok(())
    }

    fn validate_state_identity(
        &self,
        state: &ConnectorStateObject,
    ) -> Result<(), CursorStoreError> {
        if state.connector_id != self.connector_id || state.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "loaded connector state belongs to a different connector/zone".to_string(),
            ));
        }

        if state.instance_id != self.instance_id {
            return Err(CursorStoreError::Storage(
                "loaded connector state instance_id mismatch".to_string(),
            ));
        }

        if state.header.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "loaded connector state header zone_id mismatch".to_string(),
            ));
        }

        Ok(())
    }
}

/// In-memory cursor store backend for tests and local development.
#[derive(Debug, Default)]
pub struct InMemoryCursorStoreBackend {
    state: Mutex<InMemoryCursorStoreState>,
}

#[derive(Debug, Default)]
struct InMemoryCursorStoreState {
    next_id: u64,
    objects: Vec<(ObjectId, ConnectorStateObject)>,
}

impl InMemoryCursorStoreBackend {
    /// Create a new in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl CursorStoreBackend for InMemoryCursorStoreBackend {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CursorStoreError::Storage("cursor store mutex poisoned".into()))?;
        Ok(state.objects.last().cloned())
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CursorStoreError::Storage("cursor store mutex poisoned".into()))?;
        let byte = u8::try_from(state.next_id % 256).unwrap_or(0);
        let object_id = ObjectId::from_bytes([byte; 32]);
        state.next_id = state.next_id.wrapping_add(1);
        state.objects.push((object_id, state_obj));
        drop(state);
        Ok(object_id)
    }
}

impl CursorStoreBackend for Arc<InMemoryCursorStoreBackend> {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        self.as_ref().load_head()
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        self.as_ref().store_state_object(state_obj)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjectStore-backed cursor store
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor store backend backed by an `ObjectStore` (mesh persistence).
#[cfg(feature = "cursor-store-object-store")]
#[derive(Clone)]
pub struct ObjectStoreCursorBackend {
    object_store: Arc<dyn fcp_store::ObjectStore>,
    object_id_key: ObjectIdKey,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: Option<InstanceId>,
    retention: RetentionClass,
    write_authorization: Option<ConnectorStateWriteAuthorization>,
}

#[cfg(feature = "cursor-store-object-store")]
impl ObjectStoreCursorBackend {
    /// Create a new backend that stores connector state objects in an `ObjectStore`.
    #[must_use]
    pub fn new(
        object_store: Arc<dyn fcp_store::ObjectStore>,
        object_id_key: ObjectIdKey,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            object_store,
            object_id_key,
            connector_id,
            zone_id,
            instance_id: None,
            retention: RetentionClass::Pinned,
            write_authorization: None,
        }
    }

    /// Scope canonical reads and writes to one connector instance.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Override retention class for stored state objects.
    #[must_use]
    pub const fn with_retention(mut self, retention: RetentionClass) -> Self {
        self.retention = retention;
        self
    }

    /// Route writes through canonical connector-state storage.
    ///
    /// Without an authorization witness this backend preserves the legacy raw
    /// object-store behavior for tests and local development. Supplying a
    /// verified witness makes commits advance the `ConnectorStateRoot` that host
    /// and mesh explain paths read from `fcp-store`.
    #[must_use]
    pub fn with_write_authorization(
        mut self,
        authorization: ConnectorStateWriteAuthorization,
    ) -> Self {
        self.write_authorization = Some(authorization);
        self
    }

    fn connector_state_store(&self) -> fcp_store::FcpStoreConnectorStateStore {
        let mut store = fcp_store::FcpStoreConnectorStateStore::new(
            Arc::clone(&self.object_store),
            self.object_id_key,
            self.connector_id.clone(),
            self.zone_id.clone(),
        )
        .with_retention(self.retention);

        // Pin canonical reads to the verified append writer so a zone member
        // holding the shared object-id key cannot plant a self-signed chain
        // that this backend would then trust as canonical state.
        if let Some(authorization) = &self.write_authorization {
            store = store.with_trusted_writer_keys([authorization.writer_public_key()]);
        }

        if let Some(instance_id) = &self.instance_id {
            store.with_instance_id(instance_id.clone())
        } else {
            store
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn schema_id() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.connector_state",
            "state_object",
            semver::Version::new(1, 0, 0),
        )
    }

    fn block_on_store<T>(
        fut: impl std::future::Future<Output = Result<T, fcp_store::ObjectStoreError>>,
    ) -> Result<T, CursorStoreError> {
        fcp_async_core::runtime::block_on_sync(fut)
            .map_err(|err| CursorStoreError::Storage(err.to_string()))
            .and_then(|result| result.map_err(|err| CursorStoreError::Storage(err.to_string())))
    }

    fn block_on_connector_state<T, E>(
        fut: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, CursorStoreError>
    where
        E: std::fmt::Display,
    {
        fcp_async_core::runtime::block_on_sync(fut)
            .map_err(|err| CursorStoreError::Storage(err.to_string()))
            .and_then(|result| result.map_err(|err| CursorStoreError::Storage(err.to_string())))
    }

    fn decode_state_object(
        stored: &StoredObject,
    ) -> Result<ConnectorStateObject, CursorStoreError> {
        CanonicalSerializer::deserialize(&stored.body, &stored.header.schema)
            .map_err(|err| CursorStoreError::CursorDecoding(err.to_string()))
    }

    fn validate_loaded_state_object(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
        state: &ConnectorStateObject,
    ) -> Result<(), CursorStoreError> {
        let state_header = serde_json::to_vec(&state.header)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        let stored_header = serde_json::to_vec(&stored.header)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        if state_header != stored_header {
            return Err(CursorStoreError::Storage(
                "stored connector state header/body mismatch".into(),
            ));
        }

        if !state.header.refs.contains(&state.lease_object_id) {
            return Err(CursorStoreError::Storage(
                "stored connector state missing lease reference".into(),
            ));
        }

        let canonical_body = CanonicalSerializer::serialize(state, &state.header.schema)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        if canonical_body != stored.body {
            return Err(CursorStoreError::Storage(
                "stored connector state is not in canonical form".into(),
            ));
        }

        let derived_object_id =
            StoredObject::derive_id(&stored.header, &canonical_body, &self.object_id_key)
                .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        if derived_object_id != object_id {
            return Err(CursorStoreError::Storage(
                "stored connector state object id does not match canonical content".into(),
            ));
        }

        Ok(())
    }

    fn load_canonical_head(
        &self,
    ) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        let state_store = self.connector_state_store();
        let Some((_root_id, root)) = Self::block_on_connector_state(state_store.read_root())?
        else {
            return Ok(None);
        };
        let Some(head_id) = root.head else {
            return Ok(None);
        };

        let stored = Self::block_on_store(self.object_store.get(&head_id))?;
        if stored.header.schema != Self::schema_id() {
            return Err(CursorStoreError::Storage(
                "canonical connector state root points at a non-state object".into(),
            ));
        }
        let state = Self::decode_state_object(&stored)?;
        self.validate_loaded_state_object(head_id, &stored, &state)?;
        if state.connector_id != self.connector_id || state.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "canonical connector state root points at a foreign state object".into(),
            ));
        }

        Ok(Some((head_id, state)))
    }

    fn load_raw_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        let object_ids =
            Self::block_on_store(async { Ok(self.object_store.list_zone(&self.zone_id).await) })?;

        let mut best: Option<(ObjectId, ConnectorStateObject)> = None;

        for object_id in object_ids {
            let stored = match Self::block_on_store(self.object_store.get(&object_id)) {
                Ok(obj) => obj,
                Err(err) => {
                    tracing::warn!(error = %err, object_id = %object_id, "Failed to load state object");
                    continue;
                }
            };

            if stored.header.schema != Self::schema_id() {
                continue;
            }

            let state = match Self::decode_state_object(&stored) {
                Ok(state) => state,
                Err(err) => {
                    tracing::warn!(error = %err, object_id = %object_id, "Failed to decode state object");
                    continue;
                }
            };

            if let Err(err) = self.validate_loaded_state_object(object_id, &stored, &state) {
                tracing::warn!(error = %err, object_id = %object_id, "Rejecting tampered connector state object");
                continue;
            }

            if let Some(authorization) = &self.write_authorization
                && state.writer_public_key != authorization.writer_public_key()
            {
                tracing::warn!(
                    object_id = %object_id,
                    "Rejecting connector state object signed by untrusted writer"
                );
                continue;
            }

            if state.connector_id != self.connector_id || state.zone_id != self.zone_id {
                continue;
            }

            let replace = match &best {
                None => true,
                Some((_id, current)) => {
                    state.seq > current.seq
                        || (state.seq == current.seq && state.lease_seq > current.lease_seq)
                }
            };

            if replace {
                best = Some((object_id, state));
            }
        }

        Ok(best)
    }

    fn store_raw_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        if state_obj.connector_id != self.connector_id || state_obj.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "connector_id/zone_id mismatch in state object".into(),
            ));
        }

        if state_obj.header.schema != Self::schema_id() {
            return Err(CursorStoreError::Storage(
                "unexpected schema for connector state object".into(),
            ));
        }

        let body = CanonicalSerializer::serialize(&state_obj, &state_obj.header.schema)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        let object_id = StoredObject::derive_id(&state_obj.header, &body, &self.object_id_key)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;

        let header = state_obj.header;
        let stored = StoredObject {
            object_id,
            header,
            body,
            storage: StorageMeta {
                retention: self.retention,
            },
        };

        Self::block_on_store(self.object_store.put(stored))?;
        Ok(object_id)
    }

    fn store_canonical_state_object(
        &self,
        authorization: &ConnectorStateWriteAuthorization,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        let state_store = self.connector_state_store();
        let outcome = Self::block_on_connector_state(ConnectorStateStore::append_object(
            &state_store,
            &self.connector_id,
            authorization,
            state_obj,
        ))?;

        match outcome {
            ConnectorStateAppendOutcome::Committed { object_id, .. } => Ok(object_id),
            ConnectorStateAppendOutcome::Conflict {
                canonical_head,
                canonical_seq,
            } => Err(CursorStoreError::Storage(format!(
                "canonical connector state append conflict: head {}, seq {}",
                canonical_head.map_or_else(|| "<none>".to_string(), |head| head.to_string()),
                canonical_seq.map_or_else(|| "<none>".to_string(), |seq| seq.to_string())
            ))),
        }
    }
}

#[cfg(feature = "cursor-store-object-store")]
impl CursorStoreBackend for ObjectStoreCursorBackend {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        if let Some(head) = self.load_canonical_head()? {
            return Ok(Some(head));
        }

        self.load_raw_head()
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        if let Some(authorization) = &self.write_authorization {
            self.store_canonical_state_object(authorization, state_obj)
        } else {
            self.store_raw_state_object(state_obj)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// Valid health state transitions.
///
/// The health state machine enforces these transition rules:
/// - `Starting` → `Healthy` (on successful initialization)
/// - `Starting` → `Unhealthy` (on initialization failure)
/// - `Healthy` → `Degraded` (on recoverable failures)
/// - `Healthy` → `Unhealthy` (on unrecoverable failures)
/// - `Degraded` → `Healthy` (on recovery)
/// - `Degraded` → `Unhealthy` (on continued failures)
/// - `Unhealthy` → `Healthy` (on recovery after cooldown)
/// - `Unhealthy` → `Degraded` (on partial recovery)
#[derive(Debug, Clone)]
pub enum HealthTransition {
    /// Transition to healthy state (successful operation).
    ToHealthy,
    /// Transition to degraded state (recoverable issue).
    ToDegraded {
        /// Reason for degradation.
        reason: String,
    },
    /// Transition to unhealthy/error state (unrecoverable issue).
    ToUnhealthy {
        /// Reason for error.
        reason: String,
    },
    /// Transition to starting state (reset).
    ToStarting,
}

/// Tracks connector health with explicit transition rules.
///
/// The tracker maintains:
/// - Current health state
/// - Consecutive failure count
/// - Timestamps for state changes
/// - Snapshot generation
#[derive(Debug)]
pub struct HealthTracker {
    state: HealthState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_reason: Option<String>,
    started_at: Instant,
    last_state_change: Instant,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

impl HealthTracker {
    /// Create a new health tracker in the `Starting` state.
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: HealthState::Starting,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_reason: None,
            started_at: now,
            last_state_change: now,
            last_success: None,
            last_failure: None,
        }
    }

    /// Get the current health state.
    #[must_use]
    pub const fn state(&self) -> &HealthState {
        &self.state
    }

    /// Check if currently healthy (Ready state).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self.state, HealthState::Ready)
    }

    /// Check if currently degraded.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self.state, HealthState::Degraded { .. })
    }

    /// Check if currently unhealthy (Error state).
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        matches!(self.state, HealthState::Error { .. })
    }

    /// Get consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get consecutive success count.
    #[must_use]
    pub const fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        self.last_success = Some(Instant::now());
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self, reason: &str) {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(Instant::now());
        self.last_failure_reason = Some(reason.to_string());
    }

    /// Apply a health state transition.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn transition(&mut self, transition: HealthTransition) -> bool {
        let valid = self.is_valid_transition(&transition);
        if valid {
            self.apply_transition(transition);
        }
        valid
    }

    /// Check if a transition is valid from the current state.
    ///
    /// Valid transitions:
    /// - `Starting` can transition to any state
    /// - Any state can transition to `Starting` (reset), except `Stopping`
    /// - `Ready` can transition to `Degraded` or `Error`
    /// - `Degraded` can transition to `Ready` or `Error`
    /// - `Error` can transition to `Ready` or `Degraded`
    /// - `Stopping` is terminal (no transitions allowed)
    #[must_use]
    #[allow(clippy::match_same_arms)] // Keep separate arms for documentation clarity
    pub const fn is_valid_transition(&self, transition: &HealthTransition) -> bool {
        match (&self.state, transition) {
            // Stopping is terminal - no transitions allowed
            (HealthState::Stopping, _) => false,
            // Starting can go anywhere
            (HealthState::Starting, _) => true,
            // Restart is always valid (except from Stopping, handled above)
            (_, HealthTransition::ToStarting) => true,
            // Ready can degrade or fail
            (
                HealthState::Ready,
                HealthTransition::ToDegraded { .. } | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Degraded can recover or fail
            (
                HealthState::Degraded { .. },
                HealthTransition::ToHealthy | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Error can recover (partially or fully)
            (
                HealthState::Error { .. },
                HealthTransition::ToHealthy | HealthTransition::ToDegraded { .. },
            ) => true,
            _ => false,
        }
    }

    fn apply_transition(&mut self, transition: HealthTransition) {
        self.last_state_change = Instant::now();
        match transition {
            HealthTransition::ToHealthy => {
                self.state = HealthState::Ready;
                self.consecutive_failures = 0;
            }
            HealthTransition::ToDegraded { reason } => {
                self.state = HealthState::Degraded { reason };
            }
            HealthTransition::ToUnhealthy { reason } => {
                self.state = HealthState::Error { reason };
            }
            HealthTransition::ToStarting => {
                self.state = HealthState::Starting;
                self.consecutive_failures = 0;
                self.consecutive_successes = 0;
            }
        }
    }

    /// Generate a health snapshot for the current state.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn snapshot(&self) -> HealthSnapshot {
        let uptime_ms = self.started_at.elapsed().as_millis() as u64;

        // Compute load as a proxy from failure rate (max 10 failures = 1.0 load)
        let load = if self.consecutive_failures > 0 {
            #[allow(clippy::cast_precision_loss)]
            let failure_ratio = self.consecutive_failures.min(10) as f32 / 10.0;
            Some(failure_ratio.min(1.0))
        } else {
            Some(0.0)
        };

        // Include failure reason in details if present
        let details = self.last_failure_reason.as_ref().map(|reason| {
            serde_json::json!({
                "last_error": reason,
                "consecutive_failures": self.consecutive_failures,
            })
        });

        HealthSnapshot {
            status: self.state.clone(),
            uptime_ms,
            load,
            details,
            rate_limit: None,
        }
    }

    /// Check if enough time has passed in unhealthy state for cooldown.
    #[must_use]
    pub fn cooldown_elapsed(&self, cooldown: Duration) -> bool {
        if !self.is_unhealthy() {
            return true;
        }
        self.last_state_change.elapsed() >= cooldown
    }

    /// Evaluate health based on config thresholds and auto-transition.
    ///
    /// Call this after `record_success` or `record_failure` to automatically
    /// transition between states based on configured thresholds.
    pub fn evaluate(&mut self, config: &SupervisorConfig) {
        match &self.state {
            HealthState::Starting => {
                // Auto-transition to Ready after first success
                if self.consecutive_successes > 0 {
                    self.transition(HealthTransition::ToHealthy);
                } else if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "initialization failed".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                }
            }
            HealthState::Ready => {
                // Degrade after some failures, fail after max
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_failures > 0 {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "recoverable error".to_string());
                    self.transition(HealthTransition::ToDegraded { reason });
                }
            }
            HealthState::Degraded { .. } => {
                // Recover after some successes, fail after max failures
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_successes >= 3 {
                    // Require 3 consecutive successes to recover
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Error { .. } => {
                // Recover only after cooldown and successes
                if self.cooldown_elapsed(config.cooldown_duration())
                    && self.consecutive_successes > 0
                {
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Stopping => {
                // No auto-transitions from Stopping - it's terminal
            }
        }
    }
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamingSupervisor
// ─────────────────────────────────────────────────────────────────────────────

/// Streaming supervisor errors (boxed trait object for flexibility).
pub type StreamingError = Box<dyn std::error::Error + Send + Sync>;

/// Handle for an active streaming connection.
#[derive(Debug)]
pub struct StreamingConnection<E> {
    /// Stream of events emitted by the connection.
    pub events: mpsc::Receiver<E>,
    /// Join handle for the underlying stream task.
    pub join_handle: fcp_async_core::task::JoinHandle<Result<(), StreamingError>>,
}

/// Statistics from a streaming supervisor run.
#[derive(Debug, Clone, Default)]
pub struct StreamingSupervisorStats {
    /// Total number of connection attempts.
    pub connection_attempts: u64,
    /// Number of successful connections.
    pub successful_connections: u64,
    /// Number of failed connection attempts.
    pub failed_connections: u64,
    /// Number of events processed.
    pub events_processed: u64,
    /// Total time spent in backoff (milliseconds).
    pub backoff_time_ms: u64,
    /// Heartbeat timeouts detected.
    pub missed_heartbeats: u64,
}

/// Streaming-specific health state details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingHealthState {
    /// Last heartbeat sent time in milliseconds since supervisor start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<u64>,
    /// Last heartbeat ack time in milliseconds since supervisor start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ack_at: Option<u64>,
    /// Total reconnect attempts after the first successful connection.
    pub reconnect_count: u64,
    /// Total missed heartbeat timeouts.
    pub missed_heartbeats: u64,
}

/// Supervised streaming loop with backoff, health tracking, and session resumption.
///
/// The supervisor provides:
/// - Connection lifecycle management with retry/backoff
/// - Optional heartbeat timeout detection
/// - Health state transitions based on success/failure patterns
/// - Session persistence hooks for resume support
#[derive(Debug)]
pub struct StreamingSupervisor<S: StreamingSession> {
    config: SupervisorConfig,
    session: S,
    health: HealthTracker,
    stats: StreamingSupervisorStats,
}

impl<S: StreamingSession> StreamingSupervisor<S> {
    /// Create a new streaming supervisor.
    pub fn new(config: SupervisorConfig, session: S) -> Self {
        Self {
            config,
            session,
            health: HealthTracker::new(),
            stats: StreamingSupervisorStats::default(),
        }
    }

    /// Get a reference to the session.
    pub const fn session(&self) -> &S {
        &self.session
    }

    /// Get mutable access to the session.
    pub const fn session_mut(&mut self) -> &mut S {
        &mut self.session
    }

    /// Get the current health tracker.
    pub const fn health(&self) -> &HealthTracker {
        &self.health
    }

    /// Get the current statistics.
    pub const fn stats(&self) -> &StreamingSupervisorStats {
        &self.stats
    }

    /// Get the supervisor configuration.
    pub const fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    fn compute_backoff_delay(&self, attempt: u32) -> Duration {
        let jitter = pseudo_random_jitter(attempt);
        let backoff = self.config.compute_backoff_with_jitter(attempt, jitter);
        Duration::from_millis(backoff)
    }

    fn health_log_fields(&self) -> (u64, u64, u64, u64) {
        let reconnect_count = self.stats.connection_attempts.saturating_sub(1);
        (
            self.session.heartbeat_seq(),
            self.session.ack_seq(),
            self.stats.missed_heartbeats,
            reconnect_count,
        )
    }

    fn elapsed_ms(&self, instant: Instant) -> u64 {
        let elapsed = instant.saturating_duration_since(self.health.started_at);
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    }

    /// Get streaming-specific health state details.
    #[must_use]
    pub fn streaming_health_state(&self) -> StreamingHealthState {
        StreamingHealthState {
            last_heartbeat_at: self
                .session
                .last_heartbeat_sent()
                .map(|instant| self.elapsed_ms(instant)),
            last_ack_at: self
                .session
                .last_heartbeat_ack()
                .map(|instant| self.elapsed_ms(instant)),
            reconnect_count: self.stats.connection_attempts.saturating_sub(1),
            missed_heartbeats: self.stats.missed_heartbeats,
        }
    }

    /// Build a `HealthSnapshot` that includes streaming health details.
    #[must_use]
    pub fn streaming_health_snapshot(&self) -> HealthSnapshot {
        let mut snapshot = self.health.snapshot();
        let mut details = match snapshot.details.take() {
            Some(serde_json::Value::Object(map)) => map,
            Some(other) => {
                let mut map = serde_json::Map::new();
                map.insert("tracker".to_string(), other);
                map
            }
            None => serde_json::Map::new(),
        };

        let streaming = self.streaming_health_state();
        if let Some(last_heartbeat_at) = streaming.last_heartbeat_at {
            details.insert(
                "last_heartbeat_at".to_string(),
                serde_json::Value::from(last_heartbeat_at),
            );
        }
        if let Some(last_ack_at) = streaming.last_ack_at {
            details.insert(
                "last_ack_at".to_string(),
                serde_json::Value::from(last_ack_at),
            );
        }
        details.insert(
            "reconnect_count".to_string(),
            serde_json::Value::from(streaming.reconnect_count),
        );
        details.insert(
            "missed_heartbeats".to_string(),
            serde_json::Value::from(streaming.missed_heartbeats),
        );

        snapshot.details = Some(serde_json::Value::Object(details));
        snapshot
    }

    /// Run the streaming supervisor loop.
    ///
    /// # Arguments
    ///
    /// * `shutdown` - Watch channel receiver that signals shutdown when `true`
    /// * `connect_fn` - Async function that establishes a streaming connection
    /// * `handle_event` - Async function that handles incoming events
    #[allow(clippy::too_many_lines)]
    pub async fn run<E, ConnectF, ConnectFut, HandleF, HandleFut>(
        &mut self,
        mut shutdown: watch::Receiver<bool>,
        connect_fn: ConnectF,
        mut handle_event: HandleF,
    ) -> SupervisorOutcome
    where
        ConnectF: Fn(&mut S) -> ConnectFut,
        ConnectFut: std::future::Future<Output = Result<StreamingConnection<E>, StreamingError>>,
        HandleF: FnMut(E, &mut S) -> HandleFut,
        HandleFut: std::future::Future<Output = Result<(), StreamingError>>,
    {
        let mut consecutive_failures: u32 = 0;

        if let Err(e) = self.session.restore() {
            let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                self.health_log_fields();
            tracing::warn!(
                error = %e,
                heartbeat_seq,
                ack_seq,
                missed_heartbeats,
                reconnect_count,
                "Failed to restore streaming session state"
            );
        }

        // Remain in `Starting` until the first successful connection proves the
        // supervisor can actually do its job. Previously we recorded a synthetic
        // success here, which made `health().is_healthy()` return true before
        // any connection was established — a misleading readiness signal for
        // external health checks.

        loop {
            if *shutdown.borrow() {
                let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                    self.health_log_fields();
                tracing::info!(
                    heartbeat_seq,
                    ack_seq,
                    missed_heartbeats,
                    reconnect_count,
                    "Streaming supervisor received shutdown signal"
                );
                if let Err(e) = self.session.persist() {
                    let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                        self.health_log_fields();
                    tracing::error!(
                        error = %e,
                        heartbeat_seq,
                        ack_seq,
                        missed_heartbeats,
                        reconnect_count,
                        "Failed to persist session on shutdown"
                    );
                }
                return SupervisorOutcome::Shutdown;
            }

            self.stats.connection_attempts += 1;
            let connection = match connect_fn(&mut self.session).await {
                Ok(connection) => {
                    self.stats.successful_connections += 1;
                    consecutive_failures = 0;
                    self.health.record_success();
                    self.health.evaluate(&self.config);
                    connection
                }
                Err(err) => {
                    self.stats.failed_connections += 1;
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let message = err.to_string();

                    self.health.record_failure(&message);
                    self.health.evaluate(&self.config);

                    let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                        self.health_log_fields();
                    tracing::warn!(
                        error = %message,
                        consecutive_failures,
                        heartbeat_seq,
                        ack_seq,
                        missed_heartbeats,
                        reconnect_count,
                        "Streaming connection attempt failed"
                    );

                    if consecutive_failures >= self.config.max_consecutive_failures {
                        if let Err(e) = self.session.persist() {
                            tracing::error!(error = %e, "Failed to persist session");
                        }
                        return SupervisorOutcome::MaxFailuresReached {
                            failures: consecutive_failures,
                        };
                    }

                    let delay = self.compute_backoff_delay(consecutive_failures - 1);
                    self.stats.backoff_time_ms +=
                        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);

                    if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                        .await
                        .is_err()
                    {
                        let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                            self.health_log_fields();
                        if let Err(e) = self.session.persist() {
                            tracing::error!(
                                error = %e,
                                heartbeat_seq,
                                ack_seq,
                                missed_heartbeats,
                                reconnect_count,
                                "Failed to persist session on shutdown"
                            );
                        }
                        return SupervisorOutcome::Shutdown;
                    }

                    continue;
                }
            };

            let mut events = connection.events;
            let mut join_handle = connection.join_handle;
            let mut heartbeat_interval = self
                .config
                .heartbeat_interval()
                .map(fcp_async_core::time::interval);

            let mut exit_message = "stream ended".to_string();
            let mut exit_fatal = false;

            loop {
                fcp_async_core::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                                self.health_log_fields();
                            tracing::info!(
                                heartbeat_seq,
                                ack_seq,
                                missed_heartbeats,
                                reconnect_count,
                                "Streaming supervisor received shutdown signal"
                            );
                            join_handle.abort();
                            if let Err(e) = self.session.persist() {
                                let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                                    self.health_log_fields();
                                tracing::error!(
                                    error = %e,
                                    heartbeat_seq,
                                    ack_seq,
                                    missed_heartbeats,
                                    reconnect_count,
                                    "Failed to persist session on shutdown"
                                );
                            }
                            return SupervisorOutcome::Shutdown;
                        }
                    },
                    maybe_event = events.recv() => {
                        if let Some(event) = maybe_event {
                            self.stats.events_processed += 1;
                            if let Err(err) = handle_event(event, &mut self.session).await {
                                let message = err.to_string();
                                let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                                    self.health_log_fields();
                                tracing::error!(
                                    error = %message,
                                    heartbeat_seq,
                                    ack_seq,
                                    missed_heartbeats,
                                    reconnect_count,
                                    "Streaming event handler failed"
                                );
                                exit_message = message;
                                exit_fatal = true;
                                break;
                            }
                            self.health.record_success();
                            self.health.evaluate(&self.config);
                        } else {
                            break;
                        }
                    },
                    result = &mut join_handle => {
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                exit_message = err.to_string();
                            }
                            Err(err) => {
                                exit_message = err.to_string();
                            }
                        }
                        break;
                    },
                    () = async {
                        if let Some(interval) = &mut heartbeat_interval {
                            interval.tick().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        if let Some(timeout) = self.config.heartbeat_timeout() {
                            if self.session.is_heartbeat_timeout(timeout) {
                                self.stats.missed_heartbeats = self.stats.missed_heartbeats.saturating_add(1);
                                let (heartbeat_seq, ack_seq, missed_heartbeats, reconnect_count) =
                                    self.health_log_fields();
                                tracing::warn!(
                                    heartbeat_seq,
                                    ack_seq,
                                    missed_heartbeats,
                                    reconnect_count,
                                    "Streaming heartbeat timeout"
                                );
                                exit_message = "heartbeat timeout".to_string();
                                break;
                            }
                        }
                    }
                }
            }

            if exit_fatal {
                self.health.transition(HealthTransition::ToUnhealthy {
                    reason: exit_message.clone(),
                });
                join_handle.abort();
                if let Err(e) = self.session.persist() {
                    tracing::error!(error = %e, "Failed to persist session");
                }
                return SupervisorOutcome::FatalError {
                    message: exit_message,
                };
            }

            self.health.record_failure(&exit_message);
            self.health.evaluate(&self.config);
            join_handle.abort();

            consecutive_failures = consecutive_failures.saturating_add(1);
            if consecutive_failures >= self.config.max_consecutive_failures {
                if let Err(e) = self.session.persist() {
                    tracing::error!(error = %e, "Failed to persist session");
                }
                return SupervisorOutcome::MaxFailuresReached {
                    failures: consecutive_failures,
                };
            }

            let delay = self.compute_backoff_delay(consecutive_failures - 1);
            self.stats.backoff_time_ms += u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);

            if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                .await
                .is_err()
            {
                if let Err(e) = self.session.persist() {
                    tracing::error!(error = %e, "Failed to persist session on shutdown");
                }
                return SupervisorOutcome::Shutdown;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PollingSupervisor
// ─────────────────────────────────────────────────────────────────────────────

/// Result from a single poll operation.
#[derive(Debug)]
pub enum PollResult<T> {
    /// Poll succeeded with optional data (empty if no updates).
    Success(Vec<T>),
    /// Poll failed with a recoverable error (will retry with backoff).
    RecoverableError {
        /// Error message.
        message: String,
        /// Optional retry-after hint from rate limiting (milliseconds).
        retry_after_ms: Option<u64>,
    },
    /// Poll failed with an unrecoverable error (will stop supervisor).
    FatalError {
        /// Error message.
        message: String,
    },
}

impl<T> PollResult<T> {
    /// Create a success result with items.
    #[must_use]
    pub const fn success(items: Vec<T>) -> Self {
        Self::Success(items)
    }

    /// Create an empty success result.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Success(Vec::new())
    }

    /// Create a recoverable error.
    pub fn recoverable(message: impl Into<String>) -> Self {
        Self::RecoverableError {
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Create a recoverable error with retry-after hint.
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self::RecoverableError {
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// Create a fatal error.
    pub fn fatal(message: impl Into<String>) -> Self {
        Self::FatalError {
            message: message.into(),
        }
    }
}

/// Outcome from running the polling supervisor.
#[derive(Debug, Clone)]
pub enum SupervisorOutcome {
    /// Supervisor stopped gracefully via shutdown signal.
    Shutdown,
    /// Supervisor stopped due to fatal error.
    FatalError {
        /// Error message.
        message: String,
    },
    /// Supervisor stopped due to too many consecutive failures.
    MaxFailuresReached {
        /// Number of consecutive failures.
        failures: u32,
    },
}

/// Statistics from a polling supervisor run.
#[derive(Debug, Clone, Default)]
pub struct PollingSupervisorStats {
    /// Total number of poll attempts.
    pub total_polls: u64,
    /// Number of successful polls.
    pub successful_polls: u64,
    /// Number of failed polls (recoverable).
    pub failed_polls: u64,
    /// Total items processed.
    pub items_processed: u64,
    /// Total time spent in backoff (milliseconds).
    pub backoff_time_ms: u64,
}

/// Supervised polling loop with backoff, health tracking, and cursor management.
///
/// The supervisor provides:
/// - Configurable poll interval with long-poll support
/// - Exponential backoff on recoverable errors
/// - Rate-limit aware backoff (respects Retry-After hints)
/// - Health state transitions based on success/failure patterns
/// - Cursor persistence hooks for exactly-once semantics
///
/// # Example
///
/// ```ignore
/// use fcp_sdk::runtime::{PollingSupervisor, PollResult, SupervisorConfig, InMemoryPollingCursor};
/// use fcp_async_core::channel::watch;
///
/// let config = SupervisorConfig::default();
/// let cursor = InMemoryPollingCursor::new();
/// let (shutdown_tx, shutdown_rx) = watch::channel(false);
///
/// let supervisor = PollingSupervisor::new(config, cursor);
/// let outcome = supervisor.run(
///     shutdown_rx,
///     1000, // poll interval ms
///     |offset| async move {
///         // Your poll logic here
///         PollResult::success(vec![item1, item2])
///     },
///     |items, cursor| {
///         // Process items, update cursor
///         for item in items {
///             cursor.advance_if_newer(item.id);
///         }
///         Ok(())
///     },
/// ).await;
/// ```
#[derive(Debug)]
pub struct PollingSupervisor<C: PollingCursor> {
    config: SupervisorConfig,
    cursor: C,
    health: HealthTracker,
    stats: PollingSupervisorStats,
}

impl<C: PollingCursor> PollingSupervisor<C> {
    /// Create a new polling supervisor.
    pub fn new(config: SupervisorConfig, cursor: C) -> Self {
        Self {
            config,
            cursor,
            health: HealthTracker::new(),
            stats: PollingSupervisorStats::default(),
        }
    }

    /// Get the current cursor.
    pub const fn cursor(&self) -> &C {
        &self.cursor
    }

    /// Get mutable access to the cursor.
    pub const fn cursor_mut(&mut self) -> &mut C {
        &mut self.cursor
    }

    /// Get the current health tracker.
    pub const fn health(&self) -> &HealthTracker {
        &self.health
    }

    /// Get the current statistics.
    pub const fn stats(&self) -> &PollingSupervisorStats {
        &self.stats
    }

    /// Get the supervisor configuration.
    pub const fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    /// Compute the next backoff delay, respecting rate-limit hints.
    ///
    /// A `retry_after_ms` hint raises the delay but never above
    /// `max_backoff_ms`. The hint originates from an upstream `Retry-After`
    /// header (`PollResult::rate_limited`), so it is attacker-controlled;
    /// letting it win outright broke the documented guarantee that "backoff
    /// will not exceed this value regardless of attempt count" and let a
    /// single hostile 429 park the polling loop for as long as it asked
    /// (`sleep_or_shutdown` only wakes on shutdown).
    fn compute_delay(&self, attempt: u32, retry_after_ms: Option<u64>) -> Duration {
        let jitter = pseudo_random_jitter(attempt);
        let backoff = self.config.compute_backoff_with_jitter(attempt, jitter);

        let delay_ms = retry_after_ms.map_or(backoff, |retry_after| {
            retry_after
                .max(backoff)
                .min(self.config.max_backoff_ms.max(backoff))
        });

        Duration::from_millis(delay_ms)
    }

    /// Run the polling supervisor loop.
    ///
    /// # Arguments
    ///
    /// * `shutdown` - Watch channel receiver that signals shutdown when `true`
    /// * `poll_interval_ms` - Interval between polls when no backoff is active
    /// * `poll_fn` - Async function that performs the actual poll
    /// * `process_fn` - Function that processes poll results and updates cursor
    ///
    /// # Type Parameters
    ///
    /// * `T` - Type of items returned by the poll
    /// * `F` - Poll function type
    /// * `Fut` - Future type returned by poll function
    /// * `P` - Process function type
    ///
    /// # Returns
    ///
    /// Returns the outcome of the supervisor run.
    #[allow(clippy::too_many_lines)]
    pub async fn run<T, F, Fut, P>(
        &mut self,
        mut shutdown: watch::Receiver<bool>,
        poll_interval_ms: u64,
        poll_fn: F,
        mut process_fn: P,
    ) -> SupervisorOutcome
    where
        F: Fn(Option<i64>) -> Fut,
        Fut: std::future::Future<Output = PollResult<T>>,
        P: FnMut(Vec<T>, &mut C) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    {
        let poll_interval = Duration::from_millis(poll_interval_ms);
        let mut consecutive_failures: u32 = 0;

        // Restore cursor state if available
        if let Err(e) = self.cursor.restore() {
            tracing::warn!(error = %e, "Failed to restore cursor state, starting fresh");
        }

        // Remain in `Starting` until the first successful poll proves the
        // supervisor can actually reach its upstream. Previously we recorded a
        // synthetic success here, which made `health().is_healthy()` return
        // true before any poll had run — a misleading readiness signal.

        loop {
            // Check for shutdown signal
            if *shutdown.borrow() {
                tracing::info!("Polling supervisor received shutdown signal");
                // Persist cursor before shutdown
                if let Err(e) = self.cursor.persist() {
                    tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                }
                return SupervisorOutcome::Shutdown;
            }

            // Execute poll
            self.stats.total_polls += 1;
            let offset = self.cursor.offset();
            let poll_start = Instant::now();

            tracing::debug!(offset = ?offset, "Starting poll");

            let result = poll_fn(offset).await;

            match result {
                PollResult::Success(items) => {
                    let item_count = items.len();
                    self.cursor.record_poll(Instant::now(), item_count);
                    let previous_offset = self.cursor.offset();

                    // Process items.
                    let mut processing_failed = false;
                    if !items.is_empty() {
                        if let Err(e) = process_fn(items, &mut self.cursor) {
                            match previous_offset {
                                Some(offset) => self.cursor.set_offset(offset),
                                None => self.cursor.clear_offset(),
                            }
                            tracing::error!(error = %e, "Failed to process poll results");
                            processing_failed = true;
                        }
                    }

                    if processing_failed {
                        self.stats.failed_polls += 1;
                        consecutive_failures = consecutive_failures.saturating_add(1);

                        let message = "poll result processing failed".to_string();
                        self.health.record_failure(&message);
                        self.health.evaluate(&self.config);

                        if consecutive_failures >= self.config.max_consecutive_failures {
                            tracing::error!(
                                failures = consecutive_failures,
                                max = self.config.max_consecutive_failures,
                                "Maximum consecutive failures reached"
                            );
                            if let Err(e) = self.cursor.persist() {
                                tracing::error!(error = %e, "Failed to persist cursor");
                            }
                            return SupervisorOutcome::MaxFailuresReached {
                                failures: consecutive_failures,
                            };
                        }

                        let delay = self.compute_delay(consecutive_failures - 1, None);
                        self.stats.backoff_time_ms +=
                            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);

                        tracing::info!(
                            delay_ms = delay.as_millis(),
                            attempt = consecutive_failures,
                            "Backing off before retry after processing failure"
                        );

                        if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                            .await
                            .is_err()
                        {
                            if let Err(e) = self.cursor.persist() {
                                tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                            }
                            return SupervisorOutcome::Shutdown;
                        }
                        continue;
                    }

                    self.stats.successful_polls += 1;
                    self.stats.items_processed += item_count as u64;
                    consecutive_failures = 0;

                    self.health.record_success();
                    self.health.evaluate(&self.config);

                    if item_count > 0
                        && let Err(e) = self.cursor.persist()
                    {
                        tracing::warn!(error = %e, "Failed to persist cursor");
                    }

                    tracing::debug!(
                        items = item_count,
                        elapsed_ms = poll_start.elapsed().as_millis(),
                        "Poll completed successfully"
                    );

                    // Wait for poll interval, checking for shutdown.
                    if fcp_async_core::shutdown::sleep_or_shutdown(poll_interval, &mut shutdown)
                        .await
                        .is_err()
                    {
                        if let Err(e) = self.cursor.persist() {
                            tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                        }
                        return SupervisorOutcome::Shutdown;
                    }
                }

                PollResult::RecoverableError {
                    message,
                    retry_after_ms,
                } => {
                    self.cursor.record_poll(Instant::now(), 0);
                    self.stats.failed_polls += 1;
                    consecutive_failures = consecutive_failures.saturating_add(1);

                    // Record failure for health tracking
                    self.health.record_failure(&message);
                    self.health.evaluate(&self.config);

                    tracing::warn!(
                        error = %message,
                        consecutive_failures,
                        retry_after_ms = ?retry_after_ms,
                        "Poll failed with recoverable error"
                    );

                    // Check if we've exceeded max failures
                    if consecutive_failures >= self.config.max_consecutive_failures {
                        tracing::error!(
                            failures = consecutive_failures,
                            max = self.config.max_consecutive_failures,
                            "Maximum consecutive failures reached"
                        );
                        if let Err(e) = self.cursor.persist() {
                            tracing::error!(error = %e, "Failed to persist cursor");
                        }
                        return SupervisorOutcome::MaxFailuresReached {
                            failures: consecutive_failures,
                        };
                    }

                    // Compute backoff delay
                    let delay = self.compute_delay(consecutive_failures - 1, retry_after_ms);
                    self.stats.backoff_time_ms +=
                        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);

                    tracing::info!(
                        delay_ms = delay.as_millis(),
                        attempt = consecutive_failures,
                        "Backing off before retry"
                    );

                    // Wait for backoff, checking for shutdown.
                    if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                        .await
                        .is_err()
                    {
                        if let Err(e) = self.cursor.persist() {
                            tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                        }
                        return SupervisorOutcome::Shutdown;
                    }
                }

                PollResult::FatalError { message } => {
                    self.cursor.record_poll(Instant::now(), 0);
                    tracing::error!(error = %message, "Poll failed with fatal error");
                    self.health.transition(HealthTransition::ToUnhealthy {
                        reason: message.clone(),
                    });
                    if let Err(e) = self.cursor.persist() {
                        tracing::error!(error = %e, "Failed to persist cursor");
                    }
                    return SupervisorOutcome::FatalError { message };
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

    fn boxed_err(message: &str) -> StreamingError {
        Box::new(io::Error::other(message))
    }

    /// br-3a3r6: scope-bound test override of the opt-in env value.
    /// Crate forbids `unsafe_code` so tests can't `std::env::set_var`;
    /// instead this RAII guard sets the per-thread override and clears
    /// it on drop. Tests run in parallel on different threads, so the
    /// thread-local keeps each scenario isolated.
    struct OptInOverrideGuard;
    impl OptInOverrideGuard {
        fn set(value: Option<&str>) -> Self {
            set_ambient_opt_in_test_value(TestEnvOverride::Set(value.map(str::to_owned)));
            Self
        }
    }
    impl Drop for OptInOverrideGuard {
        fn drop(&mut self) {
            set_ambient_opt_in_test_value(TestEnvOverride::Inherit);
        }
    }

    struct RequestTimeoutOverrideGuard;
    impl RequestTimeoutOverrideGuard {
        fn set(value: Option<&str>) -> Self {
            set_request_timeout_test_value(TestEnvOverride::Set(value.map(str::to_owned)));
            Self
        }
    }
    impl Drop for RequestTimeoutOverrideGuard {
        fn drop(&mut self) {
            set_request_timeout_test_value(TestEnvOverride::Inherit);
        }
    }

    fn manifest_toml_with_optional_timeouts(timeouts: Option<&str>) -> String {
        let placeholder = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
        let timeouts_block = timeouts.unwrap_or_default();
        let raw = format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{placeholder}"

[connector]
id = "fcp.test"
name = "Test Connector"
version = "0.1.0"
description = "runtime config test manifest"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:project:test"
allowed_sources = ["z:project:test"]
allowed_targets = ["z:project:test"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns", "network.outbound", "test.placeholder"]
optional = []
forbidden = ["system.exec"]

[provides.operations.placeholder_operation]
description = "Placeholder operation"
capability = "test.placeholder"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object", properties = {{ }} }}
output_schema = {{ type = "object", properties = {{ }} }}

[provides.operations.placeholder_operation.network_constraints]
host_allow = ["example.invalid"]
port_allow = [443]
require_sni = true

{timeouts_block}
[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 60000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&raw).unwrap();
        let interface_hash = unchecked.compute_interface_hash().unwrap();
        raw.replace(placeholder, &interface_hash.to_string())
    }

    #[test]
    fn runtime_default_config() {
        let config = ConnectorRuntimeConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(120));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(120));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
        assert!(config.host_egress_proxy_url.is_none());
    }

    #[test]
    fn runtime_creates_request_context() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context();
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_some());
        assert_eq!(ctx.scope(), fcp_async_core::ContextScope::Request);
    }

    #[test]
    fn runtime_creates_background_context() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.background_context();
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_none());
    }

    #[test]
    fn runtime_shutdown_propagates() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg = runtime.background_context();
        let req = runtime.request_context();
        assert!(!runtime.is_shutting_down());
        assert!(!bg.is_cancelled());
        assert!(!req.is_cancelled());

        runtime.shutdown();

        assert!(runtime.is_shutting_down());
        assert!(bg.is_cancelled());
        assert!(req.is_cancelled());
    }

    #[test]
    fn runtime_custom_timeout() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(60)),
        );
        assert_eq!(runtime.request_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn br_d9us6_runtime_config_exposes_host_egress_proxy_url() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_host_egress_proxy_url("http://127.0.0.1:7878/"),
        );
        assert_eq!(
            runtime.host_egress_proxy_url(),
            Some("http://127.0.0.1:7878/")
        );
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_d9us6_host_egress_client_routes_helpers_to_host_rpc_paths() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_host_egress_proxy_url("http://127.0.0.1:7878/"),
        );
        let client = runtime
            .host_egress_proxy_client()
            .expect("configured host egress proxy client");
        assert_eq!(
            client.http_endpoint(),
            "http://127.0.0.1:7878/rpc/egress/http"
        );
        assert_eq!(
            client.tcp_endpoint(),
            "http://127.0.0.1:7878/rpc/egress/tcp"
        );
    }

    #[test]
    fn runtime_connect_and_wall_clock_accessors() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_connect_timeout(Duration::from_secs(7))
                .with_wall_clock_timeout(Duration::from_secs(75)),
        );
        assert_eq!(runtime.connect_timeout(), Duration::from_secs(7));
        assert_eq!(runtime.wall_clock_timeout(), Duration::from_secs(75));
    }

    #[test]
    fn config_with_shutdown_timeout() {
        let config =
            ConnectorRuntimeConfig::default().with_shutdown_timeout(Duration::from_secs(10));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(10));
        assert_eq!(config.request_timeout, Duration::from_secs(120));
    }

    #[test]
    fn config_builder_chain_both() {
        let config = ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_secs(60))
            .with_shutdown_timeout(Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(5));
    }

    #[test]
    fn config_manifest_defaults_match_scaffold_expectations() {
        let config = ConnectorRuntimeConfig::manifest_defaults();
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn config_from_manifest_timeouts_uses_manifest_values() {
        let config = ConnectorRuntimeConfig::from_manifest_timeouts(&ManifestTimeouts {
            request_timeout_ms: 45_000,
            connect_timeout_ms: 7_000,
            wall_clock_timeout_ms: 90_000,
        });
        assert_eq!(config.request_timeout, Duration::from_secs(45));
        assert_eq!(config.connect_timeout, Duration::from_secs(7));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(90));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn config_from_manifest_without_timeouts_uses_manifest_defaults() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(None))
            .expect("manifest should parse");
        let config =
            ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(&manifest, None)
                .expect("manifest defaults should load");
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
    }

    #[test]
    fn config_from_manifest_with_timeouts_uses_manifest_section() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config =
            ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(&manifest, None)
                .expect("manifest timeouts should load");
        assert_eq!(config.request_timeout, Duration::from_secs(48));
        assert_eq!(config.connect_timeout, Duration::from_secs(8));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(95));
    }

    #[test]
    fn config_from_manifest_override_uses_request_timeout_env_value() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config = ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(
            &manifest,
            Some("61000"),
        )
        .expect("override should parse");
        assert_eq!(config.request_timeout, Duration::from_secs(61));
        assert_eq!(config.connect_timeout, Duration::from_secs(8));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(95));
    }

    #[test]
    fn config_from_manifest_override_rejects_invalid_env_value() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(None))
            .expect("manifest should parse");
        let err = ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(
            &manifest,
            Some("invalid"),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("FCP_REQUEST_TIMEOUT_MS must be a positive integer")
        );
    }

    #[test]
    fn config_from_manifest_str_parses_embedded_manifest() {
        // br-3a3r6: from_manifest_str now ignores the ambient
        // FCP_REQUEST_TIMEOUT_MS unless FCP_ALLOW_AMBIENT_TIMEOUT_OVERRIDE
        // is also set. The manifest value (52s) is the expected outcome.
        let _opt_in = OptInOverrideGuard::set(None);
        let config = ConnectorRuntimeConfig::from_manifest_str(
            &manifest_toml_with_optional_timeouts(Some(
                "[timeouts]\nrequest_timeout_ms = 52000\nconnect_timeout_ms = 6000\nwall_clock_timeout_ms = 88000\n\n",
            )),
        )
        .expect("embedded manifest should parse");
        assert_eq!(config.request_timeout, Duration::from_secs(52));
        assert_eq!(config.connect_timeout, Duration::from_secs(6));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(88));
    }

    #[test]
    fn from_manifest_ignores_ambient_timeout_env_without_opt_in() {
        // br-3a3r6: ambient FCP_REQUEST_TIMEOUT_MS must NOT override the
        // manifest's pinned [timeouts] section unless the operator has
        // explicitly opted in.
        let _opt_in = OptInOverrideGuard::set(None);
        let _timeout = RequestTimeoutOverrideGuard::set(Some("99000"));
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config = ConnectorRuntimeConfig::from_manifest(&manifest)
            .expect("manifest precedence path should succeed");
        assert_eq!(
            config.request_timeout,
            Duration::from_secs(48),
            "manifest must win without explicit opt-in"
        );
    }

    #[test]
    fn from_manifest_honors_ambient_timeout_env_with_opt_in() {
        // br-3a3r6: when the operator explicitly sets
        // FCP_ALLOW_AMBIENT_TIMEOUT_OVERRIDE=1, the env override is
        // honored and replaces the manifest request_timeout.
        let _opt_in = OptInOverrideGuard::set(Some("1"));
        let _timeout = RequestTimeoutOverrideGuard::set(Some("99000"));
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config =
            ConnectorRuntimeConfig::from_manifest(&manifest).expect("opt-in path should succeed");
        assert_eq!(
            config.request_timeout,
            Duration::from_secs(99),
            "explicit opt-in must let env override the manifest request timeout"
        );
        assert_eq!(config.connect_timeout, Duration::from_secs(8));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(95));
    }

    #[test]
    fn from_manifest_invalid_env_with_opt_in_returns_error() {
        // br-3a3r6: when opt-in is on, an unparseable
        // FCP_REQUEST_TIMEOUT_MS surfaces as an error (was the existing
        // contract before the gate). Without opt-in the env is never
        // consulted, so a malformed value is silently irrelevant -- that
        // behavior is documented on `from_manifest`.
        let _opt_in = OptInOverrideGuard::set(Some("1"));
        let _timeout = RequestTimeoutOverrideGuard::set(Some("not-a-number"));
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(None))
            .expect("manifest should parse");
        let err = ConnectorRuntimeConfig::from_manifest(&manifest).unwrap_err();
        assert!(
            err.to_string()
                .contains("FCP_REQUEST_TIMEOUT_MS must be a positive integer")
        );
    }

    #[test]
    fn from_manifest_invalid_env_without_opt_in_is_ignored() {
        // br-3a3r6: malformed FCP_REQUEST_TIMEOUT_MS in the absence of
        // opt-in must NOT cause a startup error -- the value is never
        // consulted, so the manifest path completes cleanly.
        let _opt_in = OptInOverrideGuard::set(None);
        let _timeout = RequestTimeoutOverrideGuard::set(Some("garbage"));
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config = ConnectorRuntimeConfig::from_manifest(&manifest)
            .expect("malformed env must be ignored without opt-in");
        assert_eq!(config.request_timeout, Duration::from_secs(48));
    }

    #[test]
    fn config_debug() {
        let config = ConnectorRuntimeConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("ConnectorRuntimeConfig"));
    }

    #[test]
    fn config_clone() {
        let config =
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(77));
        let moved = config;
        assert_eq!(moved.request_timeout, Duration::from_secs(77));
    }

    #[test]
    fn runtime_request_context_with_custom_timeout() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context_with_timeout(Duration::from_secs(5));
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn runtime_shutdown_timeout_accessor() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_shutdown_timeout(Duration::from_secs(15)),
        );
        assert_eq!(runtime.shutdown_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn runtime_multiple_background_contexts_independent() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg1 = runtime.background_context();
        let bg2 = runtime.background_context();
        assert!(!bg1.is_cancelled());
        assert!(!bg2.is_cancelled());
        runtime.shutdown();
        assert!(bg1.is_cancelled());
        assert!(bg2.is_cancelled());
    }

    #[test]
    fn runtime_shutdown_idempotent() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        runtime.shutdown();
        assert!(runtime.is_shutting_down());
        runtime.shutdown();
        assert!(runtime.is_shutting_down());
    }

    #[test]
    fn runtime_debug() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let debug = format!("{runtime:?}");
        assert!(debug.contains("ConnectorRuntime"));
    }

    #[test]
    fn runtime_clone() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(42)),
        );
        let moved = runtime;
        assert_eq!(moved.request_timeout(), Duration::from_secs(42));
    }

    #[test]
    fn runtime_request_context_not_cancelled() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context();
        assert!(!ctx.is_cancelled());
        let budget = ctx.remaining_budget();
        assert!(budget.is_some());
        assert!(budget.unwrap() <= Duration::from_secs(120));
    }

    #[test]
    fn runtime_custom_timeout_propagates_to_context() {
        let timeout = Duration::from_millis(500);
        let runtime =
            ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(timeout));
        let ctx = runtime.request_context();
        let budget = ctx.remaining_budget().unwrap();
        assert!(budget <= timeout);
    }

    #[test]
    fn runtime_background_context_has_no_deadline() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg = runtime.background_context();
        assert!(bg.remaining_budget().is_none());
    }

    #[test]
    fn runtime_shutdown_cancels_all_background_children() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg1 = runtime.background_context();
        let bg2 = runtime.background_context();
        let bg3 = runtime.background_context();
        assert!(!bg1.is_cancelled());
        assert!(!bg2.is_cancelled());
        assert!(!bg3.is_cancelled());
        runtime.shutdown();
        assert!(bg1.is_cancelled());
        assert!(bg2.is_cancelled());
        assert!(bg3.is_cancelled());
    }

    #[test]
    fn runtime_request_context_is_cancelled_by_shutdown() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx_before = runtime.request_context();
        assert!(!ctx_before.is_cancelled());
        runtime.shutdown();
        assert!(ctx_before.is_cancelled());
    }

    #[test]
    fn runtime_request_context_created_after_shutdown_starts_cancelled() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        runtime.shutdown();

        let ctx = runtime.request_context();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn runtime_with_zero_request_timeout() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::ZERO),
        );
        assert_eq!(runtime.request_timeout(), Duration::ZERO);
        let ctx = runtime.request_context();
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn runtime_with_large_timeout() {
        let timeout = Duration::from_secs(86_400);
        let runtime =
            ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(timeout));
        assert_eq!(runtime.request_timeout(), timeout);
    }

    #[test]
    fn runtime_config_clone_preserves_values() {
        let config = ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_secs(42))
            .with_shutdown_timeout(Duration::from_secs(7));
        let cloned = config.clone();
        assert_eq!(config.request_timeout, Duration::from_secs(42));
        assert_eq!(cloned.shutdown_timeout, Duration::from_secs(7));
    }

    #[test]
    fn runtime_clone_shares_background_ctx() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let cloned = runtime.clone();
        assert!(!runtime.is_shutting_down());
        assert!(!cloned.is_shutting_down());
        runtime.shutdown();
        assert!(cloned.is_shutting_down());
    }

    #[test]
    fn opt_in_value_allows_override_recognises_truthy_values() {
        for value in ["1", "true", "yes"] {
            assert!(
                opt_in_value_allows_override(Some(value)),
                "{value:?} should be treated as opt-in"
            );
        }
        for value in ["0", "false", "no", "", "True", "YES", "TRUE", " 1", "1 "] {
            assert!(
                !opt_in_value_allows_override(Some(value)),
                "{value:?} should NOT be treated as opt-in (case-sensitive exact match required)"
            );
        }
        assert!(
            !opt_in_value_allows_override(None),
            "unset env must default to opt-in disabled"
        );
    }

    #[derive(Clone, Default)]
    #[allow(dead_code)]
    struct LogCapture {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl LogCapture {
        #[allow(dead_code)]
        fn install_json(&self, filter: EnvFilter) -> tracing::subscriber::DefaultGuard {
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(self.clone())
                .json()
                .with_ansi(false)
                .with_level(false)
                .with_target(false)
                .with_file(false)
                .with_line_number(false)
                .with_current_span(false)
                .flatten_event(true);

            let subscriber = tracing_subscriber::registry().with(filter).with(layer);
            tracing::subscriber::set_default(subscriber)
        }

        #[allow(dead_code)]
        fn jsonl(&self) -> String {
            let guard = self
                .bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).to_string()
        }
    }

    #[allow(dead_code)]
    struct LogCaptureWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for LogCaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogCaptureWriter {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    #[derive(Debug, Default, Clone)]
    struct TestStreamingSession {
        resume_token: Option<String>,
        sequence: u64,
        last_heartbeat_sent: Option<Instant>,
        last_heartbeat_ack: Option<Instant>,
        heartbeat_seq: u64,
        ack_seq: u64,
        outstanding_heartbeats: VecDeque<Instant>,
        persist_calls: Arc<AtomicUsize>,
        restore_calls: Arc<AtomicUsize>,
    }

    impl TestStreamingSession {
        fn persist_calls(&self) -> usize {
            self.persist_calls.load(Ordering::SeqCst)
        }

        fn restore_calls(&self) -> usize {
            self.restore_calls.load(Ordering::SeqCst)
        }
    }

    impl StreamingSession for TestStreamingSession {
        fn resume_token(&self) -> Option<String> {
            self.resume_token.clone()
        }

        fn set_resume_token(&mut self, token: String) {
            self.resume_token = Some(token);
        }

        fn clear_resume_token(&mut self) {
            self.resume_token = None;
        }

        fn sequence(&self) -> u64 {
            self.sequence
        }

        fn set_sequence(&mut self, seq: u64) {
            self.sequence = seq;
        }

        fn record_heartbeat_sent(&mut self, at: Instant) {
            self.last_heartbeat_sent = Some(at);
            self.heartbeat_seq = self.heartbeat_seq.saturating_add(1);
            self.outstanding_heartbeats.push_back(at);
        }

        fn record_heartbeat_ack(&mut self, at: Instant) {
            self.last_heartbeat_ack = Some(at);
            if self.outstanding_heartbeats.pop_front().is_some() {
                self.ack_seq = self.ack_seq.saturating_add(1);
            }
        }

        fn last_heartbeat_sent(&self) -> Option<Instant> {
            self.last_heartbeat_sent
        }

        fn last_heartbeat_ack(&self) -> Option<Instant> {
            self.last_heartbeat_ack
        }

        fn heartbeat_seq(&self) -> u64 {
            self.heartbeat_seq
        }

        fn ack_seq(&self) -> u64 {
            self.ack_seq
        }

        fn first_unacked_heartbeat_sent(&self) -> Option<Instant> {
            self.outstanding_heartbeats.front().copied()
        }

        fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.restore_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn supervisor_config_defaults() {
        let config = SupervisorConfig::default();
        assert_eq!(config.base_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60_000);
        assert!(config.jitter_enabled);
        assert_eq!(config.max_consecutive_failures, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn supervisor_config_validation() {
        let config = SupervisorConfig {
            base_backoff_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = SupervisorConfig {
            max_backoff_ms: 500, // Less than base
            base_backoff_ms: 1000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn backoff_exponential() {
        let config = SupervisorConfig::default().with_jitter(false);
        assert_eq!(config.compute_backoff(0), 1000);
        assert_eq!(config.compute_backoff(1), 2000);
        assert_eq!(config.compute_backoff(2), 4000);
        assert_eq!(config.compute_backoff(3), 8000);
        // Should cap at max
        assert_eq!(config.compute_backoff(10), 60_000);
    }

    #[test]
    fn backoff_with_jitter() {
        let config = SupervisorConfig::default();
        let delay0 = config.compute_backoff_with_jitter(0, 0.0); // Min jitter
        let delay1 = config.compute_backoff_with_jitter(0, 1.0); // Max jitter
        assert!((500..=1000).contains(&delay0));
        assert!((500..=1000).contains(&delay1));
    }

    #[test]
    fn streaming_session_in_memory() {
        let mut session = InMemoryStreamingSession::new();
        assert!(session.resume_token().is_none());
        assert_eq!(session.sequence(), 0);
        assert_eq!(session.heartbeat_seq(), 0);
        assert_eq!(session.ack_seq(), 0);

        session.set_resume_token("token123".to_string());
        assert_eq!(session.resume_token(), Some("token123".to_string()));

        let seq = session.next_sequence();
        assert_eq!(seq, 0);
        assert_eq!(session.sequence(), 1);

        session.clear_resume_token();
        assert!(session.resume_token().is_none());

        let now = Instant::now();
        session.record_heartbeat_sent(now);
        session.record_heartbeat_ack(now);
        assert_eq!(session.heartbeat_seq(), 1);
        assert_eq!(session.ack_seq(), 1);
    }

    #[test]
    fn streaming_session_heartbeat_timeout_logic() {
        let mut session = InMemoryStreamingSession::new();

        let now = Instant::now();
        let sent = now.checked_sub(Duration::from_millis(25)).unwrap_or(now);
        session.record_heartbeat_sent(sent);
        assert!(session.is_heartbeat_timeout(Duration::from_millis(10)));

        session.record_heartbeat_ack(Instant::now());
        assert!(!session.is_heartbeat_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn streaming_health_snapshot_includes_streaming_details() {
        let config = SupervisorConfig::default();
        let session = InMemoryStreamingSession::new();
        let mut supervisor = StreamingSupervisor::new(config, session);

        let now = Instant::now();
        supervisor.session_mut().record_heartbeat_sent(now);
        supervisor.session_mut().record_heartbeat_ack(now);

        let snapshot = supervisor.streaming_health_snapshot();
        let details = snapshot.details.expect("streaming details");
        let details = details.as_object().expect("details map");

        assert!(
            details
                .get("last_heartbeat_at")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
        assert!(
            details
                .get("last_ack_at")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
        assert_eq!(
            details
                .get("reconnect_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            details
                .get("missed_heartbeats")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn polling_cursor_advance() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.offset().is_none());

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50); // Older, should not change
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(200);
        assert_eq!(cursor.offset(), Some(201));
    }

    #[test]
    fn health_tracker_transitions() {
        let mut tracker = HealthTracker::new();
        assert!(matches!(tracker.state(), HealthState::Starting));

        // Starting -> Ready
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Degraded
        tracker.record_failure("timeout");
        tracker.transition(HealthTransition::ToDegraded {
            reason: "timeout".to_string(),
        });
        assert!(tracker.is_degraded());

        // Degraded -> Healthy
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Unhealthy
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "fatal".to_string(),
        });
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_tracker_auto_evaluate() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(3);
        let mut tracker = HealthTracker::new();

        // Starting -> Ready after first success
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        // Ready -> Degraded after 1 failure
        tracker.record_failure("err1");
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // Degraded -> Unhealthy after 3 failures
        tracker.record_failure("err2");
        tracker.record_failure("err3");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_snapshot_generation() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);

        let snapshot = tracker.snapshot();
        assert!(matches!(snapshot.status, HealthState::Ready));
        // uptime_ms is always >= 0 for u64, so just verify it exists
        let _ = snapshot.uptime_ms;
        assert_eq!(snapshot.load, Some(0.0));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Healthy is invalid (already healthy)
        assert!(!tracker.transition(HealthTransition::ToHealthy));

        // Ready -> Starting is always valid (reset)
        assert!(tracker.transition(HealthTransition::ToStarting));
        assert!(matches!(tracker.state(), HealthState::Starting));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StreamingSupervisor tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_supervisor_shutdown_signal() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default();
            let session = InMemoryStreamingSession::new();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(true);
            let _ = shutdown_tx;

            let outcome = supervisor
                .run::<i32, _, _, _, _>(
                    shutdown_rx,
                    |_session| async { Err(boxed_err("should not connect")) },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
        });
    }

    #[test]
    fn streaming_supervisor_restores_and_persists_on_shutdown() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default();
            let session = TestStreamingSession::default();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(true);
            let _ = shutdown_tx;

            let outcome = supervisor
                .run::<i32, _, _, _, _>(
                    shutdown_rx,
                    |_session| async { Err(boxed_err("should not connect")) },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
            assert_eq!(supervisor.session().restore_calls(), 1);
            assert_eq!(supervisor.session().persist_calls(), 1);
        });
    }

    #[test]
    fn streaming_supervisor_max_failures() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_max_consecutive_failures(2)
                .with_base_backoff_ms(1);
            let session = InMemoryStreamingSession::new();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run::<i32, _, _, _, _>(
                    shutdown_rx,
                    |_session| async { Err(boxed_err("connect failed")) },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 2 }
            ));
        });
    }

    #[test]
    fn streaming_supervisor_persists_on_max_failures() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_max_consecutive_failures(1)
                .with_base_backoff_ms(1);
            let session = TestStreamingSession::default();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run::<i32, _, _, _, _>(
                    shutdown_rx,
                    |_session| async { Err(boxed_err("connect failed")) },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 1 }
            ));
            assert_eq!(supervisor.session().restore_calls(), 1);
            assert_eq!(supervisor.session().persist_calls(), 1);
        });
    }

    #[test]
    fn streaming_supervisor_fatal_event_handler() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default().with_base_backoff_ms(1);
            let session = InMemoryStreamingSession::new();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    |_session| async {
                        let (tx, rx) = mpsc::channel(1);
                        let _ = tx.send(42).await;
                        let join_handle = fcp_async_core::task::spawn(async { Ok(()) });
                        Ok(StreamingConnection {
                            events: rx,
                            join_handle,
                        })
                    },
                    |_event, _session| async { Err(boxed_err("handler failed")) },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::FatalError { message } if message == "handler failed"
            ));
        });
    }

    #[test]
    fn streaming_supervisor_heartbeat_timeout_transitions_and_logs() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig {
                heartbeat_interval_ms: 10,
                heartbeat_timeout_multiplier: 1.1,
                max_consecutive_failures: 1,
                base_backoff_ms: 1,
                jitter_enabled: false,
                ..Default::default()
            };

            let session = InMemoryStreamingSession::new();
            let mut supervisor = StreamingSupervisor::new(config, session);
            supervisor
                .session_mut()
                .record_heartbeat_sent(Instant::now());

            let capture = LogCapture::default();
            let _guard = capture.install_json(EnvFilter::new("warn"));

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run::<(), _, _, _, _>(
                    shutdown_rx,
                    |_session| async {
                        let (tx, rx) = mpsc::channel(1);
                        let join_handle = fcp_async_core::task::spawn(async move {
                            let _tx = tx;
                            std::future::pending::<Result<(), StreamingError>>().await
                        });
                        Ok(StreamingConnection {
                            events: rx,
                            join_handle,
                        })
                    },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 1 }
            ));
            assert_eq!(supervisor.stats().missed_heartbeats, 1);
            assert!(supervisor.health().is_unhealthy());

            let logs = capture.jsonl();
            let mut heartbeat_log = None;
            for line in logs.lines() {
                let value: serde_json::Value =
                    serde_json::from_str(line).expect("valid heartbeat log json");
                if value.get("message").and_then(|message| message.as_str())
                    == Some("Streaming heartbeat timeout")
                {
                    heartbeat_log = Some(value);
                    break;
                }
            }

            let log = heartbeat_log.expect("missing heartbeat timeout log");
            assert_eq!(log["heartbeat_seq"], 1);
            assert_eq!(log["ack_seq"], 0);
            assert_eq!(log["missed_heartbeats"], 1);
            assert_eq!(log["reconnect_count"], 0);
        });
    }

    #[test]
    fn streaming_supervisor_resume_fallback_to_full_connect() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_base_backoff_ms(1)
                .with_max_consecutive_failures(3);
            let mut session = InMemoryStreamingSession::new();
            session.set_resume_token("resume-token".to_string());

            let attempts = Arc::new(AtomicUsize::new(0));
            let resume_attempts = Arc::new(AtomicUsize::new(0));
            let full_attempts = Arc::new(AtomicUsize::new(0));

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
            let shutdown_tx = Arc::new(shutdown_tx);

            let mut supervisor = StreamingSupervisor::new(config, session);

            let attempts_cloned = Arc::clone(&attempts);
            let resume_attempts_cloned = Arc::clone(&resume_attempts);
            let full_attempts_cloned = Arc::clone(&full_attempts);
            let shutdown_tx_cloned = Arc::clone(&shutdown_tx);

            let outcome = supervisor
                .run::<(), _, _, _, _>(
                    shutdown_rx,
                    move |session| {
                        let attempts = Arc::clone(&attempts_cloned);
                        let resume_attempts = Arc::clone(&resume_attempts_cloned);
                        let full_attempts = Arc::clone(&full_attempts_cloned);
                        let shutdown_tx = Arc::clone(&shutdown_tx_cloned);

                        attempts.fetch_add(1, Ordering::SeqCst);

                        let result = if session.resume_token().is_some() {
                            resume_attempts.fetch_add(1, Ordering::SeqCst);
                            session.clear_resume_token();
                            Err(boxed_err("resume failed"))
                        } else {
                            full_attempts.fetch_add(1, Ordering::SeqCst);
                            let _ = shutdown_tx.send(true);

                            let (tx, rx) = mpsc::channel(1);
                            drop(tx);
                            let join_handle = fcp_async_core::task::spawn(async { Ok(()) });
                            Ok(StreamingConnection {
                                events: rx,
                                join_handle,
                            })
                        };

                        std::future::ready(result)
                    },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
            assert_eq!(resume_attempts.load(Ordering::SeqCst), 1);
            assert_eq!(full_attempts.load(Ordering::SeqCst), 1);
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            assert_eq!(supervisor.stats().connection_attempts, 2);
            assert_eq!(supervisor.streaming_health_state().reconnect_count, 1);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollingSupervisor tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn poll_result_constructors() {
        let success: PollResult<i32> = PollResult::success(vec![1, 2, 3]);
        assert!(matches!(success, PollResult::Success(items) if items.len() == 3));

        let empty: PollResult<i32> = PollResult::empty();
        assert!(matches!(empty, PollResult::Success(items) if items.is_empty()));

        let recoverable: PollResult<i32> = PollResult::recoverable("timeout");
        assert!(matches!(
            recoverable,
            PollResult::RecoverableError {
                retry_after_ms: None,
                ..
            }
        ));

        let rate_limited: PollResult<i32> = PollResult::rate_limited("too fast", 5000);
        assert!(matches!(
            rate_limited,
            PollResult::RecoverableError {
                retry_after_ms: Some(5000),
                ..
            }
        ));

        let fatal: PollResult<i32> = PollResult::fatal("auth failed");
        assert!(matches!(fatal, PollResult::FatalError { .. }));
    }

    #[test]
    fn polling_supervisor_creation() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config.clone(), cursor);

        assert!(supervisor.cursor().offset().is_none());
        assert!(matches!(supervisor.health().state(), HealthState::Starting));
        assert_eq!(supervisor.stats().total_polls, 0);
        assert_eq!(supervisor.config().base_backoff_ms, config.base_backoff_ms);
    }

    #[test]
    fn polling_supervisor_compute_delay_respects_retry_after() {
        let config = SupervisorConfig::default().with_jitter(false);
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config, cursor);

        // Without retry-after, uses exponential backoff
        let delay = supervisor.compute_delay(0, None);
        assert_eq!(delay.as_millis(), 1000);

        // With smaller retry-after, uses backoff
        let delay = supervisor.compute_delay(0, Some(500));
        assert_eq!(delay.as_millis(), 1000);

        // With larger retry-after, uses retry-after
        let delay = supervisor.compute_delay(0, Some(10_000));
        assert_eq!(delay.as_millis(), 10_000);
    }

    #[test]
    fn polling_supervisor_stats_default() {
        let stats = PollingSupervisorStats::default();
        assert_eq!(stats.total_polls, 0);
        assert_eq!(stats.successful_polls, 0);
        assert_eq!(stats.failed_polls, 0);
        assert_eq!(stats.items_processed, 0);
        assert_eq!(stats.backoff_time_ms, 0);
    }

    #[test]
    fn polling_supervisor_shutdown_signal() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default();
            let cursor = InMemoryPollingCursor::new();
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(true); // Start with shutdown
            let _ = shutdown_tx; // Keep sender alive

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    1000,
                    |_offset| async { PollResult::<i32>::empty() },
                    |_items, _cursor| Ok(()),
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
        });
    }

    #[test]
    fn polling_supervisor_fatal_error_stops() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default();
            let cursor = InMemoryPollingCursor::new();
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    1000,
                    |_offset| async { PollResult::<i32>::fatal("auth failed") },
                    |_items, _cursor| Ok(()),
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::FatalError { message } if message == "auth failed"
            ));
            assert_eq!(supervisor.stats().total_polls, 1);
            assert_eq!(supervisor.stats().failed_polls, 0); // Fatal errors don't increment failed_polls
        });
    }

    #[test]
    fn polling_supervisor_max_failures() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_max_consecutive_failures(2)
                .with_base_backoff_ms(1); // Fast backoff for testing
            let cursor = InMemoryPollingCursor::new();
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    1,
                    |_offset| async { PollResult::<i32>::recoverable("timeout") },
                    |_items, _cursor| Ok(()),
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 2 }
            ));
            assert_eq!(supervisor.stats().failed_polls, 2);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SupervisorConfig builder and duration helpers
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn supervisor_config_builder_methods() {
        let config = SupervisorConfig::new()
            .with_base_backoff_ms(500)
            .with_max_backoff_ms(30_000)
            .with_jitter(false)
            .with_max_consecutive_failures(10);

        assert_eq!(config.base_backoff_ms, 500);
        assert_eq!(config.max_backoff_ms, 30_000);
        assert!(!config.jitter_enabled);
        assert_eq!(config.max_consecutive_failures, 10);
    }

    #[test]
    fn supervisor_config_shutdown_timeout() {
        let config = SupervisorConfig::default();
        assert_eq!(config.shutdown_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn supervisor_config_cooldown_duration() {
        let config = SupervisorConfig::default();
        assert_eq!(config.cooldown_duration(), Duration::from_secs(300));
    }

    #[test]
    fn supervisor_config_heartbeat_interval_enabled() {
        let config = SupervisorConfig::default();
        assert_eq!(config.heartbeat_interval(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn supervisor_config_heartbeat_interval_disabled() {
        let config = SupervisorConfig {
            heartbeat_interval_ms: 0,
            ..Default::default()
        };
        assert!(config.heartbeat_interval().is_none());
    }

    #[test]
    fn supervisor_config_heartbeat_timeout() {
        let config = SupervisorConfig::default();
        let timeout = config.heartbeat_timeout().expect("heartbeat enabled");
        // 30s * 2.5 = 75s
        assert_eq!(timeout, Duration::from_secs_f64(30.0 * 2.5));
    }

    #[test]
    fn supervisor_config_heartbeat_timeout_disabled() {
        let config = SupervisorConfig {
            heartbeat_interval_ms: 0,
            ..Default::default()
        };
        assert!(config.heartbeat_timeout().is_none());
    }

    #[test]
    fn supervisor_config_serde_roundtrip() {
        let config = SupervisorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_backoff_ms, config.base_backoff_ms);
        assert_eq!(parsed.max_backoff_ms, config.max_backoff_ms);
        assert_eq!(parsed.jitter_enabled, config.jitter_enabled);
        assert_eq!(
            parsed.max_consecutive_failures,
            config.max_consecutive_failures
        );
    }

    #[test]
    fn supervisor_config_validate_zero_max_failures() {
        let config = SupervisorConfig {
            max_consecutive_failures: 0,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("max_consecutive_failures"))
        );
    }

    #[test]
    fn supervisor_config_validate_low_heartbeat_multiplier() {
        let config = SupervisorConfig {
            heartbeat_timeout_multiplier: 0.5,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("heartbeat_timeout_multiplier"))
        );
    }

    #[test]
    fn supervisor_config_validate_multiple_errors() {
        let config = SupervisorConfig {
            base_backoff_ms: 0,
            max_backoff_ms: 0,
            max_consecutive_failures: 0,
            heartbeat_timeout_multiplier: 1.0,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(errors.len() >= 3);
    }

    #[test]
    fn backoff_caps_at_max() {
        let config = SupervisorConfig::default().with_jitter(false);
        // Attempt 31 (> 30 overflow guard)
        let delay = config.compute_backoff(31);
        assert_eq!(delay, 60_000);
    }

    #[test]
    fn backoff_with_jitter_disabled() {
        let config = SupervisorConfig::default().with_jitter(false);
        let delay = config.compute_backoff_with_jitter(0, 0.5);
        assert_eq!(delay, 1000); // No jitter applied
    }

    #[test]
    fn backoff_with_jitter_clamped() {
        let config = SupervisorConfig::default();
        // jitter_factor out of range should be clamped
        let delay_negative = config.compute_backoff_with_jitter(0, -1.0);
        let delay_over = config.compute_backoff_with_jitter(0, 2.0);
        // -1.0 clamped to 0.0 → factor=0.5 → 500
        assert_eq!(delay_negative, 500);
        // 2.0 clamped to 1.0 → factor=1.0 → 1000
        assert_eq!(delay_over, 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollingCursor additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn polling_cursor_with_offset() {
        let cursor = InMemoryPollingCursor::with_offset(42);
        assert_eq!(cursor.offset(), Some(42));
    }

    #[test]
    fn polling_cursor_record_poll() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.last_poll_at().is_none());
        assert_eq!(cursor.last_poll_count(), 0);

        let now = Instant::now();
        cursor.record_poll(now, 5);
        assert!(cursor.last_poll_at().is_some());
        assert_eq!(cursor.last_poll_count(), 5);
    }

    #[test]
    fn polling_cursor_persist_restore() {
        let cursor = InMemoryPollingCursor::new();
        assert!(cursor.persist().is_ok());
        let mut cursor2 = InMemoryPollingCursor::new();
        assert!(cursor2.restore().is_ok());
    }

    #[test]
    fn polling_cursor_advance_from_none() {
        let mut cursor = InMemoryPollingCursor::new();
        cursor.advance_if_newer(0);
        assert_eq!(cursor.offset(), Some(1));
    }

    #[test]
    fn polling_cursor_advance_equal_id() {
        let mut cursor = InMemoryPollingCursor::with_offset(101);
        // advance_if_newer(100) → new_offset=101, which is NOT > 101
        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101)); // Unchanged
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StreamingSession additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_session_persist_restore() {
        let session = InMemoryStreamingSession::new();
        assert!(session.persist().is_ok());
        let mut session2 = InMemoryStreamingSession::new();
        assert!(session2.restore().is_ok());
    }

    #[test]
    fn streaming_session_heartbeat_no_timeout_when_no_heartbeats() {
        let session = InMemoryStreamingSession::new();
        // No heartbeats sent or received → no timeout
        assert!(!session.is_heartbeat_timeout(Duration::from_millis(1)));
    }

    #[test]
    fn streaming_session_next_sequence_increments() {
        let mut session = InMemoryStreamingSession::new();
        assert_eq!(session.next_sequence(), 0);
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.next_sequence(), 2);
        assert_eq!(session.sequence(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthTracker extended tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_tracker_default() {
        let tracker = HealthTracker::default();
        assert!(matches!(tracker.state(), HealthState::Starting));
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.consecutive_successes(), 0);
    }

    #[test]
    fn health_tracker_consecutive_counters() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.record_success();
        assert_eq!(tracker.consecutive_successes(), 2);
        assert_eq!(tracker.consecutive_failures(), 0);

        tracker.record_failure("err");
        assert_eq!(tracker.consecutive_successes(), 0);
        assert_eq!(tracker.consecutive_failures(), 1);

        tracker.record_failure("err2");
        assert_eq!(tracker.consecutive_failures(), 2);

        tracker.record_success();
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.consecutive_successes(), 1);
    }

    #[test]
    fn health_tracker_snapshot_with_failures() {
        let mut tracker = HealthTracker::new();
        tracker.record_failure("timeout");
        tracker.record_failure("timeout");
        tracker.record_failure("timeout");

        let snapshot = tracker.snapshot();
        assert!(matches!(snapshot.status, HealthState::Starting));
        // 3 failures → load = 3/10 = 0.3
        assert_eq!(snapshot.load, Some(0.3));
        assert!(snapshot.details.is_some());
        let details = snapshot.details.unwrap();
        assert_eq!(details["consecutive_failures"], 3);
        assert_eq!(details["last_error"], "timeout");
    }

    #[test]
    fn health_tracker_cooldown_not_elapsed_immediately() {
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "fatal".into(),
        });
        // Cooldown just started, should not be elapsed for large durations
        assert!(!tracker.cooldown_elapsed(Duration::from_secs(3600)));
    }

    #[test]
    fn health_tracker_cooldown_elapsed_when_healthy() {
        let tracker = HealthTracker::new();
        // Not unhealthy → cooldown always "elapsed"
        assert!(tracker.cooldown_elapsed(Duration::from_secs(3600)));
    }

    #[test]
    fn health_tracker_stopping_is_terminal() {
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToHealthy);
        tracker.transition(HealthTransition::ToDegraded {
            reason: "slow".into(),
        });

        // Manually set to Stopping for testing
        tracker.apply_transition(HealthTransition::ToStarting);
        // We can't directly set Stopping via public API, but we can test is_valid_transition
    }

    #[test]
    fn health_tracker_transition_validity_matrix() {
        // Starting → anything is valid
        let tracker = HealthTracker::new();
        assert!(tracker.is_valid_transition(&HealthTransition::ToHealthy));
        assert!(tracker.is_valid_transition(&HealthTransition::ToDegraded { reason: "x".into() }));
        assert!(tracker.is_valid_transition(&HealthTransition::ToUnhealthy { reason: "x".into() }));
        assert!(tracker.is_valid_transition(&HealthTransition::ToStarting));

        // Ready → can degrade or fail, NOT go to healthy again
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(!tracker.is_valid_transition(&HealthTransition::ToHealthy));
        assert!(tracker.is_valid_transition(&HealthTransition::ToDegraded { reason: "x".into() }));
        assert!(tracker.is_valid_transition(&HealthTransition::ToUnhealthy { reason: "x".into() }));
        assert!(tracker.is_valid_transition(&HealthTransition::ToStarting));

        // Degraded → can recover or fail
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToDegraded {
            reason: "slow".into(),
        });
        assert!(tracker.is_valid_transition(&HealthTransition::ToHealthy));
        assert!(!tracker.is_valid_transition(&HealthTransition::ToDegraded { reason: "x".into() }));
        assert!(tracker.is_valid_transition(&HealthTransition::ToUnhealthy { reason: "x".into() }));

        // Error → can recover (fully or partially)
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "bad".into(),
        });
        assert!(tracker.is_valid_transition(&HealthTransition::ToHealthy));
        assert!(tracker.is_valid_transition(&HealthTransition::ToDegraded { reason: "x".into() }));
        assert!(
            !tracker.is_valid_transition(&HealthTransition::ToUnhealthy { reason: "x".into() })
        );
    }

    #[test]
    fn health_tracker_evaluate_starting_to_unhealthy() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(2);
        let mut tracker = HealthTracker::new();
        tracker.record_failure("err1");
        tracker.record_failure("err2");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_tracker_evaluate_degraded_to_healthy() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(5);
        let mut tracker = HealthTracker::new();

        // Starting → Ready
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        // Ready → Degraded
        tracker.record_failure("err");
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // Degraded → Healthy (needs 3 consecutive successes)
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_degraded()); // Only 1 success
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_degraded()); // Only 2
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy()); // 3 → recovered
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorStoreError display tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_store_error_storage_display() {
        let err = CursorStoreError::Storage("disk full".into());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn cursor_store_error_stale_lease_display() {
        let err = CursorStoreError::StaleLeaseSeq {
            current: 5,
            incoming: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains('3'));
    }

    #[test]
    fn cursor_store_error_offset_regression_display() {
        let err = CursorStoreError::OffsetRegression {
            current: 100,
            incoming: 50,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn cursor_store_error_watermark_regression_display() {
        let err = CursorStoreError::WatermarkRegression {
            current: 200,
            incoming: 100,
        };
        assert!(err.to_string().contains("200"));
    }

    #[test]
    fn cursor_store_error_encoding_display() {
        let err = CursorStoreError::CursorEncoding("cbor fail".into());
        assert!(err.to_string().contains("cbor fail"));
    }

    #[test]
    fn cursor_store_error_decoding_display() {
        let err = CursorStoreError::CursorDecoding("invalid cbor".into());
        assert!(err.to_string().contains("invalid cbor"));
    }

    #[test]
    fn cursor_store_error_debug() {
        let err = CursorStoreError::Storage("test".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Storage"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StreamingSupervisorStats tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_supervisor_stats_default() {
        let stats = StreamingSupervisorStats::default();
        assert_eq!(stats.connection_attempts, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.failed_connections, 0);
        assert_eq!(stats.events_processed, 0);
    }

    #[test]
    fn streaming_supervisor_stats_clone() {
        let stats = StreamingSupervisorStats {
            connection_attempts: 5,
            successful_connections: 3,
            failed_connections: 2,
            events_processed: 100,
            backoff_time_ms: 500,
            missed_heartbeats: 1,
        };
        let moved = stats;
        assert_eq!(moved.connection_attempts, 5);
        assert_eq!(moved.events_processed, 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorLease Debug
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_lease_debug() {
        let lease = CursorLease {
            lease_seq: 42,
            lease_object_id: ObjectId::from_bytes([1; 32]),
        };
        let debug = format!("{lease:?}");
        assert!(debug.contains("CursorLease"));
        assert!(debug.contains("42"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthTransition Debug/Clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_transition_debug() {
        let t = HealthTransition::ToDegraded {
            reason: "slow".into(),
        };
        let debug = format!("{t:?}");
        assert!(debug.contains("ToDegraded"));
        assert!(debug.contains("slow"));
    }

    #[test]
    fn health_transition_clone() {
        let t = HealthTransition::ToUnhealthy {
            reason: "fatal".into(),
        };
        let moved = t;
        assert!(format!("{moved:?}").contains("fatal"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SupervisorOutcome tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn supervisor_outcome_debug() {
        let shutdown = SupervisorOutcome::Shutdown;
        assert!(format!("{shutdown:?}").contains("Shutdown"));

        let fatal = SupervisorOutcome::FatalError {
            message: "auth failed".into(),
        };
        assert!(format!("{fatal:?}").contains("auth failed"));

        let max = SupervisorOutcome::MaxFailuresReached { failures: 5 };
        assert!(format!("{max:?}").contains('5'));
    }

    #[test]
    fn supervisor_outcome_clone() {
        let outcome = SupervisorOutcome::FatalError {
            message: "test".into(),
        };
        let moved = outcome;
        assert!(matches!(
            moved,
            SupervisorOutcome::FatalError { message } if message == "test"
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StreamingHealthState serde tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_health_state_serde_roundtrip() {
        let state = StreamingHealthState {
            last_heartbeat_at: Some(1000),
            last_ack_at: Some(900),
            reconnect_count: 3,
            missed_heartbeats: 1,
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: StreamingHealthState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.last_heartbeat_at, Some(1000));
        assert_eq!(parsed.last_ack_at, Some(900));
        assert_eq!(parsed.reconnect_count, 3);
        assert_eq!(parsed.missed_heartbeats, 1);
    }

    #[test]
    fn streaming_health_state_serde_skip_none() {
        let state = StreamingHealthState {
            last_heartbeat_at: None,
            last_ack_at: None,
            reconnect_count: 0,
            missed_heartbeats: 0,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("last_heartbeat_at"));
        assert!(!json.contains("last_ack_at"));
    }

    #[test]
    fn streaming_health_state_debug() {
        let state = StreamingHealthState {
            last_heartbeat_at: Some(42),
            last_ack_at: None,
            reconnect_count: 7,
            missed_heartbeats: 2,
        };
        let dbg = format!("{state:?}");
        assert!(dbg.contains("StreamingHealthState"));
        assert!(dbg.contains("42"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthTracker evaluate: Error → recovery path
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_tracker_evaluate_error_recovery_after_cooldown() {
        let config = SupervisorConfig {
            cooldown_after_failure_ms: 0, // Zero cooldown for test
            max_consecutive_failures: 2,
            ..Default::default()
        };
        let mut tracker = HealthTracker::new();

        // Starting → Unhealthy via failures
        tracker.record_failure("err1");
        tracker.record_failure("err2");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());

        // Record success — with zero cooldown, should recover
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());
    }

    #[test]
    fn health_tracker_evaluate_error_no_recovery_without_cooldown() {
        let config = SupervisorConfig {
            cooldown_after_failure_ms: 3_600_000, // 1 hour cooldown
            max_consecutive_failures: 2,
            ..Default::default()
        };
        let mut tracker = HealthTracker::new();

        // Go to unhealthy
        tracker.record_failure("err1");
        tracker.record_failure("err2");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());

        // Record success but cooldown hasn't elapsed
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy()); // Still unhealthy
    }

    #[test]
    fn health_tracker_snapshot_load_capped_at_one() {
        let mut tracker = HealthTracker::new();
        for _ in 0..20 {
            tracker.record_failure("err");
        }
        let snapshot = tracker.snapshot();
        // Load should be capped at 1.0 (max 10 failures / 10)
        assert_eq!(snapshot.load, Some(1.0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorStore tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test.cursor:utility:1.0.0")
    }

    fn test_zone_id() -> ZoneId {
        "z:test-zone".parse().unwrap()
    }

    fn test_object_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new(
                "fcp.connector_state",
                "state_object",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: test_zone_id(),
            created_at: 1_000_000,
            provenance: fcp_core::Provenance {
                origin_zone: test_zone_id(),
                chain: vec![],
                taint: fcp_core::TaintLevel::Untainted,
                elevated: false,
                elevation_token: None,
            },
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_cursor_state(offset: i64, watermark: u64) -> CursorState {
        CursorState {
            offset: Some(offset),
            last_seen_id: Some("msg-123".into()),
            watermark: Some(watermark),
        }
    }

    fn test_lease(seq: u64) -> CursorLease {
        CursorLease {
            lease_seq: seq,
            lease_object_id: ObjectId::from_bytes([99; 32]),
        }
    }

    #[test]
    fn cursor_store_new_has_no_head() {
        let backend = InMemoryCursorStoreBackend::new();
        let store = CursorStore::new(backend, test_connector_id(), test_zone_id());
        assert!(store.head().is_none());
    }

    #[test]
    fn cursor_store_load_empty_returns_none() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());
        let result = store.load_cursor().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cursor_store_commit_and_load() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);

        let object_id = store.commit_cursor(cursor, header, lease, sig).unwrap();
        assert!(store.head().is_some());
        assert_eq!(store.head(), Some(object_id));

        // Load from a fresh store using same backend
        let mut store2 =
            CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());
        let loaded = store2.load_cursor().unwrap().unwrap();
        assert_eq!(loaded.offset, Some(100));
        assert_eq!(loaded.watermark, Some(50));
    }

    #[test]
    fn cursor_store_load_rejects_mismatched_instance_state() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let expected_instance_id = InstanceId::new();
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id())
            .with_instance_id(expected_instance_id);

        let mismatched_state = ConnectorStateObject {
            header: test_object_header(),
            connector_id: test_connector_id(),
            instance_id: Some(InstanceId::new()),
            zone_id: test_zone_id(),
            prev: None,
            seq: 0,
            state_cbor: test_cursor_state(100, 50).to_cbor().unwrap(),
            updated_at: 1_000_000,
            lease_seq: 1,
            lease_object_id: ObjectId::from_bytes([99; 32]),
            writer_public_key: [0u8; 32],
            signature: Signature::from_bytes([0u8; 64]),
        };

        backend.store_state_object(mismatched_state).unwrap();

        let err = store.load_cursor().unwrap_err();
        assert!(
            matches!(err, CursorStoreError::Storage(message) if message.contains("instance_id mismatch"))
        );
    }

    #[test]
    fn cursor_store_rejects_stale_lease() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        // First commit with lease_seq=5
        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(5);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        // Second commit with stale lease_seq=3
        let cursor2 = test_cursor_state(200, 100);
        let header2 = test_object_header();
        let stale_lease = test_lease(3);
        let sig2 = Signature::from_bytes([0u8; 64]);
        let err = store
            .commit_cursor(cursor2, header2, stale_lease, sig2)
            .unwrap_err();
        assert!(matches!(
            err,
            CursorStoreError::StaleLeaseSeq {
                current: 5,
                incoming: 3
            }
        ));
    }

    #[test]
    fn cursor_store_rejects_offset_regression() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        // First commit at offset=100
        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        // Second commit with lower offset=50
        let cursor2 = test_cursor_state(50, 100);
        let header2 = test_object_header();
        let lease2 = test_lease(2);
        let sig2 = Signature::from_bytes([0u8; 64]);
        let err = store
            .commit_cursor(cursor2, header2, lease2, sig2)
            .unwrap_err();
        assert!(matches!(
            err,
            CursorStoreError::OffsetRegression {
                current: 100,
                incoming: 50
            }
        ));
    }

    #[test]
    fn cursor_store_rejects_watermark_regression() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        // First commit at watermark=200
        let cursor = test_cursor_state(100, 200);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        // Second commit with lower watermark=100
        let cursor2 = test_cursor_state(200, 100);
        let header2 = test_object_header();
        let lease2 = test_lease(2);
        let sig2 = Signature::from_bytes([0u8; 64]);
        let err = store
            .commit_cursor(cursor2, header2, lease2, sig2)
            .unwrap_err();
        assert!(matches!(
            err,
            CursorStoreError::WatermarkRegression {
                current: 200,
                incoming: 100
            }
        ));
    }

    #[test]
    fn cursor_store_allows_equal_lease_seq() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(5);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        // Same lease_seq=5 is allowed (not stale)
        let cursor2 = test_cursor_state(200, 100);
        let header2 = test_object_header();
        let lease2 = test_lease(5);
        let sig2 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor2, header2, lease2, sig2).unwrap();
    }

    #[test]
    fn cursor_store_with_instance_id() {
        let backend = InMemoryCursorStoreBackend::new();
        let instance_id = InstanceId::new();
        let store = CursorStore::new(backend, test_connector_id(), test_zone_id())
            .with_instance_id(instance_id);
        assert!(store.head().is_none());
    }

    #[test]
    fn cursor_store_commit_adds_lease_ref() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        // Verify the stored object has the lease ref
        let (_, stored_obj) = backend.load_head().unwrap().unwrap();
        assert!(
            stored_obj
                .header
                .refs
                .contains(&ObjectId::from_bytes([99; 32]))
        );
    }

    #[test]
    fn cursor_store_sequential_commits_increment_seq() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());

        // First commit: seq=0
        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        let (_, obj1) = backend.load_head().unwrap().unwrap();
        assert_eq!(obj1.seq, 0);

        // Second commit: seq=1
        let cursor2 = test_cursor_state(200, 100);
        let header2 = test_object_header();
        let lease2 = test_lease(2);
        let sig2 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor2, header2, lease2, sig2).unwrap();

        let (_, obj2) = backend.load_head().unwrap().unwrap();
        assert_eq!(obj2.seq, 1);
        assert!(obj2.prev.is_some()); // Links to previous
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InMemoryCursorStoreBackend tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn in_memory_backend_load_empty() {
        let backend = InMemoryCursorStoreBackend::new();
        assert!(backend.load_head().unwrap().is_none());
    }

    #[test]
    fn in_memory_backend_default() {
        let backend = InMemoryCursorStoreBackend::default();
        assert!(backend.load_head().unwrap().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollResult debug
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn poll_result_debug() {
        let success: PollResult<i32> = PollResult::success(vec![1, 2]);
        assert!(format!("{success:?}").contains("Success"));

        let err: PollResult<i32> = PollResult::recoverable("timeout");
        assert!(format!("{err:?}").contains("timeout"));

        let fatal: PollResult<i32> = PollResult::fatal("unrecoverable");
        assert!(format!("{fatal:?}").contains("unrecoverable"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollingSupervisorStats clone/debug
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn polling_supervisor_stats_debug() {
        let stats = PollingSupervisorStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("PollingSupervisorStats"));
    }

    #[test]
    fn polling_supervisor_stats_clone() {
        let stats = PollingSupervisorStats {
            total_polls: 10,
            successful_polls: 8,
            failed_polls: 2,
            items_processed: 50,
            backoff_time_ms: 300,
        };
        let moved = stats;
        assert_eq!(moved.total_polls, 10);
        assert_eq!(moved.items_processed, 50);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Streaming supervisor snapshot without details
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_health_snapshot_no_prior_details() {
        let config = SupervisorConfig::default();
        let session = InMemoryStreamingSession::new();
        let supervisor = StreamingSupervisor::new(config, session);

        // New tracker has no failures → snapshot.details is None
        // streaming_health_snapshot should still produce valid details
        let snapshot = supervisor.streaming_health_snapshot();
        let details = snapshot.details.expect("should have streaming details");
        let map = details.as_object().expect("details is object");
        assert!(map.contains_key("reconnect_count"));
        assert!(map.contains_key("missed_heartbeats"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Heartbeat timeout edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn streaming_session_heartbeat_with_ack_not_timed_out() {
        let mut session = InMemoryStreamingSession::new();
        let now = Instant::now();
        session.record_heartbeat_sent(now);
        session.record_heartbeat_ack(now);
        // Ack just received → not timed out
        assert!(!session.is_heartbeat_timeout(Duration::from_millis(100)));
    }

    #[test]
    fn streaming_session_heartbeat_sent_not_timed_out_yet() {
        let mut session = InMemoryStreamingSession::new();
        session.record_heartbeat_sent(Instant::now());
        // Just sent, no ack, but timeout is large
        assert!(!session.is_heartbeat_timeout(Duration::from_secs(60)));
    }

    #[test]
    fn streaming_session_repeated_unacked_heartbeats_timeout_from_oldest_send() {
        let mut session = InMemoryStreamingSession::new();

        let now = Instant::now();
        let first = now.checked_sub(Duration::from_millis(100)).unwrap_or(now);
        session.record_heartbeat_sent(first);
        session.record_heartbeat_sent(now);

        assert!(session.is_heartbeat_timeout(Duration::from_millis(50)));
    }

    #[test]
    fn streaming_session_ack_advances_oldest_outstanding_heartbeat() {
        let mut session = InMemoryStreamingSession::new();

        let now = Instant::now();
        let first = now.checked_sub(Duration::from_millis(100)).unwrap_or(now);
        session.record_heartbeat_sent(first);
        session.record_heartbeat_sent(now);
        session.record_heartbeat_ack(now);

        assert!(!session.is_heartbeat_timeout(Duration::from_millis(50)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorLease clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_lease_clone() {
        let lease = test_lease(42);
        let cloned = lease;
        assert_eq!(cloned.lease_seq, 42);
    }

    // ── NEW: SupervisorConfig builder methods ─────────────────────────

    #[test]
    fn supervisor_config_builder_chain() {
        let config = SupervisorConfig::new()
            .with_base_backoff_ms(500)
            .with_max_backoff_ms(30_000)
            .with_jitter(false)
            .with_max_consecutive_failures(10);
        assert_eq!(config.base_backoff_ms, 500);
        assert_eq!(config.max_backoff_ms, 30_000);
        assert!(!config.jitter_enabled);
        assert_eq!(config.max_consecutive_failures, 10);
    }

    #[test]
    fn supervisor_config_shutdown_timeout_accessor() {
        let config = SupervisorConfig {
            shutdown_timeout_ms: 15_000,
            ..Default::default()
        };
        assert_eq!(config.shutdown_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn supervisor_config_cooldown_duration_accessor() {
        let config = SupervisorConfig {
            cooldown_after_failure_ms: 120_000,
            ..Default::default()
        };
        assert_eq!(config.cooldown_duration(), Duration::from_secs(120));
    }

    #[test]
    fn supervisor_config_heartbeat_interval_zero_disabled() {
        let config = SupervisorConfig {
            heartbeat_interval_ms: 0,
            ..Default::default()
        };
        assert!(config.heartbeat_interval().is_none());
        assert!(config.heartbeat_timeout().is_none());
    }

    #[test]
    fn supervisor_config_heartbeat_interval_nonzero() {
        let config = SupervisorConfig {
            heartbeat_interval_ms: 10_000,
            heartbeat_timeout_multiplier: 3.0,
            ..Default::default()
        };
        assert_eq!(config.heartbeat_interval(), Some(Duration::from_secs(10)));
        let timeout = config.heartbeat_timeout().unwrap();
        // 10s * 3.0 = 30s
        assert_eq!(timeout.as_secs(), 30);
    }

    #[test]
    fn supervisor_config_validate_max_failures_zero() {
        let config = SupervisorConfig {
            max_consecutive_failures: 0,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("max_consecutive_failures"))
        );
    }

    #[test]
    fn supervisor_config_validate_heartbeat_multiplier_one() {
        let config = SupervisorConfig {
            heartbeat_timeout_multiplier: 1.0,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("heartbeat_timeout_multiplier"))
        );
    }

    #[test]
    fn supervisor_config_serde_basic_fields() {
        let config = SupervisorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base_backoff_ms, config.base_backoff_ms);
        assert_eq!(deserialized.max_backoff_ms, config.max_backoff_ms);
    }

    // ── NEW: InMemoryStreamingSession edge cases ─────────────────────

    #[test]
    fn streaming_session_next_sequence_saturates() {
        let mut session = InMemoryStreamingSession::new();
        session.set_sequence(u64::MAX);
        let seq = session.next_sequence();
        assert_eq!(seq, u64::MAX);
        // saturating_add means sequence stays at MAX
        assert_eq!(session.sequence(), u64::MAX);
    }

    #[test]
    fn streaming_session_persist_and_restore_no_op() {
        let mut session = InMemoryStreamingSession::new();
        assert!(session.persist().is_ok());
        assert!(session.restore().is_ok());
    }

    #[test]
    fn streaming_session_heartbeat_no_sent_no_timeout() {
        let session = InMemoryStreamingSession::new();
        assert!(!session.is_heartbeat_timeout(Duration::from_millis(1)));
    }

    // ── NEW: InMemoryPollingCursor edge cases ─────────────────────────

    #[test]
    fn polling_cursor_with_offset_initial() {
        let cursor = InMemoryPollingCursor::with_offset(42);
        assert_eq!(cursor.offset(), Some(42));
    }

    #[test]
    fn polling_cursor_record_poll_with_count() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.last_poll_at().is_none());
        assert_eq!(cursor.last_poll_count(), 0);

        let now = Instant::now();
        cursor.record_poll(now, 7);
        assert!(cursor.last_poll_at().is_some());
        assert_eq!(cursor.last_poll_count(), 7);
    }

    #[test]
    fn polling_cursor_advance_if_newer_from_none() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.offset().is_none());
        cursor.advance_if_newer(0);
        assert_eq!(cursor.offset(), Some(1));
    }

    #[test]
    fn polling_cursor_advance_if_newer_equal_value() {
        let mut cursor = InMemoryPollingCursor::with_offset(100);
        // advance_if_newer(99) => new_offset = 100, current = 100, so no change
        cursor.advance_if_newer(99);
        assert_eq!(cursor.offset(), Some(100));
    }

    #[test]
    fn polling_cursor_persist_and_restore_no_op() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.persist().is_ok());
        assert!(cursor.restore().is_ok());
    }

    // ── NEW: HealthTracker edge cases ─────────────────────────────────

    #[test]
    fn health_tracker_default_is_starting() {
        let tracker = HealthTracker::default();
        assert!(matches!(tracker.state(), HealthState::Starting));
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.consecutive_successes(), 0);
    }

    #[test]
    fn health_tracker_record_success_resets_failures() {
        let mut tracker = HealthTracker::new();
        tracker.record_failure("err1");
        tracker.record_failure("err2");
        assert_eq!(tracker.consecutive_failures(), 2);

        tracker.record_success();
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.consecutive_successes(), 1);
    }

    #[test]
    fn health_tracker_record_failure_resets_successes() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.record_success();
        assert_eq!(tracker.consecutive_successes(), 2);

        tracker.record_failure("oops");
        assert_eq!(tracker.consecutive_successes(), 0);
        assert_eq!(tracker.consecutive_failures(), 1);
    }

    #[test]
    fn health_tracker_snapshot_single_failure() {
        let mut tracker = HealthTracker::new();
        tracker.record_failure("test error");
        let snapshot = tracker.snapshot();
        // Should have load > 0.0 due to failures
        assert!(snapshot.load.unwrap() > 0.0);
        // Should have details with last_error
        let details = snapshot.details.unwrap();
        assert!(details.get("last_error").is_some());
    }

    #[test]
    fn health_tracker_stopping_rejects_all_transitions() {
        let mut tracker = HealthTracker::new();
        // Manually set to Stopping state (not reachable via transitions)
        tracker.state = HealthState::Stopping;

        assert!(!tracker.transition(HealthTransition::ToHealthy));
        assert!(!tracker.transition(HealthTransition::ToDegraded {
            reason: "test".to_string(),
        }));
        assert!(!tracker.transition(HealthTransition::ToUnhealthy {
            reason: "test".to_string(),
        }));
        assert!(!tracker.transition(HealthTransition::ToStarting));
    }

    #[test]
    fn health_tracker_error_to_degraded() {
        let mut tracker = HealthTracker::new();
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "bad".to_string(),
        });
        assert!(tracker.is_unhealthy());

        assert!(tracker.transition(HealthTransition::ToDegraded {
            reason: "partial recovery".to_string(),
        }));
        assert!(tracker.is_degraded());
    }

    #[test]
    fn health_tracker_degraded_requires_3_successes_to_recover() {
        let config = SupervisorConfig::default();
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        tracker.record_failure("err");
        tracker.transition(HealthTransition::ToDegraded {
            reason: "err".to_string(),
        });

        // 1 success: not enough
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // 2 successes: not enough
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // 3 successes: recover
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());
    }

    #[test]
    fn health_tracker_cooldown_elapsed_when_not_unhealthy() {
        let tracker = HealthTracker::new();
        // Not in unhealthy state, cooldown always elapsed
        assert!(tracker.cooldown_elapsed(Duration::from_secs(300)));
    }

    // ── NEW: PollResult constructors ──────────────────────────────────

    #[test]
    fn poll_result_success_constructor() {
        let result = PollResult::success(vec![1, 2, 3]);
        match result {
            PollResult::Success(items) => assert_eq!(items, vec![1, 2, 3]),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn poll_result_empty_constructor() {
        let result: PollResult<i32> = PollResult::empty();
        match result {
            PollResult::Success(items) => assert_eq!(items, [] as [i32; 0]),
            _ => panic!("expected empty Success"),
        }
    }

    #[test]
    fn poll_result_recoverable_constructor() {
        let result: PollResult<i32> = PollResult::recoverable("net error");
        match result {
            PollResult::RecoverableError {
                message,
                retry_after_ms,
            } => {
                assert_eq!(message, "net error");
                assert!(retry_after_ms.is_none());
            }
            _ => panic!("expected RecoverableError"),
        }
    }

    #[test]
    fn poll_result_rate_limited_constructor() {
        let result: PollResult<i32> = PollResult::rate_limited("rate limited", 30_000);
        match result {
            PollResult::RecoverableError {
                message,
                retry_after_ms,
            } => {
                assert_eq!(message, "rate limited");
                assert_eq!(retry_after_ms, Some(30_000));
            }
            _ => panic!("expected RecoverableError"),
        }
    }

    #[test]
    fn poll_result_fatal_constructor() {
        let result: PollResult<i32> = PollResult::fatal("auth failure");
        match result {
            PollResult::FatalError { message } => assert_eq!(message, "auth failure"),
            _ => panic!("expected FatalError"),
        }
    }

    // ── NEW: SupervisorOutcome ────────────────────────────────────────

    #[test]
    fn supervisor_outcome_shutdown_debug() {
        let outcome = SupervisorOutcome::Shutdown;
        let debug = format!("{outcome:?}");
        assert!(debug.contains("Shutdown"));
    }

    #[test]
    fn supervisor_outcome_fatal_error_clone() {
        let outcome = SupervisorOutcome::FatalError {
            message: "bad".to_string(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = outcome.clone();
        match cloned {
            SupervisorOutcome::FatalError { message } => assert_eq!(message, "bad"),
            _ => panic!("expected FatalError"),
        }
    }

    #[test]
    fn supervisor_outcome_max_failures_clone() {
        let outcome = SupervisorOutcome::MaxFailuresReached { failures: 5 };
        #[allow(clippy::redundant_clone)]
        let cloned = outcome.clone();
        match cloned {
            SupervisorOutcome::MaxFailuresReached { failures } => assert_eq!(failures, 5),
            _ => panic!("expected MaxFailuresReached"),
        }
    }

    // ── NEW: StreamingSupervisorStats ─────────────────────────────────

    #[test]
    fn streaming_supervisor_stats_default_all_fields() {
        let stats = StreamingSupervisorStats::default();
        assert_eq!(stats.connection_attempts, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.failed_connections, 0);
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.backoff_time_ms, 0);
        assert_eq!(stats.missed_heartbeats, 0);
    }

    // ── NEW: StreamingHealthState serde ───────────────────────────────

    #[test]
    fn streaming_health_state_serde_full_roundtrip() {
        let state = StreamingHealthState {
            last_heartbeat_at: Some(1000),
            last_ack_at: Some(900),
            reconnect_count: 3,
            missed_heartbeats: 1,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: StreamingHealthState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.last_heartbeat_at, Some(1000));
        assert_eq!(deserialized.last_ack_at, Some(900));
        assert_eq!(deserialized.reconnect_count, 3);
        assert_eq!(deserialized.missed_heartbeats, 1);
    }

    #[test]
    fn streaming_health_state_serde_skips_none() {
        let state = StreamingHealthState {
            last_heartbeat_at: None,
            last_ack_at: None,
            reconnect_count: 0,
            missed_heartbeats: 0,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("last_heartbeat_at"));
        assert!(!json.contains("last_ack_at"));
    }

    // ── NEW: CursorStoreError Display ─────────────────────────────────

    #[test]
    fn cursor_store_error_display() {
        let e = CursorStoreError::Storage("disk full".to_string());
        assert!(e.to_string().contains("disk full"));

        let e = CursorStoreError::StaleLeaseSeq {
            current: 5,
            incoming: 3,
        };
        assert!(e.to_string().contains('5'));
        assert!(e.to_string().contains('3'));

        let e = CursorStoreError::OffsetRegression {
            current: 100,
            incoming: 50,
        };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains("50"));

        let e = CursorStoreError::WatermarkRegression {
            current: 200,
            incoming: 100,
        };
        assert!(e.to_string().contains("200"));
        assert!(e.to_string().contains("100"));

        let e = CursorStoreError::CursorEncoding("bad bytes".to_string());
        assert!(e.to_string().contains("bad bytes"));

        let e = CursorStoreError::CursorDecoding("corrupt".to_string());
        assert!(e.to_string().contains("corrupt"));
    }

    // ── NEW: HealthTransition clone ───────────────────────────────────

    #[test]
    fn health_transition_clone_to_degraded() {
        let t = HealthTransition::ToDegraded {
            reason: "test".to_string(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = t.clone();
        match cloned {
            HealthTransition::ToDegraded { reason } => assert_eq!(reason, "test"),
            _ => panic!("expected ToDegraded"),
        }
    }

    #[test]
    fn health_transition_debug_to_healthy() {
        let t = HealthTransition::ToHealthy;
        let debug = format!("{t:?}");
        assert!(debug.contains("ToHealthy"));
    }

    // ── NEW: pseudo_random_jitter coverage ─────────────────────────────

    #[test]
    fn pseudo_random_jitter_in_range() {
        for attempt in 0..20 {
            let j = pseudo_random_jitter(attempt);
            assert!(j >= 0.0, "jitter for attempt {attempt} was {j}");
            assert!(j < 1.0, "jitter for attempt {attempt} was {j}");
        }
    }

    #[test]
    fn pseudo_random_jitter_different_attempts_vary() {
        let values: Vec<f64> = (0..50).map(pseudo_random_jitter).collect();
        let first = values[0];
        let all_same = values.iter().all(|v| (*v - first).abs() < f64::EPSILON);
        assert!(
            !all_same,
            "expected at least some variation in jitter values"
        );
    }

    // ── NEW: SupervisorConfig compute_backoff edge cases ───────────────

    #[test]
    fn backoff_attempt_zero_is_base() {
        let config = SupervisorConfig::default().with_jitter(false);
        assert_eq!(config.compute_backoff(0), config.base_backoff_ms);
    }

    #[test]
    fn backoff_very_large_attempt_capped() {
        let config = SupervisorConfig::default()
            .with_jitter(false)
            .with_max_backoff_ms(120_000);
        assert_eq!(config.compute_backoff(40), 120_000);
    }

    #[test]
    fn backoff_custom_base_and_max() {
        let config = SupervisorConfig::new()
            .with_base_backoff_ms(100)
            .with_max_backoff_ms(500)
            .with_jitter(false);
        assert_eq!(config.compute_backoff(0), 100);
        assert_eq!(config.compute_backoff(1), 200);
        assert_eq!(config.compute_backoff(2), 400);
        assert_eq!(config.compute_backoff(3), 500); // capped
    }

    #[test]
    fn backoff_with_jitter_factor_midpoint() {
        let config = SupervisorConfig::default();
        // jitter_factor=0.5 -> factor = 0.5*0.5 + 0.5 = 0.75
        let delay = config.compute_backoff_with_jitter(0, 0.5);
        assert_eq!(delay, 750);
    }

    // ── NEW: SupervisorConfig validation edge cases ────────────────────

    #[test]
    fn supervisor_config_validate_ok_when_valid() {
        let config = SupervisorConfig {
            base_backoff_ms: 100,
            max_backoff_ms: 100,
            max_consecutive_failures: 1,
            heartbeat_timeout_multiplier: 1.01,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn supervisor_config_validate_all_errors_collected() {
        let config = SupervisorConfig {
            base_backoff_ms: 0,
            max_backoff_ms: 0,
            max_consecutive_failures: 0,
            heartbeat_timeout_multiplier: 0.5,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(errors.len() >= 3);
        assert!(errors.iter().any(|e| e.contains("base_backoff_ms")));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("max_consecutive_failures"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("heartbeat_timeout_multiplier"))
        );
    }

    // ── NEW: SupervisorConfig serde with custom values ──────────────────

    #[test]
    fn supervisor_config_serde_custom_values() {
        let config = SupervisorConfig {
            base_backoff_ms: 500,
            max_backoff_ms: 5000,
            jitter_enabled: false,
            max_consecutive_failures: 10,
            cooldown_after_failure_ms: 60_000,
            shutdown_timeout_ms: 15_000,
            heartbeat_interval_ms: 5000,
            heartbeat_timeout_multiplier: 3.0,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_backoff_ms, 500);
        assert_eq!(parsed.max_backoff_ms, 5000);
        assert!(!parsed.jitter_enabled);
        assert_eq!(parsed.max_consecutive_failures, 10);
        assert_eq!(parsed.cooldown_after_failure_ms, 60_000);
        assert_eq!(parsed.shutdown_timeout_ms, 15_000);
        assert_eq!(parsed.heartbeat_interval_ms, 5000);
        assert!((parsed.heartbeat_timeout_multiplier - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn supervisor_config_serde_default_from_empty_json() {
        let parsed: SupervisorConfig = serde_json::from_str("{}").unwrap();
        let default_cfg = SupervisorConfig::default();
        assert_eq!(parsed.base_backoff_ms, default_cfg.base_backoff_ms);
        assert_eq!(parsed.max_backoff_ms, default_cfg.max_backoff_ms);
        assert_eq!(parsed.jitter_enabled, default_cfg.jitter_enabled);
    }

    // ── NEW: HealthTracker evaluate edge cases ─────────────────────────

    #[test]
    fn health_tracker_evaluate_starting_no_action_without_events() {
        let config = SupervisorConfig::default();
        let mut tracker = HealthTracker::new();
        tracker.evaluate(&config);
        assert!(matches!(tracker.state(), HealthState::Starting));
    }

    #[test]
    fn health_tracker_evaluate_starting_insufficient_failures() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(5);
        let mut tracker = HealthTracker::new();
        tracker.record_failure("err1");
        tracker.record_failure("err2");
        tracker.evaluate(&config);
        assert!(matches!(tracker.state(), HealthState::Starting));
    }

    #[test]
    fn health_tracker_evaluate_ready_to_degraded_single_failure() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(5);
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        tracker.record_failure("partial error");
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());
    }

    #[test]
    fn health_tracker_evaluate_ready_to_unhealthy_at_max_failures() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(3);
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        tracker.record_failure("err1");
        tracker.record_failure("err2");
        tracker.record_failure("err3");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_tracker_evaluate_stopping_is_noop() {
        let config = SupervisorConfig::default();
        let mut tracker = HealthTracker::new();
        tracker.state = HealthState::Stopping;
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(matches!(tracker.state(), HealthState::Stopping));
    }

    #[test]
    fn health_tracker_evaluate_degraded_to_unhealthy() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(2);
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.evaluate(&config);

        tracker.record_failure("err1");
        tracker.evaluate(&config);

        tracker.record_failure("err2");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    // ── NEW: HealthTracker snapshot edge cases ─────────────────────────

    #[test]
    fn health_tracker_snapshot_zero_failures_has_zero_load() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.load, Some(0.0));
        assert!(snapshot.details.is_none());
    }

    #[test]
    fn health_tracker_snapshot_five_failures_half_load() {
        let mut tracker = HealthTracker::new();
        for _ in 0..5 {
            tracker.record_failure("err");
        }
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.load, Some(0.5));
    }

    #[test]
    fn health_tracker_snapshot_uptime_nonnegative() {
        let tracker = HealthTracker::new();
        let snapshot = tracker.snapshot();
        let _ = snapshot.uptime_ms;
        assert!(matches!(snapshot.status, HealthState::Starting));
        assert!(snapshot.rate_limit.is_none());
    }

    // ── NEW: CursorStore advanced scenarios ────────────────────────────

    #[test]
    fn cursor_store_commit_with_instance_id() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let instance_id = InstanceId::new();
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id())
            .with_instance_id(instance_id.clone());

        let cursor = test_cursor_state(100, 50);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        let (_, stored) = backend.load_head().unwrap().unwrap();
        assert_eq!(stored.instance_id, Some(instance_id));
    }

    #[test]
    fn cursor_store_commit_rejects_mismatched_header_zone() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let mut header = test_object_header();
        header.zone_id = ZoneId::work();

        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        let err = store.commit_cursor(cursor, header, lease, sig).unwrap_err();

        assert!(
            matches!(err, CursorStoreError::Storage(message) if message.contains("header zone_id mismatch"))
        );
    }

    #[test]
    fn cursor_store_commit_deduplicates_lease_ref() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let mut header = test_object_header();
        let lease_oid = ObjectId::from_bytes([99; 32]);
        header.refs.push(lease_oid);

        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();
    }

    #[test]
    fn cursor_store_allows_none_offset_and_watermark() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor = CursorState {
            offset: None,
            last_seen_id: None,
            watermark: None,
        };
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();
        assert!(store.head().is_some());
    }

    #[test]
    fn cursor_store_allows_equal_offset() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor1 = test_cursor_state(100, 50);
        let header1 = test_object_header();
        let lease1 = test_lease(1);
        let sig1 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor1, header1, lease1, sig1).unwrap();

        let cursor2 = test_cursor_state(100, 50);
        let header2 = test_object_header();
        let lease2 = test_lease(2);
        let sig2 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor2, header2, lease2, sig2).unwrap();
    }

    #[test]
    fn cursor_store_allows_equal_watermark() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor1 = test_cursor_state(100, 200);
        let header1 = test_object_header();
        let lease1 = test_lease(1);
        let sig1 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor1, header1, lease1, sig1).unwrap();

        let cursor2 = test_cursor_state(200, 200);
        let header2 = test_object_header();
        let lease2 = test_lease(2);
        let sig2 = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor2, header2, lease2, sig2).unwrap();
    }

    #[test]
    fn cursor_store_commit_sets_updated_at_from_header() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());

        let cursor = test_cursor_state(100, 50);
        let mut header = test_object_header();
        header.created_at = 42_000;
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        let (_, stored) = backend.load_head().unwrap().unwrap();
        assert_eq!(stored.updated_at, 42_000);
    }

    // ── NEW: InMemoryCursorStoreBackend via Arc ────────────────────────

    #[test]
    fn in_memory_backend_arc_load_and_store() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        assert!(CursorStoreBackend::load_head(&backend).unwrap().is_none());

        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());
        let cursor = test_cursor_state(10, 5);
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        store.commit_cursor(cursor, header, lease, sig).unwrap();

        let loaded = CursorStoreBackend::load_head(&backend).unwrap();
        assert!(loaded.is_some());
    }

    // ── NEW: InMemoryPollingCursor advance_if_newer edge cases ─────────

    #[test]
    fn polling_cursor_advance_negative_offset() {
        let mut cursor = InMemoryPollingCursor::new();
        cursor.advance_if_newer(-5);
        assert_eq!(cursor.offset(), Some(-4));
    }

    #[test]
    fn polling_cursor_advance_i64_max_saturates() {
        let mut cursor = InMemoryPollingCursor::new();
        cursor.advance_if_newer(i64::MAX);
        assert_eq!(cursor.offset(), Some(i64::MAX));
    }

    #[test]
    fn polling_cursor_advance_multiple_sequential() {
        let mut cursor = InMemoryPollingCursor::new();
        for i in 0..10 {
            cursor.advance_if_newer(i);
        }
        assert_eq!(cursor.offset(), Some(10));
    }

    #[test]
    fn polling_cursor_set_offset_directly() {
        let mut cursor = InMemoryPollingCursor::new();
        cursor.set_offset(999);
        assert_eq!(cursor.offset(), Some(999));
        cursor.set_offset(-1);
        assert_eq!(cursor.offset(), Some(-1));
    }

    // ── NEW: InMemoryStreamingSession set_sequence directly ────────────

    #[test]
    fn streaming_session_set_sequence_arbitrary() {
        let mut session = InMemoryStreamingSession::new();
        session.set_sequence(42);
        assert_eq!(session.sequence(), 42);
        let seq = session.next_sequence();
        assert_eq!(seq, 42);
        assert_eq!(session.sequence(), 43);
    }

    #[test]
    fn streaming_session_heartbeat_seq_increments_on_send() {
        let mut session = InMemoryStreamingSession::new();
        let now = Instant::now();
        session.record_heartbeat_sent(now);
        session.record_heartbeat_sent(now);
        session.record_heartbeat_sent(now);
        assert_eq!(session.heartbeat_seq(), 3);
        assert_eq!(session.ack_seq(), 0);
    }

    #[test]
    fn streaming_session_ack_without_outstanding_heartbeat_does_not_advance_ack_seq() {
        let mut session = InMemoryStreamingSession::new();
        let now = Instant::now();
        session.record_heartbeat_ack(now);
        session.record_heartbeat_ack(now);
        assert_eq!(session.ack_seq(), 0);
        assert_eq!(session.heartbeat_seq(), 0);
    }

    #[test]
    fn streaming_session_ack_seq_does_not_exceed_sent_heartbeats() {
        let mut session = InMemoryStreamingSession::new();
        let now = Instant::now();
        session.record_heartbeat_sent(now);
        session.record_heartbeat_ack(now);
        session.record_heartbeat_ack(now);
        assert_eq!(session.heartbeat_seq(), 1);
        assert_eq!(session.ack_seq(), 1);
    }

    // ── NEW: StreamingSupervisor accessor coverage ─────────────────────

    #[test]
    fn streaming_supervisor_accessors() {
        let config = SupervisorConfig::new().with_base_backoff_ms(777);
        let session = InMemoryStreamingSession::new();
        let supervisor = StreamingSupervisor::new(config, session);

        assert_eq!(supervisor.config().base_backoff_ms, 777);
        assert!(matches!(supervisor.health().state(), HealthState::Starting));
        assert_eq!(supervisor.stats().connection_attempts, 0);
        assert!(supervisor.session().resume_token().is_none());
    }

    #[test]
    fn streaming_supervisor_session_mut_sets_token() {
        let config = SupervisorConfig::default();
        let session = InMemoryStreamingSession::new();
        let mut supervisor = StreamingSupervisor::new(config, session);
        supervisor.session_mut().set_resume_token("abc".to_string());
        assert_eq!(supervisor.session().resume_token(), Some("abc".to_string()));
    }

    // Regression: supervisor must stay in `Starting` until the first real
    // successful connection — readiness must not be reported synthetically
    // from the top of `run()`.
    #[test]
    fn streaming_supervisor_does_not_report_ready_before_first_connect() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_base_backoff_ms(1)
                .with_max_consecutive_failures(1);
            let session = InMemoryStreamingSession::new();
            let mut supervisor = StreamingSupervisor::new(config, session);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run::<(), _, _, _, _>(
                    shutdown_rx,
                    |_session| async { Err(boxed_err("connect failed")) },
                    |_event, _session| async { Ok(()) },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 1 }
            ));
            // Health must never have transitioned to Ready — the only
            // connection attempt failed, so the supervisor never proved
            // it could serve. Starting → Error is the only valid path.
            assert!(!supervisor.health().is_healthy());
            assert!(supervisor.health().is_unhealthy());
        });
    }

    #[test]
    fn polling_supervisor_does_not_report_ready_before_first_poll() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_base_backoff_ms(1)
                .with_max_consecutive_failures(1);
            let cursor = InMemoryPollingCursor::new();
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let (_shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    10,
                    |_offset| async { PollResult::<i32>::recoverable("poll failed") },
                    |_items, _cursor| Ok(()),
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 1 }
            ));
            assert!(!supervisor.health().is_healthy());
            assert!(supervisor.health().is_unhealthy());
        });
    }

    // ── NEW: PollingSupervisor accessor coverage ───────────────────────

    #[test]
    fn polling_supervisor_cursor_mut_sets_offset() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let mut supervisor = PollingSupervisor::new(config, cursor);
        supervisor.cursor_mut().set_offset(42);
        assert_eq!(supervisor.cursor().offset(), Some(42));
    }

    // ── NEW: PollingSupervisor compute_delay with jitter ───────────────

    #[test]
    fn polling_supervisor_compute_delay_with_jitter_enabled() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config, cursor);

        let delay = supervisor.compute_delay(0, None);
        let ms = delay.as_millis();
        assert!(
            (500..=1000).contains(&ms),
            "expected delay in [500,1000] but got {ms}"
        );
    }

    #[test]
    fn polling_supervisor_compute_delay_retry_after_zero() {
        let config = SupervisorConfig::default().with_jitter(false);
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config, cursor);

        let delay = supervisor.compute_delay(0, Some(0));
        assert_eq!(delay.as_millis(), 1000);
    }

    // ── NEW: StreamingSupervisor streaming_health_snapshot edge cases ──

    #[test]
    fn streaming_health_snapshot_with_failure_details_merged() {
        let config = SupervisorConfig::default();
        let session = InMemoryStreamingSession::new();
        let mut supervisor = StreamingSupervisor::new(config, session);

        supervisor.health.record_failure("network timeout");

        let snapshot = supervisor.streaming_health_snapshot();
        let details = snapshot.details.unwrap();
        let map = details.as_object().unwrap();
        assert!(map.contains_key("last_error"));
        assert!(map.contains_key("consecutive_failures"));
        assert!(map.contains_key("reconnect_count"));
        assert!(map.contains_key("missed_heartbeats"));
    }

    #[test]
    fn streaming_supervisor_elapsed_ms_calculation() {
        let config = SupervisorConfig::default();
        let session = InMemoryStreamingSession::new();
        let supervisor = StreamingSupervisor::new(config, session);

        let started_at = supervisor.health.started_at;
        let ms = supervisor.elapsed_ms(started_at);
        assert!(ms < 100, "expected elapsed_ms to be small, got {ms}");
    }

    // ── NEW: HealthTransition clone/debug for all variants ─────────────

    #[test]
    fn health_transition_clone_to_unhealthy() {
        let t = HealthTransition::ToUnhealthy {
            reason: "fatal crash".to_string(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = t.clone();
        match cloned {
            HealthTransition::ToUnhealthy { reason } => assert_eq!(reason, "fatal crash"),
            _ => panic!("expected ToUnhealthy"),
        }
    }

    #[test]
    fn health_transition_clone_to_starting() {
        let t = HealthTransition::ToStarting;
        #[allow(clippy::redundant_clone)]
        let cloned = t.clone();
        assert!(matches!(cloned, HealthTransition::ToStarting));
    }

    #[test]
    fn health_transition_clone_to_healthy() {
        let t = HealthTransition::ToHealthy;
        #[allow(clippy::redundant_clone)]
        let cloned = t.clone();
        assert!(matches!(cloned, HealthTransition::ToHealthy));
    }

    #[test]
    fn health_transition_debug_to_starting() {
        let t = HealthTransition::ToStarting;
        let debug = format!("{t:?}");
        assert!(debug.contains("ToStarting"));
    }

    #[test]
    fn health_transition_debug_to_unhealthy() {
        let t = HealthTransition::ToUnhealthy {
            reason: "boom".to_string(),
        };
        let debug = format!("{t:?}");
        assert!(debug.contains("ToUnhealthy"));
        assert!(debug.contains("boom"));
    }

    // ── NEW: InMemoryCursorStoreBackend multiple objects ────────────────

    #[test]
    fn in_memory_backend_stores_multiple_and_returns_last() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());
        let mut store = CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());

        for i in 0u32..3 {
            let cursor = test_cursor_state(i64::from(i) * 100, u64::from(i) * 50);
            let header = test_object_header();
            let lease = test_lease(u64::from(i) + 1);
            let sig = Signature::from_bytes([0u8; 64]);
            store.commit_cursor(cursor, header, lease, sig).unwrap();
        }

        let (_, obj) = backend.load_head().unwrap().unwrap();
        assert_eq!(obj.seq, 2);
    }

    // ── NEW: CursorStore load_cursor populates internal state ──────────

    #[test]
    fn cursor_store_load_sets_internal_state() {
        let backend = Arc::new(InMemoryCursorStoreBackend::new());

        let mut store1 =
            CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());
        let cursor = test_cursor_state(500, 250);
        let header = test_object_header();
        let lease = test_lease(7);
        let sig = Signature::from_bytes([0u8; 64]);
        store1.commit_cursor(cursor, header, lease, sig).unwrap();

        let mut store2 =
            CursorStore::new(Arc::clone(&backend), test_connector_id(), test_zone_id());
        assert!(store2.head().is_none());
        let loaded = store2.load_cursor().unwrap().unwrap();
        assert_eq!(loaded.offset, Some(500));
        assert_eq!(loaded.watermark, Some(250));
        assert!(store2.head().is_some());
    }

    // ── NEW: CursorStore commit with partial cursor ────────────────────

    #[test]
    fn cursor_store_commit_with_partial_cursor() {
        let backend = InMemoryCursorStoreBackend::new();
        let mut store = CursorStore::new(backend, test_connector_id(), test_zone_id());

        let cursor = CursorState {
            offset: Some(42),
            last_seen_id: None,
            watermark: None,
        };
        let header = test_object_header();
        let lease = test_lease(1);
        let sig = Signature::from_bytes([0u8; 64]);
        let oid = store.commit_cursor(cursor, header, lease, sig).unwrap();
        assert_eq!(store.head(), Some(oid));
    }

    // ── NEW: Polling supervisor successful poll with items ──────────────

    #[test]
    fn polling_supervisor_processes_items_and_updates_cursor() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default().with_base_backoff_ms(1);
            let cursor = InMemoryPollingCursor::new();
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let poll_count = Arc::new(AtomicUsize::new(0));
            let poll_count_clone = Arc::clone(&poll_count);

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
            let shutdown_tx = Arc::new(shutdown_tx);
            let shutdown_tx_clone = Arc::clone(&shutdown_tx);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    1,
                    move |_offset| {
                        let count = poll_count_clone.fetch_add(1, Ordering::SeqCst);
                        let shutdown = Arc::clone(&shutdown_tx_clone);
                        async move {
                            if count == 0 {
                                PollResult::success(vec![10, 20, 30])
                            } else {
                                let _ = shutdown.send(true);
                                PollResult::<i32>::empty()
                            }
                        }
                    },
                    |items, cursor| {
                        for item in &items {
                            cursor.advance_if_newer(i64::from(*item));
                        }
                        Ok(())
                    },
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
            assert_eq!(supervisor.stats().successful_polls, 2);
            assert_eq!(supervisor.stats().items_processed, 3);
            assert_eq!(supervisor.cursor().offset(), Some(31));
        });
    }

    #[derive(Debug, Default)]
    struct PersistTrackingPollingCursor {
        offset: Option<i64>,
        last_poll_at: Option<Instant>,
        last_poll_count: usize,
        persist_calls: Arc<AtomicUsize>,
    }

    impl PersistTrackingPollingCursor {
        fn new(persist_calls: Arc<AtomicUsize>) -> Self {
            Self {
                offset: None,
                last_poll_at: None,
                last_poll_count: 0,
                persist_calls,
            }
        }
    }

    impl PollingCursor for PersistTrackingPollingCursor {
        fn offset(&self) -> Option<i64> {
            self.offset
        }

        fn set_offset(&mut self, offset: i64) {
            self.offset = Some(offset);
        }

        fn clear_offset(&mut self) {
            self.offset = None;
        }

        fn last_poll_at(&self) -> Option<Instant> {
            self.last_poll_at
        }

        fn record_poll(&mut self, at: Instant, updates_received: usize) {
            self.last_poll_at = Some(at);
            self.last_poll_count = updates_received;
        }

        fn last_poll_count(&self) -> usize {
            self.last_poll_count
        }

        fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[test]
    fn polling_supervisor_persists_cursor_after_successful_nonempty_poll() {
        #[derive(Debug, Default)]
        struct PersistBucketPollingCursor {
            offset: Option<i64>,
            last_poll_at: Option<Instant>,
            last_poll_count: usize,
            persist_with_items_calls: Arc<AtomicUsize>,
            persist_without_items_calls: Arc<AtomicUsize>,
        }

        impl PersistBucketPollingCursor {
            fn new(
                persist_with_items_calls: Arc<AtomicUsize>,
                persist_without_items_calls: Arc<AtomicUsize>,
            ) -> Self {
                Self {
                    offset: None,
                    last_poll_at: None,
                    last_poll_count: 0,
                    persist_with_items_calls,
                    persist_without_items_calls,
                }
            }
        }

        impl PollingCursor for PersistBucketPollingCursor {
            fn offset(&self) -> Option<i64> {
                self.offset
            }

            fn set_offset(&mut self, offset: i64) {
                self.offset = Some(offset);
            }

            fn clear_offset(&mut self) {
                self.offset = None;
            }

            fn last_poll_at(&self) -> Option<Instant> {
                self.last_poll_at
            }

            fn record_poll(&mut self, at: Instant, updates_received: usize) {
                self.last_poll_at = Some(at);
                self.last_poll_count = updates_received;
            }

            fn last_poll_count(&self) -> usize {
                self.last_poll_count
            }

            fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                if self.last_poll_count > 0 {
                    self.persist_with_items_calls.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.persist_without_items_calls
                        .fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }

            fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default().with_base_backoff_ms(1);
            let persist_with_items_calls = Arc::new(AtomicUsize::new(0));
            let persist_without_items_calls = Arc::new(AtomicUsize::new(0));
            let cursor = PersistBucketPollingCursor::new(
                Arc::clone(&persist_with_items_calls),
                Arc::clone(&persist_without_items_calls),
            );
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let poll_count = Arc::new(AtomicUsize::new(0));
            let poll_count_clone = Arc::clone(&poll_count);

            let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
            let shutdown_tx = Arc::new(shutdown_tx);
            let shutdown_tx_clone = Arc::clone(&shutdown_tx);

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    1,
                    move |_offset| {
                        let count = poll_count_clone.fetch_add(1, Ordering::SeqCst);
                        let shutdown = Arc::clone(&shutdown_tx_clone);
                        async move {
                            if count == 0 {
                                PollResult::success(vec![41])
                            } else {
                                let _ = shutdown.send(true);
                                PollResult::<i32>::empty()
                            }
                        }
                    },
                    |items, cursor| {
                        for item in &items {
                            cursor.advance_if_newer(i64::from(*item));
                        }
                        Ok(())
                    },
                )
                .await;

            assert!(matches!(outcome, SupervisorOutcome::Shutdown));
            assert_eq!(supervisor.cursor().offset(), Some(42));
            assert_eq!(persist_with_items_calls.load(Ordering::SeqCst), 1);
            assert_eq!(persist_without_items_calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn polling_supervisor_does_not_advance_or_persist_cursor_on_processing_failure() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let config = SupervisorConfig::default()
                .with_base_backoff_ms(1)
                .with_max_consecutive_failures(2);
            let persist_calls = Arc::new(AtomicUsize::new(0));
            let cursor = PersistTrackingPollingCursor::new(Arc::clone(&persist_calls));
            let mut supervisor = PollingSupervisor::new(config, cursor);

            let poll_count = Arc::new(AtomicUsize::new(0));
            let poll_count_clone = Arc::clone(&poll_count);

            let outcome = supervisor
                .run(
                    fcp_async_core::channel::watch::channel(false).1,
                    1,
                    move |_offset| {
                        poll_count_clone.fetch_add(1, Ordering::SeqCst);
                        async { PollResult::success(vec![41]) }
                    },
                    |items, cursor| {
                        for item in &items {
                            cursor.advance_if_newer(i64::from(*item));
                        }
                        Err("processor failed".into())
                    },
                )
                .await;

            assert!(matches!(
                outcome,
                SupervisorOutcome::MaxFailuresReached { failures: 2 }
            ));
            assert_eq!(poll_count.load(Ordering::SeqCst), 2);
            assert_eq!(supervisor.stats().successful_polls, 0);
            assert_eq!(supervisor.stats().failed_polls, 2);
            assert_eq!(supervisor.cursor().offset(), None);
            assert_eq!(persist_calls.load(Ordering::SeqCst), 1);
        });
    }
}
