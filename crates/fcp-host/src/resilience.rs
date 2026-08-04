//! Resilience primitives for `fcp-host`.
//!
//! This module provides host-side resilience controls that can be applied to
//! connector RPCs:
//! - circuit breakers to stop cascading failures
//! - bulkheads to isolate connector saturation
//! - health-based routing with probe-only recovery
//! - adaptive load shedding that respects request priority

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fcp_async_core::sync::{OwnedSemaphorePermit, Semaphore};
use fcp_async_core::time;
use fcp_kernel::{ConnectorHealth, ConnectorId};
use fcp_prelude::ZoneId;
use serde::{Deserialize, Serialize};

const MAX_PER_MILLE: u32 = 1_000;
const MAX_PER_MILLE_U16: u16 = 1_000;
const DEFAULT_CONFORMAL_COVERAGE_PER_MILLE: u16 = 990;
const DEFAULT_MIN_CONFORMAL_CALIBRATION_SAMPLES: usize = 3;

/// br-6bgp1: bounds on the actual sleep applied when the
/// backpressure controller picks `BackpressureAction::Delay`. The
/// floor keeps the delay observable in tracing tests; the ceiling
/// keeps it negligible against the dispatch path so a single
/// adaptive decision cannot starve a request. Operators that want
/// stronger backpressure should rely on bulkhead permit exhaustion
/// (which provides the actual queueing) — `Delay` is a soft hint,
/// not a long-tail throttle.
const MIN_BACKPRESSURE_DELAY_MS: u64 = 1;
const MAX_BACKPRESSURE_DELAY_MS: u64 = 10;

/// Request priority used by load shedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPriority {
    /// Essential traffic that should never be shed.
    Critical,
    /// Important operational traffic.
    High,
    /// Default traffic.
    Normal,
    /// Best-effort traffic that can be shed aggressively.
    Low,
}

impl RequestPriority {
    const fn shed_factor_per_mille(self) -> u32 {
        match self {
            Self::Critical => 0,
            Self::High => 300,
            Self::Normal => 700,
            Self::Low => MAX_PER_MILLE,
        }
    }
}

/// Error returned by the resilience layer.
#[derive(Debug, PartialEq, Eq)]
pub enum ResilienceError<E> {
    /// The request was shed due to host load.
    LoadShed { load_per_mille: u16 },
    /// The connector is currently considered unhealthy.
    Unhealthy { reason: String },
    /// The connector circuit breaker is open.
    CircuitOpen { retry_after: Duration },
    /// Half-open probe traffic is already in flight.
    HalfOpenLimited,
    /// Bulkhead queue is full.
    BulkheadFull,
    /// Bulkhead queue wait timed out.
    QueueTimeout { timeout: Duration },
    /// Operation timed out while executing.
    TimedOut { timeout: Duration },
    /// The wrapped operation itself failed.
    Inner(E),
}

impl<E: std::fmt::Debug> std::fmt::Display for ResilienceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadShed { load_per_mille } => {
                write!(f, "request load shed at {load_per_mille}‰ load")
            }
            Self::Unhealthy { reason } => write!(f, "connector unhealthy: {reason}"),
            Self::CircuitOpen { retry_after } => write!(
                f,
                "circuit breaker open for another {}ms",
                retry_after.as_millis()
            ),
            Self::HalfOpenLimited => write!(f, "half-open probe already in flight"),
            Self::BulkheadFull => write!(f, "bulkhead queue is full"),
            Self::QueueTimeout { timeout } => {
                write!(
                    f,
                    "bulkhead queue timed out after {}ms",
                    timeout.as_millis()
                )
            }
            Self::TimedOut { timeout } => {
                write!(f, "operation timed out after {}ms", timeout.as_millis())
            }
            Self::Inner(error) => write!(f, "inner error: {error:?}"),
        }
    }
}

impl<E> std::error::Error for ResilienceError<E> where E: std::error::Error + 'static {}

/// Top-level resilience configuration.
#[derive(Debug, Clone, Default)]
pub struct ResilienceConfig {
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Bulkhead configuration.
    pub bulkhead: BulkheadConfig,
    /// Health routing configuration.
    pub health: HealthRouterConfig,
    /// Load shedding configuration.
    pub load_shed: LoadShedConfig,
    /// Optional end-to-end operation timeout.
    pub operation_timeout: Option<Duration>,
}

/// Failure matching policy for circuit breaker tripping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePredicate {
    /// Any explicit error or timeout.
    AnyError,
    /// Only timeouts contribute to the breaker.
    TimeoutsOnly,
    /// Slow successes count as failures.
    SlowResponses { threshold: Duration },
    /// Explicit failures, timeouts, or slow successes count as failures.
    ErrorOrSlowResponses { threshold: Duration },
}

impl FailurePredicate {
    fn matches(self, outcome: OutcomeKind, latency: Duration) -> bool {
        match self {
            Self::AnyError => matches!(outcome, OutcomeKind::Failure | OutcomeKind::TimedOut),
            Self::TimeoutsOnly => outcome == OutcomeKind::TimedOut,
            Self::SlowResponses { threshold } => {
                outcome == OutcomeKind::Success && latency > threshold
            }
            Self::ErrorOrSlowResponses { threshold } => {
                matches!(outcome, OutcomeKind::Failure | OutcomeKind::TimedOut)
                    || (outcome == OutcomeKind::Success && latency > threshold)
            }
        }
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failures required to open the breaker.
    pub failure_threshold: u32,
    /// Successes required to close a half-open breaker.
    pub success_threshold: u32,
    /// How long the breaker remains open before a probe is allowed.
    pub open_duration: Duration,
    /// Failure counting window.
    pub window_duration: Duration,
    /// Which outcomes count as failures.
    pub failure_predicate: FailurePredicate,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration: Duration::from_secs(5),
            window_duration: Duration::from_secs(30),
            failure_predicate: FailurePredicate::AnyError,
        }
    }
}

/// Observable circuit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Requests are rejected until open duration elapses.
    Open,
    /// Limited probe traffic is allowed while recovering.
    HalfOpen,
}

/// Bulkhead configuration.
#[derive(Debug, Clone)]
pub struct BulkheadConfig {
    /// Maximum in-flight requests for a connector.
    pub max_concurrent: usize,
    /// Maximum queued waiters for a connector.
    pub max_queued: usize,
    /// Maximum wait time for a queue slot.
    pub queue_timeout: Duration,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            max_queued: 32,
            queue_timeout: Duration::from_millis(250),
        }
    }
}

/// Health router configuration.
#[derive(Debug, Clone)]
pub struct HealthRouterConfig {
    /// Consecutive failures required to mark a connector unavailable.
    pub unhealthy_threshold: u32,
    /// Consecutive successes required to recover from unavailable.
    pub recovery_success_threshold: u32,
    /// Latency threshold for degraded status.
    pub latency_degraded_threshold: Duration,
    /// Error-rate threshold for degraded status.
    pub error_rate_degraded_threshold_per_mille: u16,
    /// Minimum spacing between probe requests.
    pub probe_interval: Duration,
    /// Sliding window used for error-rate estimation.
    pub error_window: Duration,
    /// EWMA alpha in per-mille form.
    pub latency_alpha_per_mille: u16,
}

impl Default for HealthRouterConfig {
    fn default() -> Self {
        Self {
            unhealthy_threshold: 3,
            recovery_success_threshold: 2,
            latency_degraded_threshold: Duration::from_millis(750),
            error_rate_degraded_threshold_per_mille: 500,
            probe_interval: Duration::from_secs(5),
            error_window: Duration::from_secs(30),
            latency_alpha_per_mille: 200,
        }
    }
}

/// Load shedding configuration.
#[derive(Debug, Clone)]
pub struct LoadShedConfig {
    /// Start shedding at this load.
    pub shed_threshold_per_mille: u16,
    /// Shed all eligible traffic at this load.
    pub full_shed_threshold_per_mille: u16,
    /// Priority classes that may be shed.
    pub sheddable_priorities: Vec<RequestPriority>,
}

impl Default for LoadShedConfig {
    fn default() -> Self {
        Self {
            shed_threshold_per_mille: 850,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low, RequestPriority::Normal],
        }
    }
}

/// Runtime state evaluated by the host backpressure controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureState {
    /// Host signals are comfortably below warning thresholds.
    Normal,
    /// Bulkhead queues are consuming meaningful request budget.
    QueueCongested,
    /// Host CPU or equivalent load pressure is saturated.
    CpuSaturated,
    /// Host memory pressure threatens connector stability.
    MemoryPressure,
    /// Downstream service limits or retry feedback dominate the decision.
    DownstreamThrottled,
    /// Calibration or replay verification says adaptive decisions are unsafe.
    CalibrationDrift,
}

impl BackpressureState {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::QueueCongested => "queue_congested",
            Self::CpuSaturated => "cpu_saturated",
            Self::MemoryPressure => "memory_pressure",
            Self::DownstreamThrottled => "downstream_throttled",
            Self::CalibrationDrift => "calibration_drift",
        }
    }
}

/// Action selected by the host backpressure controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureAction {
    /// Admit work immediately.
    Admit,
    /// Admit work while exposing warning evidence to operators.
    AdmitWithWarning,
    /// Delay work through existing queueing/backoff paths.
    Delay,
    /// Shed work intentionally.
    Shed,
    /// Cancel low-priority work to preserve higher-value traffic.
    CancelLowPriority,
    /// Defer to the static conservative policy.
    FallbackStaticPolicy,
}

impl BackpressureAction {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::AdmitWithWarning => "admit_with_warning",
            Self::Delay => "delay",
            Self::Shed => "shed",
            Self::CancelLowPriority => "cancel_low_priority",
            Self::FallbackStaticPolicy => "fallback_static_policy",
        }
    }
}

/// Calibration state supplied to the backpressure controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureCalibrationStatus {
    /// Calibration is present and inside the accepted envelope.
    Valid,
    /// Observed coverage has drifted below the configured floor.
    CoverageDrift,
    /// Required telemetry was unavailable.
    MissingTelemetry,
    /// Offline replay could not reproduce the decision.
    ReplayMismatch,
    /// Controller artifact integrity verification failed.
    ArtifactVerificationFailed,
}

/// Conservative fallback trigger retained in the decision evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureFallbackTrigger {
    /// Observed coverage is below the accepted envelope.
    CoverageDrift,
    /// Required telemetry is absent.
    MissingTelemetry,
    /// Replay did not reproduce the selected action.
    ReplayMismatch,
    /// Controller artifact verification failed.
    ArtifactVerificationFailed,
}

/// Calibration envelope for adaptive backpressure decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureCalibration {
    /// Current calibration status.
    pub status: BackpressureCalibrationStatus,
    /// Observed coverage in per-mille units, when known.
    pub coverage_per_mille: Option<u16>,
    /// Minimum accepted coverage in per-mille units.
    pub min_coverage_per_mille: u16,
}

impl BackpressureCalibration {
    /// Build a valid calibration envelope at the default coverage floor.
    #[must_use]
    pub const fn valid() -> Self {
        Self {
            status: BackpressureCalibrationStatus::Valid,
            coverage_per_mille: Some(DEFAULT_CONFORMAL_COVERAGE_PER_MILLE),
            min_coverage_per_mille: DEFAULT_CONFORMAL_COVERAGE_PER_MILLE,
        }
    }

    /// Build a calibration envelope that has drifted below its floor.
    #[must_use]
    pub const fn coverage_drift(coverage_per_mille: u16, min_coverage_per_mille: u16) -> Self {
        Self {
            status: BackpressureCalibrationStatus::CoverageDrift,
            coverage_per_mille: Some(coverage_per_mille),
            min_coverage_per_mille,
        }
    }

    /// Build a calibration envelope with a non-coverage fallback status.
    #[must_use]
    pub const fn fallback(status: BackpressureCalibrationStatus) -> Self {
        Self {
            status,
            coverage_per_mille: None,
            min_coverage_per_mille: DEFAULT_CONFORMAL_COVERAGE_PER_MILLE,
        }
    }

    fn fallback_trigger(self) -> Option<BackpressureFallbackTrigger> {
        match self.status {
            BackpressureCalibrationStatus::Valid => {
                let coverage = self.coverage_per_mille?;
                (coverage < self.min_coverage_per_mille)
                    .then_some(BackpressureFallbackTrigger::CoverageDrift)
            }
            BackpressureCalibrationStatus::CoverageDrift => {
                Some(BackpressureFallbackTrigger::CoverageDrift)
            }
            BackpressureCalibrationStatus::MissingTelemetry => {
                Some(BackpressureFallbackTrigger::MissingTelemetry)
            }
            BackpressureCalibrationStatus::ReplayMismatch => {
                Some(BackpressureFallbackTrigger::ReplayMismatch)
            }
            BackpressureCalibrationStatus::ArtifactVerificationFailed => {
                Some(BackpressureFallbackTrigger::ArtifactVerificationFailed)
            }
        }
    }
}

/// Telemetry snapshot consumed by the host backpressure controller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureTelemetry {
    /// Bulkhead queue or active-permit pressure in per-mille units.
    pub queue_pressure_per_mille: Option<u16>,
    /// Host CPU or equivalent executor pressure in per-mille units.
    pub cpu_pressure_per_mille: Option<u16>,
    /// Memory pressure in per-mille units.
    pub memory_pressure_per_mille: Option<u16>,
    /// Downstream retry-after hint in milliseconds.
    pub downstream_retry_after_ms: Option<u64>,
    /// Retry amplification estimate in per-mille units.
    pub retry_amplification_per_mille: Option<u16>,
    /// Useful-work value estimate in per-mille units.
    pub useful_work_per_mille: Option<u16>,
}

impl BackpressureTelemetry {
    /// Build telemetry from the existing host resilience load signals.
    #[must_use]
    pub fn from_resilience_pressure(
        effective_load_per_mille: u32,
        queue_pressure_per_mille: u32,
    ) -> Self {
        Self {
            queue_pressure_per_mille: Some(to_u16(queue_pressure_per_mille)),
            cpu_pressure_per_mille: Some(to_u16(effective_load_per_mille)),
            memory_pressure_per_mille: None,
            downstream_retry_after_ms: None,
            retry_amplification_per_mille: None,
            useful_work_per_mille: None,
        }
    }

    const fn missing_required_signal(self) -> bool {
        self.queue_pressure_per_mille.is_none()
            && self.cpu_pressure_per_mille.is_none()
            && self.memory_pressure_per_mille.is_none()
            && self.downstream_retry_after_ms.is_none()
            && self.retry_amplification_per_mille.is_none()
    }

    fn max_pressure_per_mille(self) -> u16 {
        [
            self.queue_pressure_per_mille,
            self.cpu_pressure_per_mille,
            self.memory_pressure_per_mille,
            self.retry_amplification_per_mille,
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0)
    }
}

/// Fairness pressure consumed by the host backpressure controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureFairnessContext {
    /// Connector class under pressure, such as `request_response_saas`.
    pub connector_class: String,
    /// Zone currently asking for admission.
    pub zone_id: String,
    /// Capability class currently asking for admission.
    pub capability: String,
    /// Saturation for this connector class.
    pub connector_class_pressure_per_mille: u16,
    /// Current zone share within the saturated connector class.
    pub zone_share_per_mille: u16,
    /// Current capability share within the saturated connector class.
    pub capability_share_per_mille: u16,
    /// Expected fair share for the active zone/capability cohort.
    pub target_share_per_mille: u16,
    /// Requests already admitted in the fairness window.
    pub admitted_count: u64,
    /// Requests already shed in the fairness window.
    pub shed_count: u64,
}

impl BackpressureFairnessContext {
    /// Build a fairness context, clamping per-mille values into the valid range.
    #[must_use]
    pub fn new(input: BackpressureFairnessContextInput) -> Self {
        Self {
            connector_class: input.connector_class,
            zone_id: input.zone_id,
            capability: input.capability,
            connector_class_pressure_per_mille: clamp_per_mille_u16(
                input.connector_class_pressure_per_mille,
            ),
            zone_share_per_mille: clamp_per_mille_u16(input.zone_share_per_mille),
            capability_share_per_mille: clamp_per_mille_u16(input.capability_share_per_mille),
            target_share_per_mille: clamp_per_mille_u16(input.target_share_per_mille),
            admitted_count: input.admitted_count,
            shed_count: input.shed_count,
        }
    }

    /// Largest share overshoot above the configured fair target.
    #[must_use]
    pub fn imbalance_per_mille(&self) -> u16 {
        self.zone_share_per_mille
            .max(self.capability_share_per_mille)
            .saturating_sub(self.target_share_per_mille)
    }

    /// Fraction of the current fairness window that has already been shed.
    #[must_use]
    pub fn shed_ratio_per_mille(&self) -> u16 {
        let shed_count = usize::try_from(self.shed_count).unwrap_or(usize::MAX);
        let total_count = usize::try_from(self.admitted_count.saturating_add(self.shed_count))
            .unwrap_or(usize::MAX);
        if total_count == 0 {
            // No traffic yet in this window means nothing has been shed. Without
            // this guard `ratio_per_mille(0, 0)` returns 1000 (its full-pressure
            // sentinel for a zero denominator), which would hand a fresh, empty
            // window a bogus 50% starvation credit in `pressure_per_mille`.
            return 0;
        }
        to_u16(ratio_per_mille(shed_count, total_count))
    }

    /// Pressure term used by the fairness loss model.
    #[must_use]
    pub fn pressure_per_mille(&self) -> u16 {
        let saturation = self
            .connector_class_pressure_per_mille
            .saturating_sub(self.target_share_per_mille);
        let starvation_credit = self.shed_ratio_per_mille() / 2;
        self.imbalance_per_mille()
            .max(saturation)
            .saturating_sub(starvation_credit)
    }

    /// Operator-facing fairness score: 1000 means balanced, 0 means maximally unfair.
    #[must_use]
    pub fn fairness_score_per_mille(&self) -> u16 {
        to_u16(MAX_PER_MILLE.saturating_sub(u32::from(self.pressure_per_mille())))
    }
}

/// Input object for [`BackpressureFairnessContext::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackpressureFairnessContextInput {
    pub connector_class: String,
    pub zone_id: String,
    pub capability: String,
    pub connector_class_pressure_per_mille: u16,
    pub zone_share_per_mille: u16,
    pub capability_share_per_mille: u16,
    pub target_share_per_mille: u16,
    pub admitted_count: u64,
    pub shed_count: u64,
}

/// Expected-loss term names used by the backpressure controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureLossTermKind {
    /// Tail-latency cost.
    TailLatency,
    /// Useful work dropped by rejection or cancellation.
    DroppedUsefulWork,
    /// Retry amplification induced by the action.
    RetryAmplification,
    /// Memory exhaustion risk.
    MemoryExhaustion,
    /// Fairness violation risk.
    FairnessViolation,
    /// Operator surprise or auditability risk.
    OperatorSurprise,
}

impl BackpressureLossTermKind {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TailLatency => "tail_latency",
            Self::DroppedUsefulWork => "dropped_useful_work",
            Self::RetryAmplification => "retry_amplification",
            Self::MemoryExhaustion => "memory_exhaustion",
            Self::FairnessViolation => "fairness_violation",
            Self::OperatorSurprise => "operator_surprise",
        }
    }
}

/// One deterministic expected-loss term.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureLossTerm {
    /// Stable loss term name.
    pub kind: BackpressureLossTermKind,
    /// Modeled value in per-mille style integer units.
    pub value: u32,
    /// Term weight in millionths.
    pub weight_microunits: i64,
}

impl BackpressureLossTerm {
    /// Build a weighted loss term.
    #[must_use]
    pub const fn new(kind: BackpressureLossTermKind, value: u32, weight_microunits: i64) -> Self {
        Self {
            kind,
            value,
            weight_microunits,
        }
    }

    /// Weighted score for deterministic action comparison.
    #[must_use]
    pub fn weighted_score(&self) -> i128 {
        i128::from(self.value).saturating_mul(i128::from(self.weight_microunits))
    }
}

/// Weights for the controller loss matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureLossWeights {
    /// Weight for tail-latency loss.
    pub tail_latency: i64,
    /// Weight for useful-work loss.
    pub dropped_useful_work: i64,
    /// Weight for retry-amplification loss.
    pub retry_amplification: i64,
    /// Weight for memory-exhaustion loss.
    pub memory_exhaustion: i64,
    /// Weight for fairness loss.
    pub fairness_violation: i64,
    /// Weight for operator-surprise loss.
    pub operator_surprise: i64,
}

impl Default for BackpressureLossWeights {
    fn default() -> Self {
        Self {
            tail_latency: 1_000_000,
            dropped_useful_work: 1_200_000,
            retry_amplification: 900_000,
            memory_exhaustion: 1_500_000,
            fairness_violation: 1_300_000,
            operator_surprise: 500_000,
        }
    }
}

/// Thresholds used to classify host backpressure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureControllerThresholds {
    /// Pressure at which warning admission starts.
    pub warning_per_mille: u16,
    /// Pressure at which queueing/backoff should dominate.
    pub soft_limit_per_mille: u16,
    /// Pressure at which hard shedding or cancellation may dominate.
    pub hard_limit_per_mille: u16,
}

impl Default for BackpressureControllerThresholds {
    fn default() -> Self {
        Self {
            warning_per_mille: 600,
            soft_limit_per_mille: 850,
            hard_limit_per_mille: 950,
        }
    }
}

/// Configuration for the host backpressure controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackpressureControllerConfig {
    /// State classification thresholds.
    pub thresholds: BackpressureControllerThresholds,
    /// Expected-loss weights.
    pub weights: BackpressureLossWeights,
}

/// Inputs needed to replay one backpressure decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureControllerInput {
    /// Subject being admitted, delayed, shed, or cancelled.
    pub subject: String,
    /// Request priority.
    pub priority: RequestPriority,
    /// Telemetry snapshot.
    pub telemetry: BackpressureTelemetry,
    /// Optional connector-class/zone/capability fairness pressure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fairness: Option<BackpressureFairnessContext>,
    /// Calibration envelope.
    pub calibration: BackpressureCalibration,
}

impl BackpressureControllerInput {
    /// Build controller input.
    #[must_use]
    pub fn new(
        subject: impl Into<String>,
        priority: RequestPriority,
        telemetry: BackpressureTelemetry,
        calibration: BackpressureCalibration,
    ) -> Self {
        Self {
            subject: subject.into(),
            priority,
            telemetry,
            fairness: None,
            calibration,
        }
    }

    /// Attach fairness pressure to the controller input.
    #[must_use]
    pub fn with_fairness(mut self, fairness: BackpressureFairnessContext) -> Self {
        self.fairness = Some(fairness);
        self
    }
}

/// Evaluation for one candidate action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureActionEvaluation {
    /// Candidate action.
    pub action: BackpressureAction,
    /// Deterministic expected-loss score.
    pub expected_loss_score: i64,
    /// Terms that produced the score.
    pub loss_terms: Vec<BackpressureLossTerm>,
}

/// Next-best action retained for audit and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureCounterfactual {
    /// Action that was not selected.
    pub action: BackpressureAction,
    /// Deterministic expected-loss score for the action.
    pub expected_loss_score: i64,
    /// Why the counterfactual lost.
    pub reason: String,
}

/// Replay record embedded in every backpressure decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureReplayRecord {
    /// Controller configuration used for the decision.
    pub controller: BackpressureController,
    /// Input snapshot used for the decision.
    pub input: BackpressureControllerInput,
}

/// Replayable host backpressure decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureDecision {
    /// Classified backpressure state.
    pub state: BackpressureState,
    /// Selected action.
    pub action: BackpressureAction,
    /// Deterministic score for the selected action.
    pub selected_loss_score: i64,
    /// Selected action loss terms.
    pub loss_terms: Vec<BackpressureLossTerm>,
    /// Next-best action, when present.
    pub counterfactual: Option<BackpressureCounterfactual>,
    /// Conservative fallback trigger, when fallback is active.
    pub fallback_trigger: Option<BackpressureFallbackTrigger>,
    /// Human-readable fallback reason.
    pub fallback_reason: Option<String>,
    /// All candidate action evaluations.
    pub evaluations: Vec<BackpressureActionEvaluation>,
    /// Replay material sufficient to reproduce the decision offline.
    pub replay: BackpressureReplayRecord,
}

impl BackpressureDecision {
    /// Whether this decision rejects work immediately.
    #[must_use]
    pub const fn rejects_work(&self) -> bool {
        matches!(
            self.action,
            BackpressureAction::Shed | BackpressureAction::CancelLowPriority
        )
    }

    /// Replay this decision from its embedded record.
    #[must_use]
    pub fn replay(&self) -> Self {
        self.replay.controller.decide(self.replay.input.clone())
    }

    /// Whether offline replay reproduces the selected action and score.
    #[must_use]
    pub fn replay_matches(&self) -> bool {
        let replayed = self.replay();
        replayed.state == self.state
            && replayed.action == self.action
            && replayed.selected_loss_score == self.selected_loss_score
            && replayed.fallback_trigger == self.fallback_trigger
    }
}

/// Stable JSONL schema for k3zfl.13 fairness load-shedding proof records.
pub const FAIRNESS_LOAD_SHEDDING_SCHEMA_VERSION: &str = "fairness-load-shedding/v1";
/// Owning bead for fairness-aware load shedding proof evidence.
pub const FAIRNESS_LOAD_SHEDDING_BEAD: &str = "flywheel_connectors-k3zfl.13";

/// Latency percentile summary for fairness proof records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessLatencyPercentiles {
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

/// Input object for [`FairnessLoadSheddingEvidenceRecord::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessLoadSheddingEvidenceInput {
    pub scenario_id: String,
    pub decision: BackpressureDecision,
    pub fairness: BackpressureFairnessContext,
    pub queue_depth: u64,
    pub latency_samples_ms: Vec<u64>,
    pub audit_receipt_id: Option<String>,
    pub cleanup_result: String,
    pub skip_reason: Option<String>,
}

/// Redaction-safe JSONL record for fairness-aware load-shedding proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessLoadSheddingEvidenceRecord {
    pub record_type: String,
    pub schema_version: String,
    pub bead_id: String,
    pub generated_at: DateTime<Utc>,
    pub scenario_id: String,
    pub connector_class: String,
    pub zone: String,
    pub capability: String,
    pub queue_depth: u64,
    pub admitted_count: u64,
    pub shed_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    pub backpressure_action: String,
    pub rejects_work: bool,
    pub decision_replay_matches: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterfactual_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_trigger: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream_retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_amplification_per_mille: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_percentiles: Option<FairnessLatencyPercentiles>,
    pub fairness_score: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_receipt_id: Option<String>,
    pub cleanup_result: String,
    pub operator_guidance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl FairnessLoadSheddingEvidenceRecord {
    /// Build a proof record from a replayable backpressure decision.
    #[must_use]
    pub fn new(input: FairnessLoadSheddingEvidenceInput) -> Self {
        let FairnessLoadSheddingEvidenceInput {
            scenario_id,
            decision,
            fairness,
            queue_depth,
            latency_samples_ms,
            audit_receipt_id,
            cleanup_result,
            skip_reason,
        } = input;

        let action = decision.action;
        let rejects_work = decision.rejects_work();
        let replay_matches = decision.replay_matches();
        let telemetry = decision.replay.input.telemetry;
        let counterfactual_action = decision
            .counterfactual
            .as_ref()
            .map(|counterfactual| counterfactual.action.as_str().to_string());
        let fallback_trigger = decision
            .fallback_trigger
            .map(backpressure_fallback_trigger_label)
            .map(str::to_string);
        let fairness_score = fairness.fairness_score_per_mille();
        let denial_reason = if rejects_work {
            Some(decision.fallback_reason.unwrap_or_else(|| {
                format!(
                    "{} selected by fairness-aware backpressure",
                    action.as_str()
                )
            }))
        } else {
            None
        };

        Self {
            record_type: "fairness_load_shedding".to_string(),
            schema_version: FAIRNESS_LOAD_SHEDDING_SCHEMA_VERSION.to_string(),
            bead_id: FAIRNESS_LOAD_SHEDDING_BEAD.to_string(),
            generated_at: Utc::now(),
            scenario_id: redact_evidence_text(&scenario_id),
            connector_class: redact_evidence_text(&fairness.connector_class),
            zone: redact_evidence_text(&fairness.zone_id),
            capability: redact_evidence_text(&fairness.capability),
            queue_depth,
            admitted_count: fairness.admitted_count,
            shed_count: fairness.shed_count,
            denial_reason: denial_reason.as_deref().map(redact_evidence_text),
            backpressure_action: action.as_str().to_string(),
            rejects_work,
            decision_replay_matches: replay_matches,
            counterfactual_action,
            fallback_trigger,
            downstream_retry_after_ms: telemetry.downstream_retry_after_ms,
            retry_amplification_per_mille: telemetry.retry_amplification_per_mille,
            latency_percentiles: latency_percentiles_from_millis(&latency_samples_ms),
            fairness_score,
            audit_receipt_id: audit_receipt_id.as_deref().map(redact_evidence_text),
            cleanup_result: redact_evidence_text(&cleanup_result),
            operator_guidance: redact_evidence_text(&operator_guidance_for_fairness_decision(
                action,
                fairness_score,
                rejects_work,
                telemetry.downstream_retry_after_ms,
                telemetry.retry_amplification_per_mille,
            )),
            skip_reason: skip_reason.as_deref().map(redact_evidence_text),
        }
    }

    /// Build an explicit skip record when proof prerequisites are unavailable.
    #[must_use]
    pub fn structured_skip(
        scenario_id: impl AsRef<str>,
        connector_class: impl AsRef<str>,
        zone: impl AsRef<str>,
        capability: impl AsRef<str>,
        skip_reason: impl AsRef<str>,
    ) -> Self {
        Self {
            record_type: "fairness_load_shedding".to_string(),
            schema_version: FAIRNESS_LOAD_SHEDDING_SCHEMA_VERSION.to_string(),
            bead_id: FAIRNESS_LOAD_SHEDDING_BEAD.to_string(),
            generated_at: Utc::now(),
            scenario_id: redact_evidence_text(scenario_id.as_ref()),
            connector_class: redact_evidence_text(connector_class.as_ref()),
            zone: redact_evidence_text(zone.as_ref()),
            capability: redact_evidence_text(capability.as_ref()),
            queue_depth: 0,
            admitted_count: 0,
            shed_count: 0,
            denial_reason: None,
            backpressure_action: "not_attempted".to_string(),
            rejects_work: false,
            decision_replay_matches: false,
            counterfactual_action: None,
            fallback_trigger: None,
            downstream_retry_after_ms: None,
            retry_amplification_per_mille: None,
            latency_percentiles: None,
            fairness_score: 0,
            audit_receipt_id: None,
            cleanup_result: "not_applicable".to_string(),
            operator_guidance: "inspect skip_reason and run host-backed fairness evidence when prerequisites are available".to_string(),
            skip_reason: Some(redact_evidence_text(skip_reason.as_ref())),
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

/// Deterministic expected-loss controller for host resource/backpressure choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackpressureController {
    config: BackpressureControllerConfig,
}

impl BackpressureController {
    /// Build a controller with explicit configuration.
    #[must_use]
    pub const fn new(config: BackpressureControllerConfig) -> Self {
        Self { config }
    }

    /// Choose an action and retain enough evidence for deterministic replay.
    #[must_use]
    pub fn decide(&self, input: BackpressureControllerInput) -> BackpressureDecision {
        let fallback_trigger = Self::fallback_trigger(&input);
        let state = self.classify_state(&input, fallback_trigger);
        let mut evaluations = self.evaluate_actions(state, &input);
        evaluations.sort_by(|left, right| {
            left.expected_loss_score
                .cmp(&right.expected_loss_score)
                .then_with(|| left.action.cmp(&right.action))
        });

        let selected_action = if fallback_trigger.is_some() {
            BackpressureAction::FallbackStaticPolicy
        } else {
            evaluations
                .first()
                .map_or(BackpressureAction::FallbackStaticPolicy, |evaluation| {
                    evaluation.action
                })
        };
        let selected = evaluations
            .iter()
            .find(|evaluation| evaluation.action == selected_action)
            .cloned()
            .unwrap_or_else(|| fallback_evaluation(&self.config.weights));
        let counterfactual = evaluations
            .iter()
            .find(|evaluation| evaluation.action != selected_action)
            .map(|evaluation| BackpressureCounterfactual {
                action: evaluation.action,
                expected_loss_score: evaluation.expected_loss_score,
                reason: counterfactual_reason(selected_action, evaluation.action),
            });
        let fallback_reason = fallback_trigger.map(fallback_reason);

        BackpressureDecision {
            state,
            action: selected.action,
            selected_loss_score: selected.expected_loss_score,
            loss_terms: selected.loss_terms,
            counterfactual,
            fallback_trigger,
            fallback_reason,
            evaluations,
            replay: BackpressureReplayRecord {
                controller: *self,
                input,
            },
        }
    }

    fn fallback_trigger(
        input: &BackpressureControllerInput,
    ) -> Option<BackpressureFallbackTrigger> {
        input.calibration.fallback_trigger().or_else(|| {
            input
                .telemetry
                .missing_required_signal()
                .then_some(BackpressureFallbackTrigger::MissingTelemetry)
        })
    }

    fn classify_state(
        &self,
        input: &BackpressureControllerInput,
        fallback_trigger: Option<BackpressureFallbackTrigger>,
    ) -> BackpressureState {
        if matches!(
            fallback_trigger,
            Some(
                BackpressureFallbackTrigger::CoverageDrift
                    | BackpressureFallbackTrigger::ReplayMismatch
                    | BackpressureFallbackTrigger::ArtifactVerificationFailed
            )
        ) {
            return BackpressureState::CalibrationDrift;
        }

        if input.telemetry.downstream_retry_after_ms.unwrap_or(0) > 0
            || input.telemetry.retry_amplification_per_mille.unwrap_or(0)
                >= self.config.thresholds.soft_limit_per_mille
        {
            return BackpressureState::DownstreamThrottled;
        }

        if input.telemetry.memory_pressure_per_mille.unwrap_or(0)
            >= self.config.thresholds.soft_limit_per_mille
        {
            return BackpressureState::MemoryPressure;
        }

        if input.telemetry.cpu_pressure_per_mille.unwrap_or(0)
            >= self.config.thresholds.hard_limit_per_mille
        {
            return BackpressureState::CpuSaturated;
        }

        if input.telemetry.queue_pressure_per_mille.unwrap_or(0)
            >= self.config.thresholds.soft_limit_per_mille
        {
            return BackpressureState::QueueCongested;
        }

        if input.telemetry.max_pressure_per_mille() >= self.config.thresholds.warning_per_mille {
            return BackpressureState::QueueCongested;
        }

        BackpressureState::Normal
    }

    fn evaluate_actions(
        &self,
        state: BackpressureState,
        input: &BackpressureControllerInput,
    ) -> Vec<BackpressureActionEvaluation> {
        [
            BackpressureAction::Admit,
            BackpressureAction::AdmitWithWarning,
            BackpressureAction::Delay,
            BackpressureAction::Shed,
            BackpressureAction::CancelLowPriority,
            BackpressureAction::FallbackStaticPolicy,
        ]
        .into_iter()
        .map(|action| self.evaluate_action(state, input, action))
        .collect()
    }

    fn evaluate_action(
        &self,
        state: BackpressureState,
        input: &BackpressureControllerInput,
        action: BackpressureAction,
    ) -> BackpressureActionEvaluation {
        let terms = vec![
            BackpressureLossTerm::new(
                BackpressureLossTermKind::TailLatency,
                tail_latency_loss(state, input.telemetry, action),
                self.config.weights.tail_latency,
            ),
            BackpressureLossTerm::new(
                BackpressureLossTermKind::DroppedUsefulWork,
                dropped_useful_work_loss(input.priority, input.telemetry, action),
                self.config.weights.dropped_useful_work,
            ),
            BackpressureLossTerm::new(
                BackpressureLossTermKind::RetryAmplification,
                retry_amplification_loss(state, input.telemetry, action),
                self.config.weights.retry_amplification,
            ),
            BackpressureLossTerm::new(
                BackpressureLossTermKind::MemoryExhaustion,
                memory_exhaustion_loss(state, input.telemetry, action),
                self.config.weights.memory_exhaustion,
            ),
            BackpressureLossTerm::new(
                BackpressureLossTermKind::FairnessViolation,
                fairness_violation_loss(input.priority, action, input.fairness.as_ref()),
                self.config.weights.fairness_violation,
            ),
            BackpressureLossTerm::new(
                BackpressureLossTermKind::OperatorSurprise,
                operator_surprise_loss(state, action),
                self.config.weights.operator_surprise,
            ),
        ];
        BackpressureActionEvaluation {
            action,
            expected_loss_score: score_loss_terms(&terms),
            loss_terms: terms,
        }
    }
}

/// Routing decision derived from connector health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route normally.
    Allow,
    /// Route, but the connector is degraded.
    AllowDegraded { reason: String },
    /// Route a limited probe to test recovery.
    AllowProbe,
    /// Reject due to unhealthy state.
    Reject { reason: String },
}

/// Configuration for per-zone conformal SLO route prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformalSloConfig {
    /// Target coverage for the conformal latency bound, in per-mille units.
    pub target_coverage_per_mille: u16,
    /// Minimum per-zone calibration samples required before a route is eligible.
    pub min_calibration_samples: usize,
}

impl Default for ConformalSloConfig {
    fn default() -> Self {
        Self {
            target_coverage_per_mille: DEFAULT_CONFORMAL_COVERAGE_PER_MILLE,
            min_calibration_samples: DEFAULT_MIN_CONFORMAL_CALIBRATION_SAMPLES,
        }
    }
}

impl ConformalSloConfig {
    /// Create a predictor config, clamping coverage to the valid range.
    #[must_use]
    pub fn new(target_coverage_per_mille: u16, min_calibration_samples: usize) -> Self {
        Self {
            target_coverage_per_mille: target_coverage_per_mille.min(to_u16(MAX_PER_MILLE)),
            min_calibration_samples,
        }
    }

    fn conformal_rank(self, sample_count: usize) -> usize {
        if sample_count == 0 {
            return 0;
        }

        let coverage = u64::from(self.target_coverage_per_mille).min(u64::from(MAX_PER_MILLE));
        let sample_count_u64 = u64::try_from(sample_count).unwrap_or(u64::MAX - 1);
        let rank_one_based = sample_count_u64
            .saturating_add(1)
            .saturating_mul(coverage)
            .div_ceil(u64::from(MAX_PER_MILLE))
            .max(1);
        usize::try_from(rank_one_based.saturating_sub(1))
            .unwrap_or_else(|_| sample_count.saturating_sub(1))
            .min(sample_count.saturating_sub(1))
    }
}

/// One observed route outcome used to calibrate per-zone SLO predictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalSloCalibrationSample {
    /// Zone the route served.
    pub zone_id: ZoneId,
    /// Mesh path label, such as `direct` or `derp`.
    pub path_id: String,
    /// Observed end-to-end route latency.
    pub observed_latency_ms: u64,
    /// SLO budget that was in effect for this route.
    pub slo_budget_ms: u64,
    /// Whether the connector invocation succeeded.
    pub success: bool,
    /// Remaining host budget at routing time, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<u64>,
    /// Observation timestamp in Unix milliseconds.
    pub observed_at_ms: u64,
}

impl ConformalSloCalibrationSample {
    /// Create a calibration sample from an observed route outcome.
    #[must_use]
    pub fn new(
        zone_id: ZoneId,
        path_id: impl Into<String>,
        observed_latency_ms: u64,
        slo_budget_ms: u64,
        success: bool,
        budget_remaining: Option<u64>,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            zone_id,
            path_id: path_id.into(),
            observed_latency_ms,
            slo_budget_ms,
            success,
            budget_remaining,
            observed_at_ms,
        }
    }

    fn met_slo(&self) -> bool {
        self.success
            && self.observed_latency_ms <= self.slo_budget_ms
            && self.budget_remaining != Some(0)
    }

    const fn latency_for_bound(&self) -> u64 {
        if self.success {
            self.observed_latency_ms
        } else {
            self.slo_budget_ms.saturating_add(1)
        }
    }
}

/// A route candidate the host can choose before invoking a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalSloRouteCandidate {
    /// Zone the request will execute in.
    pub zone_id: ZoneId,
    /// Mesh path label, such as `direct` or `derp`.
    pub path_id: String,
    /// Current route latency estimate before conformal calibration.
    pub estimated_latency_ms: u64,
    /// Per-call SLO budget allocated to this zone.
    pub slo_budget_ms: u64,
    /// Remaining host budget for the zone, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<u64>,
}

impl ConformalSloRouteCandidate {
    /// Create a route candidate.
    #[must_use]
    pub fn new(
        zone_id: ZoneId,
        path_id: impl Into<String>,
        estimated_latency_ms: u64,
        slo_budget_ms: u64,
        budget_remaining: Option<u64>,
    ) -> Self {
        Self {
            zone_id,
            path_id: path_id.into(),
            estimated_latency_ms,
            slo_budget_ms,
            budget_remaining,
        }
    }
}

/// Prediction for one route candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalSloRoutePrediction {
    /// Zone the request would execute in.
    pub zone_id: ZoneId,
    /// Mesh path label.
    pub path_id: String,
    /// Predicted p99-ish latency bound from the per-zone conformal set.
    pub predicted_p99_ms: u64,
    /// Probability of meeting the SLO, in per-mille units.
    pub coverage_probability_per_mille: u16,
    /// Number of per-zone calibration samples used.
    pub calibration_samples: usize,
    /// Whether the current budget signal says this route is exhausted.
    pub budget_exhausted: bool,
    /// Whether this route satisfies the SLO and budget constraints.
    pub meets_slo_budget: bool,
    /// Operator-facing explanation for the verdict.
    pub reason: String,
}

/// Host routing decision after evaluating conformal SLO predictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveSloRoutingDecision {
    /// Selected route, or `None` when every route is predicted to miss budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<ConformalSloRoutePrediction>,
    /// Predictions for every candidate, sorted in route preference order.
    pub predictions: Vec<ConformalSloRoutePrediction>,
    /// Operator-facing summary.
    pub reason: String,
}

/// Per-zone conformal predictor for pre-routing connector traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformalSloPredictor {
    config: ConformalSloConfig,
}

impl Default for ConformalSloPredictor {
    fn default() -> Self {
        Self::new(ConformalSloConfig::default())
    }
}

impl ConformalSloPredictor {
    /// Create a predictor with explicit configuration.
    #[must_use]
    pub const fn new(config: ConformalSloConfig) -> Self {
        Self { config }
    }

    /// Return predictions for every candidate, sorted in route preference order.
    #[must_use]
    pub fn predict(
        &self,
        candidates: &[ConformalSloRouteCandidate],
        calibration: &[ConformalSloCalibrationSample],
    ) -> Vec<ConformalSloRoutePrediction> {
        let mut predictions = candidates
            .iter()
            .map(|candidate| self.predict_one(candidate, calibration))
            .collect::<Vec<_>>();
        predictions.sort_by(preferred_prediction_order);
        predictions
    }

    /// Select the best route subject to conformal SLO and host-budget checks.
    #[must_use]
    pub fn choose_route(
        &self,
        candidates: &[ConformalSloRouteCandidate],
        calibration: &[ConformalSloCalibrationSample],
    ) -> AdaptiveSloRoutingDecision {
        let predictions = self.predict(candidates, calibration);
        let selected = predictions
            .iter()
            .find(|prediction| prediction.meets_slo_budget)
            .cloned();
        let reason = selected.as_ref().map_or_else(
            || "no route predicted to meet the per-zone SLO budget".to_string(),
            |prediction| {
                format!(
                    "selected {} for {}: predicted p99 {}ms with {}‰ coverage",
                    prediction.path_id,
                    prediction.zone_id,
                    prediction.predicted_p99_ms,
                    prediction.coverage_probability_per_mille
                )
            },
        );

        AdaptiveSloRoutingDecision {
            selected,
            predictions,
            reason,
        }
    }

    fn predict_one(
        &self,
        candidate: &ConformalSloRouteCandidate,
        calibration: &[ConformalSloCalibrationSample],
    ) -> ConformalSloRoutePrediction {
        let exact_samples = calibration
            .iter()
            .filter(|sample| {
                sample.zone_id == candidate.zone_id && sample.path_id == candidate.path_id
            })
            .collect::<Vec<_>>();
        let zone_samples = if exact_samples.len() >= self.config.min_calibration_samples {
            exact_samples
        } else {
            calibration
                .iter()
                .filter(|sample| sample.zone_id == candidate.zone_id)
                .collect::<Vec<_>>()
        };

        let calibration_samples = zone_samples.len();
        let predicted_p99_ms = predicted_latency_bound_ms(
            &zone_samples,
            candidate.estimated_latency_ms,
            self.config.conformal_rank(calibration_samples),
        );
        let coverage_probability_per_mille = to_u16(ratio_per_mille(
            zone_samples
                .iter()
                .filter(|sample| sample.met_slo())
                .count()
                .saturating_add(1),
            calibration_samples.saturating_add(2),
        ));
        let budget_exhausted = candidate.budget_remaining == Some(0);
        let enough_calibration = calibration_samples >= self.config.min_calibration_samples;
        let meets_slo_budget =
            !budget_exhausted && enough_calibration && predicted_p99_ms <= candidate.slo_budget_ms;

        ConformalSloRoutePrediction {
            zone_id: candidate.zone_id.clone(),
            path_id: candidate.path_id.clone(),
            predicted_p99_ms,
            coverage_probability_per_mille,
            calibration_samples,
            budget_exhausted,
            meets_slo_budget,
            reason: conformal_prediction_reason(
                budget_exhausted,
                enough_calibration,
                calibration_samples,
                self.config.min_calibration_samples,
                predicted_p99_ms,
                candidate.slo_budget_ms,
            ),
        }
    }
}

/// Per-connector resilience counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResilienceMetricsSnapshot {
    /// Total requests seen by the layer.
    pub requests: u64,
    /// Successful requests.
    pub successes: u64,
    /// Explicit failures from the inner operation.
    pub failures: u64,
    /// Timed out operations.
    pub timeouts: u64,
    /// Requests rejected by an open circuit.
    pub circuit_rejections: u64,
    /// Times the breaker transitioned to open.
    pub circuit_opened: u64,
    /// Requests rejected by the bulkhead.
    pub bulkhead_rejections: u64,
    /// Requests shed due to load.
    pub load_shed: u64,
    /// Requests admitted after an explicit backpressure delay.
    pub backpressure_delays: u64,
    /// Requests admitted with an operator-visible backpressure warning.
    pub backpressure_warnings: u64,
    /// Probe requests allowed through.
    pub probe_requests: u64,
}

/// Host resilience layer composed from circuit breaker, bulkhead, and health routing.
#[derive(Debug)]
pub struct ResilienceLayer {
    config: ResilienceConfig,
    connectors: RwLock<HashMap<ConnectorId, Arc<ConnectorState>>>,
    health_router: HealthRouter,
    load_shedder: LoadShedder,
    backpressure_controller: BackpressureController,
}

impl Default for ResilienceLayer {
    fn default() -> Self {
        Self::new(ResilienceConfig::default())
    }
}

/// Outcome of the load-shed / backpressure gate for a request that was *not*
/// shed. Carries the observability the controller decided on so that the
/// delay/warning metric and log fire only once admission is actually
/// guaranteed — after the routing, circuit, and bulkhead gates also pass —
/// rather than in `check_load_shed`, where a request later rejected downstream
/// would still be counted as delayed/warned. See bead `bp-metric-overcount`.
struct AdmissionControl {
    /// Bounded backpressure delay to apply before acquiring a bulkhead permit.
    delay: Option<Duration>,
    /// The controller's decision, retained for the deferred metric + log.
    decision: BackpressureDecision,
}

impl ResilienceLayer {
    /// Create a resilience layer with the supplied configuration.
    #[must_use]
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            load_shedder: LoadShedder::new(config.load_shed.clone()),
            backpressure_controller: BackpressureController::default(),
            health_router: HealthRouter::new(config.health.clone()),
            config,
            connectors: RwLock::new(HashMap::new()),
        }
    }

    /// Ensure a connector has initialized resilience state.
    pub fn ensure_connector(&self, connector_id: &ConnectorId) {
        let mut entries = lock_unpoisoned(&self.health_router.entries);
        entries
            .entry(connector_id.clone())
            .or_insert_with(|| HealthEntry::new(&self.config.health));
    }

    /// Override the manual base load used by the shedder.
    pub fn set_base_load_per_mille(&self, load_per_mille: u16) {
        self.load_shedder.set_base_load_per_mille(load_per_mille);
    }

    /// Get the current health-derived routing state for a connector.
    #[must_use]
    pub fn connector_health(&self, connector_id: &ConnectorId) -> ConnectorHealth {
        self.health_router.health(connector_id)
    }

    /// Get the current circuit state for a connector.
    #[must_use]
    pub fn circuit_state(&self, connector_id: &ConnectorId) -> CircuitState {
        self.connector_state(connector_id).circuit.state()
    }

    /// Snapshot metrics for a connector.
    #[must_use]
    pub fn metrics(&self, connector_id: &ConnectorId) -> ResilienceMetricsSnapshot {
        self.connector_state(connector_id).metrics.snapshot()
    }

    /// Evaluate current host backpressure for a connector without executing work.
    #[must_use]
    pub fn backpressure_decision(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
    ) -> BackpressureDecision {
        self.backpressure_decision_inner(connector_id, priority, operation, None)
    }

    /// Evaluate current host backpressure with explicit fairness pressure.
    #[must_use]
    pub fn backpressure_decision_with_fairness(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        fairness: BackpressureFairnessContext,
    ) -> BackpressureDecision {
        self.backpressure_decision_inner(connector_id, priority, operation, Some(fairness))
    }

    fn backpressure_decision_inner(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        fairness: Option<BackpressureFairnessContext>,
    ) -> BackpressureDecision {
        let state = self.connector_state(connector_id);
        let queue_pressure = state.bulkhead.pressure_per_mille();
        let effective_load = self.load_shedder.effective_load_per_mille(queue_pressure);
        self.backpressure_controller
            .decide(backpressure_controller_input(
                format!("{connector_id}:{operation}"),
                priority,
                effective_load,
                queue_pressure,
                fairness,
            ))
    }

    /// Execute a connector operation with all resilience protections applied.
    ///
    /// # Errors
    ///
    /// Returns a [`ResilienceError`] when the operation is shed, rejected, or
    /// when the wrapped operation itself fails.
    pub async fn execute<F, T, E>(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        future: F,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        self.execute_inner(connector_id, priority, operation, None, future)
            .await
    }

    /// Execute a connector operation with explicit fairness pressure.
    ///
    /// # Errors
    ///
    /// Returns a [`ResilienceError`] when the operation is shed, rejected, or
    /// when the wrapped operation itself fails.
    pub async fn execute_with_fairness<F, T, E>(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        fairness: BackpressureFairnessContext,
        future: F,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        self.execute_inner(connector_id, priority, operation, Some(fairness), future)
            .await
    }

    async fn execute_inner<F, T, E>(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        fairness: Option<BackpressureFairnessContext>,
        future: F,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let state = self.connector_state(connector_id);
        let effective_load = self.record_request(&state);
        let admission = self.check_load_shed(
            &state,
            connector_id,
            priority,
            operation,
            effective_load,
            fairness,
        )?;
        let probe_reservation = self.check_routing(connector_id, operation)?;
        if let Err(error) = Self::check_circuit(&state, connector_id, operation) {
            self.health_router
                .cancel_probe_reservation(probe_reservation);
            return Err(error);
        }
        if let Some(delay) = admission.delay {
            // br-6bgp1: actually apply the controller's `Delay`
            // before claiming a bulkhead permit. The sleep is bounded
            // (1-10ms) so a single decision cannot starve a request;
            // operators that need stronger backpressure should rely
            // on bulkhead permit exhaustion (which provides the
            // unbounded-queueing path).
            time::sleep(delay).await;
        }
        let permit = match self.acquire_bulkhead(&state, connector_id, operation).await {
            Ok(permit) => permit,
            Err(error) => {
                self.health_router
                    .cancel_probe_reservation(probe_reservation);
                return Err(error);
            }
        };
        // Admission is now guaranteed. Record the deferred backpressure
        // delay/warning observability so the metrics count only requests that
        // actually cleared every gate, never ones rejected downstream.
        Self::record_admission_backpressure(
            &state,
            connector_id,
            priority,
            operation,
            effective_load,
            &admission,
        );
        if probe_reservation.is_some() {
            state.metrics.probe_requests.fetch_add(1, Ordering::Relaxed);
        }
        let started_at = Instant::now();
        let result = self
            .run_operation(&state, connector_id, operation, future, started_at)
            .await;
        drop(permit);
        self.record_completion(&state, connector_id, started_at.elapsed(), &result);
        result
    }

    fn record_request(&self, state: &ConnectorState) -> u32 {
        state.metrics.requests.fetch_add(1, Ordering::Relaxed);
        self.load_shedder
            .effective_load_per_mille(state.bulkhead.pressure_per_mille())
    }

    fn check_load_shed<E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        effective_load: u32,
        fairness: Option<BackpressureFairnessContext>,
    ) -> Result<AdmissionControl, ResilienceError<E>> {
        let decision = self
            .backpressure_controller
            .decide(backpressure_controller_input(
                format!("{connector_id}:{operation}"),
                priority,
                effective_load,
                state.bulkhead.pressure_per_mille(),
                fairness,
            ));
        let should_shed = if decision.action == BackpressureAction::FallbackStaticPolicy {
            self.load_shedder.should_shed(priority, effective_load)
        } else {
            decision.rejects_work()
        };

        if should_shed {
            state.metrics.load_shed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                connector_id = %connector_id,
                operation,
                load_per_mille = effective_load,
                priority = ?priority,
                backpressure_state = decision.state.as_str(),
                backpressure_action = decision.action.as_str(),
                fallback_trigger = ?decision.fallback_trigger,
                "request shed due to load"
            );
            return Err(ResilienceError::LoadShed {
                load_per_mille: to_u16(effective_load),
            });
        }

        // br-6bgp1 (Delay) / br-uwih7 (AdmitWithWarning): the controller's
        // delay and warning actions are surfaced to operators via a metric and
        // log. That observability is *not* emitted here: a request that clears
        // load shedding can still be rejected by the routing, circuit, or
        // bulkhead gates that run after this function returns, and a delayed
        // request has not even slept yet. Emitting now would count phantom
        // delays/warnings for never-admitted requests (bead bp-metric-overcount).
        // Instead we return the decision and let `execute_inner` record it via
        // `record_admission_backpressure` once admission is guaranteed.
        let delay = backpressure_delay_duration(&decision);
        Ok(AdmissionControl { delay, decision })
    }

    /// Emit the deferred backpressure delay/warning metric and log for a request
    /// that has now passed every admission gate (load shed, routing, circuit,
    /// bulkhead). Counting here — rather than in `check_load_shed` — ensures the
    /// `backpressure_delays` / `backpressure_warnings` metrics reflect only
    /// requests that were actually admitted (bead bp-metric-overcount).
    fn record_admission_backpressure(
        state: &ConnectorState,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        effective_load: u32,
        admission: &AdmissionControl,
    ) {
        if let Some(delay) = admission.delay {
            let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            state
                .metrics
                .backpressure_delays
                .fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                connector_id = %connector_id,
                operation,
                delay_ms,
                priority = ?priority,
                backpressure_state = admission.decision.state.as_str(),
                backpressure_action = admission.decision.action.as_str(),
                "request delayed due to backpressure"
            );
        } else if admission.decision.action == BackpressureAction::AdmitWithWarning {
            state
                .metrics
                .backpressure_warnings
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                connector_id = %connector_id,
                operation,
                load_per_mille = effective_load,
                priority = ?priority,
                backpressure_state = admission.decision.state.as_str(),
                backpressure_action = admission.decision.action.as_str(),
                fallback_trigger = ?admission.decision.fallback_trigger,
                "request admitted with backpressure warning"
            );
        }
    }

    fn check_routing<E>(
        &self,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<Option<ProbeReservation>, ResilienceError<E>> {
        match self.health_router.reserve_route(connector_id) {
            RouteReservation::Allow => Ok(None),
            RouteReservation::AllowProbe(reservation) => Ok(Some(reservation)),
            RouteReservation::Reject { reason } => {
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    reason,
                    "connector rejected by health router"
                );
                Err(ResilienceError::Unhealthy { reason })
            }
        }
    }

    fn check_circuit<E>(
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<(), ResilienceError<E>> {
        match state.circuit.before_call() {
            Ok(CircuitPermit::Regular | CircuitPermit::Probe) => Ok(()),
            Err(CircuitReject::Open { retry_after }) => {
                state
                    .metrics
                    .circuit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    retry_after_ms = retry_after.as_millis(),
                    "circuit breaker rejected request"
                );
                Err(ResilienceError::CircuitOpen { retry_after })
            }
            Err(CircuitReject::HalfOpenLimited) => {
                state
                    .metrics
                    .circuit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    "half-open probe already in flight"
                );
                Err(ResilienceError::HalfOpenLimited)
            }
        }
    }

    async fn acquire_bulkhead<E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<OwnedSemaphorePermit, ResilienceError<E>> {
        match state.bulkhead.acquire().await {
            Ok(permit) => Ok(permit),
            Err(BulkheadAcquireError::QueueFull) => {
                state.circuit.cancel_inflight_probe();
                state
                    .metrics
                    .bulkhead_rejections
                    .fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "bulkhead queue full");
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    "bulkhead queue full"
                );
                Err(ResilienceError::BulkheadFull)
            }
            Err(BulkheadAcquireError::QueueTimeout { timeout }) => {
                state.circuit.cancel_inflight_probe();
                state
                    .metrics
                    .bulkhead_rejections
                    .fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "bulkhead queue timeout");
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    timeout_ms = timeout.as_millis(),
                    "bulkhead queue timed out"
                );
                Err(ResilienceError::QueueTimeout { timeout })
            }
        }
    }

    async fn run_operation<F, T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        future: F,
        started_at: Instant,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        if let Some(timeout) = self.config.operation_timeout {
            return self
                .run_operation_with_timeout(
                    state,
                    connector_id,
                    operation,
                    future,
                    started_at,
                    timeout,
                )
                .await;
        }

        future.await.map_err(ResilienceError::Inner)
    }

    async fn run_operation_with_timeout<F, T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        future: F,
        started_at: Instant,
        timeout: Duration,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        if let Ok(inner) = time::timeout(timeout, future).await {
            return inner.map_err(ResilienceError::Inner);
        }

        self.record_timeout(
            state,
            connector_id,
            operation,
            timeout,
            started_at.elapsed(),
        );
        Err(ResilienceError::TimedOut { timeout })
    }

    fn record_timeout(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        timeout: Duration,
        latency: Duration,
    ) {
        state.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
        self.apply_circuit_outcome(state, OutcomeKind::TimedOut, latency);
        self.health_router
            .record_timeout(connector_id, timeout, latency);
        tracing::warn!(
            connector_id = %connector_id,
            operation,
            timeout_ms = timeout.as_millis(),
            "connector operation timed out"
        );
    }

    fn record_completion<T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        latency: Duration,
        result: &Result<T, ResilienceError<E>>,
    ) {
        match result {
            Ok(_) => {
                state.metrics.successes.fetch_add(1, Ordering::Relaxed);
                self.health_router.record_success(connector_id, latency);
                self.apply_circuit_outcome(state, OutcomeKind::Success, latency);
            }
            Err(ResilienceError::Inner(_)) => {
                state.metrics.failures.fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "connector operation failed");
                self.apply_circuit_outcome(state, OutcomeKind::Failure, latency);
            }
            Err(_) => {}
        }
    }

    fn apply_circuit_outcome(
        &self,
        state: &ConnectorState,
        outcome: OutcomeKind,
        latency: Duration,
    ) {
        if self
            .config
            .circuit_breaker
            .failure_predicate
            .matches(outcome, latency)
        {
            if state.circuit.record_failure() {
                state.metrics.circuit_opened.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            state.circuit.record_success();
        }
    }

    fn connector_state(&self, connector_id: &ConnectorId) -> Arc<ConnectorState> {
        // Fast path: try to get the existing state with a read lock
        {
            let states = self
                .connectors
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(state) = states.get(connector_id) {
                return Arc::clone(state);
            }
        }

        // Slow path: upgrade to write lock and insert if missing
        let mut states = self
            .connectors
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            states
                .entry(connector_id.clone())
                .or_insert_with(|| Arc::new(ConnectorState::new(&self.config))),
        )
    }
}

/// Merge two connector health sources and keep the worst status.
#[must_use]
pub fn merge_connector_health(
    primary: ConnectorHealth,
    secondary: ConnectorHealth,
) -> ConnectorHealth {
    match (
        health_severity(&primary),
        health_severity(&secondary),
        primary,
        secondary,
    ) {
        (HealthSeverity::Healthy, HealthSeverity::Healthy, ConnectorHealth::Healthy, _) => {
            ConnectorHealth::Healthy
        }
        (HealthSeverity::Unavailable, _, ConnectorHealth::Unavailable { reason, since }, other)
        | (_, HealthSeverity::Unavailable, other, ConnectorHealth::Unavailable { reason, since }) =>
        {
            let combined =
                combine_reason_strings(&reason, health_reason(&other).unwrap_or_default());
            ConnectorHealth::Unavailable {
                reason: combined,
                since: earlier_since(Some(since), unavailable_since(&other)).unwrap_or(since),
            }
        }
        (HealthSeverity::Degraded, _, ConnectorHealth::Degraded { reason }, other)
        | (_, HealthSeverity::Degraded, other, ConnectorHealth::Degraded { reason }) => {
            ConnectorHealth::Degraded {
                reason: combine_reason_strings(&reason, health_reason(&other).unwrap_or_default()),
            }
        }
        _ => ConnectorHealth::Healthy,
    }
}

#[derive(Debug)]
struct ConnectorState {
    circuit: CircuitBreaker,
    bulkhead: Bulkhead,
    metrics: ConnectorMetrics,
}

impl ConnectorState {
    fn new(config: &ResilienceConfig) -> Self {
        Self {
            circuit: CircuitBreaker::new(config.circuit_breaker.clone()),
            bulkhead: Bulkhead::new(config.bulkhead.clone()),
            metrics: ConnectorMetrics::default(),
        }
    }
}

#[derive(Debug, Default)]
struct ConnectorMetrics {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    timeouts: AtomicU64,
    circuit_rejections: AtomicU64,
    circuit_opened: AtomicU64,
    bulkhead_rejections: AtomicU64,
    load_shed: AtomicU64,
    backpressure_delays: AtomicU64,
    backpressure_warnings: AtomicU64,
    probe_requests: AtomicU64,
}

impl ConnectorMetrics {
    fn snapshot(&self) -> ResilienceMetricsSnapshot {
        ResilienceMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            circuit_rejections: self.circuit_rejections.load(Ordering::Relaxed),
            circuit_opened: self.circuit_opened.load(Ordering::Relaxed),
            bulkhead_rejections: self.bulkhead_rejections.load(Ordering::Relaxed),
            load_shed: self.load_shed.load(Ordering::Relaxed),
            backpressure_delays: self.backpressure_delays.load(Ordering::Relaxed),
            backpressure_warnings: self.backpressure_warnings.load(Ordering::Relaxed),
            probe_requests: self.probe_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Success,
    Failure,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitPermit {
    Regular,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitReject {
    Open { retry_after: Duration },
    HalfOpenLimited,
}

#[derive(Debug)]
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<CircuitInner>,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    failures: u32,
    successes: u32,
    window_started_at: Instant,
    opened_until: Option<Instant>,
    probe_in_flight: bool,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(CircuitInner {
                state: CircuitState::Closed,
                failures: 0,
                successes: 0,
                window_started_at: Instant::now(),
                opened_until: None,
                probe_in_flight: false,
            }),
        }
    }

    fn state(&self) -> CircuitState {
        lock_unpoisoned(&self.inner).state
    }

    fn before_call(&self) -> Result<CircuitPermit, CircuitReject> {
        let now = Instant::now();
        let mut inner = lock_unpoisoned(&self.inner);
        let decision = match inner.state {
            CircuitState::Closed => Ok(CircuitPermit::Regular),
            CircuitState::Open => {
                if let Some(until) = inner.opened_until {
                    if now < until {
                        Err(CircuitReject::Open {
                            retry_after: until.saturating_duration_since(now),
                        })
                    } else {
                        inner.state = CircuitState::HalfOpen;
                        inner.failures = 0;
                        inner.probe_in_flight = true;
                        Ok(CircuitPermit::Probe)
                    }
                } else {
                    inner.state = CircuitState::HalfOpen;
                    inner.failures = 0;
                    inner.probe_in_flight = true;
                    Ok(CircuitPermit::Probe)
                }
            }
            CircuitState::HalfOpen => {
                if inner.probe_in_flight {
                    Err(CircuitReject::HalfOpenLimited)
                } else {
                    inner.probe_in_flight = true;
                    Ok(CircuitPermit::Probe)
                }
            }
        };
        drop(inner);
        decision
    }

    fn cancel_inflight_probe(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        if inner.state == CircuitState::HalfOpen {
            inner.probe_in_flight = false;
        }
    }

    fn record_success(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        match inner.state {
            CircuitState::Closed => {
                inner.failures = 0;
                inner.window_started_at = Instant::now();
            }
            CircuitState::HalfOpen => {
                inner.probe_in_flight = false;
                inner.successes = inner.successes.saturating_add(1);
                if inner.successes >= self.config.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.failures = 0;
                    inner.successes = 0;
                    inner.opened_until = None;
                    inner.window_started_at = Instant::now();
                }
            }
            CircuitState::Open => {}
        }
    }

    fn record_failure(&self) -> bool {
        let mut inner = lock_unpoisoned(&self.inner);
        let now = Instant::now();

        if now.saturating_duration_since(inner.window_started_at) > self.config.window_duration {
            inner.failures = 0;
            inner.window_started_at = now;
        }

        inner.probe_in_flight = false;
        inner.successes = 0;

        let opened = match inner.state {
            // A failure from a request that was admitted while Closed can complete
            // *after* other concurrent failures have already tripped the breaker.
            // The breaker is already open — such a straggler must not re-run
            // `open_circuit` (which would reset `opened_until`, pushing the first
            // recovery probe later than the configured `open_duration`, and
            // double-count `circuit_opened`). Mirror `record_success`, which also
            // no-ops in the Open state.
            CircuitState::Open => false,
            CircuitState::HalfOpen => open_circuit(&mut inner, &self.config),
            CircuitState::Closed => {
                inner.failures = inner.failures.saturating_add(1);
                inner.failures >= self.config.failure_threshold
                    && open_circuit(&mut inner, &self.config)
            }
        };
        drop(inner);
        opened
    }
}

fn open_circuit(inner: &mut CircuitInner, config: &CircuitBreakerConfig) -> bool {
    inner.state = CircuitState::Open;
    inner.failures = 0;
    inner.successes = 0;
    inner.opened_until = Some(Instant::now() + config.open_duration);
    true
}

#[derive(Debug)]
struct Bulkhead {
    permits: Arc<Semaphore>,
    config: BulkheadConfig,
    queued: AtomicUsize,
}

/// Decrements the bulkhead's `queued` counter on drop, so the count is released
/// on both normal completion and cancellation of the queue-wait future.
struct QueuedGuard<'a>(&'a AtomicUsize);

impl Drop for QueuedGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkheadAcquireError {
    QueueFull,
    QueueTimeout { timeout: Duration },
}

impl Bulkhead {
    fn new(config: BulkheadConfig) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_concurrent)),
            config,
            queued: AtomicUsize::new(0),
        }
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, BulkheadAcquireError> {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return Ok(permit);
        }

        let queued_before = self.queued.fetch_add(1, Ordering::SeqCst);
        if queued_before >= self.config.max_queued {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            return Err(BulkheadAcquireError::QueueFull);
        }

        // Decrement `queued` via a drop guard rather than a plain statement after
        // the await: if the enclosing `execute` future is cancelled (e.g. client
        // disconnect) while parked in the queue wait, a bare `fetch_sub` would
        // never run, permanently over-counting `queued`. That phantom count
        // eventually pins `queued >= max_queued`, so every later waiter is
        // rejected with `QueueFull` even with no real waiters (the queue bricks),
        // and it also inflates `pressure_per_mille`. The guard runs on both normal
        // completion and cancellation.
        let _queued_guard = QueuedGuard(&self.queued);

        let permit_result = time::timeout(
            self.config.queue_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await;

        match permit_result {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(BulkheadAcquireError::QueueTimeout {
                timeout: self.config.queue_timeout,
            }),
        }
    }

    fn pressure_per_mille(&self) -> u32 {
        let active = self
            .config
            .max_concurrent
            .saturating_sub(self.permits.available_permits());
        let active_pressure = ratio_per_mille(active, self.config.max_concurrent);
        let queue_pressure = ratio_per_mille(
            self.queued.load(Ordering::Relaxed),
            self.config.max_queued.max(1),
        );
        active_pressure.max(queue_pressure)
    }
}

#[derive(Debug)]
struct HealthRouter {
    config: HealthRouterConfig,
    entries: Mutex<HashMap<ConnectorId, HealthEntry>>,
}

#[derive(Debug)]
struct HealthEntry {
    status: ConnectorHealth,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_probe_at: Option<Instant>,
    unavailable_since: Option<DateTime<Utc>>,
    avg_latency: LatencyEwma,
    error_window: ErrorWindow,
}

#[derive(Debug)]
struct ProbeReservation {
    connector_id: ConnectorId,
    reserved_at: Instant,
    previous_last_probe_at: Option<Instant>,
}

#[derive(Debug)]
enum RouteReservation {
    Allow,
    AllowProbe(ProbeReservation),
    Reject { reason: String },
}

impl HealthEntry {
    fn new(config: &HealthRouterConfig) -> Self {
        Self {
            status: ConnectorHealth::Healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_probe_at: None,
            unavailable_since: None,
            avg_latency: LatencyEwma::new(config.latency_alpha_per_mille),
            error_window: ErrorWindow::new(config.error_window),
        }
    }
}

impl HealthRouter {
    fn new(config: HealthRouterConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn reserve_route(&self, connector_id: &ConnectorId) -> RouteReservation {
        let mut entries = lock_unpoisoned(&self.entries);
        let decision = {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            match &entry.status {
                ConnectorHealth::Healthy | ConnectorHealth::Degraded { .. } => {
                    RouteReservation::Allow
                }
                ConnectorHealth::Unavailable { reason, .. } => {
                    let now = Instant::now();
                    let probe_allowed = entry.last_probe_at.is_none_or(|last| {
                        now.saturating_duration_since(last) >= self.config.probe_interval
                    });
                    if probe_allowed {
                        let reserved_at = now;
                        let previous_last_probe_at = entry.last_probe_at;
                        entry.last_probe_at = Some(reserved_at);
                        RouteReservation::AllowProbe(ProbeReservation {
                            connector_id: connector_id.clone(),
                            reserved_at,
                            previous_last_probe_at,
                        })
                    } else {
                        RouteReservation::Reject {
                            reason: reason.clone(),
                        }
                    }
                }
            }
        };
        drop(entries);
        decision
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn can_route(&self, connector_id: &ConnectorId) -> RoutingDecision {
        let mut entries = lock_unpoisoned(&self.entries);
        let decision = {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            match &entry.status {
                ConnectorHealth::Healthy => RoutingDecision::Allow,
                ConnectorHealth::Degraded { reason } => RoutingDecision::AllowDegraded {
                    reason: reason.clone(),
                },
                ConnectorHealth::Unavailable { reason, .. } => {
                    let now = Instant::now();
                    let probe_allowed = entry.last_probe_at.is_none_or(|last| {
                        now.saturating_duration_since(last) >= self.config.probe_interval
                    });
                    if probe_allowed {
                        entry.last_probe_at = Some(now);
                        RoutingDecision::AllowProbe
                    } else {
                        RoutingDecision::Reject {
                            reason: reason.clone(),
                        }
                    }
                }
            }
        };
        drop(entries);
        decision
    }

    fn cancel_probe_reservation(&self, reservation: Option<ProbeReservation>) {
        let Some(reservation) = reservation else {
            return;
        };

        let mut entries = lock_unpoisoned(&self.entries);
        if let Some(entry) = entries.get_mut(&reservation.connector_id)
            && matches!(entry.status, ConnectorHealth::Unavailable { .. })
            && entry.last_probe_at == Some(reservation.reserved_at)
        {
            entry.last_probe_at = reservation.previous_last_probe_at;
        }
    }

    fn record_success(&self, connector_id: &ConnectorId, latency: Duration) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));

            entry.consecutive_failures = 0;
            entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
            entry.avg_latency.record(latency);
            entry.error_window.record_success();
            recalculate_health(entry, &self.config, Some("successful probe"));
        }
        drop(entries);
    }

    fn record_failure(&self, connector_id: &ConnectorId, reason: &str) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));

            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.consecutive_successes = 0;
            entry.error_window.record_failure();
            recalculate_health(entry, &self.config, Some(reason));
        }
        drop(entries);
    }

    fn record_timeout(&self, connector_id: &ConnectorId, timeout: Duration, latency: Duration) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));

            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.consecutive_successes = 0;
            entry.avg_latency.record(latency.max(timeout));
            entry.error_window.record_failure();
            recalculate_health(entry, &self.config, Some("operation timed out"));
        }
        drop(entries);
    }

    fn health(&self, connector_id: &ConnectorId) -> ConnectorHealth {
        let entries = lock_unpoisoned(&self.entries);
        entries
            .get(connector_id)
            .map_or(ConnectorHealth::Healthy, |entry| entry.status.clone())
    }
}

fn recalculate_health(
    entry: &mut HealthEntry,
    config: &HealthRouterConfig,
    failure_reason: Option<&str>,
) {
    if entry.consecutive_failures >= config.unhealthy_threshold {
        let reason = failure_reason.unwrap_or("consecutive failures");
        let since = entry.unavailable_since.unwrap_or_else(Utc::now);
        if entry.unavailable_since.is_none() {
            entry.last_probe_at = Some(Instant::now());
        }
        entry.unavailable_since = Some(since);
        entry.status = ConnectorHealth::Unavailable {
            reason: format!("{reason} ({})", entry.consecutive_failures),
            since,
        };
        return;
    }

    let avg_latency = entry.avg_latency.value().unwrap_or_default();
    let error_rate = entry.error_window.error_rate_per_mille();
    let slow = avg_latency > config.latency_degraded_threshold;
    let error_prone = error_rate >= u32::from(config.error_rate_degraded_threshold_per_mille);
    let recovering = entry.unavailable_since.is_some()
        && entry.consecutive_successes < config.recovery_success_threshold;

    if recovering {
        entry.status = ConnectorHealth::Unavailable {
            reason: "recovering with probe traffic".to_string(),
            since: entry.unavailable_since.unwrap_or_else(Utc::now),
        };
        return;
    }

    if slow || error_prone || entry.consecutive_failures > 0 {
        let mut reasons = Vec::new();
        if slow {
            reasons.push(format!("avg latency {}ms", avg_latency.as_millis()));
        }
        if error_prone {
            reasons.push(format!("error rate {error_rate}‰"));
        }
        if entry.consecutive_failures > 0 {
            reasons.push(format!("{} recent failures", entry.consecutive_failures));
        }
        entry.status = ConnectorHealth::degraded(reasons.join(", "));
        entry.unavailable_since = None;
        return;
    }

    entry.status = ConnectorHealth::Healthy;
    entry.unavailable_since = None;
}

#[derive(Debug)]
struct LoadShedder {
    config: LoadShedConfig,
    base_load_per_mille: AtomicU32,
    sequence: AtomicU64,
}

impl LoadShedder {
    const fn new(config: LoadShedConfig) -> Self {
        Self {
            config,
            base_load_per_mille: AtomicU32::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    fn set_base_load_per_mille(&self, load_per_mille: u16) {
        self.base_load_per_mille.store(
            u32::from(load_per_mille).min(MAX_PER_MILLE),
            Ordering::Relaxed,
        );
    }

    fn effective_load_per_mille(&self, observed_pressure_per_mille: u32) -> u32 {
        self.base_load_per_mille
            .load(Ordering::Relaxed)
            .max(observed_pressure_per_mille)
            .min(MAX_PER_MILLE)
    }

    fn should_shed(&self, priority: RequestPriority, load_per_mille: u32) -> bool {
        if !self.config.sheddable_priorities.contains(&priority) {
            return false;
        }

        let shed_threshold = u32::from(self.config.shed_threshold_per_mille);
        if load_per_mille < shed_threshold {
            return false;
        }

        let full_threshold = u32::from(self.config.full_shed_threshold_per_mille)
            .max(shed_threshold.saturating_add(1));
        let base_probability = if load_per_mille >= full_threshold {
            MAX_PER_MILLE
        } else {
            let numerator = load_per_mille.saturating_sub(shed_threshold) * MAX_PER_MILLE;
            let denominator = full_threshold.saturating_sub(shed_threshold);
            numerator / denominator
        };

        let final_probability =
            (base_probability * priority.shed_factor_per_mille()) / MAX_PER_MILLE;
        if final_probability == 0 {
            return false;
        }

        // Use a simple LCG-like hash on the sequence to avoid bursty drops
        // (dropping contiguous blocks of traffic), distributing drops smoothly.
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let ticket = u32::try_from(seq.wrapping_mul(2_654_435_761) % u64::from(MAX_PER_MILLE))
            .expect("ticket stays below MAX_PER_MILLE");
        ticket < final_probability
    }
}

#[derive(Debug)]
struct ErrorWindow {
    duration: Duration,
    started_at: Instant,
    successes: u32,
    failures: u32,
}

impl ErrorWindow {
    fn new(duration: Duration) -> Self {
        Self {
            duration,
            started_at: Instant::now(),
            successes: 0,
            failures: 0,
        }
    }

    fn record_success(&mut self) {
        self.roll_if_needed();
        self.successes = self.successes.saturating_add(1);
    }

    fn record_failure(&mut self) {
        self.roll_if_needed();
        self.failures = self.failures.saturating_add(1);
    }

    fn error_rate_per_mille(&self) -> u32 {
        let total = u64::from(self.successes) + u64::from(self.failures);
        if total == 0 {
            return 0;
        }
        u32::try_from((u64::from(self.failures) * u64::from(MAX_PER_MILLE)) / total)
            .unwrap_or(MAX_PER_MILLE)
    }

    fn roll_if_needed(&mut self) {
        if self.started_at.elapsed() >= self.duration {
            self.started_at = Instant::now();
            self.successes = 0;
            self.failures = 0;
        }
    }
}

#[derive(Debug)]
struct LatencyEwma {
    alpha_per_mille: u16,
    value_millis: Option<u64>,
}

impl LatencyEwma {
    const fn new(alpha_per_mille: u16) -> Self {
        Self {
            alpha_per_mille,
            value_millis: None,
        }
    }

    fn record(&mut self, latency: Duration) {
        let sample_millis = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        self.value_millis = Some(match self.value_millis {
            None => sample_millis,
            Some(current) => {
                let alpha = u128::from(self.alpha_per_mille).min(u128::from(MAX_PER_MILLE));
                let retained = u128::from(MAX_PER_MILLE).saturating_sub(alpha);

                let current_128 = u128::from(current);
                let sample_128 = u128::from(sample_millis);

                let new_value =
                    ((current_128 * retained) + (sample_128 * alpha)) / u128::from(MAX_PER_MILLE);

                u64::try_from(new_value).unwrap_or(u64::MAX)
            }
        });
    }

    fn value(&self) -> Option<Duration> {
        self.value_millis.map(Duration::from_millis)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HealthSeverity {
    Healthy,
    Degraded,
    Unavailable,
}

const fn health_severity(health: &ConnectorHealth) -> HealthSeverity {
    match health {
        ConnectorHealth::Healthy => HealthSeverity::Healthy,
        ConnectorHealth::Degraded { .. } => HealthSeverity::Degraded,
        ConnectorHealth::Unavailable { .. } => HealthSeverity::Unavailable,
    }
}

#[allow(clippy::missing_const_for_fn)]
fn health_reason(health: &ConnectorHealth) -> Option<&str> {
    match health {
        ConnectorHealth::Healthy => None,
        ConnectorHealth::Degraded { reason } | ConnectorHealth::Unavailable { reason, .. } => {
            Some(reason)
        }
    }
}

const fn unavailable_since(health: &ConnectorHealth) -> Option<DateTime<Utc>> {
    match health {
        ConnectorHealth::Unavailable { since, .. } => Some(*since),
        _ => None,
    }
}

fn earlier_since(
    left: Option<DateTime<Utc>>,
    right: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn combine_reason_strings(left: &str, right: &str) -> String {
    match (left.is_empty(), right.is_empty(), left == right) {
        (true, false, _) => right.to_string(),
        (false, true, _) | (false, false, true) => left.to_string(),
        (false, false, false) => format!("{left}; {right}"),
        (true, true, _) => String::new(),
    }
}

fn ratio_per_mille(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return MAX_PER_MILLE;
    }
    let numerator = numerator as u128;
    let denominator = denominator as u128;
    let ratio = (numerator.saturating_mul(u128::from(MAX_PER_MILLE))) / denominator;
    u32::try_from(ratio)
        .unwrap_or(MAX_PER_MILLE)
        .min(MAX_PER_MILLE)
}

fn predicted_latency_bound_ms(
    samples: &[&ConformalSloCalibrationSample],
    estimated_latency_ms: u64,
    rank: usize,
) -> u64 {
    if samples.is_empty() {
        return estimated_latency_ms;
    }

    let mut latencies = samples
        .iter()
        .map(|sample| sample.latency_for_bound())
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    estimated_latency_ms.max(latencies[rank.min(latencies.len().saturating_sub(1))])
}

fn conformal_prediction_reason(
    budget_exhausted: bool,
    enough_calibration: bool,
    calibration_samples: usize,
    min_calibration_samples: usize,
    predicted_p99_ms: u64,
    slo_budget_ms: u64,
) -> String {
    if budget_exhausted {
        return "zone budget exhausted".to_string();
    }
    if !enough_calibration {
        return format!(
            "insufficient per-zone calibration: {calibration_samples} < {min_calibration_samples}"
        );
    }
    if predicted_p99_ms > slo_budget_ms {
        return format!("predicted p99 {predicted_p99_ms}ms exceeds SLO budget {slo_budget_ms}ms");
    }
    format!("predicted p99 {predicted_p99_ms}ms fits SLO budget {slo_budget_ms}ms")
}

fn preferred_prediction_order(
    left: &ConformalSloRoutePrediction,
    right: &ConformalSloRoutePrediction,
) -> std::cmp::Ordering {
    right
        .meets_slo_budget
        .cmp(&left.meets_slo_budget)
        .then_with(|| {
            right
                .coverage_probability_per_mille
                .cmp(&left.coverage_probability_per_mille)
        })
        .then_with(|| left.predicted_p99_ms.cmp(&right.predicted_p99_ms))
        .then_with(|| left.zone_id.as_str().cmp(right.zone_id.as_str()))
        .then_with(|| left.path_id.cmp(&right.path_id))
}

fn backpressure_controller_input(
    subject: String,
    priority: RequestPriority,
    effective_load_per_mille: u32,
    queue_pressure_per_mille: u32,
    fairness: Option<BackpressureFairnessContext>,
) -> BackpressureControllerInput {
    let input = BackpressureControllerInput::new(
        subject,
        priority,
        BackpressureTelemetry::from_resilience_pressure(
            effective_load_per_mille,
            queue_pressure_per_mille,
        ),
        BackpressureCalibration::valid(),
    );
    match fairness {
        Some(fairness) => input.with_fairness(fairness),
        None => input,
    }
}

fn latency_percentiles_from_millis(samples: &[u64]) -> Option<FairnessLatencyPercentiles> {
    let mut sorted = samples.to_vec();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_unstable();
    Some(FairnessLatencyPercentiles {
        p50_ms: nearest_rank_u64(&sorted, 500)?,
        p95_ms: nearest_rank_u64(&sorted, 950)?,
        p99_ms: nearest_rank_u64(&sorted, 990)?,
    })
}

fn nearest_rank_u64(sorted: &[u64], per_mille: usize) -> Option<u64> {
    let len = sorted.len();
    if len == 0 {
        return None;
    }
    let rank = len.saturating_mul(per_mille).saturating_add(999) / 1_000;
    sorted.get(rank.saturating_sub(1).min(len - 1)).copied()
}

fn redact_evidence_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if [
        "token",
        "secret",
        "password",
        "credential",
        "bearer",
        "private_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

const fn backpressure_fallback_trigger_label(trigger: BackpressureFallbackTrigger) -> &'static str {
    match trigger {
        BackpressureFallbackTrigger::CoverageDrift => "coverage_drift",
        BackpressureFallbackTrigger::MissingTelemetry => "missing_telemetry",
        BackpressureFallbackTrigger::ReplayMismatch => "replay_mismatch",
        BackpressureFallbackTrigger::ArtifactVerificationFailed => "artifact_verification_failed",
    }
}

fn operator_guidance_for_fairness_decision(
    action: BackpressureAction,
    fairness_score: u16,
    rejects_work: bool,
    downstream_retry_after_ms: Option<u64>,
    retry_amplification_per_mille: Option<u16>,
) -> String {
    if rejects_work {
        return format!(
            "rejected overrepresented low-value work with fairness_score={fairness_score}; reduce offered load, split saturated connector classes, or retry after pressure falls"
        );
    }

    if downstream_retry_after_ms.unwrap_or(0) > 0
        || retry_amplification_per_mille.unwrap_or(0) >= 850
    {
        return "downstream throttling is active; preserve capability enforcement and prefer delayed retry over admission bursts".to_string();
    }

    match action {
        BackpressureAction::Admit | BackpressureAction::AdmitWithWarning => {
            "traffic admitted under current fairness envelope; continue monitoring fairness_score and queue_depth".to_string()
        }
        BackpressureAction::Delay => {
            "traffic delayed to protect tail latency and fairness; keep retries bounded and preserve priority ordering".to_string()
        }
        BackpressureAction::FallbackStaticPolicy => {
            "adaptive fairness controller fell back to static policy; inspect fallback_trigger before increasing load".to_string()
        }
        BackpressureAction::Shed | BackpressureAction::CancelLowPriority => {
            "rejected work under fairness pressure; preserve fail-closed policy and avoid retry amplification".to_string()
        }
    }
}

fn fallback_evaluation(weights: &BackpressureLossWeights) -> BackpressureActionEvaluation {
    let terms = vec![
        BackpressureLossTerm::new(
            BackpressureLossTermKind::TailLatency,
            0,
            weights.tail_latency,
        ),
        BackpressureLossTerm::new(
            BackpressureLossTermKind::DroppedUsefulWork,
            0,
            weights.dropped_useful_work,
        ),
        BackpressureLossTerm::new(
            BackpressureLossTermKind::RetryAmplification,
            0,
            weights.retry_amplification,
        ),
        BackpressureLossTerm::new(
            BackpressureLossTermKind::MemoryExhaustion,
            0,
            weights.memory_exhaustion,
        ),
        BackpressureLossTerm::new(
            BackpressureLossTermKind::FairnessViolation,
            0,
            weights.fairness_violation,
        ),
        BackpressureLossTerm::new(
            BackpressureLossTermKind::OperatorSurprise,
            0,
            weights.operator_surprise,
        ),
    ];
    BackpressureActionEvaluation {
        action: BackpressureAction::FallbackStaticPolicy,
        expected_loss_score: score_loss_terms(&terms),
        loss_terms: terms,
    }
}

fn fallback_reason(trigger: BackpressureFallbackTrigger) -> String {
    match trigger {
        BackpressureFallbackTrigger::CoverageDrift => {
            "coverage drift requires conservative static policy".to_string()
        }
        BackpressureFallbackTrigger::MissingTelemetry => {
            "missing telemetry requires conservative static policy".to_string()
        }
        BackpressureFallbackTrigger::ReplayMismatch => {
            "replay mismatch requires conservative static policy".to_string()
        }
        BackpressureFallbackTrigger::ArtifactVerificationFailed => {
            "controller artifact verification failed".to_string()
        }
    }
}

fn counterfactual_reason(
    selected_action: BackpressureAction,
    counterfactual_action: BackpressureAction,
) -> String {
    if selected_action == BackpressureAction::FallbackStaticPolicy {
        return format!(
            "{} suppressed because fallback is active",
            counterfactual_action.as_str()
        );
    }

    format!(
        "{} had higher expected loss than {}",
        counterfactual_action.as_str(),
        selected_action.as_str()
    )
}

fn tail_latency_loss(
    state: BackpressureState,
    telemetry: BackpressureTelemetry,
    action: BackpressureAction,
) -> u32 {
    let pressure = u32::from(telemetry.max_pressure_per_mille());
    let base = match state {
        BackpressureState::Normal => pressure / 4,
        BackpressureState::QueueCongested
        | BackpressureState::DownstreamThrottled
        | BackpressureState::CalibrationDrift => pressure,
        BackpressureState::CpuSaturated => pressure.saturating_mul(2),
        BackpressureState::MemoryPressure => pressure.saturating_mul(3) / 2,
    };

    match action {
        BackpressureAction::Admit | BackpressureAction::FallbackStaticPolicy => base,
        BackpressureAction::AdmitWithWarning => base.saturating_add(50),
        BackpressureAction::Delay => match state {
            BackpressureState::QueueCongested | BackpressureState::DownstreamThrottled => base / 2,
            BackpressureState::Normal => base.saturating_add(100),
            BackpressureState::CpuSaturated
            | BackpressureState::MemoryPressure
            | BackpressureState::CalibrationDrift => base,
        },
        BackpressureAction::Shed => 0,
        BackpressureAction::CancelLowPriority => {
            if state == BackpressureState::MemoryPressure {
                base / 8
            } else {
                base / 4
            }
        }
    }
}

fn dropped_useful_work_loss(
    priority: RequestPriority,
    telemetry: BackpressureTelemetry,
    action: BackpressureAction,
) -> u32 {
    let useful_work = u32::from(
        telemetry
            .useful_work_per_mille
            .unwrap_or_else(|| default_useful_work_per_mille(priority)),
    );
    let priority_factor = match priority {
        RequestPriority::Critical => 4,
        RequestPriority::High => 3,
        RequestPriority::Normal => 2,
        RequestPriority::Low => 1,
    };
    let priority_weighted_work = useful_work.saturating_mul(priority_factor);

    match action {
        BackpressureAction::Admit
        | BackpressureAction::AdmitWithWarning
        | BackpressureAction::Delay
        | BackpressureAction::FallbackStaticPolicy => 0,
        BackpressureAction::Shed => priority_weighted_work,
        BackpressureAction::CancelLowPriority => {
            if priority == RequestPriority::Low {
                priority_weighted_work / 4
            } else {
                priority_weighted_work.saturating_mul(2)
            }
        }
    }
}

fn retry_amplification_loss(
    state: BackpressureState,
    telemetry: BackpressureTelemetry,
    action: BackpressureAction,
) -> u32 {
    let retry_pressure = u32::from(telemetry.retry_amplification_per_mille.unwrap_or(0)).max(
        if telemetry.downstream_retry_after_ms.unwrap_or(0) > 0 {
            MAX_PER_MILLE
        } else {
            0
        },
    );
    let base = if state == BackpressureState::DownstreamThrottled {
        retry_pressure.saturating_mul(2)
    } else {
        retry_pressure
    };

    match action {
        BackpressureAction::Admit | BackpressureAction::FallbackStaticPolicy => base,
        BackpressureAction::AdmitWithWarning | BackpressureAction::CancelLowPriority => base / 2,
        BackpressureAction::Delay => base / 4,
        BackpressureAction::Shed => base / 3,
    }
}

fn memory_exhaustion_loss(
    state: BackpressureState,
    telemetry: BackpressureTelemetry,
    action: BackpressureAction,
) -> u32 {
    let memory_pressure = u32::from(telemetry.memory_pressure_per_mille.unwrap_or(0));
    let base = if state == BackpressureState::MemoryPressure {
        memory_pressure.saturating_mul(2)
    } else {
        memory_pressure
    };

    match action {
        BackpressureAction::Admit | BackpressureAction::AdmitWithWarning => base,
        BackpressureAction::Delay | BackpressureAction::FallbackStaticPolicy => base / 2,
        BackpressureAction::Shed => 0,
        BackpressureAction::CancelLowPriority => {
            if state == BackpressureState::MemoryPressure {
                0
            } else {
                base / 4
            }
        }
    }
}

fn fairness_violation_loss(
    priority: RequestPriority,
    action: BackpressureAction,
    fairness: Option<&BackpressureFairnessContext>,
) -> u32 {
    let base = match action {
        BackpressureAction::Admit | BackpressureAction::AdmitWithWarning => 0,
        BackpressureAction::Delay => 80,
        BackpressureAction::Shed => {
            if priority == RequestPriority::Low {
                40
            } else {
                400
            }
        }
        BackpressureAction::CancelLowPriority => {
            if priority == RequestPriority::Low {
                20
            } else {
                800
            }
        }
        BackpressureAction::FallbackStaticPolicy => 120,
    };

    let Some(fairness) = fairness else {
        return base;
    };

    let pressure = u32::from(fairness.pressure_per_mille());
    match action {
        BackpressureAction::Admit => base.saturating_add(pressure),
        BackpressureAction::AdmitWithWarning | BackpressureAction::FallbackStaticPolicy => {
            base.saturating_add(pressure / 2)
        }
        BackpressureAction::Delay => base.saturating_add(pressure / 3),
        BackpressureAction::Shed => {
            if priority == RequestPriority::Low {
                base.saturating_sub(pressure / 10)
            } else {
                base.saturating_add(pressure)
            }
        }
        BackpressureAction::CancelLowPriority => {
            if priority == RequestPriority::Low {
                base.saturating_sub(pressure / 8)
            } else {
                base.saturating_add(pressure.saturating_mul(2))
            }
        }
    }
}

fn operator_surprise_loss(state: BackpressureState, action: BackpressureAction) -> u32 {
    match action {
        BackpressureAction::Admit => {
            if state == BackpressureState::Normal {
                0
            } else {
                300
            }
        }
        BackpressureAction::AdmitWithWarning => 40,
        BackpressureAction::Delay | BackpressureAction::CancelLowPriority => 80,
        BackpressureAction::Shed => 220,
        BackpressureAction::FallbackStaticPolicy => {
            if state == BackpressureState::CalibrationDrift {
                20
            } else {
                240
            }
        }
    }
}

/// br-6bgp1: derive the actual sleep duration that should be applied
/// when the controller picks `BackpressureAction::Delay`. Returns
/// `None` for every other action so the caller's `if let Some(delay)`
/// is the single point that distinguishes "real delay needed" from
/// "no delay applied". The duration scales with observed pressure
/// inside the [`MIN_BACKPRESSURE_DELAY_MS`, `MAX_BACKPRESSURE_DELAY_MS`]
/// envelope; downstream `retry_after_ms` overrides up to the same
/// ceiling so an explicit upstream signal isn't silently scaled
/// down below it.
fn backpressure_delay_duration(decision: &BackpressureDecision) -> Option<Duration> {
    if decision.action != BackpressureAction::Delay {
        return None;
    }
    let telemetry = decision.replay.input.telemetry;
    let pressure_delay_ms = u64::from(telemetry.max_pressure_per_mille() / 100);
    let retry_after_ms = telemetry.downstream_retry_after_ms.unwrap_or(0);
    let delay_ms = retry_after_ms
        .max(MIN_BACKPRESSURE_DELAY_MS.saturating_add(pressure_delay_ms))
        .clamp(MIN_BACKPRESSURE_DELAY_MS, MAX_BACKPRESSURE_DELAY_MS);
    Some(Duration::from_millis(delay_ms))
}

const fn default_useful_work_per_mille(priority: RequestPriority) -> u16 {
    match priority {
        RequestPriority::Critical => 1_000,
        RequestPriority::High => 900,
        RequestPriority::Normal => 700,
        RequestPriority::Low => 300,
    }
}

fn score_loss_terms(terms: &[BackpressureLossTerm]) -> i64 {
    let score = terms.iter().fold(0_i128, |acc, term| {
        acc.saturating_add(term.weighted_score())
    });
    i64::try_from(score).unwrap_or(i64::MAX)
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
}

const fn clamp_per_mille_u16(value: u16) -> u16 {
    if value > MAX_PER_MILLE_U16 {
        MAX_PER_MILLE_U16
    } else {
        value
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_async_core::task;

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.host:test:v1")
    }

    fn swarm_decision_action(
        action: BackpressureAction,
    ) -> fcp_testkit::evidence_helpers::SwarmDecisionAction {
        match action {
            BackpressureAction::Admit | BackpressureAction::AdmitWithWarning => {
                fcp_testkit::evidence_helpers::SwarmDecisionAction::Admit
            }
            BackpressureAction::Delay => fcp_testkit::evidence_helpers::SwarmDecisionAction::Delay,
            BackpressureAction::Shed | BackpressureAction::CancelLowPriority => {
                fcp_testkit::evidence_helpers::SwarmDecisionAction::Shed
            }
            BackpressureAction::FallbackStaticPolicy => {
                fcp_testkit::evidence_helpers::SwarmDecisionAction::Fallback
            }
        }
    }

    fn fairness_context(
        connector_class_pressure_per_mille: u16,
        zone_share_per_mille: u16,
        admitted_count: u64,
        shed_count: u64,
    ) -> BackpressureFairnessContext {
        BackpressureFairnessContext::new(BackpressureFairnessContextInput {
            connector_class: "request_response_saas".to_string(),
            zone_id: "z:work".to_string(),
            capability: "saas.write".to_string(),
            connector_class_pressure_per_mille,
            zone_share_per_mille,
            capability_share_per_mille: zone_share_per_mille,
            target_share_per_mille: 500,
            admitted_count,
            shed_count,
        })
    }

    #[fcp_async_core::runtime::test]
    async fn circuit_breaker_opens_after_failures() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 2,
                open_duration: Duration::from_millis(50),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        for _ in 0..2 {
            let result = layer
                .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                    Err::<(), _>("boom")
                })
                .await;
            assert!(matches!(result, Err(ResilienceError::Inner("boom"))));
        }

        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);
        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.failures, 2);
        assert_eq!(metrics.circuit_opened, 1);

        let result = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::CircuitOpen { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn circuit_breaker_recovers_after_probe_successes() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        let _ = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Err::<(), _>("boom")
            })
            .await;
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);

        time::sleep(Duration::from_millis(40)).await;
        let first_probe = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(first_probe.is_ok());
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::HalfOpen);

        let second_probe = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(second_probe.is_ok());
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Closed);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_rejects_requests_beyond_queue_limit() {
        let bulkhead = Arc::new(Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 2,
            queue_timeout: Duration::from_secs(1),
        }));

        let first_permit = bulkhead.acquire().await.expect("first permit");

        let second = {
            let bulkhead = Arc::clone(&bulkhead);
            task::spawn(async move { bulkhead.acquire().await })
        };
        let third = {
            let bulkhead = Arc::clone(&bulkhead);
            task::spawn(async move { bulkhead.acquire().await })
        };

        while bulkhead.queued.load(Ordering::Relaxed) < 2 {
            time::sleep(Duration::from_millis(1)).await;
        }

        let fourth = bulkhead.acquire().await;
        assert!(matches!(fourth, Err(BulkheadAcquireError::QueueFull)));

        drop(first_permit);
        drop(second.await.expect("join").expect("second permit"));
        drop(third.await.expect("join").expect("third permit"));
    }

    #[fcp_async_core::runtime::test]
    async fn health_router_allows_probe_after_unhealthy_period() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 10,
                success_threshold: 1,
                open_duration: Duration::from_millis(10),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            health: HealthRouterConfig {
                unhealthy_threshold: 2,
                recovery_success_threshold: 1,
                probe_interval: Duration::from_millis(30),
                ..HealthRouterConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        for _ in 0..2 {
            let _ = layer
                .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                    Err::<(), _>("boom")
                })
                .await;
        }

        assert!(matches!(
            layer.connector_health(&connector_id),
            ConnectorHealth::Unavailable { .. }
        ));

        let rejected = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(rejected, Err(ResilienceError::Unhealthy { .. })));

        time::sleep(Duration::from_millis(40)).await;
        let recovered = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(recovered.is_ok());
        assert_eq!(layer.metrics(&connector_id).probe_requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn load_shedding_respects_priority() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            load_shed: LoadShedConfig {
                shed_threshold_per_mille: 500,
                full_shed_threshold_per_mille: 1_000,
                sheddable_priorities: vec![
                    RequestPriority::Low,
                    RequestPriority::Normal,
                    RequestPriority::High,
                ],
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(950);

        let mut low_shed = 0_u32;
        let mut critical_shed = 0_u32;
        for _ in 0..100 {
            if matches!(
                layer
                    .execute(&connector_id, RequestPriority::Low, "invoke", async {
                        Ok::<(), &str>(())
                    },)
                    .await,
                Err(ResilienceError::LoadShed { .. })
            ) {
                low_shed = low_shed.saturating_add(1);
            }
        }

        for _ in 0..100 {
            if matches!(
                layer
                    .execute(&connector_id, RequestPriority::Critical, "invoke", async {
                        Ok::<(), &str>(())
                    },)
                    .await,
                Err(ResilienceError::LoadShed { .. })
            ) {
                critical_shed = critical_shed.saturating_add(1);
            }
        }

        assert!(low_shed >= 80);
        assert_eq!(critical_shed, 0);
    }

    /// br-6bgp1 + br-uwih7: pin that `backpressure_delay_duration`
    /// returns `Some(_)` ONLY for `BackpressureAction::Delay` and
    /// `None` for every other action. Pre-fix the action enum had
    /// six variants but the integration only branched on two of
    /// them; this regression catches any future drift where an
    /// action variant is added without a corresponding integration
    /// branch (the `Delay` action would silently downgrade to
    /// `Admit` again, the bug the original commit shipped with).
    #[test]
    fn br_6bgp1_backpressure_delay_duration_returns_some_only_for_delay_action() {
        let controller = BackpressureController::default();
        // Telemetry shape that produces Action::Delay with default weights
        // (state=QueueCongested, Normal priority, q=900, cpu=250).
        let delay_decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(900),
                cpu_pressure_per_mille: Some(250),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));
        assert_eq!(delay_decision.action, BackpressureAction::Delay);
        let delay = backpressure_delay_duration(&delay_decision);
        assert!(
            delay.is_some(),
            "Delay action MUST yield a real sleep duration — pre-fix it returned None"
        );
        let delay = delay.unwrap_or(Duration::ZERO);
        let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        assert!(
            (MIN_BACKPRESSURE_DELAY_MS..=MAX_BACKPRESSURE_DELAY_MS).contains(&delay_ms),
            "delay {delay:?} must be inside [{MIN_BACKPRESSURE_DELAY_MS}ms, \
             {MAX_BACKPRESSURE_DELAY_MS}ms]"
        );

        // Every other action variant MUST yield None so the
        // execute() path does not erroneously sleep for actions the
        // controller did not ask to delay.
        for action in [
            BackpressureAction::Admit,
            BackpressureAction::AdmitWithWarning,
            BackpressureAction::Shed,
            BackpressureAction::CancelLowPriority,
            BackpressureAction::FallbackStaticPolicy,
        ] {
            let mut synthetic = delay_decision.clone();
            synthetic.action = action;
            assert!(
                backpressure_delay_duration(&synthetic).is_none(),
                "br-6bgp1: backpressure_delay_duration MUST return None for {action:?} — \
                 only Delay should produce a sleep. Pre-fix this helper did not exist and \
                 every action silently fell through to immediate admit"
            );
        }
    }

    /// br-6bgp1: the Delay sleep duration is bounded so a single
    /// adaptive decision cannot starve a request. Pin the bounds.
    #[test]
    fn br_6bgp1_backpressure_delay_duration_clamps_to_envelope() {
        let controller = BackpressureController::default();
        let mut decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(900),
                cpu_pressure_per_mille: Some(250),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));
        assert_eq!(decision.action, BackpressureAction::Delay);

        // Even an absurd downstream retry-after hint is clamped to MAX.
        decision.replay.input.telemetry.downstream_retry_after_ms = Some(60_000);
        assert_eq!(
            backpressure_delay_duration(&decision),
            Some(Duration::from_millis(MAX_BACKPRESSURE_DELAY_MS)),
            "br-6bgp1: 60s downstream retry-after must clamp to MAX_BACKPRESSURE_DELAY_MS, \
             not propagate as an unbounded sleep that would let an upstream throttle starve \
             every in-flight request"
        );

        // No pressure + no retry hint still floors at MIN, so the
        // sleep is observable.
        decision.replay.input.telemetry = BackpressureTelemetry {
            queue_pressure_per_mille: Some(0),
            cpu_pressure_per_mille: Some(0),
            ..BackpressureTelemetry::default()
        };
        assert_eq!(
            backpressure_delay_duration(&decision),
            Some(Duration::from_millis(MIN_BACKPRESSURE_DELAY_MS)),
            "br-6bgp1: zero pressure must floor at MIN_BACKPRESSURE_DELAY_MS so the sleep \
             remains observable in tracing tests"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn br_6bgp1_delay_action_waits_and_records_metric() {
        let layer = ResilienceLayer::default();
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(900);
        assert_eq!(
            layer
                .backpressure_decision(&connector_id, RequestPriority::Normal, "invoke")
                .action,
            BackpressureAction::Delay
        );

        let operation_started_at = Arc::new(Mutex::new(None));
        let operation_started_at_clone = Arc::clone(&operation_started_at);
        let started_at = Instant::now();
        let result = layer
            .execute(
                &connector_id,
                RequestPriority::Normal,
                "invoke",
                async move {
                    *lock_unpoisoned(&operation_started_at_clone) = Some(Instant::now());
                    Ok::<(), &str>(())
                },
            )
            .await;

        assert!(result.is_ok());
        let observed_start = (*lock_unpoisoned(&operation_started_at))
            .expect("operation body should run after the backpressure delay");
        assert!(
            observed_start.saturating_duration_since(started_at)
                >= Duration::from_millis(MIN_BACKPRESSURE_DELAY_MS),
            "br-6bgp1: Delay action must sleep before the operation body starts"
        );
        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.backpressure_delays, 1);
        assert_eq!(metrics.backpressure_warnings, 0);
        assert_eq!(metrics.successes, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn br_uwih7_admit_with_warning_records_operator_metric() {
        let layer = ResilienceLayer::default();
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(950);
        assert_eq!(
            layer
                .backpressure_decision(&connector_id, RequestPriority::High, "invoke")
                .action,
            BackpressureAction::AdmitWithWarning
        );

        let result = layer
            .execute(&connector_id, RequestPriority::High, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;

        assert!(result.is_ok());
        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.backpressure_delays, 0);
        assert_eq!(metrics.backpressure_warnings, 1);
        assert_eq!(metrics.successes, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn bp_metric_overcount_delay_rejected_by_circuit_is_not_counted() {
        // Regression (bead bp-metric-overcount): a request whose backpressure
        // decision is `Delay` but which is then rejected by the circuit breaker
        // must NOT increment `backpressure_delays` — the delay never happened.
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                // Long enough that the breaker stays Open for the second call.
                open_duration: Duration::from_secs(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        // Admit and fail one request at low load to trip the breaker Open.
        layer.set_base_load_per_mille(0);
        let opened = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Err::<(), _>("boom")
            })
            .await;
        assert!(matches!(opened, Err(ResilienceError::Inner("boom"))));
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);

        // Now raise load so the next request's decision is `Delay`, then submit
        // it. The circuit gate rejects it before admission, so no delay metric.
        layer.set_base_load_per_mille(900);
        assert_eq!(
            layer
                .backpressure_decision(&connector_id, RequestPriority::Normal, "invoke")
                .action,
            BackpressureAction::Delay
        );
        let rejected = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(rejected, Err(ResilienceError::CircuitOpen { .. })));

        let metrics = layer.metrics(&connector_id);
        assert_eq!(
            metrics.backpressure_delays, 0,
            "a Delay request rejected by the circuit must not be counted as delayed"
        );
        assert_eq!(metrics.backpressure_warnings, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn bp_metric_overcount_warning_rejected_by_circuit_is_not_counted() {
        // Regression (bead bp-metric-overcount): a request whose backpressure
        // decision is `AdmitWithWarning` but which is then rejected by the
        // circuit breaker must NOT increment `backpressure_warnings` — it was
        // never admitted.
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_secs(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        layer.set_base_load_per_mille(0);
        let opened = layer
            .execute(&connector_id, RequestPriority::High, "invoke", async {
                Err::<(), _>("boom")
            })
            .await;
        assert!(matches!(opened, Err(ResilienceError::Inner("boom"))));
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);

        layer.set_base_load_per_mille(950);
        assert_eq!(
            layer
                .backpressure_decision(&connector_id, RequestPriority::High, "invoke")
                .action,
            BackpressureAction::AdmitWithWarning
        );
        let rejected = layer
            .execute(&connector_id, RequestPriority::High, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(rejected, Err(ResilienceError::CircuitOpen { .. })));

        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.backpressure_delays, 0);
        assert_eq!(
            metrics.backpressure_warnings, 0,
            "an AdmitWithWarning request rejected by the circuit must not be counted"
        );
    }

    #[test]
    fn backpressure_controller_admits_normal_load() {
        let controller = BackpressureController::default();
        let decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(25),
                cpu_pressure_per_mille: Some(50),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));

        assert_eq!(decision.state, BackpressureState::Normal);
        assert_eq!(decision.action, BackpressureAction::Admit);
        assert!(decision.replay_matches());
    }

    #[test]
    fn backpressure_controller_delays_queue_congestion_with_counterfactual() {
        let controller = BackpressureController::default();
        let decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(900),
                cpu_pressure_per_mille: Some(250),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));

        assert_eq!(decision.state, BackpressureState::QueueCongested);
        assert_eq!(decision.action, BackpressureAction::Delay);
        let counterfactual = decision
            .counterfactual
            .as_ref()
            .expect("decision should retain next-best action");
        assert!(counterfactual.expected_loss_score >= decision.selected_loss_score);
        assert!(decision.replay_matches());
    }

    #[test]
    fn backpressure_controller_cancels_low_priority_memory_pressure() {
        let controller = BackpressureController::default();
        let decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/export",
            RequestPriority::Low,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(200),
                cpu_pressure_per_mille: Some(300),
                memory_pressure_per_mille: Some(970),
                useful_work_per_mille: Some(300),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));

        assert_eq!(decision.state, BackpressureState::MemoryPressure);
        assert_eq!(decision.action, BackpressureAction::CancelLowPriority);
        assert!(decision.rejects_work());
        assert!(decision.replay_matches());
    }

    #[test]
    fn backpressure_controller_falls_back_on_missing_telemetry() {
        let controller = BackpressureController::default();
        let decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry::default(),
            BackpressureCalibration::valid(),
        ));

        assert_eq!(decision.action, BackpressureAction::FallbackStaticPolicy);
        assert_eq!(
            decision.fallback_trigger,
            Some(BackpressureFallbackTrigger::MissingTelemetry)
        );
        assert!(decision.fallback_reason.is_some());
        assert!(decision.replay_matches());
    }

    #[test]
    fn backpressure_controller_falls_back_on_calibration_drift() {
        let controller = BackpressureController::default();
        let decision = controller.decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(500),
                cpu_pressure_per_mille: Some(500),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::coverage_drift(900, 990),
        ));

        assert_eq!(decision.state, BackpressureState::CalibrationDrift);
        assert_eq!(decision.action, BackpressureAction::FallbackStaticPolicy);
        assert_eq!(
            decision.fallback_trigger,
            Some(BackpressureFallbackTrigger::CoverageDrift)
        );
        assert!(decision.replay_matches());
    }

    #[test]
    fn backpressure_decision_card_is_offline_replayable() {
        use fcp_testkit::evidence_helpers::{
            SwarmCalibrationStatus, SwarmDecisionAction, SwarmDecisionCard,
            SwarmDecisionCounterfactual, SwarmDecisionDomain, SwarmDecisionEvidencePointer,
            SwarmDecisionFallback, SwarmDecisionLossTerm,
        };
        use std::collections::BTreeMap;

        let decision = BackpressureController::default().decide(BackpressureControllerInput::new(
            "fcp.host:test:v1/invoke",
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(900),
                cpu_pressure_per_mille: Some(250),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
            BackpressureCalibration::valid(),
        ));
        let counterfactual = decision
            .counterfactual
            .as_ref()
            .expect("decision should have a counterfactual");
        let mut replay_inputs = BTreeMap::new();
        replay_inputs.insert(
            "backpressure_decision".to_string(),
            serde_json::to_value(&decision).expect("decision should serialize"),
        );

        let card = SwarmDecisionCard::new(
            "backpressure-controller-card",
            SwarmDecisionDomain::Backpressure,
            decision.replay.input.subject.clone(),
            decision.state.as_str(),
            swarm_decision_action(decision.action),
            decision.selected_loss_score,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_loss_terms(
            decision
                .loss_terms
                .iter()
                .map(|term| {
                    SwarmDecisionLossTerm::new(
                        term.kind.as_str(),
                        i64::from(term.value),
                        term.weight_microunits,
                        "per_mille",
                    )
                })
                .collect(),
        )
        .with_calibration(SwarmCalibrationStatus::Valid)
        .with_counterfactual(SwarmDecisionCounterfactual::new(
            swarm_decision_action(counterfactual.action),
            counterfactual.expected_loss_score,
            counterfactual.reason.clone(),
        ))
        .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::inline_summary(
            "host.backpressure.loss_matrix",
        )])
        .with_replay_inputs(replay_inputs);

        assert!(card.is_replayable_offline());
        assert!(card.safe_to_disable());
    }

    #[test]
    fn resilience_layer_exposes_current_backpressure_decision() {
        let layer = ResilienceLayer::default();
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(950);

        let decision = layer.backpressure_decision(&connector_id, RequestPriority::Low, "invoke");

        assert_eq!(decision.state, BackpressureState::CpuSaturated);
        assert_eq!(decision.action, BackpressureAction::Shed);
        assert!(decision.rejects_work());
        assert!(decision.replay_matches());
    }

    #[fcp_async_core::runtime::test]
    async fn backpressure_sheds_burst_low_priority_then_recovers() {
        let layer = ResilienceLayer::default();
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(980);

        let shed = layer
            .execute(&connector_id, RequestPriority::Low, "invoke", async {
                Ok::<_, &str>("should not run")
            })
            .await;
        assert!(matches!(shed, Err(ResilienceError::LoadShed { .. })));
        assert_eq!(layer.metrics(&connector_id).load_shed, 1);

        layer.set_base_load_per_mille(0);
        let recovered = layer
            .execute(&connector_id, RequestPriority::Low, "invoke", async {
                Ok::<_, &str>("recovered")
            })
            .await;

        assert_eq!(recovered.unwrap(), "recovered");
        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.requests, 2);
        assert_eq!(metrics.successes, 1);
        assert_eq!(metrics.load_shed, 1);
    }

    #[test]
    fn backpressure_controller_reduces_loss_vs_static_policy_in_swarm_mix() {
        let controller = BackpressureController::default();
        let scenarios = [
            (
                RequestPriority::Normal,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(920),
                    cpu_pressure_per_mille: Some(220),
                    useful_work_per_mille: Some(800),
                    ..BackpressureTelemetry::default()
                },
                500_i64,
            ),
            (
                RequestPriority::Low,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(250),
                    cpu_pressure_per_mille: Some(350),
                    memory_pressure_per_mille: Some(970),
                    useful_work_per_mille: Some(300),
                    ..BackpressureTelemetry::default()
                },
                350_i64,
            ),
            (
                RequestPriority::Normal,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(400),
                    cpu_pressure_per_mille: Some(300),
                    downstream_retry_after_ms: Some(2_000),
                    retry_amplification_per_mille: Some(900),
                    useful_work_per_mille: Some(700),
                    ..BackpressureTelemetry::default()
                },
                150_i64,
            ),
        ];

        let mut controller_loss = 0_i64;
        let mut static_policy_loss = 0_i64;
        for (index, (priority, telemetry, count)) in scenarios.into_iter().enumerate() {
            let decision = controller.decide(BackpressureControllerInput::new(
                format!("fcp.host:swarm:v1/invoke:{index}"),
                priority,
                telemetry,
                BackpressureCalibration::valid(),
            ));
            let static_loss = decision
                .evaluations
                .iter()
                .find(|evaluation| evaluation.action == BackpressureAction::FallbackStaticPolicy)
                .expect("static fallback evaluation should be retained")
                .expected_loss_score;

            assert!(decision.replay_matches());
            assert!(decision.selected_loss_score <= static_loss);
            controller_loss =
                controller_loss.saturating_add(decision.selected_loss_score.saturating_mul(count));
            static_policy_loss =
                static_policy_loss.saturating_add(static_loss.saturating_mul(count));
        }

        assert!(controller_loss < static_policy_loss);
    }

    #[test]
    fn fairness_context_scores_overrepresented_saturated_class() {
        let saturated = fairness_context(980, 860, 80, 20);
        let protected = fairness_context(980, 860, 20, 80);

        assert_eq!(saturated.imbalance_per_mille(), 360);
        assert!(saturated.pressure_per_mille() > protected.pressure_per_mille());
        assert!(saturated.fairness_score_per_mille() < protected.fairness_score_per_mille());
        assert_eq!(protected.shed_ratio_per_mille(), 800);
    }

    #[test]
    fn backpressure_controller_sheds_low_priority_overrepresented_class() {
        let controller = BackpressureController::default();
        let decision = controller.decide(
            BackpressureControllerInput::new(
                "fcp.host:request-response-saas:v1/write",
                RequestPriority::Low,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(920),
                    cpu_pressure_per_mille: Some(800),
                    useful_work_per_mille: Some(100),
                    ..BackpressureTelemetry::default()
                },
                BackpressureCalibration::valid(),
            )
            .with_fairness(fairness_context(980, 860, 80, 20)),
        );

        assert_eq!(decision.action, BackpressureAction::Shed);
        assert!(decision.rejects_work());
        assert!(decision.replay_matches());
        let fairness_term = decision
            .loss_terms
            .iter()
            .find(|term| term.kind == BackpressureLossTermKind::FairnessViolation)
            .expect("fairness term retained");
        assert!(
            fairness_term.value <= 5,
            "fairness-aware low-priority shedding should keep the fairness loss near zero"
        );
    }

    #[test]
    fn backpressure_controller_preserves_critical_under_fairness_pressure() {
        let controller = BackpressureController::default();
        let decision = controller.decide(
            BackpressureControllerInput::new(
                "fcp.host:request-response-saas:v1/emergency",
                RequestPriority::Critical,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(980),
                    cpu_pressure_per_mille: Some(980),
                    useful_work_per_mille: Some(1_000),
                    ..BackpressureTelemetry::default()
                },
                BackpressureCalibration::valid(),
            )
            .with_fairness(fairness_context(990, 900, 20, 0)),
        );

        assert!(
            !decision.rejects_work(),
            "critical traffic may warn or delay, but fairness pressure must not shed it"
        );
        assert_ne!(decision.action, BackpressureAction::Shed);
        assert_ne!(decision.action, BackpressureAction::CancelLowPriority);
        assert!(decision.replay_matches());
    }

    #[fcp_async_core::runtime::test]
    async fn execute_with_fairness_sheds_before_operation_body_runs() {
        let layer = ResilienceLayer::default();
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(920);
        let ran = Arc::new(AtomicU32::new(0));
        let ran_clone = Arc::clone(&ran);

        let result = layer
            .execute_with_fairness(
                &connector_id,
                RequestPriority::Low,
                "write",
                fairness_context(980, 860, 80, 20),
                async move {
                    ran_clone.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), &str>(())
                },
            )
            .await;

        assert!(matches!(result, Err(ResilienceError::LoadShed { .. })));
        assert_eq!(ran.load(Ordering::Relaxed), 0);
        assert_eq!(layer.metrics(&connector_id).load_shed, 1);
    }

    #[test]
    fn shed_ratio_zero_traffic_grants_no_starvation_credit() {
        // Regression: a fresh fairness window that has processed no traffic has,
        // by definition, shed nothing. `ratio_per_mille(0, 0)` returns its
        // zero-denominator sentinel of 1000, so without the zero-traffic guard
        // `shed_ratio_per_mille` would report full shedding and hand the empty
        // window a bogus 500-per-mille starvation credit that masks real
        // imbalance in `pressure_per_mille`.
        let ctx = BackpressureFairnessContext::new(BackpressureFairnessContextInput {
            connector_class: "request_response_saas".to_string(),
            zone_id: "z:work".to_string(),
            capability: "cap".to_string(),
            connector_class_pressure_per_mille: 0,
            zone_share_per_mille: 400,
            capability_share_per_mille: 0,
            target_share_per_mille: 0,
            admitted_count: 0,
            shed_count: 0,
        });

        assert_eq!(ctx.shed_ratio_per_mille(), 0);
        // imbalance = 400, saturation = 0, starvation_credit = 0 → pressure = 400.
        // (A phantom 1000 shed ratio would give a 500 credit → pressure = 0.)
        assert_eq!(ctx.pressure_per_mille(), 400);
    }

    #[test]
    fn fairness_load_shedding_evidence_record_is_jsonl_and_redacted() {
        let fairness = BackpressureFairnessContext::new(BackpressureFairnessContextInput {
            connector_class: "request_response_saas".to_string(),
            zone_id: "z:work".to_string(),
            capability: "secret-capability-token".to_string(),
            connector_class_pressure_per_mille: 980,
            zone_share_per_mille: 860,
            capability_share_per_mille: 840,
            target_share_per_mille: 500,
            admitted_count: 80,
            shed_count: 20,
        });
        let decision = BackpressureController::default().decide(
            BackpressureControllerInput::new(
                "fcp.host:request-response-saas:v1/write",
                RequestPriority::Low,
                BackpressureTelemetry {
                    queue_pressure_per_mille: Some(920),
                    cpu_pressure_per_mille: Some(800),
                    useful_work_per_mille: Some(100),
                    ..BackpressureTelemetry::default()
                },
                BackpressureCalibration::valid(),
            )
            .with_fairness(fairness.clone()),
        );

        let record = FairnessLoadSheddingEvidenceRecord::new(FairnessLoadSheddingEvidenceInput {
            scenario_id: "single_connector_saturation".to_string(),
            decision,
            fairness,
            queue_depth: 31,
            latency_samples_ms: vec![8, 13, 21, 34, 55],
            audit_receipt_id: Some("audit-receipt-k3zfl-13".to_string()),
            cleanup_result: "no_remote_state_created".to_string(),
            skip_reason: None,
        });
        let line = record.to_jsonl_line().expect("record serializes");

        assert!(line.contains("\"record_type\":\"fairness_load_shedding\""));
        assert!(line.contains("\"backpressure_action\":\"shed\""));
        assert!(line.contains("\"queue_depth\":31"));
        assert!(line.contains("\"fairness_score\""));
        assert!(line.contains("\"operator_guidance\""));
        assert!(line.contains("\"capability\":\"[REDACTED]\""));
        assert!(!line.contains("secret-capability-token"));
        assert!(record.decision_replay_matches);
        assert!(record.rejects_work);
        assert_eq!(
            record.latency_percentiles,
            Some(FairnessLatencyPercentiles {
                p50_ms: 21,
                p95_ms: 55,
                p99_ms: 55,
            })
        );
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_only_failure_predicate_trips_on_timeout() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            operation_timeout: Some(Duration::from_millis(25)),
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 1,
                open_duration: Duration::from_millis(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::TimeoutsOnly,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        let result = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                time::sleep(Duration::from_millis(60)).await;
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::TimedOut { .. })));
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);
        assert_eq!(layer.metrics(&connector_id).timeouts, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn probe_reservation_rolls_back_when_circuit_is_still_open() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 1,
                open_duration: Duration::from_millis(200),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            health: HealthRouterConfig {
                unhealthy_threshold: 1,
                recovery_success_threshold: 1,
                probe_interval: Duration::from_millis(100),
                ..HealthRouterConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        let failure = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Err::<(), _>("boom")
            })
            .await;
        assert!(matches!(failure, Err(ResilienceError::Inner("boom"))));
        assert!(matches!(
            layer.connector_health(&connector_id),
            ConnectorHealth::Unavailable { .. }
        ));

        time::sleep(Duration::from_millis(110)).await;
        let rejected = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(rejected, Err(ResilienceError::CircuitOpen { .. })));
        assert_eq!(layer.metrics(&connector_id).probe_requests, 0);

        time::sleep(Duration::from_millis(100)).await;
        let recovered = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(recovered.is_ok());
        assert_eq!(layer.metrics(&connector_id).probe_requests, 1);
    }

    #[test]
    fn merge_connector_health_prefers_worse_status() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::unavailable("down"),
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. RequestPriority shed factors
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn critical_shed_factor_is_zero() {
        assert_eq!(RequestPriority::Critical.shed_factor_per_mille(), 0);
    }

    #[test]
    fn high_shed_factor_is_300() {
        assert_eq!(RequestPriority::High.shed_factor_per_mille(), 300);
    }

    #[test]
    fn normal_shed_factor_is_700() {
        assert_eq!(RequestPriority::Normal.shed_factor_per_mille(), 700);
    }

    #[test]
    fn low_shed_factor_is_max_per_mille() {
        assert_eq!(RequestPriority::Low.shed_factor_per_mille(), MAX_PER_MILLE);
        assert_eq!(RequestPriority::Low.shed_factor_per_mille(), 1_000);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. ResilienceError Display
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_error_display_load_shed() {
        let err: ResilienceError<&str> = ResilienceError::LoadShed {
            load_per_mille: 950,
        };
        let msg = format!("{err}");
        assert!(msg.contains("950"));
        assert!(msg.contains("load shed"));
    }

    #[test]
    fn resilience_error_display_unhealthy() {
        let err: ResilienceError<&str> = ResilienceError::Unhealthy {
            reason: "too many failures".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("unhealthy"));
        assert!(msg.contains("too many failures"));
    }

    #[test]
    fn resilience_error_display_circuit_open() {
        let err: ResilienceError<&str> = ResilienceError::CircuitOpen {
            retry_after: Duration::from_secs(5),
        };
        let msg = format!("{err}");
        assert!(msg.contains("circuit breaker open"));
        assert!(msg.contains("5000ms"));
    }

    #[test]
    fn resilience_error_display_half_open_limited() {
        let err: ResilienceError<&str> = ResilienceError::HalfOpenLimited;
        let msg = format!("{err}");
        assert!(msg.contains("half-open"));
        assert!(msg.contains("in flight"));
    }

    #[test]
    fn resilience_error_display_bulkhead_full() {
        let err: ResilienceError<&str> = ResilienceError::BulkheadFull;
        let msg = format!("{err}");
        assert!(msg.contains("bulkhead queue is full"));
    }

    #[test]
    fn resilience_error_display_queue_timeout() {
        let err: ResilienceError<&str> = ResilienceError::QueueTimeout {
            timeout: Duration::from_millis(250),
        };
        let msg = format!("{err}");
        assert!(msg.contains("timed out"));
        assert!(msg.contains("250ms"));
    }

    #[test]
    fn resilience_error_display_timed_out() {
        let err: ResilienceError<&str> = ResilienceError::TimedOut {
            timeout: Duration::from_secs(1),
        };
        let msg = format!("{err}");
        assert!(msg.contains("operation timed out"));
        assert!(msg.contains("1000ms"));
    }

    #[test]
    fn resilience_error_display_inner() {
        let err: ResilienceError<&str> = ResilienceError::Inner("kaboom");
        let msg = format!("{err}");
        assert!(msg.contains("inner error"));
        assert!(msg.contains("kaboom"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. Config defaults
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_config_default_has_none_timeout() {
        let config = ResilienceConfig::default();
        assert!(config.operation_timeout.is_none());
    }

    #[test]
    fn circuit_breaker_config_default_values() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.open_duration, Duration::from_secs(5));
        assert_eq!(config.window_duration, Duration::from_secs(30));
        assert_eq!(config.failure_predicate, FailurePredicate::AnyError);
    }

    #[test]
    fn bulkhead_config_default_values() {
        let config = BulkheadConfig::default();
        assert_eq!(config.max_concurrent, 16);
        assert_eq!(config.max_queued, 32);
        assert_eq!(config.queue_timeout, Duration::from_millis(250));
    }

    #[test]
    fn health_router_config_default_values() {
        let config = HealthRouterConfig::default();
        assert_eq!(config.unhealthy_threshold, 3);
        assert_eq!(config.recovery_success_threshold, 2);
        assert_eq!(
            config.latency_degraded_threshold,
            Duration::from_millis(750)
        );
        assert_eq!(config.error_rate_degraded_threshold_per_mille, 500);
        assert_eq!(config.probe_interval, Duration::from_secs(5));
        assert_eq!(config.error_window, Duration::from_secs(30));
        assert_eq!(config.latency_alpha_per_mille, 200);
    }

    #[test]
    fn load_shed_config_default_values() {
        let config = LoadShedConfig::default();
        assert_eq!(config.shed_threshold_per_mille, 850);
        assert_eq!(config.full_shed_threshold_per_mille, 1_000);
        assert_eq!(
            config.sheddable_priorities,
            vec![RequestPriority::Low, RequestPriority::Normal]
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. FailurePredicate::matches
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn any_error_matches_failure() {
        assert!(FailurePredicate::AnyError.matches(OutcomeKind::Failure, Duration::ZERO));
    }

    #[test]
    fn any_error_matches_timed_out() {
        assert!(FailurePredicate::AnyError.matches(OutcomeKind::TimedOut, Duration::ZERO));
    }

    #[test]
    fn any_error_does_not_match_success() {
        assert!(!FailurePredicate::AnyError.matches(OutcomeKind::Success, Duration::ZERO));
    }

    #[test]
    fn timeouts_only_matches_timed_out() {
        assert!(FailurePredicate::TimeoutsOnly.matches(OutcomeKind::TimedOut, Duration::ZERO));
    }

    #[test]
    fn timeouts_only_does_not_match_failure() {
        assert!(!FailurePredicate::TimeoutsOnly.matches(OutcomeKind::Failure, Duration::ZERO));
    }

    #[test]
    fn slow_responses_matches_success_above_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        assert!(pred.matches(OutcomeKind::Success, Duration::from_millis(200)));
    }

    #[test]
    fn slow_responses_does_not_match_success_below_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(50)));
    }

    #[test]
    fn error_or_slow_responses_matches_all_failure_types() {
        let pred = FailurePredicate::ErrorOrSlowResponses {
            threshold: Duration::from_millis(100),
        };
        // Matches Failure
        assert!(pred.matches(OutcomeKind::Failure, Duration::ZERO));
        // Matches TimedOut
        assert!(pred.matches(OutcomeKind::TimedOut, Duration::ZERO));
        // Matches slow Success
        assert!(pred.matches(OutcomeKind::Success, Duration::from_millis(200)));
        // Does NOT match fast Success
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(50)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. CircuitBreaker state machine
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn new_breaker_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn closed_breaker_returns_regular_permit() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.before_call(), Ok(CircuitPermit::Regular));
    }

    #[test]
    fn failures_below_threshold_stay_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn failures_at_threshold_open_breaker() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let opened = cb.record_failure();
        assert!(opened);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn half_open_with_probe_in_flight_returns_half_open_limited() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure(); // Opens
        // Transition to HalfOpen via before_call (open_duration = 0)
        let first = cb.before_call();
        assert_eq!(first, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Second call should be rejected
        let second = cb.before_call();
        assert_eq!(second, Err(CircuitReject::HalfOpenLimited));
    }

    #[test]
    fn half_open_without_probe_gives_probe_permit() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let permit = cb.before_call();
        assert_eq!(permit, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn open_before_duration_returns_circuit_open_with_retry_after() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_mins(1),
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        let result = cb.before_call();
        assert!(
            matches!(result, Err(CircuitReject::Open { retry_after }) if retry_after > Duration::ZERO)
        );
    }

    #[test]
    fn open_after_duration_transitions_to_half_open() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // open_duration is zero so it should immediately transition
        let result = cb.before_call();
        assert_eq!(result, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn record_success_in_closed_resets_failures() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // After success, failures are reset, so two more should not open
        cb.record_failure();
        cb.record_failure();
        let opened = cb.record_failure();
        assert!(opened); // Now it should open (3 consecutive after reset)
    }

    #[test]
    fn record_success_in_half_open_increments_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // Transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        // Still HalfOpen (need 3 successes)
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_successes_reaching_threshold_closes_breaker() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // Transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn record_failure_in_half_open_reopens_immediately() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // Transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        let opened = cb.record_failure();
        assert!(opened);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn record_failure_on_already_open_circuit_is_noop() {
        // Regression: a request admitted while the breaker was still Closed can
        // fail *after* concurrent failures have already tripped the breaker. Such
        // a straggler must not re-run `open_circuit` — that would push
        // `opened_until` later than the configured `open_duration` (delaying the
        // first recovery probe) and double-count the circuit-opened transition.
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(30),
            ..CircuitBreakerConfig::default()
        });

        // First failure trips the breaker and reports the open transition.
        assert!(cb.record_failure());
        assert_eq!(cb.state(), CircuitState::Open);
        let opened_until = lock_unpoisoned(&cb.inner).opened_until;
        assert!(opened_until.is_some());

        // The straggler failure is a no-op: it reports `false` (no new
        // transition) and leaves `opened_until` untouched.
        assert!(!cb.record_failure());
        assert_eq!(cb.state(), CircuitState::Open);
        assert_eq!(lock_unpoisoned(&cb.inner).opened_until, opened_until);
    }

    #[test]
    fn cancel_inflight_probe_clears_probe_flag() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // HalfOpen, probe_in_flight = true
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Would normally reject
        assert_eq!(cb.before_call(), Err(CircuitReject::HalfOpenLimited));
        cb.cancel_inflight_probe();
        // Now probe should be allowed again
        assert_eq!(cb.before_call(), Ok(CircuitPermit::Probe));
    }

    #[test]
    fn cancel_inflight_probe_is_noop_in_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.cancel_inflight_probe(); // Should not panic or change state
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn open_without_opened_until_transitions_to_half_open() {
        // This tests the edge case where opened_until is None in Open State
        // We need to manually construct this scenario
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        {
            let mut inner = lock_unpoisoned(&cb.inner);
            inner.state = CircuitState::Open;
            inner.opened_until = None;
        }
        let result = cb.before_call();
        assert_eq!(result, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 6. Bulkhead
    // ─────────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn bulkhead_allows_up_to_max_concurrent() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 3,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        let p1 = bh.acquire().await;
        let p2 = bh.acquire().await;
        let p3 = bh.acquire().await;
        assert!(p1.is_ok());
        assert!(p2.is_ok());
        assert!(p3.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_zero_queue_allows_immediate_permit() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 0,
            queue_timeout: Duration::from_millis(10),
        });
        assert!(bh.acquire().await.is_ok());
    }

    #[test]
    fn bulkhead_pressure_per_mille_zero_when_idle() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 16,
            max_queued: 32,
            queue_timeout: Duration::from_millis(250),
        });
        assert_eq!(bh.pressure_per_mille(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_pressure_increases_under_load() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 4,
            max_queued: 32,
            queue_timeout: Duration::from_secs(1),
        });
        let _p1 = bh.acquire().await.unwrap();
        let _p2 = bh.acquire().await.unwrap();
        // 2 out of 4 = 500 per mille
        assert_eq!(bh.pressure_per_mille(), 500);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_queue_timeout_produces_error() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 1,
            queue_timeout: Duration::from_millis(10),
        });
        let _hold = bh.acquire().await.unwrap();
        let result = bh.acquire().await;
        assert!(matches!(
            result,
            Err(BulkheadAcquireError::QueueTimeout { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_tracks_queued_count() {
        let bh = Arc::new(Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 10,
            queue_timeout: Duration::from_secs(5),
        }));
        let _hold = bh.acquire().await.unwrap();
        // Spawn a waiter
        let bh2 = Arc::clone(&bh);
        let _waiter = task::spawn(async move {
            let _ = bh2.acquire().await;
        });
        // Give it a moment to enqueue
        time::sleep(Duration::from_millis(10)).await;
        assert!(bh.queued.load(Ordering::Relaxed) >= 1);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_queued_released_when_wait_future_cancelled() {
        // Regression: if the enclosing request future is cancelled (e.g. client
        // disconnect) while parked in the queue wait, the `queued` counter must
        // still be released. A bare post-await `fetch_sub` would be skipped on
        // cancellation, permanently over-counting `queued` until it pins at
        // `max_queued` and bricks the queue with phantom `QueueFull` rejections.
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 4,
            queue_timeout: Duration::from_secs(30),
        });
        // Hold the only permit so the next acquire must enqueue and park.
        let _hold = bh.acquire().await.unwrap();

        // Cancel the waiter by timing out the *enclosing* future well before the
        // 30s internal queue_timeout could ever fire. This drops the parked
        // acquire future mid-wait, which must run the queued drop guard.
        let cancelled = time::timeout(Duration::from_millis(20), bh.acquire()).await;
        assert!(cancelled.is_err());

        assert_eq!(bh.queued.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_pressure_active_vs_queue() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 10,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        // No load
        assert_eq!(bh.pressure_per_mille(), 0);
        // Half concurrent capacity
        let mut permits = Vec::with_capacity(10);
        for _ in 0..5 {
            permits.push(bh.acquire().await.unwrap());
        }
        assert_eq!(bh.pressure_per_mille(), 500);
        // Full concurrent capacity
        for _ in 0..5 {
            permits.push(bh.acquire().await.unwrap());
        }
        assert_eq!(bh.pressure_per_mille(), 1_000);
        assert_eq!(permits.len(), 10);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 7. HealthRouter
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_router_new_connector_routes_as_allow() {
        let router = HealthRouter::new(HealthRouterConfig::default());
        let cid = test_connector_id();
        let decision = router.can_route(&cid);
        assert_eq!(decision, RoutingDecision::Allow);
    }

    #[test]
    fn health_router_failures_below_threshold_keep_healthy() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 3,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "error");
        router.record_failure(&cid, "error");
        // 2 failures, threshold is 3 -> still degraded but not unavailable
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_failures_at_threshold_mark_unavailable() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 2,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "error");
        router.record_failure(&cid, "error");
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_record_success_resets_failure_count() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 3,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "err");
        router.record_failure(&cid, "err");
        router.record_success(&cid, Duration::from_millis(10));
        // After success, failures are reset; two more should not trip threshold
        router.record_failure(&cid, "err");
        router.record_failure(&cid, "err");
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_record_success_after_unavailable_starts_recovery() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            recovery_success_threshold: 3,
            probe_interval: Duration::ZERO,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // One success is not enough for recovery (need 3)
        router.record_success(&cid, Duration::from_millis(10));
        // Should still be unavailable (recovering)
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_degraded_routing_includes_reason() {
        let router = HealthRouter::new(HealthRouterConfig::default());
        let cid = test_connector_id();
        // Record one failure (below unhealthy threshold) to trigger degraded
        router.record_failure(&cid, "flaky");
        let decision = router.can_route(&cid);
        assert!(matches!(
            decision,
            RoutingDecision::AllowDegraded { reason } if !reason.is_empty()
        ));
    }

    #[test]
    fn health_router_probe_interval_respected_second_probe_rejected() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            probe_interval: Duration::from_mins(1),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        // First call after threshold is hit: recalculate_health sets last_probe_at,
        // so with a 60s interval the first can_route sees it was "just probed"
        // and rejects.
        let first = router.can_route(&cid);
        assert!(matches!(first, RoutingDecision::Reject { .. }));
        // Second call also rejected (still within 60s interval)
        let second = router.can_route(&cid);
        assert!(matches!(second, RoutingDecision::Reject { .. }));
    }

    #[test]
    fn health_router_probe_interval_respected_probe_after_interval_allowed() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            probe_interval: Duration::ZERO,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        // First probe
        let first = router.can_route(&cid);
        assert_eq!(first, RoutingDecision::AllowProbe);
        // With zero interval, second should also be allowed
        let second = router.can_route(&cid);
        assert_eq!(second, RoutingDecision::AllowProbe);
    }

    #[test]
    fn health_router_record_timeout_increments_failures() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_timeout(&cid, Duration::from_secs(5), Duration::from_secs(5));
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_degraded_from_high_error_rate() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 100, // High so we don't trip unavailable
            error_rate_degraded_threshold_per_mille: 500,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        // Record 10 failures, 0 successes -> 1000 per mille error rate
        for _ in 0..10 {
            router.record_failure(&cid, "err");
        }
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn health_router_degraded_from_high_latency() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 100,
            latency_degraded_threshold: Duration::from_millis(100),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        // Record successes with high latency
        for _ in 0..10 {
            router.record_success(&cid, Duration::from_millis(500));
        }
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn health_router_recovery_from_unavailable_requires_success_threshold() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            recovery_success_threshold: 2,
            probe_interval: Duration::ZERO,
            latency_degraded_threshold: Duration::from_mins(1),
            error_rate_degraded_threshold_per_mille: 999,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // First success — still recovering
        router.record_success(&cid, Duration::from_millis(1));
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // Second success — should recover
        router.record_success(&cid, Duration::from_millis(1));
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 8. ConformalSloPredictor
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn conformal_slo_predictor_routes_highest_budget_fitting_path() {
        let predictor = ConformalSloPredictor::new(ConformalSloConfig::new(990, 3));
        let zone = ZoneId::work();
        let calibration = vec![
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 120, 100, true, Some(10), 1),
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 130, 100, true, Some(10), 2),
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 125, 100, true, Some(10), 3),
            ConformalSloCalibrationSample::new(zone.clone(), "derp", 80, 100, true, Some(10), 4),
            ConformalSloCalibrationSample::new(zone.clone(), "derp", 90, 100, true, Some(10), 5),
            ConformalSloCalibrationSample::new(zone.clone(), "derp", 85, 100, true, Some(10), 6),
        ];
        let candidates = vec![
            ConformalSloRouteCandidate::new(zone.clone(), "direct", 70, 100, Some(10)),
            ConformalSloRouteCandidate::new(zone, "derp", 80, 100, Some(10)),
        ];

        let decision = predictor.choose_route(&candidates, &calibration);

        let selected = decision.selected.expect("route selected");
        assert_eq!(selected.path_id, "derp");
        assert!(selected.meets_slo_budget);
        assert!(
            decision
                .predictions
                .iter()
                .any(|prediction| prediction.path_id == "direct" && !prediction.meets_slo_budget)
        );
    }

    #[test]
    fn conformal_slo_predictor_refuses_budget_exhausted_route() {
        let predictor = ConformalSloPredictor::new(ConformalSloConfig::new(990, 3));
        let zone = ZoneId::work();
        let calibration = vec![
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 20, 100, true, Some(10), 1),
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 25, 100, true, Some(10), 2),
            ConformalSloCalibrationSample::new(zone.clone(), "direct", 30, 100, true, Some(10), 3),
        ];
        let candidates = vec![ConformalSloRouteCandidate::new(
            zone,
            "direct",
            25,
            100,
            Some(0),
        )];

        let decision = predictor.choose_route(&candidates, &calibration);

        assert!(decision.selected.is_none());
        assert!(decision.predictions[0].budget_exhausted);
        assert_eq!(decision.predictions[0].reason, "zone budget exhausted");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 9. LoadShedder
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn load_shedder_no_shedding_below_threshold() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 500,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Load is 400, below threshold of 500
        assert!(!shedder.should_shed(RequestPriority::Low, 400));
    }

    #[test]
    fn load_shedder_non_sheddable_priority_never_shed() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Even at max load, Critical is not in sheddable list
        assert!(!shedder.should_shed(RequestPriority::Critical, 1_000));
        assert!(!shedder.should_shed(RequestPriority::High, 1_000));
        assert!(!shedder.should_shed(RequestPriority::Normal, 1_000));
    }

    #[test]
    fn load_shedder_effective_load_takes_max_of_base_and_pressure() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(600);
        // pressure=400, base=600 -> max=600
        assert_eq!(shedder.effective_load_per_mille(400), 600);
        // pressure=800, base=600 -> max=800
        assert_eq!(shedder.effective_load_per_mille(800), 800);
    }

    #[test]
    fn load_shedder_effective_load_caps_at_1000() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(1_000);
        assert_eq!(shedder.effective_load_per_mille(2_000), 1_000);
    }

    #[test]
    fn load_shedder_full_shed_threshold_sheds_all_eligible() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 500,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // At full_shed threshold, all Low requests should be shed
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 1_000) {
                shed_count += 1;
            }
        }
        assert_eq!(shed_count, 1_000);
    }

    #[test]
    fn load_shedder_shedding_probability_scales_linearly() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // At load=500/1000, threshold=800, full=1000
        // base_probability = (500-800)*1000 / (1000-800) = -300*1000/200 = 0
        // final = 0 * 1000 / 1000 = 0
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 500) {
                shed_count += 1;
            }
        }
        assert!(
            (400..=600).contains(&shed_count),
            "expected ~500 sheds, got {shed_count}"
        );
    }

    #[test]
    fn load_shedder_set_base_load_caps_at_1000() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(5_000);
        assert_eq!(shedder.effective_load_per_mille(0), 1_000);
    }

    #[test]
    fn load_shedder_critical_never_shed_even_at_max_load() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![
                RequestPriority::Critical,
                RequestPriority::High,
                RequestPriority::Normal,
                RequestPriority::Low,
            ],
        });
        // Even though Critical is in the list, its shed_factor is 0
        // so final_probability = base * 0 / 1000 = 0
        for _ in 0..100 {
            assert!(!shedder.should_shed(RequestPriority::Critical, 1_000));
        }
    }

    #[test]
    fn load_shedder_mid_range_load_partially_sheds() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 800,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // load=900, threshold=800, full=1000
        // base_probability = (900-800)*1000 / (1000-800) = 100*1000/200 = 500
        // final = 500 * 1000 / 1000 = 500
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 900) {
                shed_count += 1;
            }
        }
        assert!(
            (400..=600).contains(&shed_count),
            "expected ~500 sheds, got {shed_count}"
        );
    }

    #[test]
    fn load_shedder_sequence_based_deterministic_pattern() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Same load and priority should produce deterministic pattern based on sequence
        let results: Vec<bool> = (0..10)
            .map(|_| shedder.should_shed(RequestPriority::Low, 500))
            .collect();
        // The sequence counter increments, so results are deterministic
        // Re-create shedder to verify same results
        let shedder2 = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        let results2: Vec<bool> = (0..10)
            .map(|_| shedder2.should_shed(RequestPriority::Low, 500))
            .collect();
        assert_eq!(results, results2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 9. ErrorWindow
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_window_new_has_zero_rate() {
        let window = ErrorWindow::new(Duration::from_secs(30));
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_all_failures_gives_1000() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        for _ in 0..10 {
            window.record_failure();
        }
        assert_eq!(window.error_rate_per_mille(), 1_000);
    }

    #[test]
    fn error_window_all_successes_gives_zero() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        for _ in 0..10 {
            window.record_success();
        }
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_mixed_gives_proportional_rate() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        // 3 failures out of 10 total = 300 per mille
        for _ in 0..7 {
            window.record_success();
        }
        for _ in 0..3 {
            window.record_failure();
        }
        assert_eq!(window.error_rate_per_mille(), 300);
    }

    #[test]
    fn error_window_rolls_after_duration() {
        // Create a window with zero duration so it rolls immediately
        let mut window = ErrorWindow::new(Duration::ZERO);
        window.record_failure();
        // After roll, counters should be reset, then the new failure is added
        // The window's roll_if_needed is called at the start of record_*
        // With Duration::ZERO, elapsed > duration is true, so it resets
        // Then records the failure, giving 1000 per mille
        window.record_failure();
        assert_eq!(window.error_rate_per_mille(), 1_000);
    }

    #[test]
    fn error_window_after_roll_counters_reset() {
        let mut window = ErrorWindow::new(Duration::ZERO);
        for _ in 0..10 {
            window.record_failure();
        }
        // With zero duration, each call rolls and resets.
        // Last record_failure: resets to 0, then adds 1 failure.
        // error_rate_per_mille = 1000 (1 failure, 0 successes)
        assert_eq!(window.error_rate_per_mille(), 1_000);
        // Now record a success, which will roll again
        window.record_success();
        // After roll: 0 failures, 0 successes, then adds 1 success = 0 rate
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_record_success_increments() {
        let mut window = ErrorWindow::new(Duration::from_mins(1));
        window.record_success();
        window.record_success();
        assert_eq!(window.successes, 2);
        assert_eq!(window.failures, 0);
    }

    #[test]
    fn error_window_record_failure_increments() {
        let mut window = ErrorWindow::new(Duration::from_mins(1));
        window.record_failure();
        window.record_failure();
        assert_eq!(window.failures, 2);
        assert_eq!(window.successes, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 10. LatencyEwma
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_ewma_new_has_none_value() {
        let ewma = LatencyEwma::new(200);
        assert!(ewma.value().is_none());
    }

    #[test]
    fn latency_ewma_first_sample_sets_exact_value() {
        let mut ewma = LatencyEwma::new(200);
        ewma.record(Duration::from_millis(100));
        assert_eq!(ewma.value(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn latency_ewma_second_sample_blends_with_alpha() {
        let mut ewma = LatencyEwma::new(500); // alpha = 500/1000 = 0.5
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 500 + 200 * 500) / 1000 = (50000 + 100000) / 1000 = 150
        assert_eq!(ewma.value(), Some(Duration::from_millis(150)));
    }

    #[test]
    fn latency_ewma_high_alpha_weights_new_sample() {
        let mut ewma = LatencyEwma::new(900); // alpha = 0.9
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 100 + 200 * 900) / 1000 = (10000 + 180000) / 1000 = 190
        assert_eq!(ewma.value(), Some(Duration::from_millis(190)));
    }

    #[test]
    fn latency_ewma_low_alpha_weights_old_sample() {
        let mut ewma = LatencyEwma::new(100); // alpha = 0.1
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 900 + 200 * 100) / 1000 = (90000 + 20000) / 1000 = 110
        assert_eq!(ewma.value(), Some(Duration::from_millis(110)));
    }

    #[test]
    fn latency_ewma_value_returns_duration() {
        let mut ewma = LatencyEwma::new(200);
        ewma.record(Duration::from_millis(42));
        let val = ewma.value().unwrap();
        assert_eq!(val, Duration::from_millis(42));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 11. Helper functions
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ratio_per_mille_zero_numerator() {
        assert_eq!(ratio_per_mille(0, 10), 0);
    }

    #[test]
    fn ratio_per_mille_half() {
        assert_eq!(ratio_per_mille(5, 10), 500);
    }

    #[test]
    fn ratio_per_mille_full() {
        assert_eq!(ratio_per_mille(10, 10), 1_000);
    }

    #[test]
    fn ratio_per_mille_over_capped() {
        assert_eq!(ratio_per_mille(15, 10), 1_000);
    }

    #[test]
    fn ratio_per_mille_zero_denominator() {
        assert_eq!(ratio_per_mille(0, 0), 1_000);
    }

    #[test]
    fn to_u16_zero() {
        assert_eq!(to_u16(0), 0);
    }

    #[test]
    fn to_u16_mid_value() {
        assert_eq!(to_u16(500), 500);
    }

    #[test]
    fn to_u16_max_u16() {
        assert_eq!(to_u16(65535), 65535);
    }

    #[test]
    fn to_u16_over_max_capped() {
        assert_eq!(to_u16(100_000), 65535);
    }

    #[test]
    fn health_severity_for_each_variant() {
        assert_eq!(
            health_severity(&ConnectorHealth::Healthy),
            HealthSeverity::Healthy
        );
        assert_eq!(
            health_severity(&ConnectorHealth::degraded("slow")),
            HealthSeverity::Degraded
        );
        assert_eq!(
            health_severity(&ConnectorHealth::unavailable("down")),
            HealthSeverity::Unavailable
        );
    }

    #[test]
    fn health_reason_for_each_variant() {
        assert_eq!(health_reason(&ConnectorHealth::Healthy), None);
        assert_eq!(
            health_reason(&ConnectorHealth::degraded("slow")),
            Some("slow")
        );
        assert_eq!(
            health_reason(&ConnectorHealth::unavailable("down")),
            Some("down")
        );
    }

    #[test]
    fn unavailable_since_returns_some_for_unavailable() {
        let now = Utc::now();
        let health = ConnectorHealth::Unavailable {
            reason: "test".to_string(),
            since: now,
        };
        assert_eq!(unavailable_since(&health), Some(now));
    }

    #[test]
    fn unavailable_since_returns_none_for_others() {
        assert_eq!(unavailable_since(&ConnectorHealth::Healthy), None);
        assert_eq!(unavailable_since(&ConnectorHealth::degraded("slow")), None);
    }

    #[test]
    fn earlier_since_picks_earlier_date() {
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now();
        assert_eq!(earlier_since(Some(t1), Some(t2)), Some(t1));
        assert_eq!(earlier_since(Some(t2), Some(t1)), Some(t1));
    }

    #[test]
    fn earlier_since_handles_none_variants() {
        let t1 = Utc::now();
        assert_eq!(earlier_since(Some(t1), None), Some(t1));
        assert_eq!(earlier_since(None, Some(t1)), Some(t1));
        assert_eq!(earlier_since(None, None), None);
    }

    #[test]
    fn combine_reason_strings_all_branches() {
        // left only
        assert_eq!(combine_reason_strings("left", ""), "left");
        // right only
        assert_eq!(combine_reason_strings("", "right"), "right");
        // both same
        assert_eq!(combine_reason_strings("same", "same"), "same");
        // both different
        assert_eq!(combine_reason_strings("a", "b"), "a; b");
        // both empty
        assert_eq!(combine_reason_strings("", ""), String::new());
    }

    #[test]
    fn merge_connector_health_healthy_plus_healthy() {
        let merged = merge_connector_health(ConnectorHealth::Healthy, ConnectorHealth::Healthy);
        assert!(matches!(merged, ConnectorHealth::Healthy));
    }

    #[test]
    fn merge_connector_health_degraded_plus_degraded_combines() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::degraded("flaky"),
        );
        match &merged {
            ConnectorHealth::Degraded { reason } => {
                assert!(reason.contains("slow"));
                assert!(reason.contains("flaky"));
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn merge_connector_health_unavailable_plus_healthy_picks_unavailable() {
        let merged = merge_connector_health(
            ConnectorHealth::unavailable("down"),
            ConnectorHealth::Healthy,
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn merge_connector_health_degraded_plus_unavailable_picks_unavailable() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::unavailable("down"),
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 12. ResilienceLayer integration
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn default_layer_creates_without_panic() {
        let _layer = ResilienceLayer::default();
    }

    #[test]
    fn ensure_connector_initializes_state() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        layer.ensure_connector(&cid);
        // Should have state now
        assert_eq!(layer.circuit_state(&cid), CircuitState::Closed);
        assert!(matches!(
            layer.connector_health(&cid),
            ConnectorHealth::Healthy
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn successful_execute_increments_successes_metric() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(42)
            })
            .await;
        assert!(result.is_ok());
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.successes, 1);
        assert_eq!(metrics.requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn failed_execute_increments_failures_metric() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Err::<(), _>("fail")
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::Inner("fail"))));
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.failures, 1);
        assert_eq!(metrics.requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn metrics_snapshot_reflects_all_counters() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        // 2 successes, 1 failure
        for _ in 0..2 {
            let _ = layer
                .execute(&cid, RequestPriority::Normal, "op", async {
                    Ok::<_, &str>(())
                })
                .await;
        }
        let _ = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Err::<(), _>("err")
            })
            .await;
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.requests, 3);
        assert_eq!(metrics.successes, 2);
        assert_eq!(metrics.failures, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn multiple_connectors_have_independent_state() {
        let layer = Arc::new(ResilienceLayer::new(ResilienceConfig {
            bulkhead: BulkheadConfig {
                max_concurrent: 1,
                max_queued: 0,
                queue_timeout: Duration::from_millis(10),
            },
            ..ResilienceConfig::default()
        }));
        let cid1 = ConnectorId::from_static("fcp.host:test1:v1");
        let cid2 = ConnectorId::from_static("fcp.host:test2:v1");
        let first = layer
            .execute(&cid1, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(())
            })
            .await;
        assert!(first.is_ok());
        let second = layer
            .execute(&cid2, RequestPriority::Normal, "op", async {
                Err::<(), _>("err")
            })
            .await;
        assert!(matches!(second, Err(ResilienceError::Inner("err"))));
        assert_eq!(layer.metrics(&cid1).successes, 1);
        assert_eq!(layer.metrics(&cid1).failures, 0);
        assert_eq!(layer.metrics(&cid2).successes, 0);
        assert_eq!(layer.metrics(&cid2).failures, 1);
    }

    #[test]
    fn half_open_limited_rejects_second_probe() {
        // Test at the CircuitBreaker level: when a probe is in-flight,
        // the next call returns HalfOpenLimited
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 10,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        // Trip the breaker
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // Transition to HalfOpen with first probe
        let first = cb.before_call();
        assert_eq!(first, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Second call should be HalfOpenLimited
        let second = cb.before_call();
        assert_eq!(second, Err(CircuitReject::HalfOpenLimited));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 13. ResilienceMetricsSnapshot
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_default_is_all_zeros() {
        let snapshot = ResilienceMetricsSnapshot::default();
        assert_eq!(snapshot.requests, 0);
        assert_eq!(snapshot.successes, 0);
        assert_eq!(snapshot.failures, 0);
        assert_eq!(snapshot.timeouts, 0);
        assert_eq!(snapshot.circuit_rejections, 0);
        assert_eq!(snapshot.circuit_opened, 0);
        assert_eq!(snapshot.bulkhead_rejections, 0);
        assert_eq!(snapshot.load_shed, 0);
        assert_eq!(snapshot.backpressure_delays, 0);
        assert_eq!(snapshot.backpressure_warnings, 0);
        assert_eq!(snapshot.probe_requests, 0);
    }

    #[test]
    fn metrics_snapshot_partial_eq_works() {
        let a = ResilienceMetricsSnapshot::default();
        let b = ResilienceMetricsSnapshot::default();
        assert_eq!(a, b);

        let c = ResilienceMetricsSnapshot {
            requests: 1,
            ..Default::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn metrics_snapshot_clone_preserves_all_fields() {
        let original = ResilienceMetricsSnapshot {
            requests: 10,
            successes: 8,
            failures: 1,
            timeouts: 1,
            circuit_rejections: 2,
            circuit_opened: 1,
            bulkhead_rejections: 3,
            load_shed: 4,
            backpressure_delays: 5,
            backpressure_warnings: 6,
            probe_requests: 7,
        };
        let cloned = original;
        assert_eq!(original.requests, cloned.requests);
        assert_eq!(original.successes, cloned.successes);
        assert_eq!(original.failures, cloned.failures);
        assert_eq!(original.timeouts, cloned.timeouts);
        assert_eq!(original.circuit_rejections, cloned.circuit_rejections);
        assert_eq!(original.circuit_opened, cloned.circuit_opened);
        assert_eq!(original.bulkhead_rejections, cloned.bulkhead_rejections);
        assert_eq!(original.load_shed, cloned.load_shed);
        assert_eq!(original.backpressure_delays, cloned.backpressure_delays);
        assert_eq!(original.backpressure_warnings, cloned.backpressure_warnings);
        assert_eq!(original.probe_requests, cloned.probe_requests);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 14. RequestPriority trait coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_priority_debug() {
        for p in [
            RequestPriority::Critical,
            RequestPriority::High,
            RequestPriority::Normal,
            RequestPriority::Low,
        ] {
            let dbg = format!("{p:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn request_priority_clone() {
        let a = RequestPriority::High;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn request_priority_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RequestPriority::Critical);
        set.insert(RequestPriority::High);
        set.insert(RequestPriority::Normal);
        set.insert(RequestPriority::Low);
        assert_eq!(set.len(), 4);
        // Duplicates should not increase size
        set.insert(RequestPriority::Critical);
        assert_eq!(set.len(), 4);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 15. ResilienceError trait coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_error_debug_all_variants() {
        let variants: Vec<ResilienceError<&str>> = vec![
            ResilienceError::LoadShed {
                load_per_mille: 900,
            },
            ResilienceError::Unhealthy {
                reason: "down".into(),
            },
            ResilienceError::CircuitOpen {
                retry_after: Duration::from_secs(10),
            },
            ResilienceError::HalfOpenLimited,
            ResilienceError::BulkheadFull,
            ResilienceError::QueueTimeout {
                timeout: Duration::from_millis(100),
            },
            ResilienceError::TimedOut {
                timeout: Duration::from_secs(5),
            },
            ResilienceError::Inner("test"),
        ];
        for err in &variants {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn resilience_error_eq_load_shed() {
        let a: ResilienceError<&str> = ResilienceError::LoadShed {
            load_per_mille: 800,
        };
        let b: ResilienceError<&str> = ResilienceError::LoadShed {
            load_per_mille: 800,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn resilience_error_ne_different_variants() {
        let a: ResilienceError<&str> = ResilienceError::BulkheadFull;
        let b: ResilienceError<&str> = ResilienceError::HalfOpenLimited;
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 16. CircuitState trait coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn circuit_state_debug() {
        for state in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let dbg = format!("{state:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn circuit_state_clone() {
        let a = CircuitState::HalfOpen;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 17. RoutingDecision trait coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn routing_decision_debug() {
        let decisions = vec![
            RoutingDecision::Allow,
            RoutingDecision::AllowDegraded {
                reason: "slow".into(),
            },
            RoutingDecision::AllowProbe,
            RoutingDecision::Reject {
                reason: "down".into(),
            },
        ];
        for d in &decisions {
            let dbg = format!("{d:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn routing_decision_eq() {
        assert_eq!(RoutingDecision::Allow, RoutingDecision::Allow);
        assert_eq!(RoutingDecision::AllowProbe, RoutingDecision::AllowProbe);
        assert_ne!(RoutingDecision::Allow, RoutingDecision::AllowProbe);
    }

    #[test]
    fn routing_decision_clone() {
        let a = RoutingDecision::AllowDegraded {
            reason: "slow".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 18. Config clone coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_config_clone() {
        let config = ResilienceConfig {
            operation_timeout: Some(Duration::from_secs(10)),
            ..ResilienceConfig::default()
        };
        let cloned = config.clone();
        assert_eq!(config.operation_timeout, cloned.operation_timeout);
        assert_eq!(
            config.circuit_breaker.failure_threshold,
            cloned.circuit_breaker.failure_threshold
        );
    }

    #[test]
    fn circuit_breaker_config_clone() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            ..CircuitBreakerConfig::default()
        };
        let cloned = config.clone();
        assert_eq!(config.failure_threshold, cloned.failure_threshold);
        assert_eq!(config.success_threshold, cloned.success_threshold);
    }

    #[test]
    fn bulkhead_config_clone() {
        let config = BulkheadConfig {
            max_concurrent: 8,
            max_queued: 16,
            queue_timeout: Duration::from_millis(500),
        };
        let cloned = config.clone();
        assert_eq!(config.max_concurrent, cloned.max_concurrent);
        assert_eq!(config.max_queued, cloned.max_queued);
        assert_eq!(config.queue_timeout, cloned.queue_timeout);
    }

    #[test]
    fn health_router_config_clone() {
        let config = HealthRouterConfig {
            unhealthy_threshold: 5,
            recovery_success_threshold: 3,
            ..HealthRouterConfig::default()
        };
        let cloned = config.clone();
        assert_eq!(config.unhealthy_threshold, cloned.unhealthy_threshold);
        assert_eq!(
            config.recovery_success_threshold,
            cloned.recovery_success_threshold
        );
    }

    #[test]
    fn load_shed_config_clone() {
        let config = LoadShedConfig {
            shed_threshold_per_mille: 600,
            full_shed_threshold_per_mille: 900,
            sheddable_priorities: vec![RequestPriority::Low],
        };
        let cloned = config.clone();
        assert_eq!(
            config.shed_threshold_per_mille,
            cloned.shed_threshold_per_mille
        );
        assert_eq!(config.sheddable_priorities, cloned.sheddable_priorities);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 19. Config debug coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_config_debug() {
        let config = ResilienceConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ResilienceConfig"));
    }

    #[test]
    fn circuit_breaker_config_debug() {
        let config = CircuitBreakerConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("CircuitBreakerConfig"));
    }

    #[test]
    fn bulkhead_config_debug() {
        let config = BulkheadConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("BulkheadConfig"));
    }

    #[test]
    fn health_router_config_debug() {
        let config = HealthRouterConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("HealthRouterConfig"));
    }

    #[test]
    fn load_shed_config_debug() {
        let config = LoadShedConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("LoadShedConfig"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 20. FailurePredicate edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn failure_predicate_slow_responses_exact_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        // Exact threshold should NOT match (only strictly above)
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(100)));
    }

    #[test]
    fn failure_predicate_slow_responses_does_not_match_failure() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        // SlowResponses only matches Success, not Failure
        assert!(!pred.matches(OutcomeKind::Failure, Duration::from_millis(200)));
    }

    #[test]
    fn failure_predicate_error_or_slow_exact_threshold() {
        let pred = FailurePredicate::ErrorOrSlowResponses {
            threshold: Duration::from_millis(100),
        };
        // At exact threshold, slow success should NOT match
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(100)));
        // But one ms over should
        assert!(pred.matches(OutcomeKind::Success, Duration::from_millis(101)));
    }

    #[test]
    fn failure_predicate_clone() {
        let a = FailurePredicate::AnyError;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn failure_predicate_debug() {
        let dbg = format!("{:?}", FailurePredicate::TimeoutsOnly);
        assert!(dbg.contains("TimeoutsOnly"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 21. HealthSeverity ordering
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_severity_ordering() {
        assert!(HealthSeverity::Healthy < HealthSeverity::Degraded);
        assert!(HealthSeverity::Degraded < HealthSeverity::Unavailable);
        assert!(HealthSeverity::Healthy < HealthSeverity::Unavailable);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 22. merge_connector_health edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn merge_connector_health_healthy_plus_degraded() {
        let merged =
            merge_connector_health(ConnectorHealth::Healthy, ConnectorHealth::degraded("lag"));
        assert!(matches!(merged, ConnectorHealth::Degraded { .. }));
        if let ConnectorHealth::Degraded { reason } = &merged {
            assert!(reason.contains("lag"));
        }
    }

    #[test]
    fn merge_connector_health_unavailable_plus_degraded() {
        let merged = merge_connector_health(
            ConnectorHealth::unavailable("crash"),
            ConnectorHealth::degraded("slow"),
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn merge_connector_health_both_unavailable_combines_reasons() {
        let merged = merge_connector_health(
            ConnectorHealth::unavailable("err1"),
            ConnectorHealth::unavailable("err2"),
        );
        if let ConnectorHealth::Unavailable { reason, .. } = &merged {
            assert!(reason.contains("err1"));
            assert!(reason.contains("err2"));
        } else {
            panic!("expected Unavailable");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 23. LatencyEwma edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_ewma_zero_alpha() {
        let mut ewma = LatencyEwma::new(0);
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(500));
        // alpha=0 means new sample has zero weight, retained=1000
        // new = (100 * 1000 + 500 * 0) / 1000 = 100
        assert_eq!(ewma.value(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn latency_ewma_max_alpha() {
        let mut ewma = LatencyEwma::new(1000);
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(500));
        // alpha=1000, retained=0
        // new = (100 * 0 + 500 * 1000) / 1000 = 500
        assert_eq!(ewma.value(), Some(Duration::from_millis(500)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 24. ratio_per_mille edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ratio_per_mille_one_of_one() {
        assert_eq!(ratio_per_mille(1, 1), 1_000);
    }

    #[test]
    fn ratio_per_mille_one_of_three() {
        assert_eq!(ratio_per_mille(1, 3), 333);
    }

    #[test]
    fn ratio_per_mille_two_of_three() {
        assert_eq!(ratio_per_mille(2, 3), 666);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 25. FailurePredicate additional edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn failure_predicate_slow_responses_does_not_match_timed_out() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        // SlowResponses only cares about Success outcomes above threshold
        assert!(!pred.matches(OutcomeKind::TimedOut, Duration::from_millis(200)));
    }

    #[test]
    fn failure_predicate_timeouts_only_does_not_match_success() {
        assert!(
            !FailurePredicate::TimeoutsOnly.matches(OutcomeKind::Success, Duration::from_secs(100))
        );
    }

    #[test]
    fn failure_predicate_slow_responses_zero_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::ZERO,
        };
        // Any non-zero latency success should match
        assert!(pred.matches(OutcomeKind::Success, Duration::from_nanos(1)));
        // Zero latency at zero threshold should NOT match (not strictly above)
        assert!(!pred.matches(OutcomeKind::Success, Duration::ZERO));
    }

    #[test]
    fn failure_predicate_error_or_slow_zero_latency_failure() {
        let pred = FailurePredicate::ErrorOrSlowResponses {
            threshold: Duration::from_secs(10),
        };
        // Failure with zero latency still matches (errors always match)
        assert!(pred.matches(OutcomeKind::Failure, Duration::ZERO));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 26. CircuitBreaker window expiry and edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn circuit_breaker_window_expiry_resets_failure_count() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            window_duration: Duration::ZERO, // window expires immediately
            ..CircuitBreakerConfig::default()
        });
        // First failure - will be counted then window expires on next call
        cb.record_failure();
        cb.record_failure();
        // With zero window, each record_failure resets the counter first
        // So we never accumulate 3 failures → stays closed
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_record_success_in_open_is_noop() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_mins(10),
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure(); // opens
        assert_eq!(cb.state(), CircuitState::Open);
        cb.record_success(); // should be noop in Open state
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_breaker_half_open_failure_resets_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure(); // open
        let _ = cb.before_call(); // half-open
        cb.record_success(); // 1 success
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Now fail - should reopen and reset success count
        let opened = cb.record_failure();
        assert!(opened);
        assert_eq!(cb.state(), CircuitState::Open);
        // Transition back to half-open
        let _ = cb.before_call();
        // Need all 3 successes again, not just 2
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_success_threshold_one() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // half-open
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_cancel_probe_in_open_is_noop() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_mins(10),
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        cb.cancel_inflight_probe(); // noop since state is Open, not HalfOpen
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 27. Bulkhead pressure edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn bulkhead_pressure_with_zero_max_queued() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 4,
            max_queued: 0,
            queue_timeout: Duration::from_millis(10),
        });
        // max_queued is 0, so queue_pressure denominator uses max(0,1)=1
        assert_eq!(bh.pressure_per_mille(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_full_concurrent_shows_max_pressure() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 2,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        let _p1 = bh.acquire().await.unwrap();
        let _p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.pressure_per_mille(), 1_000);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_permit_release_reduces_pressure() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 2,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        let p1 = bh.acquire().await.unwrap();
        let _p2 = bh.acquire().await.unwrap();
        assert_eq!(bh.pressure_per_mille(), 1_000);
        drop(p1);
        assert_eq!(bh.pressure_per_mille(), 500);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 28. LoadShedder edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn load_shedder_equal_shed_and_full_threshold() {
        // When shed_threshold == full_shed_threshold, full_threshold is clamped
        // to shed_threshold + 1
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 500,
            full_shed_threshold_per_mille: 500,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // At load=500 (equal to shed threshold), should start shedding
        // full_threshold = max(500, 501) = 501
        // base_prob = (500-500)*1000 / (501-500) = 0
        assert!(!shedder.should_shed(RequestPriority::Low, 500));
        // At load=501 (at adjusted full threshold)
        // base_prob = (501-500)*1000 / 1 = 1000
        assert!(shedder.should_shed(RequestPriority::Low, 501));
    }

    #[test]
    fn load_shedder_empty_sheddable_priorities() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![],
        });
        // No priority is in the sheddable list
        assert!(!shedder.should_shed(RequestPriority::Low, 1_000));
        assert!(!shedder.should_shed(RequestPriority::Normal, 1_000));
        assert!(!shedder.should_shed(RequestPriority::High, 1_000));
        assert!(!shedder.should_shed(RequestPriority::Critical, 1_000));
    }

    #[test]
    fn load_shedder_high_priority_partial_shedding() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::High, RequestPriority::Low],
        });
        // At full load, High has shed_factor 300/1000
        // final_probability = 1000 * 300 / 1000 = 300
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::High, 1_000) {
                shed_count += 1;
            }
        }
        assert!(
            (250..=350).contains(&shed_count),
            "expected ~300 sheds for High, got {shed_count}"
        );
    }

    #[test]
    fn load_shedder_base_zero_pressure_zero_no_shed() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        // base=0, pressure=0 → effective load = 0, below shed threshold
        assert_eq!(shedder.effective_load_per_mille(0), 0);
        assert!(!shedder.should_shed(RequestPriority::Low, 0));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 29. ErrorWindow edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_window_single_success() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        window.record_success();
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_single_failure() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        window.record_failure();
        assert_eq!(window.error_rate_per_mille(), 1_000);
    }

    #[test]
    fn error_window_half_error_rate() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        window.record_success();
        window.record_failure();
        assert_eq!(window.error_rate_per_mille(), 500);
    }

    #[test]
    fn error_window_one_of_four_failure_rate() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        for _ in 0..3 {
            window.record_success();
        }
        window.record_failure();
        assert_eq!(window.error_rate_per_mille(), 250);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 30. LatencyEwma edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_ewma_alpha_above_1000_clamped() {
        let mut ewma = LatencyEwma::new(2000); // alpha > MAX_PER_MILLE
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(500));
        // alpha clamped to 1000, retained=0
        // new = (100 * 0 + 500 * 1000) / 1000 = 500
        assert_eq!(ewma.value(), Some(Duration::from_millis(500)));
    }

    #[test]
    fn latency_ewma_multiple_samples_converge() {
        let mut ewma = LatencyEwma::new(500); // alpha = 0.5
        // Record many samples of same value → should converge to that value
        for _ in 0..20 {
            ewma.record(Duration::from_millis(200));
        }
        assert_eq!(ewma.value(), Some(Duration::from_millis(200)));
    }

    #[test]
    fn latency_ewma_zero_latency() {
        let mut ewma = LatencyEwma::new(500);
        ewma.record(Duration::ZERO);
        assert_eq!(ewma.value(), Some(Duration::ZERO));
    }

    #[test]
    fn latency_ewma_very_large_latency() {
        let mut ewma = LatencyEwma::new(500);
        ewma.record(Duration::from_hours(1));
        assert_eq!(ewma.value(), Some(Duration::from_hours(1)));
    }

    #[test]
    fn latency_ewma_alternating_high_low() {
        let mut ewma = LatencyEwma::new(500); // alpha = 0.5
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(300));
        // new = (100 * 500 + 300 * 500) / 1000 = 200
        assert_eq!(ewma.value(), Some(Duration::from_millis(200)));
        ewma.record(Duration::from_millis(100));
        // new = (200 * 500 + 100 * 500) / 1000 = 150
        assert_eq!(ewma.value(), Some(Duration::from_millis(150)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 31. merge_connector_health edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn merge_connector_health_degraded_plus_healthy_picks_degraded() {
        let merged =
            merge_connector_health(ConnectorHealth::degraded("slow"), ConnectorHealth::Healthy);
        assert!(matches!(merged, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn merge_connector_health_unavailable_plus_unavailable_uses_earlier_since() {
        let t1 = Utc::now() - chrono::Duration::hours(5);
        let t2 = Utc::now() - chrono::Duration::hours(1);
        let merged = merge_connector_health(
            ConnectorHealth::Unavailable {
                reason: "err1".into(),
                since: t1,
            },
            ConnectorHealth::Unavailable {
                reason: "err2".into(),
                since: t2,
            },
        );
        if let ConnectorHealth::Unavailable { since, .. } = merged {
            assert_eq!(since, t1);
        } else {
            panic!("expected Unavailable");
        }
    }

    #[test]
    fn merge_connector_health_same_degraded_reason_deduplicates() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::degraded("slow"),
        );
        if let ConnectorHealth::Degraded { reason } = &merged {
            // combine_reason_strings with same strings returns one copy
            assert_eq!(reason, "slow");
        } else {
            panic!("expected Degraded");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 32. HealthRouter deeper scenarios
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_router_unknown_connector_is_healthy() {
        let router = HealthRouter::new(HealthRouterConfig::default());
        let cid = ConnectorId::from_static("fcp.host:unknown:v1");
        assert!(matches!(router.health(&cid), ConnectorHealth::Healthy));
    }

    #[test]
    fn health_router_full_recovery_cycle() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 2,
            recovery_success_threshold: 2,
            probe_interval: Duration::ZERO,
            latency_degraded_threshold: Duration::from_mins(1),
            error_rate_degraded_threshold_per_mille: 999,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();

        // Start healthy
        assert!(matches!(router.health(&cid), ConnectorHealth::Healthy));

        // Two failures → unavailable
        router.record_failure(&cid, "down");
        router.record_failure(&cid, "down");
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));

        // First success → still recovering
        router.record_success(&cid, Duration::from_millis(1));
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));

        // Second success → fully recovered
        router.record_success(&cid, Duration::from_millis(1));
        let health = router.health(&cid);
        assert!(
            !matches!(health, ConnectorHealth::Unavailable { .. }),
            "expected healthy or degraded after recovery, got {health:?}"
        );
    }

    #[test]
    fn health_router_timeout_uses_max_of_timeout_and_latency() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 100,
            latency_degraded_threshold: Duration::from_millis(100),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        // Record timeout where timeout > latency → uses timeout value
        router.record_timeout(&cid, Duration::from_millis(500), Duration::from_millis(200));
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn health_router_many_successes_stay_healthy() {
        let router = HealthRouter::new(HealthRouterConfig {
            latency_degraded_threshold: Duration::from_secs(10),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        for _ in 0..20 {
            router.record_success(&cid, Duration::from_millis(5));
        }
        assert!(matches!(router.health(&cid), ConnectorHealth::Healthy));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 33. ResilienceLayer additional integration tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ensure_connector_is_idempotent() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        layer.ensure_connector(&cid);
        layer.ensure_connector(&cid);
        // Should not panic or create duplicate state
        assert_eq!(layer.circuit_state(&cid), CircuitState::Closed);
    }

    #[test]
    fn set_base_load_updates_shedder() {
        let layer = ResilienceLayer::default();
        layer.set_base_load_per_mille(750);
        // Verify via the load shedder's effective load
        let effective = layer.load_shedder.effective_load_per_mille(0);
        assert_eq!(effective, 750);
    }

    #[fcp_async_core::runtime::test]
    async fn execute_returns_inner_value_on_success() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Ok::<_, &str>("hello")
            })
            .await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[fcp_async_core::runtime::test]
    async fn execute_with_timeout_succeeds_within_limit() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            operation_timeout: Some(Duration::from_secs(5)),
            ..ResilienceConfig::default()
        });
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(42)
            })
            .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[fcp_async_core::runtime::test]
    async fn execute_timeout_records_metric() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            operation_timeout: Some(Duration::from_millis(10)),
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 100, // High to avoid circuit tripping
                ..CircuitBreakerConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                time::sleep(Duration::from_millis(50)).await;
                Ok::<_, &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::TimedOut { .. })));
        assert_eq!(layer.metrics(&cid).timeouts, 1);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 34. ratio_per_mille additional edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ratio_per_mille_large_values() {
        // Large numerator and denominator that could overflow u32
        let result = ratio_per_mille(usize::MAX, usize::MAX);
        assert_eq!(result, 1_000);
    }

    #[test]
    fn ratio_per_mille_numerator_zero_denominator_large() {
        assert_eq!(ratio_per_mille(0, usize::MAX), 0);
    }

    #[test]
    fn ratio_per_mille_small_fraction() {
        // 1/1000 = 1 per mille
        assert_eq!(ratio_per_mille(1, 1_000), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 35. to_u16 additional edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn to_u16_one() {
        assert_eq!(to_u16(1), 1);
    }

    #[test]
    fn to_u16_just_below_max() {
        assert_eq!(to_u16(65534), 65534);
    }

    #[test]
    fn to_u16_u32_max() {
        assert_eq!(to_u16(u32::MAX), u16::MAX);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 36. ResilienceError additional trait tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_error_is_std_error() {
        // Verify the std::error::Error impl compiles and works
        let err: ResilienceError<std::io::Error> = ResilienceError::BulkheadFull;
        let as_error: &dyn std::error::Error = &err;
        assert_eq!(as_error.to_string(), err.to_string());
    }

    #[test]
    fn resilience_error_display_all_variants_nonempty() {
        let variants: Vec<ResilienceError<&str>> = vec![
            ResilienceError::LoadShed { load_per_mille: 0 },
            ResilienceError::Unhealthy {
                reason: String::new(),
            },
            ResilienceError::CircuitOpen {
                retry_after: Duration::ZERO,
            },
            ResilienceError::HalfOpenLimited,
            ResilienceError::BulkheadFull,
            ResilienceError::QueueTimeout {
                timeout: Duration::ZERO,
            },
            ResilienceError::TimedOut {
                timeout: Duration::ZERO,
            },
            ResilienceError::Inner(""),
        ];
        for err in &variants {
            let msg = format!("{err}");
            assert!(!msg.is_empty(), "Display should produce non-empty string");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 37. combine_reason_strings edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn combine_reason_strings_long_strings() {
        let left = "a".repeat(100);
        let right = "b".repeat(100);
        let result = combine_reason_strings(&left, &right);
        assert!(result.contains(&left));
        assert!(result.contains(&right));
        assert!(result.contains("; "));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 38. earlier_since with equal dates
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn earlier_since_equal_dates_returns_either() {
        let t = Utc::now();
        let result = earlier_since(Some(t), Some(t));
        assert_eq!(result, Some(t));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 39. HealthSeverity edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_severity_clone() {
        let a = HealthSeverity::Degraded;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn health_severity_debug() {
        let dbg = format!("{:?}", HealthSeverity::Unavailable);
        assert!(dbg.contains("Unavailable"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 40. ResilienceLayer connector_state creates on demand
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_created_on_demand_for_unknown_connector() {
        let layer = ResilienceLayer::default();
        let cid = ConnectorId::from_static("fcp.host:brandnew:v1");
        // Accessing metrics for a connector that was never registered should
        // create the state on demand
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.requests, 0);
        assert_eq!(layer.circuit_state(&cid), CircuitState::Closed);
    }

    #[test]
    fn multiple_connectors_independent_circuit_state() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                ..CircuitBreakerConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let cid1 = ConnectorId::from_static("fcp.host:c1:v1");
        let cid2 = ConnectorId::from_static("fcp.host:c2:v1");

        // Trip circuit for cid1
        let state1 = layer.connector_state(&cid1);
        state1.circuit.record_failure();
        assert_eq!(layer.circuit_state(&cid1), CircuitState::Open);

        // cid2 should still be closed
        assert_eq!(layer.circuit_state(&cid2), CircuitState::Closed);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 41. ConnectorMetrics snapshot isolation
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_default_snapshot_all_zeros() {
        let metrics = ConnectorMetrics::default();
        let snap = metrics.snapshot();
        assert_eq!(snap, ResilienceMetricsSnapshot::default());
    }

    #[test]
    fn connector_metrics_snapshot_reflects_increments() {
        let metrics = ConnectorMetrics::default();
        metrics.requests.fetch_add(5, Ordering::Relaxed);
        metrics.successes.fetch_add(3, Ordering::Relaxed);
        metrics.failures.fetch_add(1, Ordering::Relaxed);
        metrics.timeouts.fetch_add(1, Ordering::Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.requests, 5);
        assert_eq!(snap.successes, 3);
        assert_eq!(snap.failures, 1);
        assert_eq!(snap.timeouts, 1);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 42. OutcomeKind coverage
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn outcome_kind_eq() {
        assert_eq!(OutcomeKind::Success, OutcomeKind::Success);
        assert_eq!(OutcomeKind::Failure, OutcomeKind::Failure);
        assert_eq!(OutcomeKind::TimedOut, OutcomeKind::TimedOut);
        assert_ne!(OutcomeKind::Success, OutcomeKind::Failure);
        assert_ne!(OutcomeKind::Failure, OutcomeKind::TimedOut);
    }

    #[test]
    fn outcome_kind_debug() {
        for kind in [
            OutcomeKind::Success,
            OutcomeKind::Failure,
            OutcomeKind::TimedOut,
        ] {
            let dbg = format!("{kind:?}");
            assert!(!dbg.is_empty());
        }
    }
}
