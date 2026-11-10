//! Retry controller with exponential backoff and jitter.
//!
//! Provides the core retry loop engine for transient failures.  Integrates
//! with the error taxonomy (`FcpErrorCode::retryable()`) and rate-limit
//! details (`retry_after_ms`) to decide whether, when, and how many times
//! to retry a failed operation.
//!
//! # Design principles
//!
//! 1. **Explicit eligibility** — only codes marked `retryable()` are retried;
//!    everything else fails immediately.
//! 2. **Bounded** — `max_retries` is always finite; exhaustion is terminal.
//! 3. **Jittered** — backoff includes ±25 % jitter to decorrelate burst retries.
//! 4. **Rate-limit aware** — if the error carries `retry_after_ms`, the
//!    controller uses the server-provided delay instead of computed backoff.
//! 5. **Idempotency-conscious** — callers must opt-in to retry for
//!    non-idempotent operations (the controller does not assume safety).

use fcp_kernel::FcpError;
use serde::Serialize;

use crate::error_taxonomy::{FcpErrorCode, StructuredError, structured_from_fcp_error};

// ── Policy ──────────────────────────────────────────────────────────────

/// Configuration for the retry controller.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retry).
    pub max_retries: u32,
    /// Base delay for the first retry (milliseconds).
    pub base_delay_ms: u64,
    /// Maximum computed delay (milliseconds). Server retry delays are not shortened.
    pub max_delay_ms: u64,
    /// Jitter factor (0.0 = no jitter, 0.25 = ±25%).
    pub jitter_factor: f64,
    /// Additional error categories (by tag) to retry on, beyond
    /// `FcpErrorCode::retryable()`.
    pub extra_retryable: Vec<String>,
    /// Error categories to *never* retry, even if `retryable()` is true.
    pub never_retry: Vec<String>,
    /// Whether to honor `retry_after_ms` from error details.
    pub honor_retry_after: bool,
}

impl RetryPolicy {
    /// Default policy: 3 retries, 1s base, 16s cap, ±25% jitter.
    pub fn default_policy() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1_000,
            max_delay_ms: 16_000,
            jitter_factor: 0.25,
            extra_retryable: Vec::new(),
            never_retry: Vec::new(),
            honor_retry_after: true,
        }
    }

    /// No-retry policy (for non-idempotent operations or `--no-retry` flag).
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            base_delay_ms: 0,
            max_delay_ms: 0,
            jitter_factor: 0.0,
            extra_retryable: Vec::new(),
            never_retry: Vec::new(),
            honor_retry_after: false,
        }
    }

    /// Builder: set max retries.
    #[must_use]
    pub const fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Builder: set base delay.
    #[must_use]
    pub const fn with_base_delay_ms(mut self, ms: u64) -> Self {
        self.base_delay_ms = ms;
        self
    }

    /// Builder: set max delay cap.
    #[must_use]
    pub const fn with_max_delay_ms(mut self, ms: u64) -> Self {
        self.max_delay_ms = ms;
        self
    }

    /// Builder: set jitter factor.
    #[must_use]
    pub fn with_jitter_factor(mut self, factor: f64) -> Self {
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// Whether a given error code is eligible for retry under this policy.
    pub fn is_retryable(&self, code: FcpErrorCode) -> bool {
        let cat_tag = code.category().tag();

        // Never-retry list takes precedence.
        if self.never_retry.iter().any(|t| t == cat_tag) {
            return false;
        }

        // Taxonomy retryable or extra-retryable list.
        code.retryable() || self.extra_retryable.iter().any(|t| t == cat_tag)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

// ── Backoff computation ─────────────────────────────────────────────────

/// Compute the delay for a given attempt number using exponential backoff
/// with jitter.
///
/// `attempt` is 1-based (first retry = 1).
/// Returns delay in milliseconds.
pub fn compute_backoff(policy: &RetryPolicy, attempt: u32, jitter_seed: u64) -> u64 {
    if attempt == 0 || policy.base_delay_ms == 0 || policy.max_delay_ms == 0 {
        return 0;
    }

    // Exponential: base * 2^(attempt-1), capped at max_delay.
    let exponent = (attempt - 1).min(20); // prevent overflow
    let raw = policy.base_delay_ms.saturating_mul(1u64 << exponent);
    let capped = raw.min(policy.max_delay_ms);

    // Apply jitter: delay * (1 ± jitter_factor).
    if policy.jitter_factor <= 0.0 {
        return capped;
    }

    // Deterministic jitter from seed (for testability).
    // Map seed to [-1.0, 1.0] range.
    let jitter_raw = ((jitter_seed % 10_001) as f64 / 5_000.0) - 1.0;
    let jitter_offset = (capped as f64) * policy.jitter_factor * jitter_raw;
    let jittered = (capped as f64 + jitter_offset).round() as u64;

    // Positive jitter must not widen the configured backoff ceiling.
    jittered.max(1).min(policy.max_delay_ms)
}

// ── Attempt record ──────────────────────────────────────────────────────

/// Record of a single retry attempt.
#[derive(Clone, Debug, Serialize)]
pub struct RetryAttempt {
    /// 1-based attempt number.
    pub attempt: u32,
    /// Error code that triggered the retry.
    pub error_code: String,
    /// Error category.
    pub error_category: String,
    /// Delay before this attempt (milliseconds).
    pub delay_ms: u64,
    /// Whether this delay came from `retry_after_ms` (server-directed).
    pub server_directed: bool,
}

// ── Retry decision ──────────────────────────────────────────────────────

/// The controller's decision for a failed attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RetryDecision {
    /// Retry after the specified delay.
    Retry {
        /// Delay in milliseconds.
        delay_ms: u64,
        /// 1-based attempt number for the upcoming retry.
        attempt: u32,
        /// Whether the delay is server-directed (from retry_after_ms).
        server_directed: bool,
    },
    /// Do not retry — the error is not retryable.
    NonRetryable {
        /// The error code.
        code: String,
        /// Why it's not retryable.
        reason: String,
    },
    /// Do not retry — max attempts exhausted.
    Exhausted {
        /// Total attempts made.
        attempts_made: u32,
        /// Max retries in the policy.
        max_retries: u32,
    },
}

impl RetryDecision {
    /// Whether this decision allows retry.
    pub const fn should_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    /// Get the delay in milliseconds, if retrying.
    pub const fn delay_ms(&self) -> u64 {
        match self {
            Self::Retry { delay_ms, .. } => *delay_ms,
            Self::NonRetryable { .. } | Self::Exhausted { .. } => 0,
        }
    }
}

// ── Retry outcome ───────────────────────────────────────────────────────

/// Final outcome after the retry loop completes.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RetryOutcome {
    /// The operation succeeded (possibly after retries).
    Success {
        /// Total attempts made (1 = no retries needed).
        total_attempts: u32,
        /// History of retry attempts (empty if first try succeeded).
        retry_history: Vec<RetryAttempt>,
    },
    /// The operation failed with a non-retryable error.
    NonRetryable {
        /// The final error.
        error: StructuredError,
        /// Total attempts before the non-retryable error.
        total_attempts: u32,
        /// History of retry attempts before the final error.
        retry_history: Vec<RetryAttempt>,
    },
    /// All retry attempts exhausted; the last error is final.
    Exhausted {
        /// The final error from the last attempt.
        error: StructuredError,
        /// Total attempts made (initial + retries).
        total_attempts: u32,
        /// Max retries in the policy.
        max_retries: u32,
        /// History of all retry attempts.
        retry_history: Vec<RetryAttempt>,
    },
}

impl RetryOutcome {
    /// Whether the operation ultimately succeeded.
    pub const fn succeeded(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Total attempts made.
    pub const fn total_attempts(&self) -> u32 {
        match self {
            Self::Success { total_attempts, .. }
            | Self::NonRetryable { total_attempts, .. }
            | Self::Exhausted { total_attempts, .. } => *total_attempts,
        }
    }

    /// The retry history.
    pub fn retry_history(&self) -> &[RetryAttempt] {
        match self {
            Self::Success { retry_history, .. }
            | Self::NonRetryable { retry_history, .. }
            | Self::Exhausted { retry_history, .. } => retry_history,
        }
    }
}

// ── Controller ──────────────────────────────────────────────────────────

/// Stateful retry controller that tracks attempts and computes decisions.
#[derive(Clone, Debug)]
pub struct RetryController {
    policy: RetryPolicy,
    attempts_made: u32,
    history: Vec<RetryAttempt>,
    jitter_seed: u64,
}

impl RetryController {
    /// Create a new controller with the given policy.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            attempts_made: 0,
            history: Vec::new(),
            jitter_seed: 42, // deterministic default for tests
        }
    }

    /// Set the jitter seed (for deterministic testing or random runtime).
    #[must_use]
    pub const fn with_jitter_seed(mut self, seed: u64) -> Self {
        self.jitter_seed = seed;
        self
    }

    /// Record a successful attempt.  Finalizes the outcome.
    pub fn record_success(&mut self) -> RetryOutcome {
        self.attempts_made += 1;
        RetryOutcome::Success {
            total_attempts: self.attempts_made,
            retry_history: self.history.clone(),
        }
    }

    /// Record a definitive connector failure without widening its retryability.
    ///
    /// The concrete FCP error is authoritative even if the broad taxonomy or
    /// `extra_retryable` policy allows its category. Callers must separately
    /// enforce operation idempotency, preserve effect identity, and refuse to
    /// call this for a transport failure with an unknown execution outcome.
    pub fn record_fcp_failure(&mut self, error: &FcpError) -> RetryDecision {
        let structured = structured_from_fcp_error(error);
        if !error.is_retryable() {
            self.attempts_made += 1;
            return RetryDecision::NonRetryable {
                code: structured.code.to_owned(),
                reason: "The connector failure does not permit retry".to_owned(),
            };
        }
        self.record_failure(&structured)
    }

    /// Record a failed attempt and get the retry decision.
    ///
    /// If the decision is `Retry`, the caller should wait the specified
    /// delay and then retry.  If `NonRetryable` or `Exhausted`, the caller
    /// should stop.
    pub fn record_failure(&mut self, error: &StructuredError) -> RetryDecision {
        self.attempts_made += 1;

        // Parse the error code.
        let code = FcpErrorCode::from_str(error.code);

        // Check retryability.
        match code {
            Some(c) if !self.policy.is_retryable(c) => {
                return RetryDecision::NonRetryable {
                    code: error.code.to_string(),
                    reason: format!("{} errors are not retryable", error.category),
                };
            }
            None if !error.retryable => {
                return RetryDecision::NonRetryable {
                    code: error.code.to_string(),
                    reason: "Unknown error code, not marked retryable".to_string(),
                };
            }
            _ => {}
        }

        // Check exhaustion.
        if self.attempts_made > self.policy.max_retries {
            return RetryDecision::Exhausted {
                attempts_made: self.attempts_made,
                max_retries: self.policy.max_retries,
            };
        }

        // Compute delay.
        let (delay_ms, server_directed) = self.compute_delay(error);

        // Record attempt.
        self.history.push(RetryAttempt {
            attempt: self.attempts_made,
            error_code: error.code.to_string(),
            error_category: error.category.to_string(),
            delay_ms,
            server_directed,
        });

        // Advance jitter seed for next attempt.
        self.jitter_seed = self
            .jitter_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);

        RetryDecision::Retry {
            delay_ms,
            attempt: self.attempts_made + 1,
            server_directed,
        }
    }

    /// Finalize as exhausted with the given error.
    pub fn finalize_exhausted(&self, error: StructuredError) -> RetryOutcome {
        RetryOutcome::Exhausted {
            error,
            total_attempts: self.attempts_made,
            max_retries: self.policy.max_retries,
            retry_history: self.history.clone(),
        }
    }

    /// Finalize as non-retryable with the given error.
    pub fn finalize_non_retryable(&self, error: StructuredError) -> RetryOutcome {
        RetryOutcome::NonRetryable {
            error,
            total_attempts: self.attempts_made,
            retry_history: self.history.clone(),
        }
    }

    /// Get the number of attempts made so far.
    pub const fn attempts_made(&self) -> u32 {
        self.attempts_made
    }

    /// Get the retry history.
    pub fn history(&self) -> &[RetryAttempt] {
        &self.history
    }

    fn compute_delay(&self, error: &StructuredError) -> (u64, bool) {
        // Check for server-directed retry_after_ms.
        if self.policy.honor_retry_after {
            if let Some(details) = &error.details {
                if let Some(retry_after) = details.get("retry_after_ms") {
                    if let Some(ms) = retry_after.as_u64() {
                        // Retry-After is a server-imposed lower bound. A caller
                        // whose remaining budget cannot cover it must stop;
                        // retrying sooner would violate provider admission.
                        return (ms, true);
                    }
                }
            }
        }

        // Compute exponential backoff with jitter.
        let delay = compute_backoff(&self.policy, self.attempts_made, self.jitter_seed);
        (delay, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_taxonomy::FcpErrorCode;

    fn make_retryable_error() -> StructuredError {
        StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited")
    }

    fn make_non_retryable_error() -> StructuredError {
        StructuredError::new(FcpErrorCode::FcpErrValidationFailed, "Invalid input")
    }

    fn make_rate_limited_with_retry_after(ms: u64) -> StructuredError {
        StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited")
            .with_details(serde_json::json!({ "retry_after_ms": ms }))
    }

    fn make_timeout_error() -> StructuredError {
        StructuredError::new(FcpErrorCode::FcpErrUpstreamTimeout, "Request timed out")
    }

    fn make_transport_error() -> StructuredError {
        StructuredError::new(FcpErrorCode::FcpErrTransportFailed, "Connection reset")
    }

    // ── RetryPolicy ──────────────────────────────────────────────────

    #[test]
    fn default_policy_has_3_retries() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
    }

    #[test]
    fn default_policy_has_1s_base_delay() {
        let p = RetryPolicy::default();
        assert_eq!(p.base_delay_ms, 1_000);
    }

    #[test]
    fn default_policy_has_16s_max_delay() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_delay_ms, 16_000);
    }

    #[test]
    fn default_policy_has_25_percent_jitter() {
        let p = RetryPolicy::default();
        assert!((p.jitter_factor - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn default_policy_honors_retry_after() {
        let p = RetryPolicy::default();
        assert!(p.honor_retry_after);
    }

    #[test]
    fn no_retry_policy_has_zero_retries() {
        let p = RetryPolicy::no_retry();
        assert_eq!(p.max_retries, 0);
    }

    #[test]
    fn no_retry_policy_does_not_honor_retry_after() {
        let p = RetryPolicy::no_retry();
        assert!(!p.honor_retry_after);
    }

    #[test]
    fn builder_sets_max_retries() {
        let p = RetryPolicy::default().with_max_retries(5);
        assert_eq!(p.max_retries, 5);
    }

    #[test]
    fn builder_sets_base_delay() {
        let p = RetryPolicy::default().with_base_delay_ms(500);
        assert_eq!(p.base_delay_ms, 500);
    }

    #[test]
    fn builder_sets_max_delay() {
        let p = RetryPolicy::default().with_max_delay_ms(30_000);
        assert_eq!(p.max_delay_ms, 30_000);
    }

    #[test]
    fn builder_clamps_jitter_factor() {
        let p = RetryPolicy::default().with_jitter_factor(2.0);
        assert!((p.jitter_factor - 1.0).abs() < f64::EPSILON);
        let p = RetryPolicy::default().with_jitter_factor(-0.5);
        assert!(p.jitter_factor.abs() < f64::EPSILON);
    }

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrRateLimited));
    }

    #[test]
    fn timeout_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrUpstreamTimeout));
    }

    #[test]
    fn transport_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrTransportFailed));
    }

    #[test]
    fn validation_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrValidationFailed));
    }

    #[test]
    fn auth_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrUnauthorized));
    }

    #[test]
    fn policy_denied_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrPolicyDenied));
    }

    #[test]
    fn never_retry_overrides_taxonomy() {
        let p = RetryPolicy {
            never_retry: vec!["rate_limit".to_string()],
            ..RetryPolicy::default()
        };
        assert!(!p.is_retryable(FcpErrorCode::FcpErrRateLimited));
    }

    #[test]
    fn extra_retryable_adds_categories() {
        let p = RetryPolicy {
            extra_retryable: vec!["auth".to_string()],
            ..RetryPolicy::default()
        };
        assert!(p.is_retryable(FcpErrorCode::FcpErrUnauthorized));
    }

    #[test]
    fn never_retry_takes_precedence_over_extra() {
        let p = RetryPolicy {
            extra_retryable: vec!["auth".to_string()],
            never_retry: vec!["auth".to_string()],
            ..RetryPolicy::default()
        };
        assert!(!p.is_retryable(FcpErrorCode::FcpErrUnauthorized));
    }

    // ── compute_backoff ──────────────────────────────────────────────

    #[test]
    fn backoff_attempt_zero_returns_zero() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        assert_eq!(compute_backoff(&p, 0, 0), 0);
    }

    #[test]
    fn backoff_attempt_one_returns_base_delay() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        assert_eq!(compute_backoff(&p, 1, 0), 1_000);
    }

    #[test]
    fn backoff_attempt_two_returns_2x_base() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        assert_eq!(compute_backoff(&p, 2, 0), 2_000);
    }

    #[test]
    fn backoff_attempt_three_returns_4x_base() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        assert_eq!(compute_backoff(&p, 3, 0), 4_000);
    }

    #[test]
    fn backoff_is_capped_at_max_delay() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_max_delay_ms(3_000);
        assert_eq!(compute_backoff(&p, 3, 0), 3_000);
        assert_eq!(compute_backoff(&p, 10, 0), 3_000);
    }

    #[test]
    fn backoff_with_jitter_stays_within_bounds() {
        let p = RetryPolicy::default().with_jitter_factor(0.25);
        for seed in 0..100 {
            let delay = compute_backoff(&p, 1, seed);
            // 1000 ± 25% = 750..1250
            assert!(delay >= 750, "delay {} too low for seed {}", delay, seed);
            assert!(delay <= 1250, "delay {} too high for seed {}", delay, seed);
        }
    }

    #[test]
    fn backoff_zero_base_delay_returns_zero() {
        let p = RetryPolicy::default().with_base_delay_ms(0);
        assert_eq!(compute_backoff(&p, 1, 42), 0);
    }

    #[test]
    fn backoff_large_attempt_does_not_overflow() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        let delay = compute_backoff(&p, 100, 0);
        assert_eq!(delay, p.max_delay_ms);
    }

    #[test]
    fn backoff_jitter_is_deterministic_for_same_seed() {
        let p = RetryPolicy::default();
        let d1 = compute_backoff(&p, 1, 12345);
        let d2 = compute_backoff(&p, 1, 12345);
        assert_eq!(d1, d2);
    }

    #[test]
    fn backoff_jitter_varies_with_seed() {
        let p = RetryPolicy::default();
        let d1 = compute_backoff(&p, 1, 0);
        let d2 = compute_backoff(&p, 1, 5000);
        // Different seeds should (usually) produce different delays.
        // With 25% jitter range, the probability of collision is tiny.
        assert_ne!(d1, d2);
    }

    // ── RetryController ──────────────────────────────────────────────

    #[test]
    fn controller_initial_attempts_is_zero() {
        let ctrl = RetryController::new(RetryPolicy::default());
        assert_eq!(ctrl.attempts_made(), 0);
    }

    #[test]
    fn controller_success_on_first_try() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let outcome = ctrl.record_success();
        assert!(outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 1);
        assert!(outcome.retry_history().is_empty());
    }

    #[test]
    fn controller_retry_on_retryable_error() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();
        let decision = ctrl.record_failure(&err);
        assert!(decision.should_retry());
    }

    #[test]
    fn controller_no_retry_on_non_retryable_error() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_non_retryable_error();
        let decision = ctrl.record_failure(&err);
        assert!(!decision.should_retry());
        assert!(matches!(decision, RetryDecision::NonRetryable { .. }));
    }

    #[test]
    fn controller_fcp_failure_cannot_promote_explicit_non_retryable_errors() {
        let failures = [
            FcpError::External {
                service: "provider".to_owned(),
                message: "Definitive rejection".to_owned(),
                status_code: Some(503),
                retryable: false,
                retry_after: Some(std::time::Duration::from_secs(1)),
            },
            FcpError::HealthCheckFailed {
                reason: "Manual repair required".to_owned(),
            },
            FcpError::Unauthorized {
                code: 401,
                message: "Credential rejected".to_owned(),
            },
        ];

        for error in failures {
            assert!(!error.is_retryable());
            let category = structured_from_fcp_error(&error).category.to_owned();
            let mut ctrl = RetryController::new(RetryPolicy {
                extra_retryable: vec![category],
                ..RetryPolicy::default()
            });
            assert!(matches!(
                ctrl.record_fcp_failure(&error),
                RetryDecision::NonRetryable { .. }
            ));
            assert_eq!(ctrl.attempts_made(), 1);
            assert!(ctrl.history().is_empty());
        }
    }

    #[test]
    fn controller_fcp_failure_preserves_provider_delay_and_retry_bound() {
        let error = FcpError::External {
            service: "provider".to_owned(),
            message: "Retry after maintenance".to_owned(),
            status_code: Some(503),
            retryable: true,
            retry_after: Some(std::time::Duration::from_millis(45_001)),
        };
        let mut ctrl = RetryController::new(
            RetryPolicy::default()
                .with_max_retries(1)
                .with_max_delay_ms(100),
        );
        assert_eq!(
            ctrl.record_fcp_failure(&error),
            RetryDecision::Retry {
                delay_ms: 45_001,
                attempt: 2,
                server_directed: true,
            }
        );
        assert_eq!(ctrl.history().len(), 1);
        assert_eq!(ctrl.history()[0].delay_ms, 45_001);
        assert!(ctrl.history()[0].server_directed);
        assert_eq!(
            ctrl.record_fcp_failure(&error),
            RetryDecision::Exhausted {
                attempts_made: 2,
                max_retries: 1,
            }
        );
        assert_eq!(ctrl.history().len(), 1);
    }

    #[test]
    fn controller_fcp_failure_respects_never_retry_policy() {
        let error = FcpError::RateLimited {
            retry_after_ms: 10,
            violation: None,
        };
        let category = structured_from_fcp_error(&error).category.to_owned();
        let mut ctrl = RetryController::new(RetryPolicy {
            never_retry: vec![category],
            ..RetryPolicy::default()
        });
        assert!(matches!(
            ctrl.record_fcp_failure(&error),
            RetryDecision::NonRetryable { .. }
        ));
        assert_eq!(ctrl.attempts_made(), 1);
        assert!(ctrl.history().is_empty());
    }

    #[test]
    fn controller_exhaustion_after_max_retries() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(2));
        let err = make_retryable_error();

        // First failure: retry
        let d1 = ctrl.record_failure(&err);
        assert!(d1.should_retry());

        // Second failure: retry
        let d2 = ctrl.record_failure(&err);
        assert!(d2.should_retry());

        // Third failure: exhausted (2 retries used)
        let d3 = ctrl.record_failure(&err);
        assert!(!d3.should_retry());
        assert!(matches!(d3, RetryDecision::Exhausted { .. }));
    }

    #[test]
    fn controller_success_after_retries() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();

        let d = ctrl.record_failure(&err);
        assert!(d.should_retry());

        let outcome = ctrl.record_success();
        assert!(outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 2);
        assert_eq!(outcome.retry_history().len(), 1);
    }

    #[test]
    fn controller_retry_history_records_error_codes() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();

        ctrl.record_failure(&err);
        let outcome = ctrl.record_success();

        let hist = outcome.retry_history();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].error_code, "FCP_ERR_RATE_LIMITED");
        assert_eq!(hist[0].error_category, "rate_limit");
        assert_eq!(hist[0].attempt, 1);
    }

    #[test]
    fn controller_honors_retry_after_ms() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_rate_limited_with_retry_after(5_000);

        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                delay_ms,
                server_directed,
                ..
            } => {
                assert_eq!(delay_ms, 5_000);
                assert!(server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_retry_after_is_not_shortened_by_max_delay() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_delay_ms(3_000));
        let err = make_rate_limited_with_retry_after(10_000);

        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry { delay_ms, .. } => {
                assert_eq!(delay_ms, 10_000);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_ignores_retry_after_when_disabled() {
        let mut ctrl = RetryController::new(RetryPolicy {
            honor_retry_after: false,
            ..RetryPolicy::default()
        });
        let err = make_rate_limited_with_retry_after(5_000);

        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                delay_ms,
                server_directed,
                ..
            } => {
                assert_ne!(delay_ms, 5_000);
                assert!(!server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_no_retry_policy_rejects_immediately() {
        let mut ctrl = RetryController::new(RetryPolicy::no_retry());
        let err = make_retryable_error();

        let decision = ctrl.record_failure(&err);
        assert!(!decision.should_retry());
        assert!(matches!(decision, RetryDecision::Exhausted { .. }));
    }

    #[test]
    fn controller_different_error_types_in_sequence() {
        let mut ctrl = RetryController::new(RetryPolicy::default());

        let timeout = make_timeout_error();
        let d1 = ctrl.record_failure(&timeout);
        assert!(d1.should_retry());

        let transport = make_transport_error();
        let d2 = ctrl.record_failure(&transport);
        assert!(d2.should_retry());

        let outcome = ctrl.record_success();
        assert!(outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 3);
        assert_eq!(outcome.retry_history().len(), 2);
        assert_eq!(
            outcome.retry_history()[0].error_code,
            "FCP_ERR_UPSTREAM_TIMEOUT"
        );
        assert_eq!(
            outcome.retry_history()[1].error_code,
            "FCP_ERR_TRANSPORT_FAILED"
        );
    }

    #[test]
    fn controller_non_retryable_after_retryable_stops() {
        let mut ctrl = RetryController::new(RetryPolicy::default());

        let retryable = make_retryable_error();
        let d1 = ctrl.record_failure(&retryable);
        assert!(d1.should_retry());

        let non_retryable = make_non_retryable_error();
        let d2 = ctrl.record_failure(&non_retryable);
        assert!(!d2.should_retry());
        assert!(matches!(d2, RetryDecision::NonRetryable { .. }));
    }

    #[test]
    fn controller_backoff_increases_across_attempts() {
        let policy = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_max_retries(5);
        let mut ctrl = RetryController::new(policy);
        let err = make_retryable_error();

        let mut delays = Vec::new();
        for _ in 0..4 {
            match ctrl.record_failure(&err) {
                RetryDecision::Retry { delay_ms, .. } => delays.push(delay_ms),
                other => panic!("Expected Retry, got {:?}", other),
            }
        }

        // Exponential: 1000, 2000, 4000, 8000
        assert_eq!(delays, vec![1_000, 2_000, 4_000, 8_000]);
    }

    // ── RetryDecision ────────────────────────────────────────────────

    #[test]
    fn retry_decision_delay_ms_returns_delay() {
        let d = RetryDecision::Retry {
            delay_ms: 1000,
            attempt: 2,
            server_directed: false,
        };
        assert_eq!(d.delay_ms(), 1000);
    }

    #[test]
    fn non_retryable_decision_delay_is_zero() {
        let d = RetryDecision::NonRetryable {
            code: "FCP_ERR_VALIDATION_FAILED".to_string(),
            reason: "Not retryable".to_string(),
        };
        assert_eq!(d.delay_ms(), 0);
    }

    #[test]
    fn exhausted_decision_delay_is_zero() {
        let d = RetryDecision::Exhausted {
            attempts_made: 4,
            max_retries: 3,
        };
        assert_eq!(d.delay_ms(), 0);
    }

    // ── RetryOutcome ─────────────────────────────────────────────────

    #[test]
    fn retry_outcome_success_succeeded() {
        let o = RetryOutcome::Success {
            total_attempts: 1,
            retry_history: vec![],
        };
        assert!(o.succeeded());
    }

    #[test]
    fn retry_outcome_non_retryable_not_succeeded() {
        let o = RetryOutcome::NonRetryable {
            error: make_non_retryable_error(),
            total_attempts: 1,
            retry_history: vec![],
        };
        assert!(!o.succeeded());
    }

    #[test]
    fn retry_outcome_exhausted_not_succeeded() {
        let o = RetryOutcome::Exhausted {
            error: make_retryable_error(),
            total_attempts: 4,
            max_retries: 3,
            retry_history: vec![],
        };
        assert!(!o.succeeded());
    }

    #[test]
    fn retry_outcome_total_attempts_matches() {
        let o = RetryOutcome::Success {
            total_attempts: 3,
            retry_history: vec![],
        };
        assert_eq!(o.total_attempts(), 3);
    }

    // ── Serialization ────────────────────────────────────────────────

    #[test]
    fn retry_decision_serializes_to_json() {
        let d = RetryDecision::Retry {
            delay_ms: 1000,
            attempt: 2,
            server_directed: false,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "retry");
        assert_eq!(json["delay_ms"], 1000);
        assert_eq!(json["attempt"], 2);
    }

    #[test]
    fn non_retryable_decision_serializes() {
        let d = RetryDecision::NonRetryable {
            code: "FCP_ERR_VALIDATION_FAILED".to_string(),
            reason: "Not retryable".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "non_retryable");
    }

    #[test]
    fn exhausted_decision_serializes() {
        let d = RetryDecision::Exhausted {
            attempts_made: 4,
            max_retries: 3,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "exhausted");
        assert_eq!(json["attempts_made"], 4);
    }

    #[test]
    fn retry_outcome_success_serializes() {
        let o = RetryOutcome::Success {
            total_attempts: 2,
            retry_history: vec![RetryAttempt {
                attempt: 1,
                error_code: "FCP_ERR_RATE_LIMITED".to_string(),
                error_category: "rate_limit".to_string(),
                delay_ms: 1000,
                server_directed: false,
            }],
        };
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["outcome"], "success");
        assert_eq!(json["total_attempts"], 2);
        assert_eq!(json["retry_history"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn retry_outcome_exhausted_serializes() {
        let o = RetryOutcome::Exhausted {
            error: make_retryable_error(),
            total_attempts: 4,
            max_retries: 3,
            retry_history: vec![],
        };
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["outcome"], "exhausted");
        assert_eq!(json["max_retries"], 3);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn controller_with_max_retries_one() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(1));
        let err = make_retryable_error();

        let d1 = ctrl.record_failure(&err);
        assert!(d1.should_retry());

        let d2 = ctrl.record_failure(&err);
        assert!(!d2.should_retry());
    }

    #[test]
    fn controller_jitter_seed_affects_delay() {
        let policy = RetryPolicy::default().with_max_retries(1);
        let mut ctrl1 = RetryController::new(policy.clone()).with_jitter_seed(100);
        let mut ctrl2 = RetryController::new(policy).with_jitter_seed(9999);
        let err = make_retryable_error();

        let d1 = ctrl1.record_failure(&err);
        let d2 = ctrl2.record_failure(&err);

        // Different seeds should produce different delays (with high probability).
        match (d1, d2) {
            (
                RetryDecision::Retry { delay_ms: ms1, .. },
                RetryDecision::Retry { delay_ms: ms2, .. },
            ) => {
                assert_ne!(ms1, ms2);
            }
            _ => panic!("Expected both to be Retry"),
        }
    }

    #[test]
    fn finalize_exhausted_preserves_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(2));
        let err = make_retryable_error();

        ctrl.record_failure(&err);
        ctrl.record_failure(&err);
        ctrl.record_failure(&err); // exhausted

        let outcome = ctrl.finalize_exhausted(err);
        assert!(!outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 3);
        assert_eq!(outcome.retry_history().len(), 2); // 2 retries recorded
    }

    #[test]
    fn finalize_non_retryable_preserves_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let retryable = make_retryable_error();
        let non_retryable = make_non_retryable_error();

        ctrl.record_failure(&retryable);
        ctrl.record_failure(&non_retryable);

        let outcome = ctrl.finalize_non_retryable(non_retryable);
        assert!(!outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 2);
        assert_eq!(outcome.retry_history().len(), 1); // only the retryable one was recorded as retry
    }

    #[test]
    fn all_retryable_codes_are_accepted_by_default_policy() {
        use crate::error_taxonomy::ALL_CODES;
        let policy = RetryPolicy::default();
        for code in ALL_CODES {
            let expected = code.retryable();
            let actual = policy.is_retryable(*code);
            assert_eq!(actual, expected, "Mismatch for {:?}", code);
        }
    }

    #[test]
    fn retry_attempt_serializes_completely() {
        let attempt = RetryAttempt {
            attempt: 1,
            error_code: "FCP_ERR_RATE_LIMITED".to_string(),
            error_category: "rate_limit".to_string(),
            delay_ms: 1500,
            server_directed: true,
        };
        let json = serde_json::to_value(&attempt).unwrap();
        assert_eq!(json["attempt"], 1);
        assert_eq!(json["error_code"], "FCP_ERR_RATE_LIMITED");
        assert_eq!(json["delay_ms"], 1500);
        assert!(json["server_directed"].as_bool().unwrap());
    }

    #[test]
    fn controller_history_grows_with_retries() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(5));
        let err = make_retryable_error();

        for i in 1..=3 {
            ctrl.record_failure(&err);
            assert_eq!(ctrl.history().len(), i);
        }
    }

    #[test]
    fn backoff_exponential_sequence_without_jitter() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_base_delay_ms(100)
            .with_max_delay_ms(100_000);

        let delays: Vec<u64> = (1..=8).map(|a| compute_backoff(&p, a, 0)).collect();
        assert_eq!(delays, vec![100, 200, 400, 800, 1600, 3200, 6400, 12800]);
    }

    #[test]
    fn circuit_open_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrCircuitOpen));
    }

    #[test]
    fn connector_unavailable_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrConnectorUnavailable));
    }

    #[test]
    fn health_check_failed_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrHealthCheckFailed));
    }

    #[test]
    fn resource_exhausted_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrResourceExhausted));
    }

    #[test]
    fn internal_error_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrInternal));
    }

    #[test]
    fn parse_failed_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrParseFailed));
    }

    // ── RetryPolicy additional tests ────────────────────────────────

    #[test]
    fn default_policy_empty_extra_retryable() {
        let p = RetryPolicy::default();
        assert!(p.extra_retryable.is_empty());
    }

    #[test]
    fn default_policy_empty_never_retry() {
        let p = RetryPolicy::default();
        assert!(p.never_retry.is_empty());
    }

    #[test]
    fn no_retry_policy_zero_base_delay() {
        let p = RetryPolicy::no_retry();
        assert_eq!(p.base_delay_ms, 0);
    }

    #[test]
    fn no_retry_policy_zero_max_delay() {
        let p = RetryPolicy::no_retry();
        assert_eq!(p.max_delay_ms, 0);
    }

    #[test]
    fn no_retry_policy_zero_jitter() {
        let p = RetryPolicy::no_retry();
        assert!(p.jitter_factor.abs() < f64::EPSILON);
    }

    #[test]
    fn builder_chain_all_fields() {
        let p = RetryPolicy::default()
            .with_max_retries(10)
            .with_base_delay_ms(200)
            .with_max_delay_ms(5_000)
            .with_jitter_factor(0.5);
        assert_eq!(p.max_retries, 10);
        assert_eq!(p.base_delay_ms, 200);
        assert_eq!(p.max_delay_ms, 5_000);
        assert!((p.jitter_factor - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_jitter_factor_clamps_negative_to_zero() {
        let p = RetryPolicy::default().with_jitter_factor(-10.0);
        assert!(p.jitter_factor.abs() < f64::EPSILON);
    }

    #[test]
    fn builder_jitter_factor_clamps_large_positive_to_one() {
        let p = RetryPolicy::default().with_jitter_factor(100.0);
        assert!((p.jitter_factor - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_jitter_factor_preserves_zero() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        assert!(p.jitter_factor.abs() < f64::EPSILON);
    }

    #[test]
    fn builder_jitter_factor_preserves_one() {
        let p = RetryPolicy::default().with_jitter_factor(1.0);
        assert!((p.jitter_factor - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_clone_preserves_all_fields() {
        let mut p = RetryPolicy::default()
            .with_max_retries(7)
            .with_base_delay_ms(500);
        p.extra_retryable = vec!["auth".to_string()];
        p.never_retry = vec!["parse".to_string()];
        let cloned = p.clone();
        assert_eq!(p.max_retries, cloned.max_retries);
        assert_eq!(p.base_delay_ms, cloned.base_delay_ms);
        assert_eq!(p.max_delay_ms, cloned.max_delay_ms);
        assert_eq!(p.extra_retryable, cloned.extra_retryable);
        assert_eq!(p.never_retry, cloned.never_retry);
        assert_eq!(p.honor_retry_after, cloned.honor_retry_after);
    }

    #[test]
    fn policy_debug_output_not_empty() {
        let p = RetryPolicy::default();
        let debug = format!("{:?}", p);
        assert!(!debug.is_empty());
        assert!(debug.contains("RetryPolicy"));
    }

    #[test]
    fn default_trait_matches_default_policy() {
        let from_trait = RetryPolicy::default();
        let from_fn = RetryPolicy::default_policy();
        assert_eq!(from_trait.max_retries, from_fn.max_retries);
        assert_eq!(from_trait.base_delay_ms, from_fn.base_delay_ms);
        assert_eq!(from_trait.max_delay_ms, from_fn.max_delay_ms);
        assert_eq!(from_trait.honor_retry_after, from_fn.honor_retry_after);
    }

    #[test]
    fn never_retry_overrides_transport_category() {
        let p = RetryPolicy {
            never_retry: vec!["transport".to_string()],
            ..RetryPolicy::default()
        };
        assert!(!p.is_retryable(FcpErrorCode::FcpErrTransportFailed));
        assert!(!p.is_retryable(FcpErrorCode::FcpErrUpstreamTimeout));
    }

    #[test]
    fn never_retry_overrides_connector_category() {
        let p = RetryPolicy {
            never_retry: vec!["connector".to_string()],
            ..RetryPolicy::default()
        };
        assert!(!p.is_retryable(FcpErrorCode::FcpErrCircuitOpen));
        assert!(!p.is_retryable(FcpErrorCode::FcpErrConnectorUnavailable));
    }

    #[test]
    fn extra_retryable_adds_validation_category() {
        let p = RetryPolicy {
            extra_retryable: vec!["validation".to_string()],
            ..RetryPolicy::default()
        };
        assert!(p.is_retryable(FcpErrorCode::FcpErrValidationFailed));
        assert!(p.is_retryable(FcpErrorCode::FcpErrInvalidInput));
    }

    #[test]
    fn extra_retryable_adds_policy_category() {
        let p = RetryPolicy {
            extra_retryable: vec!["policy".to_string()],
            ..RetryPolicy::default()
        };
        assert!(p.is_retryable(FcpErrorCode::FcpErrPolicyDenied));
    }

    #[test]
    fn extra_retryable_adds_internal_category() {
        let p = RetryPolicy {
            extra_retryable: vec!["internal".to_string()],
            ..RetryPolicy::default()
        };
        assert!(p.is_retryable(FcpErrorCode::FcpErrInternal));
    }

    #[test]
    fn budget_exceeded_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrBudgetExceeded));
    }

    #[test]
    fn dependency_unavailable_is_retryable() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(FcpErrorCode::FcpErrDependencyUnavailable));
    }

    #[test]
    fn external_service_is_retryable() {
        let p = RetryPolicy::default();
        // external category — check taxonomy
        let code = FcpErrorCode::FcpErrExternalService;
        assert_eq!(p.is_retryable(code), code.retryable());
    }

    #[test]
    fn conflict_retryable_matches_taxonomy() {
        let p = RetryPolicy::default();
        let code = FcpErrorCode::FcpErrConflict;
        assert_eq!(p.is_retryable(code), code.retryable());
    }

    #[test]
    fn resource_not_found_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrResourceNotFound));
    }

    #[test]
    fn capability_denied_is_not_retryable() {
        let p = RetryPolicy::default();
        assert!(!p.is_retryable(FcpErrorCode::FcpErrCapabilityDenied));
    }

    #[test]
    fn connector_not_configured_retryable_matches_taxonomy() {
        let p = RetryPolicy::default();
        let code = FcpErrorCode::FcpErrConnectorNotConfigured;
        assert_eq!(p.is_retryable(code), code.retryable());
    }

    // ── compute_backoff additional tests ────────────────────────────

    #[test]
    fn backoff_with_jitter_factor_one_full_range() {
        let p = RetryPolicy::default()
            .with_jitter_factor(1.0)
            .with_base_delay_ms(1_000)
            .with_max_delay_ms(100_000);
        for seed in 0..100 {
            let delay = compute_backoff(&p, 1, seed);
            // 1000 ± 100% = 0..2000, but min is 1
            assert!(delay >= 1, "delay {} too low for seed {}", delay, seed);
            assert!(delay <= 2_000, "delay {} too high for seed {}", delay, seed);
        }
    }

    #[test]
    fn backoff_with_very_small_base_delay() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_base_delay_ms(1)
            .with_max_delay_ms(1_000);
        assert_eq!(compute_backoff(&p, 1, 0), 1);
        assert_eq!(compute_backoff(&p, 2, 0), 2);
        assert_eq!(compute_backoff(&p, 3, 0), 4);
        assert_eq!(compute_backoff(&p, 10, 0), 512);
    }

    #[test]
    fn backoff_attempt_four_returns_8x_base() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_max_delay_ms(100_000);
        assert_eq!(compute_backoff(&p, 4, 0), 8_000);
    }

    #[test]
    fn backoff_attempt_five_returns_16x_base_capped() {
        let p = RetryPolicy::default().with_jitter_factor(0.0);
        // 16x base = 16_000, which equals the default max_delay_ms
        assert_eq!(compute_backoff(&p, 5, 0), 16_000);
    }

    #[test]
    fn backoff_max_delay_one_ms() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_max_delay_ms(1);
        assert_eq!(compute_backoff(&p, 1, 0), 1);
        assert_eq!(compute_backoff(&p, 5, 0), 1);
    }

    #[test]
    fn backoff_positive_jitter_never_exceeds_max_delay() {
        for max_delay in [0, 1, 16_000, u64::MAX] {
            let policy = RetryPolicy::default()
                .with_base_delay_ms(u64::MAX)
                .with_max_delay_ms(max_delay)
                .with_jitter_factor(1.0);
            for attempt in [1, 20, u32::MAX] {
                for seed in [0, 5_000, 10_000, u64::MAX] {
                    let delay = compute_backoff(&policy, attempt, seed);
                    assert!(delay <= max_delay);
                    if max_delay > 0 {
                        assert!(delay > 0);
                    }
                }
            }
        }
    }

    #[test]
    fn backoff_jitter_seed_boundary_zero() {
        let p = RetryPolicy::default().with_jitter_factor(0.25);
        let delay = compute_backoff(&p, 1, 0);
        // seed 0 => jitter_raw = (0 % 10001) / 5000 - 1.0 = -1.0
        // jitter_offset = 1000 * 0.25 * (-1.0) = -250
        // jittered = 1000 - 250 = 750
        assert_eq!(delay, 750);
    }

    #[test]
    fn backoff_jitter_seed_boundary_5000() {
        let p = RetryPolicy::default().with_jitter_factor(0.25);
        let delay = compute_backoff(&p, 1, 5_000);
        // seed 5000 => jitter_raw = (5000 % 10001) / 5000 - 1.0 = 0.0
        // jitter_offset = 1000 * 0.25 * 0.0 = 0
        // jittered = 1000
        assert_eq!(delay, 1_000);
    }

    #[test]
    fn backoff_jitter_seed_boundary_10000() {
        let p = RetryPolicy::default().with_jitter_factor(0.25);
        let delay = compute_backoff(&p, 1, 10_000);
        // seed 10000 => jitter_raw = (10000 % 10001) / 5000 - 1.0 = 1.0
        // jitter_offset = 1000 * 0.25 * 1.0 = 250
        // jittered = 1000 + 250 = 1250
        assert_eq!(delay, 1_250);
    }

    #[test]
    fn backoff_jitter_seed_wraps_at_10001() {
        let p = RetryPolicy::default().with_jitter_factor(0.25);
        let delay_0 = compute_backoff(&p, 1, 0);
        let delay_10001 = compute_backoff(&p, 1, 10_001);
        // 10001 % 10001 == 0, so same as seed 0
        assert_eq!(delay_0, delay_10001);
    }

    #[test]
    fn backoff_exponent_capped_at_20() {
        let p = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_base_delay_ms(1)
            .with_max_delay_ms(u64::MAX);
        // attempt 22 => exponent capped at 20 => 1 * 2^20 = 1_048_576
        let delay_21 = compute_backoff(&p, 21, 0);
        let delay_22 = compute_backoff(&p, 22, 0);
        assert_eq!(delay_21, 1_048_576);
        assert_eq!(delay_22, 1_048_576); // capped at same value
    }

    #[test]
    fn backoff_never_returns_zero_with_jitter() {
        // Even with maximum negative jitter, result is clamped to 1
        let p = RetryPolicy::default()
            .with_jitter_factor(1.0)
            .with_base_delay_ms(1)
            .with_max_delay_ms(1_000);
        // seed 0 gives jitter_raw = -1.0 => offset = -1 => jittered = 0 => max(0,1) = 1
        let delay = compute_backoff(&p, 1, 0);
        assert!(delay >= 1);
    }

    // ── RetryAttempt additional tests ───────────────────────────────

    #[test]
    fn retry_attempt_clone() {
        let attempt = RetryAttempt {
            attempt: 3,
            error_code: "FCP_ERR_RATE_LIMITED".to_string(),
            error_category: "rate_limit".to_string(),
            delay_ms: 4_000,
            server_directed: false,
        };
        let cloned = attempt.clone();
        assert_eq!(attempt.attempt, cloned.attempt);
        assert_eq!(attempt.error_code, cloned.error_code);
        assert_eq!(attempt.delay_ms, cloned.delay_ms);
        assert_eq!(attempt.server_directed, cloned.server_directed);
    }

    #[test]
    fn retry_attempt_debug_not_empty() {
        let attempt = RetryAttempt {
            attempt: 1,
            error_code: "FCP_ERR_TRANSPORT_FAILED".to_string(),
            error_category: "transport".to_string(),
            delay_ms: 500,
            server_directed: true,
        };
        let debug = format!("{:?}", attempt);
        assert!(debug.contains("RetryAttempt"));
        assert!(debug.contains("FCP_ERR_TRANSPORT_FAILED"));
    }

    #[test]
    fn retry_attempt_serializes_server_directed_false() {
        let attempt = RetryAttempt {
            attempt: 2,
            error_code: "FCP_ERR_UPSTREAM_TIMEOUT".to_string(),
            error_category: "transport".to_string(),
            delay_ms: 2_000,
            server_directed: false,
        };
        let json = serde_json::to_value(&attempt).unwrap();
        assert!(!json["server_directed"].as_bool().unwrap());
        assert_eq!(json["error_category"], "transport");
    }

    // ── RetryDecision additional tests ──────────────────────────────

    #[test]
    fn retry_decision_clone() {
        let d = RetryDecision::Retry {
            delay_ms: 500,
            attempt: 2,
            server_directed: true,
        };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn retry_decision_eq_different_variants() {
        let retry = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 2,
            server_directed: false,
        };
        let non_retryable = RetryDecision::NonRetryable {
            code: "FCP_ERR_INTERNAL".to_string(),
            reason: "Internal error".to_string(),
        };
        assert_ne!(retry, non_retryable);
    }

    #[test]
    fn retry_decision_eq_same_retry_different_delay() {
        let d1 = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 2,
            server_directed: false,
        };
        let d2 = RetryDecision::Retry {
            delay_ms: 2_000,
            attempt: 2,
            server_directed: false,
        };
        assert_ne!(d1, d2);
    }

    #[test]
    fn retry_decision_eq_same_retry_different_attempt() {
        let d1 = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 2,
            server_directed: false,
        };
        let d2 = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 3,
            server_directed: false,
        };
        assert_ne!(d1, d2);
    }

    #[test]
    fn retry_decision_eq_same_retry_different_server_directed() {
        let d1 = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 2,
            server_directed: false,
        };
        let d2 = RetryDecision::Retry {
            delay_ms: 1_000,
            attempt: 2,
            server_directed: true,
        };
        assert_ne!(d1, d2);
    }

    #[test]
    fn retry_decision_debug_contains_variant() {
        let d = RetryDecision::Exhausted {
            attempts_made: 4,
            max_retries: 3,
        };
        let debug = format!("{:?}", d);
        assert!(debug.contains("Exhausted"));
    }

    #[test]
    fn retry_decision_retry_should_retry_true() {
        let d = RetryDecision::Retry {
            delay_ms: 100,
            attempt: 1,
            server_directed: false,
        };
        assert!(d.should_retry());
    }

    #[test]
    fn retry_decision_non_retryable_should_retry_false() {
        let d = RetryDecision::NonRetryable {
            code: "FCP_ERR_INTERNAL".to_string(),
            reason: "fatal".to_string(),
        };
        assert!(!d.should_retry());
    }

    #[test]
    fn retry_decision_exhausted_should_retry_false() {
        let d = RetryDecision::Exhausted {
            attempts_made: 5,
            max_retries: 4,
        };
        assert!(!d.should_retry());
    }

    #[test]
    fn retry_decision_serializes_server_directed_field() {
        let d = RetryDecision::Retry {
            delay_ms: 5_000,
            attempt: 2,
            server_directed: true,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert!(json["server_directed"].as_bool().unwrap());
    }

    #[test]
    fn non_retryable_decision_serializes_code_and_reason() {
        let d = RetryDecision::NonRetryable {
            code: "FCP_ERR_POLICY_DENIED".to_string(),
            reason: "Policy blocks this".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["code"], "FCP_ERR_POLICY_DENIED");
        assert_eq!(json["reason"], "Policy blocks this");
    }

    #[test]
    fn exhausted_decision_serializes_max_retries() {
        let d = RetryDecision::Exhausted {
            attempts_made: 6,
            max_retries: 5,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["max_retries"], 5);
        assert_eq!(json["attempts_made"], 6);
    }

    // ── RetryOutcome additional tests ───────────────────────────────

    #[test]
    fn retry_outcome_non_retryable_total_attempts() {
        let o = RetryOutcome::NonRetryable {
            error: make_non_retryable_error(),
            total_attempts: 3,
            retry_history: vec![],
        };
        assert_eq!(o.total_attempts(), 3);
    }

    #[test]
    fn retry_outcome_exhausted_total_attempts() {
        let o = RetryOutcome::Exhausted {
            error: make_retryable_error(),
            total_attempts: 5,
            max_retries: 4,
            retry_history: vec![],
        };
        assert_eq!(o.total_attempts(), 5);
    }

    #[test]
    fn retry_outcome_success_retry_history_empty() {
        let o = RetryOutcome::Success {
            total_attempts: 1,
            retry_history: vec![],
        };
        assert!(o.retry_history().is_empty());
    }

    #[test]
    fn retry_outcome_non_retryable_retry_history() {
        let attempt = RetryAttempt {
            attempt: 1,
            error_code: "FCP_ERR_TRANSPORT_FAILED".to_string(),
            error_category: "transport".to_string(),
            delay_ms: 1_000,
            server_directed: false,
        };
        let o = RetryOutcome::NonRetryable {
            error: make_non_retryable_error(),
            total_attempts: 2,
            retry_history: vec![attempt],
        };
        assert_eq!(o.retry_history().len(), 1);
        assert_eq!(o.retry_history()[0].error_code, "FCP_ERR_TRANSPORT_FAILED");
    }

    #[test]
    fn retry_outcome_exhausted_retry_history() {
        let attempts: Vec<RetryAttempt> = (1..=3)
            .map(|i| RetryAttempt {
                attempt: i,
                error_code: "FCP_ERR_RATE_LIMITED".to_string(),
                error_category: "rate_limit".to_string(),
                delay_ms: 1_000 * u64::from(i),
                server_directed: false,
            })
            .collect();
        let o = RetryOutcome::Exhausted {
            error: make_retryable_error(),
            total_attempts: 4,
            max_retries: 3,
            retry_history: attempts,
        };
        assert_eq!(o.retry_history().len(), 3);
    }

    #[test]
    fn retry_outcome_clone() {
        let o = RetryOutcome::Success {
            total_attempts: 2,
            retry_history: vec![RetryAttempt {
                attempt: 1,
                error_code: "FCP_ERR_RATE_LIMITED".to_string(),
                error_category: "rate_limit".to_string(),
                delay_ms: 1_000,
                server_directed: false,
            }],
        };
        let cloned = o.clone();
        assert_eq!(o.total_attempts(), cloned.total_attempts());
        assert_eq!(o.retry_history().len(), cloned.retry_history().len());
    }

    #[test]
    fn retry_outcome_debug_contains_variant() {
        let o = RetryOutcome::Exhausted {
            error: make_retryable_error(),
            total_attempts: 4,
            max_retries: 3,
            retry_history: vec![],
        };
        let debug = format!("{:?}", o);
        assert!(debug.contains("Exhausted"));
    }

    #[test]
    fn retry_outcome_non_retryable_serializes() {
        let o = RetryOutcome::NonRetryable {
            error: make_non_retryable_error(),
            total_attempts: 1,
            retry_history: vec![],
        };
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["outcome"], "non_retryable");
        assert_eq!(json["total_attempts"], 1);
    }

    #[test]
    fn retry_outcome_success_serializes_empty_history() {
        let o = RetryOutcome::Success {
            total_attempts: 1,
            retry_history: vec![],
        };
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["outcome"], "success");
        assert_eq!(json["retry_history"].as_array().unwrap().len(), 0);
    }

    // ── RetryController additional tests ────────────────────────────

    #[test]
    fn controller_clone() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();
        ctrl.record_failure(&err);
        let cloned = ctrl.clone();
        assert_eq!(ctrl.attempts_made(), cloned.attempts_made());
        assert_eq!(ctrl.history().len(), cloned.history().len());
    }

    #[test]
    fn controller_debug_not_empty() {
        let ctrl = RetryController::new(RetryPolicy::default());
        let debug = format!("{:?}", ctrl);
        assert!(debug.contains("RetryController"));
    }

    #[test]
    fn controller_with_jitter_seed_returns_self() {
        let ctrl = RetryController::new(RetryPolicy::default()).with_jitter_seed(999);
        // Verify it works by recording a failure and getting a deterministic result
        let mut ctrl = ctrl;
        let err = make_retryable_error();
        let d = ctrl.record_failure(&err);
        assert!(d.should_retry());
    }

    #[test]
    fn controller_attempts_increment_on_success() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        assert_eq!(ctrl.attempts_made(), 0);
        ctrl.record_success();
        assert_eq!(ctrl.attempts_made(), 1);
    }

    #[test]
    fn controller_attempts_increment_on_failure() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();
        assert_eq!(ctrl.attempts_made(), 0);
        ctrl.record_failure(&err);
        assert_eq!(ctrl.attempts_made(), 1);
    }

    #[test]
    fn controller_history_empty_initially() {
        let ctrl = RetryController::new(RetryPolicy::default());
        assert!(ctrl.history().is_empty());
    }

    #[test]
    fn controller_record_failure_timeout_is_retryable() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_timeout_error();
        let d = ctrl.record_failure(&err);
        assert!(d.should_retry());
    }

    #[test]
    fn controller_record_failure_transport_is_retryable() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_transport_error();
        let d = ctrl.record_failure(&err);
        assert!(d.should_retry());
    }

    #[test]
    fn controller_retry_after_zero_uses_zero_delay() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_rate_limited_with_retry_after(0);
        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                delay_ms,
                server_directed,
                ..
            } => {
                assert_eq!(delay_ms, 0);
                assert!(server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_retry_after_non_numeric_ignored() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited")
            .with_details(serde_json::json!({ "retry_after_ms": "not_a_number" }));
        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                server_directed, ..
            } => {
                assert!(!server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_retry_after_null_ignored() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited")
            .with_details(serde_json::json!({ "retry_after_ms": null }));
        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                server_directed, ..
            } => {
                assert!(!server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_details_without_retry_after_key() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited")
            .with_details(serde_json::json!({ "other_key": 123 }));
        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                server_directed, ..
            } => {
                assert!(!server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_no_details_uses_computed_backoff() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = StructuredError::new(FcpErrorCode::FcpErrRateLimited, "Rate limited");
        let decision = ctrl.record_failure(&err);
        match decision {
            RetryDecision::Retry {
                server_directed, ..
            } => {
                assert!(!server_directed);
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_unknown_retryable_error_code() {
        // StructuredError with unknown code string but retryable=true
        let err = StructuredError {
            code: "FCP_ERR_CUSTOM_UNKNOWN",
            category: "custom",
            message: "Custom error".to_string(),
            retryable: true,
            recoverable: false,
            recovery: FcpErrorCode::FcpErrInternal.default_recovery(),
            details: None,
            exit_code: 1,
        };
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let d = ctrl.record_failure(&err);
        // Unknown code with retryable=true should be retried
        assert!(d.should_retry());
    }

    #[test]
    fn controller_unknown_non_retryable_error_code() {
        let err = StructuredError {
            code: "FCP_ERR_CUSTOM_UNKNOWN",
            category: "custom",
            message: "Custom error".to_string(),
            retryable: false,
            recoverable: false,
            recovery: FcpErrorCode::FcpErrInternal.default_recovery(),
            details: None,
            exit_code: 1,
        };
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let d = ctrl.record_failure(&err);
        assert!(!d.should_retry());
        match d {
            RetryDecision::NonRetryable { reason, .. } => {
                assert!(reason.contains("Unknown error code"));
            }
            other => panic!("Expected NonRetryable, got {:?}", other),
        }
    }

    #[test]
    fn controller_finalize_exhausted_with_no_history() {
        let ctrl = RetryController::new(RetryPolicy::default());
        let err = make_retryable_error();
        let outcome = ctrl.finalize_exhausted(err);
        assert!(!outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 0);
        assert!(outcome.retry_history().is_empty());
    }

    #[test]
    fn controller_finalize_non_retryable_with_no_history() {
        let ctrl = RetryController::new(RetryPolicy::default());
        let err = make_non_retryable_error();
        let outcome = ctrl.finalize_non_retryable(err);
        assert!(!outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 0);
        assert!(outcome.retry_history().is_empty());
    }

    #[test]
    fn controller_max_retries_five_full_loop() {
        let policy = RetryPolicy::default().with_max_retries(5);
        let mut ctrl = RetryController::new(policy);
        let err = make_retryable_error();

        for i in 1..=5 {
            let d = ctrl.record_failure(&err);
            assert!(d.should_retry(), "Attempt {} should allow retry", i);
        }
        // 6th failure = exhausted
        let d = ctrl.record_failure(&err);
        assert!(!d.should_retry());
        assert!(matches!(d, RetryDecision::Exhausted { .. }));
        assert_eq!(ctrl.attempts_made(), 6);
    }

    #[test]
    fn controller_jitter_seed_advances_between_attempts() {
        let policy = RetryPolicy::default().with_max_retries(5);
        let mut ctrl = RetryController::new(policy).with_jitter_seed(42);
        let err = make_retryable_error();

        let mut delays = Vec::new();
        for _ in 0..3 {
            match ctrl.record_failure(&err) {
                RetryDecision::Retry { delay_ms, .. } => delays.push(delay_ms),
                other => panic!("Expected Retry, got {:?}", other),
            }
        }
        // With advancing jitter seed and increasing backoff, all three should differ
        assert_ne!(delays[0], delays[1]);
        assert_ne!(delays[1], delays[2]);
    }

    #[test]
    fn controller_history_records_correct_attempt_numbers() {
        let policy = RetryPolicy::default().with_max_retries(5);
        let mut ctrl = RetryController::new(policy);
        let err = make_retryable_error();

        for _ in 0..3 {
            ctrl.record_failure(&err);
        }

        let history = ctrl.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].attempt, 1);
        assert_eq!(history[1].attempt, 2);
        assert_eq!(history[2].attempt, 3);
    }

    #[test]
    fn controller_history_records_delay_ms() {
        let policy = RetryPolicy::default()
            .with_jitter_factor(0.0)
            .with_max_retries(3);
        let mut ctrl = RetryController::new(policy);
        let err = make_retryable_error();

        ctrl.record_failure(&err);
        ctrl.record_failure(&err);

        let history = ctrl.history();
        assert_eq!(history[0].delay_ms, 1_000);
        assert_eq!(history[1].delay_ms, 2_000);
    }

    #[test]
    fn controller_history_records_server_directed() {
        let policy = RetryPolicy::default().with_max_retries(3);
        let mut ctrl = RetryController::new(policy);

        let err_with_retry_after = make_rate_limited_with_retry_after(3_000);
        ctrl.record_failure(&err_with_retry_after);

        let err_without = make_retryable_error();
        ctrl.record_failure(&err_without);

        let history = ctrl.history();
        assert!(history[0].server_directed);
        assert!(!history[1].server_directed);
    }

    #[test]
    fn controller_non_retryable_error_not_recorded_in_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_non_retryable_error();
        let d = ctrl.record_failure(&err);
        assert!(!d.should_retry());
        // Non-retryable errors are not added to the retry history
        assert!(ctrl.history().is_empty());
    }

    #[test]
    fn controller_exhausted_error_not_recorded_in_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(1));
        let err = make_retryable_error();
        ctrl.record_failure(&err); // retry 1 - recorded
        ctrl.record_failure(&err); // exhausted - not recorded
        assert_eq!(ctrl.history().len(), 1);
    }

    #[test]
    fn controller_record_success_returns_correct_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default());
        let err = make_timeout_error();

        ctrl.record_failure(&err);
        ctrl.record_failure(&err);
        let outcome = ctrl.record_success();

        assert!(outcome.succeeded());
        assert_eq!(outcome.total_attempts(), 3);
        let history = outcome.retry_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].error_code, "FCP_ERR_UPSTREAM_TIMEOUT");
        assert_eq!(history[1].error_code, "FCP_ERR_UPSTREAM_TIMEOUT");
    }

    #[test]
    fn controller_mixed_errors_in_history() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(5));

        ctrl.record_failure(&make_retryable_error());
        ctrl.record_failure(&make_timeout_error());
        ctrl.record_failure(&make_transport_error());
        let outcome = ctrl.record_success();

        let history = outcome.retry_history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].error_category, "rate_limit");
        assert_eq!(history[1].error_category, "transport");
        assert_eq!(history[2].error_category, "transport");
    }

    #[test]
    fn controller_retry_decision_attempt_field() {
        let mut ctrl = RetryController::new(RetryPolicy::default().with_max_retries(5));
        let err = make_retryable_error();

        // After first failure (attempts_made=1), next attempt should be 2
        match ctrl.record_failure(&err) {
            RetryDecision::Retry { attempt, .. } => assert_eq!(attempt, 2),
            other => panic!("Expected Retry, got {:?}", other),
        }

        // After second failure (attempts_made=2), next attempt should be 3
        match ctrl.record_failure(&err) {
            RetryDecision::Retry { attempt, .. } => assert_eq!(attempt, 3),
            other => panic!("Expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn controller_with_large_max_delay() {
        let policy = RetryPolicy::default()
            .with_max_delay_ms(u64::MAX)
            .with_jitter_factor(0.0);
        let mut ctrl = RetryController::new(policy);
        let err = make_retryable_error();
        let d = ctrl.record_failure(&err);
        match d {
            RetryDecision::Retry { delay_ms, .. } => {
                assert_eq!(delay_ms, 1_000); // base delay, not overflowed
            }
            other => panic!("Expected Retry, got {:?}", other),
        }
    }
}
