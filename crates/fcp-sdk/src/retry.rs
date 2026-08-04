//! Retry taxonomy helpers for connector SDKs.
//!
//! Provides a small, deterministic policy for translating retry decisions into
//! concrete delays (including Retry-After hints).
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::retry::{map_external_error, RetryPolicy};
//!
//! let attempt = 0;
//! let (decision, _err) = map_external_error(
//!     "example-service",
//!     Some(503),
//!     "Service Unavailable",
//!     None,
//! );
//!
//! let policy = RetryPolicy::new().with_jitter_enabled(false);
//! if let Some(delay) = policy.next_delay(attempt, decision, None) {
//!     // sleep for delay, then retry
//! }
//! ```

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::FcpError;
use crate::formatting::{ErrorClass, classify_error_message};

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

/// High-level retry decision for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry immediately (no delay).
    Immediate,
    /// Retry with exponential backoff (policy-controlled).
    Backoff,
    /// Retry after an explicit delay.
    After(Duration),
    /// Do not retry.
    Terminal,
}

impl RetryDecision {
    /// Returns true if this decision permits a retry.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        !matches!(self, Self::Terminal)
    }

    /// Returns an explicit retry-after duration, if present.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::After(delay) => Some(delay),
            _ => None,
        }
    }
}

/// Policy for translating retry decisions into delays.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Base delay for exponential backoff (milliseconds).
    pub base_backoff_ms: u64,
    /// Maximum backoff delay (milliseconds).
    pub max_backoff_ms: u64,
    /// Whether to add deterministic jitter to backoff delays.
    pub jitter_enabled: bool,
    /// Maximum total attempts, including the initial call.
    ///
    /// `None` means unlimited within the representable `u32` attempt space.
    pub max_attempts: Option<u32>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            jitter_enabled: true,
            max_attempts: Some(5),
        }
    }
}

impl RetryPolicy {
    /// Create a policy with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set base backoff delay.
    ///
    /// A value of 0 is silently promoted to 1 to prevent tight busy-wait loops.
    #[must_use]
    pub const fn with_base_backoff_ms(mut self, ms: u64) -> Self {
        self.base_backoff_ms = if ms == 0 { 1 } else { ms };
        self
    }

    /// Builder: set max backoff delay.
    #[must_use]
    pub const fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder: enable/disable jitter.
    #[must_use]
    pub const fn with_jitter_enabled(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Builder: set maximum total attempts, including the initial call.
    ///
    /// For example, `Some(1)` means "try once and never schedule a retry",
    /// while `Some(3)` allows at most two retry delays after the initial
    /// attempt.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Compute backoff delay for a given attempt number (0-indexed).
    ///
    /// Always returns at least 1ms when `base_backoff_ms` is non-zero
    /// to prevent tight busy-wait loops.
    #[must_use]
    pub fn compute_backoff_ms(&self, attempt: u32) -> u64 {
        let exp = attempt.min(30);
        let delay = self.base_backoff_ms.saturating_mul(1u64 << exp);
        let capped = delay.min(self.max_backoff_ms);
        if self.base_backoff_ms > 0 && capped == 0 {
            1
        } else {
            capped
        }
    }

    /// Compute backoff delay with deterministic jitter.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_backoff_with_jitter_ms(&self, attempt: u32, jitter_factor: f64) -> u64 {
        let base = self.compute_backoff_ms(attempt);
        if !self.jitter_enabled {
            return base;
        }

        let factor = jitter_factor.clamp(0.0, 1.0).mul_add(0.5, 0.5);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let jittered = (base as f64 * factor) as u64;
        // Preserve `compute_backoff_ms`'s ≥1ms guarantee: the jitter factor
        // bottoms out at 0.5, and `(1 * 0.5) as u64 == 0`, so a policy with a
        // 1ms effective backoff would otherwise retry with no delay at all —
        // exactly the tight busy-wait loop that floor exists to prevent.
        if self.base_backoff_ms > 0 {
            jittered.max(1)
        } else {
            jittered
        }
    }

    /// Clamp a server-supplied `Retry-After` hint into this policy's bounds.
    ///
    /// `Retry-After` is attacker-controlled. `max_backoff_ms` is the policy's
    /// documented ceiling, so a hint must not be able to override it — an
    /// unclamped hint let one response header park a connector for as long as
    /// the upstream asked (bounded in practice only by the request deadline,
    /// and not at all on a deadline-less background context). The floor
    /// matters too: `Retry-After: 0` from a service that just asked to be
    /// backed off would otherwise produce a zero-delay retry burst for the
    /// whole attempt budget.
    const fn clamp_retry_after_ms(&self, hint_ms: u64) -> u64 {
        let floor = if self.base_backoff_ms > 0 { 1 } else { 0 };
        let ceiling = if self.max_backoff_ms > floor {
            self.max_backoff_ms
        } else {
            floor
        };
        if hint_ms < floor {
            floor
        } else if hint_ms > ceiling {
            ceiling
        } else {
            hint_ms
        }
    }

    /// Translate a retry decision into a delay, applying Retry-After hints.
    ///
    /// `attempt` is the 0-indexed attempt that just failed. Returns `None`
    /// when retry is not permitted (terminal or the failed attempt has already
    /// exhausted the total-attempt budget).
    #[must_use]
    pub fn next_delay(
        &self,
        attempt: u32,
        decision: RetryDecision,
        retry_after_hint: Option<Duration>,
    ) -> Option<Duration> {
        // Attempt numbers are exposed as `u32`, so there is no representable
        // retry after the final `u32::MAX` attempt.
        if attempt == u32::MAX {
            return None;
        }

        if let Some(max_attempts) = self.max_attempts {
            if attempt.saturating_add(1) >= max_attempts {
                return None;
            }
        }

        match decision {
            RetryDecision::Terminal => None,
            RetryDecision::Immediate => Some(Duration::from_millis(0)),
            RetryDecision::After(delay) => Some(Duration::from_millis(
                self.clamp_retry_after_ms(duration_to_ms(delay)),
            )),
            RetryDecision::Backoff => {
                let jitter = pseudo_random_jitter(attempt);
                let mut delay_ms = self.compute_backoff_with_jitter_ms(attempt, jitter);

                if let Some(hint) = retry_after_hint {
                    delay_ms = delay_ms.max(self.clamp_retry_after_ms(duration_to_ms(hint)));
                }

                Some(Duration::from_millis(delay_ms))
            }
        }
    }
}

/// Parse an environment variable, falling back to a default if unset or unparseable.
fn env_or<T: std::str::FromStr>(var: &str, default: T) -> T {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Default retry-after for rate limiting when no hint is provided (30s).
pub const DEFAULT_RATE_LIMIT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Compute the rate-limit retry-after duration, allowing override via
/// `FCP_SDK_RATE_LIMIT_RETRY_AFTER_SECS`.
///
/// Falls back to [`DEFAULT_RATE_LIMIT_RETRY_AFTER`] (30 s) when the variable is unset.
#[must_use]
pub fn default_rate_limit_retry_after() -> Duration {
    Duration::from_secs(env_or("FCP_SDK_RATE_LIMIT_RETRY_AFTER_SECS", 30))
}

/// Classify an HTTP status code into a retry decision.
#[must_use]
pub fn decision_from_http_status(status: u16, retry_after: Option<Duration>) -> RetryDecision {
    match status {
        429 => RetryDecision::After(retry_after.unwrap_or_else(default_rate_limit_retry_after)),
        408 | 425 | 500..=599 => RetryDecision::Backoff,
        _ => RetryDecision::Terminal,
    }
}

/// Classify a free-form error message into a retry decision.
#[must_use]
pub fn decision_from_error_message(message: &str) -> RetryDecision {
    match classify_error_message(message) {
        ErrorClass::RateLimit | ErrorClass::Transient => RetryDecision::Backoff,
        ErrorClass::ParseError | ErrorClass::Terminal => RetryDecision::Terminal,
    }
}

/// Map an external error into a retry decision and standardized FCP error.
#[must_use]
pub fn map_external_error(
    service: impl Into<String>,
    status_code: Option<u16>,
    message: impl Into<String>,
    retry_after: Option<Duration>,
) -> (RetryDecision, FcpError) {
    let service = service.into();
    let message = message.into();
    let decision = status_code.map_or_else(
        || decision_from_error_message(&message),
        |code| decision_from_http_status(code, retry_after),
    );

    let fcp_error = match status_code {
        Some(429) => FcpError::RateLimited {
            retry_after_ms: duration_to_ms(
                retry_after.unwrap_or_else(default_rate_limit_retry_after),
            ),
            violation: None,
        },
        _ => FcpError::External {
            service,
            message,
            status_code,
            retryable: decision.is_retryable(),
            retry_after: retry_after.or_else(|| decision.retry_after()),
        },
    };

    (decision, fcp_error)
}

fn duration_to_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RetryDecision ────────────────────────────────────────────────────

    #[test]
    fn retry_decision_immediate_is_retryable() {
        assert!(RetryDecision::Immediate.is_retryable());
    }

    #[test]
    fn retry_decision_backoff_is_retryable() {
        assert!(RetryDecision::Backoff.is_retryable());
    }

    #[test]
    fn retry_decision_after_is_retryable() {
        assert!(RetryDecision::After(Duration::from_secs(5)).is_retryable());
    }

    #[test]
    fn retry_decision_terminal_not_retryable() {
        assert!(!RetryDecision::Terminal.is_retryable());
    }

    #[test]
    fn retry_decision_retry_after_returns_duration_for_after() {
        let d = Duration::from_secs(10);
        assert_eq!(RetryDecision::After(d).retry_after(), Some(d));
    }

    #[test]
    fn retry_decision_retry_after_returns_none_for_others() {
        assert!(RetryDecision::Immediate.retry_after().is_none());
        assert!(RetryDecision::Backoff.retry_after().is_none());
        assert!(RetryDecision::Terminal.retry_after().is_none());
    }

    #[test]
    fn retry_decision_debug_and_clone() {
        let d = RetryDecision::Backoff;
        let cloned = d;
        assert_eq!(format!("{d:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn retry_decision_eq() {
        assert_eq!(RetryDecision::Terminal, RetryDecision::Terminal);
        assert_ne!(RetryDecision::Immediate, RetryDecision::Terminal);
    }

    // ── RetryPolicy construction ─────────────────────────────────────────

    #[test]
    fn retry_policy_default() {
        let p = RetryPolicy::default();
        assert_eq!(p.base_backoff_ms, 1_000);
        assert_eq!(p.max_backoff_ms, 60_000);
        assert!(p.jitter_enabled);
        assert_eq!(p.max_attempts, Some(5));
    }

    #[test]
    fn retry_policy_new_equals_default() {
        let a = RetryPolicy::new();
        let b = RetryPolicy::default();
        assert_eq!(a.base_backoff_ms, b.base_backoff_ms);
        assert_eq!(a.max_backoff_ms, b.max_backoff_ms);
    }

    #[test]
    fn retry_policy_builder_chain() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(500)
            .with_max_backoff_ms(30_000)
            .with_jitter_enabled(false)
            .with_max_attempts(Some(3));
        assert_eq!(p.base_backoff_ms, 500);
        assert_eq!(p.max_backoff_ms, 30_000);
        assert!(!p.jitter_enabled);
        assert_eq!(p.max_attempts, Some(3));
    }

    #[test]
    fn retry_policy_unlimited_attempts() {
        let p = RetryPolicy::new().with_max_attempts(None);
        assert!(p.max_attempts.is_none());
    }

    #[test]
    fn retry_policy_debug_and_clone() {
        let p = RetryPolicy::new();
        let cloned = p.clone();
        let _ = format!("{p:?}");
        assert_eq!(cloned.base_backoff_ms, p.base_backoff_ms);
    }

    // ── compute_backoff_ms ───────────────────────────────────────────────

    #[test]
    fn compute_backoff_attempt_zero() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1_000);
    }

    #[test]
    fn compute_backoff_exponential_growth() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1_000);
        assert_eq!(p.compute_backoff_ms(1), 2_000);
        assert_eq!(p.compute_backoff_ms(2), 4_000);
        assert_eq!(p.compute_backoff_ms(3), 8_000);
    }

    #[test]
    fn compute_backoff_capped_at_max() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_max_backoff_ms(10_000)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(10), 10_000);
        assert_eq!(p.compute_backoff_ms(20), 10_000);
    }

    #[test]
    fn compute_backoff_high_attempt_capped_at_30() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        // Attempt 31 should be same as 30 (capped exponent)
        let d30 = p.compute_backoff_ms(30);
        let d31 = p.compute_backoff_ms(31);
        assert_eq!(d30, d31);
    }

    #[test]
    fn compute_backoff_zero_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(0)
            .with_jitter_enabled(false);
        // 0 is promoted to 1 to prevent busy-wait loops
        assert_eq!(p.compute_backoff_ms(5), 32); // 1 * 2^5
    }

    // ── compute_backoff_with_jitter_ms ───────────────────────────────────

    #[test]
    fn jitter_disabled_returns_base() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(
            p.compute_backoff_with_jitter_ms(0, 0.5),
            p.compute_backoff_ms(0)
        );
    }

    #[test]
    fn jitter_factor_zero_gives_half_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=0.0 → clamp(0,1)=0.0 → 0.0*0.5+0.5=0.5 → base*0.5
        let result = p.compute_backoff_with_jitter_ms(0, 0.0);
        assert_eq!(result, 500);
    }

    #[test]
    fn jitter_factor_one_gives_full_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=1.0 → clamp(0,1)=1.0 → 1.0*0.5+0.5=1.0 → base*1.0
        let result = p.compute_backoff_with_jitter_ms(0, 1.0);
        assert_eq!(result, 1_000);
    }

    #[test]
    fn jitter_factor_clamped_below_zero() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=-1.0 → clamp(0,1)=0.0 → same as factor=0.0
        let result = p.compute_backoff_with_jitter_ms(0, -1.0);
        assert_eq!(result, 500);
    }

    #[test]
    fn jitter_factor_clamped_above_one() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=5.0 → clamp(0,1)=1.0 → same as factor=1.0
        let result = p.compute_backoff_with_jitter_ms(0, 5.0);
        assert_eq!(result, 1_000);
    }

    // ── next_delay ───────────────────────────────────────────────────────

    #[test]
    fn next_delay_terminal_returns_none() {
        let p = RetryPolicy::new();
        assert!(p.next_delay(0, RetryDecision::Terminal, None).is_none());
    }

    #[test]
    fn next_delay_immediate_returns_zero() {
        let p = RetryPolicy::new();
        let delay = p.next_delay(0, RetryDecision::Immediate, None);
        assert_eq!(delay, Some(Duration::from_millis(0)));
    }

    #[test]
    fn next_delay_after_returns_explicit_duration() {
        let p = RetryPolicy::new();
        let d = Duration::from_secs(42);
        assert_eq!(p.next_delay(0, RetryDecision::After(d), None), Some(d));
    }

    #[test]
    fn next_delay_backoff_returns_computed_delay() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        let delay = p.next_delay(0, RetryDecision::Backoff, None);
        assert_eq!(delay, Some(Duration::from_secs(1)));
    }

    #[test]
    fn next_delay_exceeds_max_attempts_returns_none() {
        let p = RetryPolicy::new().with_max_attempts(Some(3));
        assert!(p.next_delay(3, RetryDecision::Backoff, None).is_none());
        assert!(p.next_delay(4, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn next_delay_within_max_attempts_returns_some() {
        let p = RetryPolicy::new().with_max_attempts(Some(3));
        // Attempt 1 (0-indexed) is NOT the last attempt → delay is computed
        assert!(p.next_delay(1, RetryDecision::Backoff, None).is_some());
        // Attempt 2 IS the last attempt (max_attempts=3) → no delay needed
        assert!(p.next_delay(2, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn next_delay_unlimited_attempts_never_none_for_retryable() {
        let p = RetryPolicy::new()
            .with_max_attempts(None)
            .with_jitter_enabled(false);
        for attempt in [0, 10, 100, 1000] {
            assert!(
                p.next_delay(attempt, RetryDecision::Backoff, None)
                    .is_some()
            );
        }
    }

    #[test]
    fn next_delay_retry_after_hint_overrides_when_larger() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(false);
        // Under the policy ceiling (default max_backoff_ms = 60s), the hint wins.
        let hint = Duration::from_secs(30);
        let delay = p.next_delay(0, RetryDecision::Backoff, Some(hint)).unwrap();
        assert_eq!(delay, hint);
    }

    /// `Retry-After` is attacker-controlled, so it may raise the delay but must
    /// never escape `max_backoff_ms` — the policy's documented ceiling. An
    /// unclamped hint let one response header park a connector for as long as
    /// the upstream asked.
    #[test]
    fn next_delay_clamps_hostile_retry_after_to_max_backoff() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(false);
        let ceiling = Duration::from_millis(p.max_backoff_ms);

        // Via the Backoff path (hint passed alongside).
        let delay = p
            .next_delay(
                0,
                RetryDecision::Backoff,
                Some(Duration::from_secs(31_536_000)),
            )
            .unwrap();
        assert_eq!(delay, ceiling);

        // Via the explicit After path, which previously returned the hint verbatim.
        let delay = p
            .next_delay(
                0,
                RetryDecision::After(Duration::from_secs(31_536_000)),
                None,
            )
            .unwrap();
        assert_eq!(delay, ceiling);
    }

    /// `Retry-After: 0` from a service that just asked to be backed off must not
    /// turn into a zero-delay retry burst for the whole attempt budget.
    #[test]
    fn next_delay_floors_zero_retry_after() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(false);
        let delay = p
            .next_delay(0, RetryDecision::After(Duration::ZERO), None)
            .unwrap();
        assert!(delay >= Duration::from_millis(1), "got {delay:?}");
    }

    /// The jitter factor bottoms out at 0.5 and truncates, so a 1ms effective
    /// backoff produced a 0ms delay — the tight busy-wait loop
    /// `compute_backoff_ms`'s floor exists to prevent.
    #[test]
    fn jittered_backoff_preserves_the_one_millisecond_floor() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1)
            .with_max_backoff_ms(1)
            .with_jitter_enabled(true);
        for attempt in 0..8 {
            assert!(
                p.compute_backoff_with_jitter_ms(attempt, 0.0) >= 1,
                "attempt {attempt} produced a zero delay"
            );
        }
    }

    #[test]
    fn next_delay_retry_after_hint_ignored_when_smaller() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(10_000)
            .with_jitter_enabled(false);
        let hint = Duration::from_millis(1);
        let delay = p.next_delay(0, RetryDecision::Backoff, Some(hint)).unwrap();
        // base_backoff of 10_000ms is larger than 1ms hint
        assert_eq!(delay, Duration::from_secs(10));
    }

    // ── decision_from_http_status ────────────────────────────────────────

    #[test]
    fn http_429_returns_after_with_default() {
        let d = decision_from_http_status(429, None);
        assert_eq!(d, RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER));
    }

    #[test]
    fn http_429_with_custom_retry_after() {
        let hint = Duration::from_secs(10);
        let d = decision_from_http_status(429, Some(hint));
        assert_eq!(d, RetryDecision::After(hint));
    }

    #[test]
    fn http_408_returns_backoff() {
        assert_eq!(decision_from_http_status(408, None), RetryDecision::Backoff);
    }

    #[test]
    fn http_425_returns_backoff() {
        assert_eq!(decision_from_http_status(425, None), RetryDecision::Backoff);
    }

    #[test]
    fn http_5xx_returns_backoff() {
        for status in [500, 502, 503, 504, 599] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Backoff,
                "status {status} should be Backoff"
            );
        }
    }

    #[test]
    fn http_4xx_non_retryable_returns_terminal() {
        for status in [400, 401, 403, 404, 422] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be Terminal"
            );
        }
    }

    #[test]
    fn http_2xx_returns_terminal() {
        assert_eq!(
            decision_from_http_status(200, None),
            RetryDecision::Terminal
        );
    }

    // ── decision_from_error_message ──────────────────────────────────────

    #[test]
    fn error_message_rate_limit_returns_backoff() {
        assert_eq!(
            decision_from_error_message("rate limit exceeded"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_timeout_returns_backoff() {
        assert_eq!(
            decision_from_error_message("connection timeout"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_parse_returns_terminal() {
        assert_eq!(
            decision_from_error_message("can't parse entities"),
            RetryDecision::Terminal
        );
    }

    #[test]
    fn error_message_unknown_returns_terminal() {
        assert_eq!(
            decision_from_error_message("something unexpected"),
            RetryDecision::Terminal
        );
    }

    // ── map_external_error ───────────────────────────────────────────────

    #[test]
    fn map_external_error_429_produces_rate_limited() {
        let (decision, error) = map_external_error("api", Some(429), "Too Many Requests", None);
        assert_eq!(
            decision,
            RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER)
        );
        assert!(matches!(error, FcpError::RateLimited { .. }));
    }

    #[test]
    fn map_external_error_503_produces_external_retryable() {
        let (decision, error) = map_external_error("api", Some(503), "Service Unavailable", None);
        assert_eq!(decision, RetryDecision::Backoff);
        match error {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected FcpError::External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_400_produces_external_non_retryable() {
        let (decision, error) = map_external_error("api", Some(400), "Bad Request", None);
        assert_eq!(decision, RetryDecision::Terminal);
        match error {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected FcpError::External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_no_status_uses_message() {
        let (decision, _error) = map_external_error("api", None, "connection timeout", None);
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn map_external_error_no_status_terminal_message() {
        let (decision, _error) = map_external_error("api", None, "invalid token format", None);
        assert_eq!(decision, RetryDecision::Terminal);
    }

    #[test]
    fn map_external_error_429_with_custom_retry_after() {
        let hint = Duration::from_secs(60);
        let (_decision, error) = map_external_error("api", Some(429), "rate limited", Some(hint));
        match error {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── duration_to_ms ───────────────────────────────────────────────────

    #[test]
    fn duration_to_ms_basic() {
        assert_eq!(duration_to_ms(Duration::from_secs(1)), 1_000);
        assert_eq!(duration_to_ms(Duration::from_millis(500)), 500);
        assert_eq!(duration_to_ms(Duration::ZERO), 0);
    }

    #[test]
    fn duration_to_ms_large_value() {
        let d = Duration::from_secs(u64::MAX);
        // Should not panic, returns u64::MAX
        assert_eq!(duration_to_ms(d), u64::MAX);
    }

    // ── DEFAULT_RATE_LIMIT_RETRY_AFTER ───────────────────────────────────

    #[test]
    fn default_retry_after_is_30s() {
        assert_eq!(DEFAULT_RATE_LIMIT_RETRY_AFTER, Duration::from_secs(30));
    }

    // ── Security regression: pseudo-random jitter (f07de35) ──

    #[test]
    fn pseudo_random_jitter_is_bounded() {
        // Jitter must always be in [0.0, 1.0)
        for attempt in 0..100 {
            let j = pseudo_random_jitter(attempt);
            assert!(j >= 0.0, "jitter must be non-negative, got {j}");
            assert!(j < 1.0, "jitter must be < 1.0, got {j}");
        }
    }

    #[test]
    fn pseudo_random_jitter_varies_across_attempts() {
        // Different attempt numbers should (with overwhelming probability)
        // produce different jitter values on the same thread.
        let mut deduped: Vec<f64> = (0..20).map(pseudo_random_jitter).collect();
        deduped.sort_by(|a, b| a.partial_cmp(b).unwrap());
        deduped.dedup();
        // At least 10 unique values out of 20 attempts (probability of
        // fewer than 10 unique from a uniform distribution is negligible).
        assert!(
            deduped.len() >= 10,
            "Expected at least 10 unique jitter values, got {}",
            deduped.len()
        );
    }

    // ── NEW: RetryDecision edge cases ─────────────────────────────────

    #[test]
    fn retry_decision_after_zero_duration() {
        let d = RetryDecision::After(Duration::ZERO);
        assert!(d.is_retryable());
        assert_eq!(d.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_decision_after_large_duration() {
        let d = RetryDecision::After(Duration::from_secs(86400));
        assert!(d.is_retryable());
        assert_eq!(d.retry_after(), Some(Duration::from_secs(86400)));
    }

    // ── NEW: RetryPolicy compute_backoff edge cases ──────────────────

    #[test]
    fn compute_backoff_attempt_one() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(1), 2_000);
    }

    #[test]
    fn compute_backoff_large_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(10_000)
            .with_max_backoff_ms(100_000)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 10_000);
        assert_eq!(p.compute_backoff_ms(1), 20_000);
        assert_eq!(p.compute_backoff_ms(2), 40_000);
        assert_eq!(p.compute_backoff_ms(3), 80_000);
        assert_eq!(p.compute_backoff_ms(4), 100_000); // capped
    }

    #[test]
    fn compute_backoff_max_equals_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_max_backoff_ms(1_000)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1_000);
        assert_eq!(p.compute_backoff_ms(5), 1_000);
    }

    // ── NEW: compute_backoff_with_jitter_ms edge cases ───────────────

    #[test]
    fn jitter_factor_half_gives_75_percent() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=0.5 -> 0.5*0.5+0.5=0.75 -> base*0.75
        let result = p.compute_backoff_with_jitter_ms(0, 0.5);
        assert_eq!(result, 750);
    }

    // ── NEW: next_delay edge cases ───────────────────────────────────

    #[test]
    fn next_delay_backoff_with_jitter_is_bounded() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_max_backoff_ms(60_000)
            .with_jitter_enabled(true)
            .with_max_attempts(None); // unlimited for this jitter bound test
        for attempt in 0..5 {
            let delay = p.next_delay(attempt, RetryDecision::Backoff, None).unwrap();
            // With jitter factor [0.5, 1.0], delay should be in [base*0.5, max_backoff]
            assert!(delay.as_millis() <= 60_000);
        }
    }

    #[test]
    fn next_delay_after_ignores_retry_after_hint() {
        let p = RetryPolicy::new();
        let d = Duration::from_secs(42);
        let hint = Duration::from_secs(100);
        // After variant uses its own duration, not the hint
        let delay = p.next_delay(0, RetryDecision::After(d), Some(hint));
        assert_eq!(delay, Some(d));
    }

    #[test]
    fn next_delay_immediate_ignores_hint() {
        let p = RetryPolicy::new();
        let hint = Duration::from_secs(100);
        let delay = p.next_delay(0, RetryDecision::Immediate, Some(hint));
        assert_eq!(delay, Some(Duration::ZERO));
    }

    #[test]
    fn next_delay_at_exact_max_attempts_returns_none() {
        let p = RetryPolicy::new().with_max_attempts(Some(5));
        assert!(p.next_delay(5, RetryDecision::Immediate, None).is_none());
    }

    #[test]
    fn next_delay_one_before_max_attempts_returns_some() {
        let p = RetryPolicy::new().with_max_attempts(Some(5));
        // Attempt 3 is NOT the last attempt (max_attempts=5) → delay is computed
        assert!(p.next_delay(3, RetryDecision::Immediate, None).is_some());
        // Attempt 4 IS the last attempt → no delay needed
        assert!(p.next_delay(4, RetryDecision::Immediate, None).is_none());
    }

    // ── NEW: decision_from_http_status edge cases ────────────────────

    #[test]
    fn http_100_returns_terminal() {
        assert_eq!(
            decision_from_http_status(100, None),
            RetryDecision::Terminal
        );
    }

    #[test]
    fn http_301_returns_terminal() {
        assert_eq!(
            decision_from_http_status(301, None),
            RetryDecision::Terminal
        );
    }

    #[test]
    fn http_501_returns_backoff() {
        assert_eq!(decision_from_http_status(501, None), RetryDecision::Backoff);
    }

    // ── NEW: decision_from_error_message edge cases ──────────────────

    #[test]
    fn error_message_unavailable_returns_backoff() {
        assert_eq!(
            decision_from_error_message("service unavailable"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_network_error_returns_backoff() {
        assert_eq!(
            decision_from_error_message("network error"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_too_many_requests_returns_backoff() {
        assert_eq!(
            decision_from_error_message("too many requests"),
            RetryDecision::Backoff
        );
    }

    // ── NEW: map_external_error edge cases ───────────────────────────

    #[test]
    fn map_external_error_500_retryable_true() {
        let (decision, error) =
            map_external_error("service", Some(500), "Internal Server Error", None);
        assert_eq!(decision, RetryDecision::Backoff);
        match error {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "service");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_404_not_retryable() {
        let (decision, error) = map_external_error("api", Some(404), "Not Found", None);
        assert_eq!(decision, RetryDecision::Terminal);
        match error {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(404));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_no_status_transient_message() {
        let (decision, error) = map_external_error("api", None, "connection refused", None);
        assert_eq!(decision, RetryDecision::Backoff);
        match error {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert!(status_code.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_with_retry_after_non_429() {
        let hint = Duration::from_secs(10);
        let (_decision, error) = map_external_error("api", Some(503), "unavailable", Some(hint));
        match error {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(hint));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── NEW: duration_to_ms edge cases ───────────────────────────────

    #[test]
    fn duration_to_ms_sub_millisecond() {
        assert_eq!(duration_to_ms(Duration::from_micros(500)), 0);
    }

    #[test]
    fn duration_to_ms_exact_millisecond() {
        assert_eq!(duration_to_ms(Duration::from_millis(1)), 1);
    }

    // ── NEW: RetryPolicy edge cases ──────────────────────────────────

    #[test]
    fn retry_policy_zero_max_attempts() {
        let p = RetryPolicy::new().with_max_attempts(Some(0));
        assert!(p.next_delay(0, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn retry_policy_max_attempts_one() {
        let p = RetryPolicy::new().with_max_attempts(Some(1));
        // max_attempts=1: only one attempt. After it fails, no delay needed.
        assert!(p.next_delay(0, RetryDecision::Backoff, None).is_none());
        assert!(p.next_delay(1, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn next_delay_at_u32_max_returns_none_even_when_unlimited() {
        let p = RetryPolicy::new().with_max_attempts(None);
        assert!(
            p.next_delay(u32::MAX, RetryDecision::Immediate, None)
                .is_none()
        );
        assert!(
            p.next_delay(u32::MAX, RetryDecision::Backoff, None)
                .is_none()
        );
    }

    #[test]
    fn compute_backoff_base_one() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1)
            .with_max_backoff_ms(1024)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1);
        assert_eq!(p.compute_backoff_ms(10), 1024);
    }

    #[test]
    fn compute_backoff_max_less_than_computed() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(500)
            .with_max_backoff_ms(500)
            .with_jitter_enabled(false);
        // Any attempt should be capped at 500
        assert_eq!(p.compute_backoff_ms(0), 500);
        assert_eq!(p.compute_backoff_ms(5), 500);
    }

    // ── NEW: decision_from_http_status comprehensive ─────────────────

    #[test]
    fn http_599_returns_backoff() {
        assert_eq!(decision_from_http_status(599, None), RetryDecision::Backoff);
    }

    #[test]
    fn http_600_returns_terminal() {
        assert_eq!(
            decision_from_http_status(600, None),
            RetryDecision::Terminal
        );
    }

    #[test]
    fn http_499_returns_terminal() {
        assert_eq!(
            decision_from_http_status(499, None),
            RetryDecision::Terminal
        );
    }

    // ── NEW: map_external_error service name propagation ─────────────

    #[test]
    fn map_external_error_service_name_preserved() {
        let (_decision, error) = map_external_error("my-service", Some(500), "error msg", None);
        match error {
            FcpError::External {
                service, message, ..
            } => {
                assert_eq!(service, "my-service");
                assert_eq!(message, "error msg");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_no_status_parse_error_is_terminal() {
        let (decision, _error) = map_external_error("svc", None, "can't parse entities", None);
        assert_eq!(decision, RetryDecision::Terminal);
    }

    // ── NEW: duration_to_ms additional edge cases ────────────────────

    #[test]
    fn duration_to_ms_one_second() {
        assert_eq!(duration_to_ms(Duration::from_secs(1)), 1_000);
    }

    #[test]
    fn duration_to_ms_fractional() {
        assert_eq!(duration_to_ms(Duration::from_millis(1500)), 1500);
    }

    // ── NEW: RetryDecision Copy semantics ──────────────────────────────

    #[test]
    fn retry_decision_is_copy() {
        let d = RetryDecision::Backoff;
        let copy1 = d;
        let copy2 = d;
        assert_eq!(copy1, copy2);
    }

    #[test]
    fn retry_decision_after_copy_preserves_duration() {
        let d = RetryDecision::After(Duration::from_secs(7));
        let copy = d;
        assert_eq!(d.retry_after(), copy.retry_after());
    }

    // ── NEW: RetryPolicy builder returns correct types ─────────────────

    #[test]
    fn retry_policy_with_base_backoff_zero() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(0)
            .with_jitter_enabled(false);
        // 0 is promoted to 1 to prevent busy-wait loops
        assert_eq!(p.compute_backoff_ms(0), 1); // 1 * 2^0
        assert_eq!(p.compute_backoff_ms(10), 1024); // 1 * 2^10
    }

    #[test]
    fn retry_policy_with_max_backoff_zero() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1000)
            .with_max_backoff_ms(0)
            .with_jitter_enabled(false);
        // min(1000, 0) = 0 but base > 0, so clamped to 1 to prevent busy-wait
        assert_eq!(p.compute_backoff_ms(0), 1);
    }

    #[test]
    fn retry_policy_with_max_backoff_less_than_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(5000)
            .with_max_backoff_ms(1000)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1000);
    }

    // ── NEW: compute_backoff_ms specific attempts ──────────────────────

    #[test]
    fn compute_backoff_attempt_four() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1000)
            .with_max_backoff_ms(100_000)
            .with_jitter_enabled(false);
        // 1000 * 2^4 = 16000
        assert_eq!(p.compute_backoff_ms(4), 16_000);
    }

    #[test]
    fn compute_backoff_attempt_exactly_30() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1)
            .with_max_backoff_ms(u64::MAX)
            .with_jitter_enabled(false);
        // 1 * 2^30 = 1073741824
        assert_eq!(p.compute_backoff_ms(30), 1_073_741_824);
    }

    #[test]
    fn compute_backoff_attempt_31_same_as_30() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1)
            .with_max_backoff_ms(u64::MAX)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(30), p.compute_backoff_ms(31));
        assert_eq!(p.compute_backoff_ms(30), p.compute_backoff_ms(100));
    }

    // ── NEW: compute_backoff_with_jitter_ms detailed ───────────────────

    #[test]
    fn jitter_factor_quarter_gives_62_percent() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1000)
            .with_jitter_enabled(true);
        // factor=0.25 -> 0.25*0.5+0.5=0.625 -> 1000*0.625=625
        let result = p.compute_backoff_with_jitter_ms(0, 0.25);
        assert_eq!(result, 625);
    }

    #[test]
    fn jitter_factor_three_quarters() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1000)
            .with_jitter_enabled(true);
        // factor=0.75 -> 0.75*0.5+0.5=0.875 -> 1000*0.875=875
        let result = p.compute_backoff_with_jitter_ms(0, 0.75);
        assert_eq!(result, 875);
    }

    #[test]
    fn jitter_with_higher_attempt_still_works() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(100)
            .with_max_backoff_ms(10_000)
            .with_jitter_enabled(true);
        // attempt=3 -> base=100*2^3=800, factor=0.5 -> 0.5*0.5+0.5=0.75 -> 800*0.75=600
        let result = p.compute_backoff_with_jitter_ms(3, 0.5);
        assert_eq!(result, 600);
    }

    // ── NEW: next_delay comprehensive combinations ─────────────────────

    #[test]
    fn next_delay_terminal_always_none_regardless_of_attempts() {
        let p = RetryPolicy::new().with_max_attempts(None);
        for attempt in [0, 1, 10, 100, 1000] {
            assert!(
                p.next_delay(attempt, RetryDecision::Terminal, None)
                    .is_none(),
                "attempt {attempt} should be None for Terminal"
            );
        }
    }

    #[test]
    fn next_delay_immediate_always_zero_regardless_of_hint() {
        let p = RetryPolicy::new();
        let hints = [
            None,
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(3600)),
        ];
        for hint in hints {
            let delay = p.next_delay(0, RetryDecision::Immediate, hint);
            assert_eq!(delay, Some(Duration::ZERO));
        }
    }

    #[test]
    fn next_delay_backoff_no_jitter_grows_exponentially() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(100)
            .with_max_backoff_ms(100_000)
            .with_jitter_enabled(false)
            .with_max_attempts(None);

        let d0 = p.next_delay(0, RetryDecision::Backoff, None).unwrap();
        let d1 = p.next_delay(1, RetryDecision::Backoff, None).unwrap();
        let d2 = p.next_delay(2, RetryDecision::Backoff, None).unwrap();

        assert_eq!(d0, Duration::from_millis(100));
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
    }

    #[test]
    fn next_delay_max_attempts_zero_always_none() {
        let p = RetryPolicy::new().with_max_attempts(Some(0));
        assert!(p.next_delay(0, RetryDecision::Immediate, None).is_none());
        assert!(p.next_delay(0, RetryDecision::Backoff, None).is_none());
        assert!(
            p.next_delay(0, RetryDecision::After(Duration::from_secs(1)), None)
                .is_none()
        );
    }

    // ── NEW: decision_from_http_status comprehensive coverage ──────────

    #[test]
    fn http_200_to_399_all_terminal() {
        for status in [200, 201, 204, 301, 302, 304, 399] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be Terminal"
            );
        }
    }

    #[test]
    fn http_400_to_428_terminal_except_408_425() {
        for status in [400, 401, 402, 403, 404, 405, 409, 410, 415, 422, 426, 428] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be Terminal"
            );
        }
    }

    #[test]
    fn http_500_to_504_all_backoff() {
        for status in [500, 501, 502, 503, 504] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Backoff,
                "status {status} should be Backoff"
            );
        }
    }

    // ── NEW: map_external_error with varied inputs ─────────────────────

    #[test]
    fn map_external_error_408_retryable() {
        let (decision, error) = map_external_error("svc", Some(408), "timeout", None);
        assert_eq!(decision, RetryDecision::Backoff);
        match error {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_425_retryable() {
        let (decision, _) = map_external_error("svc", Some(425), "too early", None);
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn map_external_error_no_status_rate_limit_message() {
        let (decision, _) = map_external_error("api", None, "rate limit hit", None);
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn map_external_error_429_default_retry_after_30s() {
        let (_, error) = map_external_error("api", Some(429), "rate limited", None);
        match error {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 30_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_503_with_hint_propagates_retry_after() {
        let hint = Duration::from_secs(45);
        let (_, error) = map_external_error("svc", Some(503), "unavailable", Some(hint));
        match error {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(hint));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_terminal_no_retry_after() {
        let (_, error) = map_external_error("svc", Some(400), "bad request", None);
        match error {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── NEW: duration_to_ms precision ──────────────────────────────────

    #[test]
    fn duration_to_ms_nanos_truncated() {
        // 1ms + 999_999ns = just under 2ms, should truncate to 1
        let d = Duration::from_millis(1) + Duration::from_nanos(999_999);
        assert_eq!(duration_to_ms(d), 1);
    }

    #[test]
    fn duration_to_ms_exactly_two_ms() {
        assert_eq!(duration_to_ms(Duration::from_millis(2)), 2);
    }

    // ── NEW: pseudo_random_jitter stress test ──────────────────────────

    #[test]
    fn pseudo_random_jitter_extreme_attempt_values() {
        for attempt in [0, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
            let j = pseudo_random_jitter(attempt);
            assert!(j >= 0.0, "jitter for attempt {attempt} must be >= 0.0");
            assert!(j < 1.0, "jitter for attempt {attempt} must be < 1.0");
        }
    }
}
