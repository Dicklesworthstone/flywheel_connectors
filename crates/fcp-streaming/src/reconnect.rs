//! Reconnection strategies and utilities.
//!
//! Provides automatic reconnection with configurable backoff.

use std::future::Future;
use std::time::Duration;

use fcp_async_core::time::sleep;
use tracing::{debug, warn};

use crate::{
    DEFAULT_RECONNECT_DELAY, MAX_RECONNECT_DELAY, MIN_RECONNECT_DELAY, StreamError, StreamResult,
};

const MAX_SAFE_RECONNECT_DELAY_SECS_F64: f64 = 9_007_199_254_740_992.0;

/// Reconnection configuration.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Maximum number of reconnection attempts.
    pub max_attempts: Option<u32>,
    /// Initial delay before first reconnection.
    pub initial_delay: Duration,
    /// Maximum permitted wait between reconnections. Server minimums beyond
    /// this limit refuse reconnect instead of being shortened.
    pub max_delay: Duration,
    /// Backoff multiplier.
    pub backoff_multiplier: f64,
    /// Whether to add jitter.
    pub jitter: bool,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: Some(10),
            initial_delay: DEFAULT_RECONNECT_DELAY,
            max_delay: MAX_RECONNECT_DELAY,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl ReconnectConfig {
    /// Create a new reconnection configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum attempts.
    #[must_use]
    pub const fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// Set unlimited reconnection attempts.
    #[must_use]
    pub const fn with_unlimited_attempts(mut self) -> Self {
        self.max_attempts = None;
        self
    }

    /// Set initial delay.
    #[must_use]
    pub const fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set maximum delay.
    #[must_use]
    pub const fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set backoff multiplier.
    #[must_use]
    pub const fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter = enabled;
        self
    }

    /// Combine local backoff with a server minimum without shortening either.
    ///
    /// # Errors
    /// Returns [`StreamError::ReconnectDelayExceeded`] if the server minimum
    /// cannot fit the local wait policy. No timer should be started in that case.
    pub fn delay_for_attempt_with_minimum(
        &self,
        attempt: u32,
        minimum: Option<Duration>,
    ) -> StreamResult<Duration> {
        let required = minimum.unwrap_or_default();
        if required > self.max_delay {
            return Err(StreamError::ReconnectDelayExceeded {
                required,
                max: self.max_delay,
            });
        }
        Ok(self.delay_for_attempt(attempt).max(required))
    }

    /// Calculate delay for a given attempt.
    ///
    /// Enforces three invariants (bead `flywheel_connectors-y54mi`):
    ///   1. **Floor:** the returned `Duration` is never below
    ///      `MIN_RECONNECT_DELAY` (100 ms) unless the caller pinned
    ///      `max_delay` even lower — a zero or sub-millisecond
    ///      `initial_delay` must not collapse the wait to a hot loop.
    ///   2. **Ceiling:** capped at `max_delay`.
    ///   3. **Bounded jitter:** when `jitter` is enabled, the final
    ///      delay is base × ±20 % (uniform in `[0.8, 1.2]`) instead
    ///      of the looser ±50 % the implementation used to apply.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        let base = self
            .initial_delay
            .as_secs_f64()
            .mul_add(self.backoff_multiplier.powi(exponent), 0.0);
        let jittered = if self.jitter {
            // ±20% jitter: uniform in [0.8, 1.2]. Tighter than the
            // previous ±50% so two clients reconnecting to the same
            // upstream don't drift apart fast enough to lose useful
            // batching at low attempt counts, but still wide enough
            // to thundering-herd-bust a synchronised reconnect storm.
            let jitter = random_float().mul_add(0.4, 0.8);
            base * jitter
        } else {
            base
        };

        // Clamp to a non-negative, finite f64 that is *exactly* representable
        // as a `Duration`. `Duration::from_secs_f64` panics on negative, NaN,
        // non-finite, OR overflowing inputs. Two separate failure modes had
        // to be guarded:
        //
        // 1. A misconfigured `backoff_multiplier` (negative, NaN, or large
        //    enough to overflow `powi` to +inf at high attempt counts) could
        //    otherwise turn a recoverable retry into a process abort.
        //
        // 2. `max_delay.as_secs_f64()` rounds up past `u64::MAX` when
        //    `max_delay` is near `Duration::MAX` (the nearest f64 to
        //    `u64::MAX` is `2^64`, one more than the largest Duration can
        //    hold). The old clamp trusted that value as the ceiling, so a
        //    user-configured huge `max_delay` combined with a +inf `jittered`
        //    would pick up `2^64` seconds and panic inside `from_secs_f64`.
        //
        // `2^53` seconds (~285 million years) is the largest integer
        // exactly representable as `f64`; capping there guarantees the
        // value round-trips safely. We then intersect with `max_delay`
        // back in `Duration` space so legitimate small ceilings still win.
        let clamped = if jittered.is_nan() || jittered < 0.0 {
            0.0
        } else {
            jittered.min(MAX_SAFE_RECONNECT_DELAY_SECS_F64)
        };
        // Apply the MIN floor BEFORE the max cap. If a caller pinned
        // `max_delay` below MIN_RECONNECT_DELAY, the ceiling wins —
        // we respect explicit user caps rather than violating them
        // to satisfy the floor. Otherwise every wait is at least 100 ms.
        let floor = MIN_RECONNECT_DELAY.min(self.max_delay);
        Duration::from_secs_f64(clamped)
            .max(floor)
            .min(self.max_delay)
    }
}

/// Reconnection handler.
#[derive(Debug)]
pub struct ReconnectHandler {
    config: ReconnectConfig,
    attempts: u32,
}

impl ReconnectHandler {
    /// Create a new reconnection handler.
    #[must_use]
    pub const fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            attempts: 0,
        }
    }

    /// Reset the reconnection state.
    pub const fn reset(&mut self) {
        self.attempts = 0;
    }

    /// Get the current attempt count.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Record a failure (increment attempt count).
    ///
    /// Uses saturating addition so the counter cannot wrap from
    /// `u32::MAX` back to zero, which would reset the retry budget.
    pub const fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Check if reconnection is allowed.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn can_reconnect(&self) -> bool {
        self.config
            .max_attempts
            .is_none_or(|max| self.attempts < max)
    }

    /// Wait for the next reconnection attempt.
    ///
    /// # Errors
    /// Returns [`StreamError::ReconnectLimitExceeded`] when the retry budget is exhausted.
    pub async fn wait_for_reconnect(&mut self) -> StreamResult<()> {
        self.wait_for_reconnect_after(None).await
    }

    /// Wait for the next attempt while preserving an upstream minimum delay.
    ///
    /// # Errors
    /// Returns a reconnect limit or delay-policy error before waiting when the
    /// next attempt cannot be admitted.
    pub async fn wait_for_reconnect_after(
        &mut self,
        minimum: Option<Duration>,
    ) -> StreamResult<()> {
        if !self.can_reconnect() {
            return Err(StreamError::ReconnectLimitExceeded {
                attempts: self.attempts,
            });
        }

        let delay = self
            .config
            .delay_for_attempt_with_minimum(self.attempts, minimum)?;
        debug!(
            attempt = self.attempts,
            delay_ms = delay.as_millis(),
            "Waiting before reconnection"
        );

        sleep(delay).await;
        self.attempts = self.attempts.saturating_add(1);

        Ok(())
    }

    /// Execute a reconnectable operation.
    ///
    /// # Errors
    /// Returns the underlying operation error or a reconnect limit error.
    pub async fn reconnect<T, F, Fut>(&mut self, mut operation: F) -> StreamResult<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = StreamResult<T>>,
    {
        loop {
            match operation().await {
                Ok(result) => {
                    self.reset();
                    return Ok(result);
                }
                Err(e) => {
                    if e.is_terminal_backpressure()
                        || matches!(&e, StreamError::ReconnectDelayExceeded { .. })
                    {
                        warn!(
                            error = %e,
                            attempt = self.attempts,
                            "Operation failed with terminal reconnect policy; refusing retry"
                        );
                        return Err(e);
                    }

                    warn!(
                        error = %e,
                        attempt = self.attempts,
                        "Operation failed, attempting reconnection"
                    );

                    if !self.can_reconnect() {
                        return Err(StreamError::ReconnectLimitExceeded {
                            attempts: self.attempts,
                        });
                    }

                    if let Err(error) = self.wait_for_reconnect_after(e.retry_after()).await {
                        // Preserve status and retry guidance from the upstream
                        // when local policy refuses its minimum wait.
                        if matches!(error, StreamError::ReconnectDelayExceeded { .. }) {
                            return Err(e);
                        }
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &ReconnectConfig {
        &self.config
    }
}

/// Execute an operation with automatic retry.
///
/// # Errors
/// Returns the underlying operation error or a reconnect limit error.
pub async fn with_retry<T, F, Fut>(config: ReconnectConfig, operation: F) -> StreamResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StreamResult<T>>,
{
    let mut handler = ReconnectHandler::new(config);
    handler.reconnect(operation).await
}

/// Simple random float generator (0.0 to 1.0).
fn random_float() -> f64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_minimum_is_never_shortened_by_jitter_or_backoff() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(2));
        for minimum in [Duration::from_nanos(1_000_000_001), config.max_delay] {
            for _ in 0..20 {
                let delay = config
                    .delay_for_attempt_with_minimum(0, Some(minimum))
                    .unwrap();
                assert!(delay >= minimum);
                assert!(delay <= config.max_delay);
            }
        }
        for minimum in [config.max_delay + Duration::from_nanos(1), Duration::MAX] {
            assert!(matches!(
                config.delay_for_attempt_with_minimum(0, Some(minimum)),
                Err(StreamError::ReconnectDelayExceeded { required, max })
                    if required == minimum && max == config.max_delay
            ));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn reconnect_refuses_provider_minimum_before_another_attempt() {
        let mut handler =
            ReconnectHandler::new(ReconnectConfig::new().with_max_delay(Duration::from_millis(1)));
        let mut calls = 0;
        let error = handler
            .reconnect(|| {
                calls += 1;
                async {
                    Err::<(), _>(StreamError::HttpError {
                        status: 429,
                        message: "provider rate limit".into(),
                        retry_after: Some(Duration::from_secs(60)),
                    })
                }
            })
            .await
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(handler.attempts(), 0);
        assert!(
            matches!(error, StreamError::HttpError { status: 429, retry_after, .. }
            if retry_after == Some(Duration::from_secs(60)))
        );
    }

    #[test]
    fn test_reconnect_config_default() {
        let config = ReconnectConfig::default();
        assert_eq!(config.max_attempts, Some(10));
        assert_eq!(config.initial_delay, DEFAULT_RECONNECT_DELAY);
        assert!(config.jitter);
    }

    #[test]
    fn test_delay_calculation_no_jitter() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(8));
        // Capped at max
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(60));
    }

    #[test]
    fn test_reconnect_handler_can_reconnect() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect());
        handler.attempts = 2;
        assert!(handler.can_reconnect());
        handler.attempts = 3;
        assert!(!handler.can_reconnect());
    }

    #[test]
    fn test_reconnect_handler_unlimited() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let mut handler = ReconnectHandler::new(config);

        handler.attempts = 1000;
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_reconnect_handler_reset() {
        let config = ReconnectConfig::new();
        let mut handler = ReconnectHandler::new(config);

        handler.attempts = 5;
        handler.reset();
        assert_eq!(handler.attempts(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_success() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut attempts = 0;

        let result = with_retry(config, || {
            attempts += 1;
            async move {
                if attempts < 2 {
                    Err(StreamError::ConnectionFailed("test".into()))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_refuses_budget_backpressure() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1));
        let mut attempts = 0;

        let result: StreamResult<()> = with_retry(config, || {
            attempts += 1;
            async move {
                Err(StreamError::HostBackpressure {
                    status: crate::HOST_BACKPRESSURE_STATUS,
                    message: "Service Unavailable".into(),
                    signal: crate::HostBackpressureSignal::new(
                        crate::FCP_BACKPRESSURE_BUDGET_EXHAUSTED,
                        Some(Duration::from_secs(10)),
                    ),
                })
            }
        })
        .await;

        assert_eq!(attempts, 1);
        assert!(matches!(
            result,
            Err(StreamError::HostBackpressure { signal, .. })
                if signal.is_budget_exhausted()
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(2)
            .with_initial_delay(Duration::from_millis(1));

        let result: StreamResult<i32> = with_retry(config, || async {
            Err(StreamError::ConnectionFailed("always fails".into()))
        })
        .await;

        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { .. })
        ));
    }

    // ── New tests ──

    #[test]
    fn test_reconnect_config_builder_chain() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(3.0)
            .with_jitter(false);

        assert_eq!(config.max_attempts, Some(5));
        assert_eq!(config.initial_delay, Duration::from_millis(100));
        assert_eq!(config.max_delay, Duration::from_secs(10));
        assert!((config.backoff_multiplier - 3.0).abs() < f64::EPSILON);
        assert!(!config.jitter);
    }

    #[test]
    fn test_delay_with_jitter_bounded() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(true);

        // ±20% jitter (0.8x..1.2x), attempt 0 base is 1s → [800ms, 1200ms].
        let delay = config.delay_for_attempt(0);
        assert!(delay >= Duration::from_millis(800));
        assert!(delay <= Duration::from_millis(1200));
    }

    #[test]
    fn test_delay_with_jitter_still_respects_max_delay() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        for _ in 0..20 {
            assert_eq!(config.delay_for_attempt(0), Duration::from_secs(5));
        }
    }

    #[test]
    fn test_delay_capped_at_max() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(10.0)
            .with_jitter(false);

        // attempt 2: 1 * 10^2 = 100s, capped at 5s
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_reconnect_handler_config_accessor() {
        let config = ReconnectConfig::new().with_max_attempts(7);
        let handler = ReconnectHandler::new(config);
        assert_eq!(handler.config().max_attempts, Some(7));
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(0)
            .with_initial_delay(Duration::from_millis(1));
        let mut handler = ReconnectHandler::new(config);

        let result = handler.wait_for_reconnect().await;
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 0 })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_increments_attempts() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        assert_eq!(handler.attempts(), 0);
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 1);
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 2);
    }

    // ── Additional ReconnectConfig tests ──

    #[test]
    fn test_delay_zero_multiplier() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(0.0)
            .with_jitter(false);

        // 0^n = 0 for n>0, so the base goes to zero at attempt > 0; the
        // MIN_RECONNECT_DELAY floor then applies.
        // attempt 0: 1 * 0^0 = 1 * 1 = 1s (unchanged, above floor).
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
        // attempt 1+: base collapses to 0 → floored to MIN_RECONNECT_DELAY.
        assert_eq!(config.delay_for_attempt(1), MIN_RECONNECT_DELAY);
    }

    #[test]
    fn test_delay_multiplier_one() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(2))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(false);

        // With multiplier 1.0, delay is constant
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(2));
    }

    #[test]
    fn test_delay_large_attempt_capped() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Very large attempt: should be capped at max_delay
        let delay = config.delay_for_attempt(100);
        assert_eq!(delay, Duration::from_secs(30));
    }

    #[test]
    fn test_delay_i32_max_attempt() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // u32::MAX attempt should gracefully handle i32 overflow
        let delay = config.delay_for_attempt(u32::MAX);
        assert_eq!(delay, Duration::from_secs(10));
    }

    #[test]
    fn test_delay_negative_multiplier_does_not_panic() {
        // A negative backoff_multiplier alternates the sign of the computed
        // base delay. Without clamping, Duration::from_secs_f64 panics on
        // negative input — turning a recoverable misconfig into a process
        // abort. The clamp must coerce negative to zero AND the MIN floor
        // must then round up to MIN_RECONNECT_DELAY.
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(-2.0)
            .with_jitter(false);

        // attempt 1 yields base = 1 * (-2)^1 = -2.0 → clamp to 0 →
        // floor to MIN_RECONNECT_DELAY.
        let delay = config.delay_for_attempt(1);
        assert_eq!(delay, MIN_RECONNECT_DELAY);
    }

    #[test]
    fn test_delay_huge_max_delay_does_not_panic() {
        // Regression: when `max_delay` is near `Duration::MAX`, its
        // `as_secs_f64()` rounds up past `u64::MAX` (the nearest f64 to
        // `u64::MAX` is `2^64`, which is one more than `Duration` can
        // hold). At high attempt counts the backoff overflows `powi` to
        // `+inf`, and the old `jittered.min(max)` clamp picked up that
        // rounded-up ceiling, causing `Duration::from_secs_f64` to panic
        // inside the retry hot path — a misconfig turning into a
        // process abort. Must be clamped to a safe f64 value first, then
        // intersected with `max_delay` back in Duration space.
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(u64::MAX))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Large attempt forces `2.0.powi(exponent)` to `+inf`.
        let delay = config.delay_for_attempt(100);
        assert!(
            delay <= Duration::from_secs(u64::MAX),
            "delay must not exceed max_delay: got {delay:?}"
        );
        assert!(
            delay > Duration::ZERO,
            "delay should have saturated to a large finite value, got {delay:?}"
        );
    }

    #[test]
    fn test_delay_huge_max_delay_with_jitter_does_not_panic() {
        // Same hazard as above but with jitter enabled — jitter
        // multiplies `+inf` by a value in `[0.5, 1.5)`, still `+inf`,
        // and the clamp path must still produce a valid Duration
        // instead of panicking on the oversized f64.
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(u64::MAX))
            .with_backoff_multiplier(2.0)
            .with_jitter(true);

        let delay = config.delay_for_attempt(100);
        assert!(
            delay <= Duration::from_secs(u64::MAX),
            "delay must not exceed max_delay: got {delay:?}"
        );
    }

    #[test]
    fn test_delay_nan_multiplier_does_not_panic() {
        // A NaN multiplier propagates through powi/mul_add to a NaN delay.
        // Duration::from_secs_f64 panics on NaN; clamp must coerce to zero
        // and MIN_RECONNECT_DELAY must then round up to the floor.
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(f64::NAN)
            .with_jitter(false);

        let delay = config.delay_for_attempt(3);
        assert_eq!(delay, MIN_RECONNECT_DELAY);
    }

    // ── Metamorphic relations ─────────────────────────────────────

    /// Metamorphic: with jitter disabled and a positive `backoff_multiplier`
    /// at least `1.0`, `delay_for_attempt` must be monotonically non-decreasing in
    /// the attempt counter all the way up to `max_delay`. A regression that
    /// inverted the exponent or corrupted the clamp would surface here.
    #[test]
    fn test_delay_monotonic_without_jitter() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(3600))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        let mut prev = config.delay_for_attempt(0);
        for attempt in 1..20 {
            let d = config.delay_for_attempt(attempt);
            assert!(
                d >= prev,
                "delay must not decrease: attempt={attempt} prev={prev:?} d={d:?}"
            );
            prev = d;
        }
    }

    /// Metamorphic: `delay_for_attempt` is a pure function of (config, attempt)
    /// when jitter is disabled — repeated calls with identical inputs must
    /// produce byte-identical Duration values. This pins the invariant that
    /// the clamp and backoff math have no hidden state and no implicit RNG
    /// use when jitter=false.
    #[test]
    fn test_delay_for_attempt_is_deterministic_without_jitter() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(250))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);

        for attempt in [0, 1, 3, 7, 15, 31] {
            let a = config.delay_for_attempt(attempt);
            let b = config.delay_for_attempt(attempt);
            assert_eq!(a, b, "attempt={attempt} a={a:?} b={b:?}");
        }
    }

    /// Metamorphic: `reset()` is idempotent. Calling `reset` after a reset must
    /// leave the handler in the same observable state as a single reset.
    /// Also verifies that `record_failure` to `reset` collapses cleanly, which
    /// is the hot-path invariant invoked by `ReconnectingWsStream` when a
    /// message finally arrives on a freshly-reconnected stream.
    #[test]
    fn test_handler_reset_is_idempotent() {
        let config = ReconnectConfig::new().with_max_attempts(10);
        let mut a = ReconnectHandler::new(config.clone());
        let mut b = ReconnectHandler::new(config);

        for _ in 0..5 {
            a.record_failure();
            b.record_failure();
        }
        assert_eq!(a.attempts(), b.attempts());

        a.reset();
        b.reset();
        b.reset(); // second reset must be a no-op
        assert_eq!(a.attempts(), b.attempts());
        assert_eq!(a.attempts(), 0);
        assert_eq!(a.can_reconnect(), b.can_reconnect());
    }

    #[test]
    fn test_config_new_equals_default() {
        let new = ReconnectConfig::new();
        let default = ReconnectConfig::default();

        assert_eq!(new.max_attempts, default.max_attempts);
        assert_eq!(new.initial_delay, default.initial_delay);
        assert_eq!(new.max_delay, default.max_delay);
        assert!((new.backoff_multiplier - default.backoff_multiplier).abs() < f64::EPSILON);
        assert_eq!(new.jitter, default.jitter);
    }

    #[test]
    fn test_config_clone() {
        let config = ReconnectConfig::new()
            .with_max_attempts(7)
            .with_jitter(false);
        let moved = config;
        assert_eq!(moved.max_attempts, Some(7));
        assert!(!moved.jitter);
    }

    // ── Additional ReconnectHandler tests ──

    #[test]
    fn test_handler_record_failure_increments() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let mut handler = ReconnectHandler::new(config);

        assert_eq!(handler.attempts(), 0);
        handler.record_failure();
        assert_eq!(handler.attempts(), 1);
        handler.record_failure();
        assert_eq!(handler.attempts(), 2);
    }

    #[test]
    fn test_handler_record_failure_then_reset() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 3);
        handler.reset();
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_handler_can_reconnect_boundary() {
        let config = ReconnectConfig::new().with_max_attempts(2);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect()); // 0 < 2
        handler.record_failure();
        assert!(handler.can_reconnect()); // 1 < 2
        handler.record_failure();
        assert!(!handler.can_reconnect()); // 2 >= 2
    }

    #[test]
    fn test_handler_zero_max_attempts() {
        let config = ReconnectConfig::new().with_max_attempts(0);
        let handler = ReconnectHandler::new(config);

        // Zero max attempts means reconnection is never allowed
        assert!(!handler.can_reconnect());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_succeeds_first_try() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1));
        let mut handler = ReconnectHandler::new(config);

        let result = handler
            .reconnect(|| async { Ok::<_, StreamError>(99) })
            .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(handler.attempts(), 0); // reset on success
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_resets_on_success() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let mut call_count = 0;
        let result = handler
            .reconnect(|| {
                call_count += 1;
                async move {
                    if call_count < 3 {
                        Err(StreamError::ConnectionFailed("fail".into()))
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(handler.attempts(), 0); // reset after success
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_immediate_success() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let result = with_retry(config, || async { Ok::<_, StreamError>("hello") }).await;
        assert_eq!(result.unwrap(), "hello");
    }

    // ── ReconnectConfig debug ──

    #[test]
    fn test_reconnect_config_debug() {
        let config = ReconnectConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("ReconnectConfig"));
    }

    #[test]
    fn test_reconnect_handler_debug() {
        let config = ReconnectConfig::new();
        let handler = ReconnectHandler::new(config);
        let debug = format!("{handler:?}");
        assert!(debug.contains("ReconnectHandler"));
    }

    // ── Delay calculation edge cases ──

    #[test]
    fn test_delay_fractional_multiplier() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(4))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(0.5)
            .with_jitter(false);

        // 4 * 0.5^0 = 4, 4 * 0.5^1 = 2, 4 * 0.5^2 = 1
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(1));
    }

    #[test]
    fn test_delay_very_small_initial() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Anything below MIN_RECONNECT_DELAY is rounded up to the floor;
        // once the exponential climb crosses the floor, the raw math wins.
        assert_eq!(config.delay_for_attempt(0), MIN_RECONNECT_DELAY); // 1ms → 100ms
        assert_eq!(config.delay_for_attempt(1), MIN_RECONNECT_DELAY); // 2ms → 100ms
        assert_eq!(config.delay_for_attempt(6), MIN_RECONNECT_DELAY); // 64ms → 100ms
        assert_eq!(config.delay_for_attempt(10), Duration::from_millis(1024));
    }

    #[test]
    fn test_delay_jitter_statistical_bounds() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        // ±20% jitter (0.8x..1.2x), base 10s → range [8s, 12s].
        for _ in 0..50 {
            let delay = config.delay_for_attempt(0);
            assert!(
                delay >= Duration::from_secs(8),
                "delay {delay:?} below lower jitter bound"
            );
            assert!(
                delay <= Duration::from_secs(12),
                "delay {delay:?} above upper jitter bound"
            );
        }
    }

    #[test]
    fn test_delay_max_exactly_equals_base() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(5))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // All attempts capped at 5s
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(100), Duration::from_secs(5));
    }

    // ── Handler lifecycle tests ──

    #[test]
    fn test_handler_multi_cycle_reset() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        // First cycle
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 2);

        // Reset simulates successful reconnection
        handler.reset();
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());

        // Second cycle
        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert!(!handler.can_reconnect());

        // Reset again
        handler.reset();
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_handler_max_attempts_one() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect());
        handler.record_failure();
        assert!(!handler.can_reconnect());
    }

    #[test]
    fn test_handler_unlimited_many_failures() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let mut handler = ReconnectHandler::new(config);

        for _ in 0..10_000 {
            handler.record_failure();
        }
        assert!(handler.can_reconnect());
        assert_eq!(handler.attempts(), 10_000);
    }

    // ── Async reconnect tests ──

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_multiple_failures_then_success() {
        let config = ReconnectConfig::new()
            .with_max_attempts(10)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let mut call_count = 0;
        let result = handler
            .reconnect(|| {
                call_count += 1;
                async move {
                    if call_count < 5 {
                        Err(StreamError::ConnectionFailed(format!("fail {call_count}")))
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count, 5);
        assert_eq!(handler.attempts(), 0); // reset on success
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_success_then_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(2)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        // First wait succeeds
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 1);

        // Second wait succeeds
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 2);

        // Third should be exhausted
        let result = handler.wait_for_reconnect().await;
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 2 })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_returns_correct_type() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let result: StreamResult<Vec<i32>> =
            with_retry(config, || async { Ok(vec![1, 2, 3]) }).await;
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }

    // ── ReconnectConfig: clone preserves all fields ─────────────────────

    #[test]
    fn test_config_clone_preserves_all_fields() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(250))
            .with_max_delay(Duration::from_secs(20))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);
        let cloned = config.clone();
        assert_eq!(config.max_attempts, cloned.max_attempts);
        assert_eq!(config.initial_delay, cloned.initial_delay);
        assert_eq!(config.max_delay, cloned.max_delay);
        assert!((config.backoff_multiplier - cloned.backoff_multiplier).abs() < f64::EPSILON);
        assert_eq!(config.jitter, cloned.jitter);
    }

    // ── ReconnectConfig: unlimited clone ─────────────────────────────────

    #[test]
    fn test_config_unlimited_attempts_clone() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let cloned = config.clone();
        assert_eq!(config.max_attempts, None);
        assert_eq!(cloned.max_attempts, None);
    }

    // ── Delay: initial_delay zero ───────────────────────────────────────

    #[test]
    fn test_delay_zero_initial_delay_is_floored() {
        // br-y54mi regression: a zero initial_delay used to propagate
        // through to Duration::ZERO, which collapsed wait_for_reconnect
        // into a hot retry storm. The MIN_RECONNECT_DELAY floor now
        // guarantees every returned delay is at least 100ms even when
        // the caller pins initial_delay to zero.
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::ZERO)
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        assert_eq!(config.delay_for_attempt(0), MIN_RECONNECT_DELAY);
        assert_eq!(config.delay_for_attempt(5), MIN_RECONNECT_DELAY);
    }

    // ── Delay: max_delay zero clamps everything ─────────────────────────

    #[test]
    fn test_delay_zero_max_delay() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(5))
            .with_max_delay(Duration::ZERO)
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Everything capped at zero
        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(10), Duration::ZERO);
    }

    // ── Handler: initial state ──────────────────────────────────────────

    #[test]
    fn test_handler_initial_state() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let handler = ReconnectHandler::new(config);
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());
        assert_eq!(handler.config().max_attempts, Some(5));
    }

    // ── Handler: record_failure up to limit ─────────────────────────────

    #[test]
    fn test_handler_exhaust_via_record_failure() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 3);
        assert!(!handler.can_reconnect());
    }

    // ── Handler: config backoff multiplier 1.5 ──────────────────────────

    #[test]
    fn test_delay_multiplier_one_point_five() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);

        // attempt 0: 100ms * 1.5^0 = 100ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        // attempt 1: 100ms * 1.5^1 = 150ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(150));
        // attempt 2: 100ms * 1.5^2 = 225ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(225));
    }

    // ── Handler: reset then reuse ───────────────────────────────────────

    #[test]
    fn test_handler_reset_restores_can_reconnect() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        assert!(!handler.can_reconnect());

        handler.reset();
        assert!(handler.can_reconnect());
        assert_eq!(handler.attempts(), 0);
    }

    // ── Async: with_retry string result ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_string_result() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let result: StreamResult<String> =
            with_retry(config, || async { Ok("done".to_string()) }).await;
        assert_eq!(result.unwrap(), "done");
    }

    // ── Async: reconnect with zero max_attempts ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_zero_max_attempts_fails_immediately() {
        let config = ReconnectConfig::new().with_max_attempts(0);
        let mut handler = ReconnectHandler::new(config);

        let result = handler
            .reconnect(|| async { Err::<i32, _>(StreamError::ConnectionFailed("fail".into())) })
            .await;

        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 0 })
        ));
    }

    // ── Additional delay calculation tests ──

    #[test]
    fn test_delay_multiplier_three() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(3.0)
            .with_jitter(false);

        // attempt 0: 100ms * 3^0 = 100ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        // attempt 1: 100ms * 3^1 = 300ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(300));
        // attempt 2: 100ms * 3^2 = 900ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(900));
    }

    #[test]
    fn test_delay_multiplier_very_large() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(100.0)
            .with_jitter(false);

        // attempt 1: 10ms * 100 = 1000ms = 1s
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        // attempt 2: capped at 5s
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_delay_jitter_multiple_samples_vary() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        // Sample many delays; at least one pair should differ (probabilistically)
        let delays: Vec<Duration> = (0..20).map(|_| config.delay_for_attempt(0)).collect();
        let all_same = delays.windows(2).all(|w| w[0] == w[1]);
        // With 20 samples and jitter, probability all are identical is astronomically low
        assert!(!all_same, "jitter should produce varying delays");
    }

    // ── Handler: config immutability ──

    #[test]
    fn test_handler_config_unchanged_after_failures() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(250));
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        // Config should be unchanged
        assert_eq!(handler.config().max_attempts, Some(5));
        assert_eq!(handler.config().initial_delay, Duration::from_millis(250));
    }

    #[test]
    fn test_handler_config_unchanged_after_reset() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.reset();
        assert_eq!(handler.config().max_attempts, Some(3));
    }

    // ── Config builder override behavior ──

    #[test]
    fn test_config_max_attempts_overrides() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_max_attempts(3);
        assert_eq!(config.max_attempts, Some(3));
    }

    #[test]
    fn test_config_unlimited_then_limited() {
        let config = ReconnectConfig::new()
            .with_unlimited_attempts()
            .with_max_attempts(7);
        assert_eq!(config.max_attempts, Some(7));
    }

    #[test]
    fn test_config_limited_then_unlimited() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_unlimited_attempts();
        assert_eq!(config.max_attempts, None);
    }

    // ── ReconnectConfig Debug output ──

    #[test]
    fn test_reconnect_config_debug_contains_fields() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_jitter(false);
        let debug = format!("{config:?}");
        assert!(debug.contains("max_attempts"));
        assert!(debug.contains("jitter"));
    }

    #[test]
    fn test_reconnect_handler_debug_contains_attempts() {
        let config = ReconnectConfig::new();
        let mut handler = ReconnectHandler::new(config);
        handler.record_failure();
        let debug = format!("{handler:?}");
        assert!(debug.contains("attempts"));
    }

    // ── y54mi regression guards ────────────────────────────────────────

    /// br-y54mi: a zero `initial_delay` at the websocket boundary
    /// previously collapsed `delay_for_attempt` to `Duration::ZERO` and
    /// turned `wait_for_reconnect` into a hot retry storm. Drive the
    /// real handler through several consecutive waits with a zero
    /// `initial_delay` and assert every wall-clock duration honours the
    /// `MIN_RECONNECT_DELAY` floor.
    #[fcp_async_core::runtime::test]
    async fn test_rapid_reconnect_waits_are_floored_by_min_delay() {
        let config = ReconnectConfig::new()
            .with_max_attempts(4)
            .with_initial_delay(Duration::ZERO) // ADVERSARIAL
            .with_max_delay(Duration::from_secs(1))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        // Scheduler-jitter tolerance: tokio timer granularity + test
        // runtime contention can shave a few ms off a `sleep(100ms)`.
        let tolerance = Duration::from_millis(15);
        let floor_observed = MIN_RECONNECT_DELAY.saturating_sub(tolerance);

        for attempt in 0..4 {
            let start = std::time::Instant::now();
            handler.wait_for_reconnect().await.unwrap();
            let elapsed = start.elapsed();
            assert!(
                elapsed >= floor_observed,
                "attempt {attempt} waited {elapsed:?}, expected >= {floor_observed:?} \
                 (MIN_RECONNECT_DELAY floor — zero initial_delay must NOT collapse to a hot loop)"
            );
        }
    }

    /// br-y54mi: with a small-but-growable `initial_delay`, consecutive
    /// `wait_for_reconnect` calls must take monotonically non-decreasing
    /// wall-clock time until the `max_delay` cap is reached. Wide slop
    /// accounts for scheduler-timer granularity; the qualitative
    /// property (waits grow, never shrink back to zero) is the guard.
    #[fcp_async_core::runtime::test]
    async fn test_rapid_reconnect_waits_are_monotonically_increasing() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(60)) // below floor to exercise the clamp
            .with_max_delay(Duration::from_millis(600))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        // Expected schedule (no jitter, floor = 100ms, cap = 600ms):
        //   attempt 0: 60ms  → floor 100ms
        //   attempt 1: 120ms
        //   attempt 2: 240ms
        //   attempt 3: 480ms
        //   attempt 4: 960ms → cap 600ms
        let mut durations = Vec::with_capacity(5);
        for _ in 0..5 {
            let start = std::time::Instant::now();
            handler.wait_for_reconnect().await.unwrap();
            durations.push(start.elapsed());
        }

        // Each wait respects the MIN floor.
        let floor_observed = MIN_RECONNECT_DELAY.saturating_sub(Duration::from_millis(15));
        for (i, d) in durations.iter().enumerate() {
            assert!(
                *d >= floor_observed,
                "attempt {i} waited {d:?}, below MIN_RECONNECT_DELAY floor"
            );
        }

        // Monotonic non-decreasing with scheduler-noise slop. The slop
        // is intentionally generous so the test survives loaded CI
        // hosts; the qualitative invariant (no regression to zero) is
        // what matters, and tighter bounds are covered by the pure
        // `delay_for_attempt` tests above.
        let slop = Duration::from_millis(30);
        for i in 1..durations.len() {
            assert!(
                durations[i] + slop >= durations[i - 1],
                "wait times non-monotonic at attempt {i}: {durations:?}"
            );
        }

        // And the total wall time is bounded above by max_delay × N + slop —
        // a sanity check that the cap really kicks in.
        let total: Duration = durations.iter().sum();
        let upper = Duration::from_millis(600) * 5 + Duration::from_millis(200);
        assert!(total <= upper, "reconnect storm exceeded cap: {total:?}");
    }

    // ── Async: reconnect preserves error type ──

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_exhausted_returns_reconnect_limit_error() {
        let config = ReconnectConfig::new()
            .with_max_attempts(1)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let result: StreamResult<i32> = handler
            .reconnect(|| async { Err(StreamError::ParseError("always fail".into())) })
            .await;

        // Should get ReconnectLimitExceeded, not the original ParseError
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { .. })
        ));
    }
}
