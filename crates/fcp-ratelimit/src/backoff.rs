//! Backoff strategies for rate limit handling.
//!
//! Provides various backoff algorithms for retry logic.

use std::time::Duration;

/// Trait for backoff strategies.
pub trait BackoffStrategy: Send + Sync {
    /// Get the next backoff duration.
    fn next_backoff(&mut self, attempt: u32) -> Duration;

    /// Reset the backoff state.
    fn reset(&mut self);

    /// Clone the strategy into a boxed trait object.
    fn clone_box(&self) -> Box<dyn BackoffStrategy>;
}

/// Exponential backoff with optional jitter.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial backoff duration.
    pub initial: Duration,

    /// Maximum backoff duration.
    pub max: Duration,

    /// Multiplier for each attempt.
    pub multiplier: f64,

    /// Whether to add jitter.
    pub jitter: Option<f64>,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff.
    #[must_use]
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            multiplier: 2.0,
            jitter: Some(0.5),
        }
    }

    /// Set the multiplier.
    #[must_use]
    pub const fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, jitter: Option<f64>) -> Self {
        self.jitter = jitter;
        self
    }

    /// Common preset: 1s initial, 60s max.
    #[must_use]
    pub const fn default_backoff() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60))
    }

    /// Common preset: aggressive (short delays).
    #[must_use]
    pub const fn aggressive() -> Self {
        Self::new(Duration::from_millis(100), Duration::from_secs(10))
    }

    /// Common preset: conservative (longer delays).
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(300))
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::default_backoff()
    }
}

impl BackoffStrategy for ExponentialBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        let max_secs = self.max.as_secs_f64();
        let initial_secs = self.initial.as_secs_f64();

        // Guard: if initial is zero, 0 * 2^n = 0 for any n.
        if initial_secs <= 0.0 {
            return Duration::ZERO;
        }
        // Guard: if max is zero, everything caps to zero.
        if max_secs <= 0.0 {
            return Duration::ZERO;
        }

        // Saturate the exponent rather than `as i32`: a very large `attempt`
        // (>= 2^31) would wrap to a negative `i32`, making `powi` UNDERFLOW to
        // ~0 and collapsing the backoff to ~zero (immediate retry) instead of
        // capping at `max`. `i32::MAX` drives `powi` to +inf → the `!is_finite`
        // guard below then correctly clamps to `max_secs`.
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        let base = initial_secs * self.multiplier.powi(exponent);

        // Guard against NaN/infinity from extreme multiplier or attempt values.
        let capped = if base.is_finite() {
            base.min(max_secs)
        } else {
            max_secs
        };

        let result = self.jitter.map_or(capped, |jitter| {
            // Clamp jitter to valid range to prevent NaN propagation.
            let jitter = jitter.clamp(0.0, 1.0);
            let random_float = rand::random::<f64>();
            let jitter_factor = random_float.mul_add(jitter * 2.0, 1.0 - jitter);
            capped * jitter_factor
        });

        // Final guard: Duration::from_secs_f64 panics on NaN/negative/infinite
        // AND on values that overflow the Duration range (e.g. when `max` is
        // Duration::MAX, `max_secs` round-trips to ~2^64 s). try_from_secs_f64
        // reports both as Err, which we map to the configured `max`.
        if result.is_finite() && result >= 0.0 {
            Duration::try_from_secs_f64(result.min(max_secs)).unwrap_or(self.max)
        } else {
            self.max
        }
    }

    fn reset(&mut self) {
        // No state to reset for exponential backoff
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Decorrelated jitter backoff.
///
/// Each backoff is randomized independently, reducing thundering herd.
#[derive(Debug, Clone)]
pub struct DecorrelatedJitter {
    /// Base duration.
    pub base: Duration,

    /// Maximum duration.
    pub max: Duration,

    /// Previous backoff (for correlation).
    previous: Duration,
}

impl DecorrelatedJitter {
    /// Create a new decorrelated jitter backoff.
    #[must_use]
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            previous: base,
        }
    }
}

impl BackoffStrategy for DecorrelatedJitter {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        // sleep = min(cap, random_between(base, sleep * 3))
        let base_secs = self.base.as_secs_f64();
        let prev_secs = self.previous.as_secs_f64();
        let max_secs = self.max.as_secs_f64();

        let range = prev_secs.mul_add(3.0, -base_secs);
        let next = if range > 0.0 {
            random_float().mul_add(range, base_secs)
        } else {
            base_secs
        };

        let capped = next.min(max_secs);
        // try_from_secs_f64 avoids the panic from_secs_f64 raises when `capped`
        // overflows the Duration range (e.g. `max == Duration::MAX`); fall back
        // to the configured cap in that case.
        self.previous = Duration::try_from_secs_f64(capped).unwrap_or(self.max);
        self.previous
    }

    fn reset(&mut self) {
        self.previous = self.base;
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Linear backoff with cap.
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    /// Initial delay.
    pub initial: Duration,

    /// Increment per attempt.
    pub increment: Duration,

    /// Maximum delay.
    pub max: Duration,
}

impl LinearBackoff {
    /// Create a new linear backoff.
    #[must_use]
    pub const fn new(initial: Duration, increment: Duration, max: Duration) -> Self {
        Self {
            initial,
            increment,
            max,
        }
    }
}

impl BackoffStrategy for LinearBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        let increment = self.increment.checked_mul(attempt).unwrap_or(self.max);
        let delay = self.initial.checked_add(increment).unwrap_or(self.max);
        delay.min(self.max)
    }

    fn reset(&mut self) {
        // No state to reset
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Constant backoff (same delay each time).
#[derive(Debug, Clone)]
pub struct ConstantBackoff {
    /// Delay duration.
    pub delay: Duration,
}

impl ConstantBackoff {
    /// Create a new constant backoff.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

impl BackoffStrategy for ConstantBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        self.delay
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// No backoff (immediate retry).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackoff;

impl BackoffStrategy for NoBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        Duration::ZERO
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(*self)
    }
}

/// Retry configuration.
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,

    /// Maximum total time for all retries.
    pub max_total_time: Option<Duration>,

    /// Backoff strategy.
    backoff: Box<dyn BackoffStrategy>,
}

impl std::fmt::Debug for RetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryConfig")
            .field("max_retries", &self.max_retries)
            .field("max_total_time", &self.max_total_time)
            .field("backoff", &"<BackoffStrategy>")
            .finish()
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    #[must_use]
    pub fn new(max_retries: u32, backoff: impl BackoffStrategy + 'static) -> Self {
        Self {
            max_retries,
            max_total_time: None,
            backoff: Box::new(backoff),
        }
    }

    /// Set maximum total retry time.
    #[must_use]
    pub const fn with_max_total_time(mut self, duration: Duration) -> Self {
        self.max_total_time = Some(duration);
        self
    }

    /// Get the next backoff duration.
    pub fn next_backoff(&mut self, attempt: u32) -> Duration {
        self.backoff.next_backoff(attempt)
    }

    /// Reset the backoff state.
    pub fn reset(&mut self) {
        self.backoff.reset();
    }
}

impl Clone for RetryConfig {
    fn clone(&self) -> Self {
        Self {
            max_retries: self.max_retries,
            max_total_time: self.max_total_time,
            backoff: self.backoff.clone_box(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::new(3, ExponentialBackoff::default())
    }
}

/// Simple random float generator (0.0 to 1.0).
fn random_float() -> f64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RateLimitConfig, RateLimitError, RateLimitState};

    // ── ExponentialBackoff ──────────────────────────────────────────────

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(4));
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(8));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(60)); // Capped
    }

    #[test]
    fn exponential_backoff_with_jitter_stays_within_bounds() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(Some(0.5));

        for attempt in 0..20 {
            let d = backoff.next_backoff(attempt);
            // With jitter=0.5, factor is in [0.5, 1.5), so max possible is 60*1.5 = 90s
            assert!(d <= Duration::from_secs(90), "jittered value too large");
            assert!(d > Duration::ZERO, "jittered value should be positive");
        }
    }

    #[test]
    fn exponential_backoff_custom_multiplier() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(100))
            .with_multiplier(3.0)
            .with_jitter(None);

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(3));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(9));
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(27));
        assert_eq!(backoff.next_backoff(4), Duration::from_secs(81));
        assert_eq!(backoff.next_backoff(5), Duration::from_secs(100)); // Capped
    }

    #[test]
    fn exponential_backoff_presets() {
        let default = ExponentialBackoff::default_backoff();
        assert_eq!(default.initial, Duration::from_secs(1));
        assert_eq!(default.max, Duration::from_secs(60));

        let aggressive = ExponentialBackoff::aggressive();
        assert_eq!(aggressive.initial, Duration::from_millis(100));
        assert_eq!(aggressive.max, Duration::from_secs(10));

        let conservative = ExponentialBackoff::conservative();
        assert_eq!(conservative.initial, Duration::from_secs(5));
        assert_eq!(conservative.max, Duration::from_secs(300));
    }

    #[test]
    fn exponential_backoff_default_trait() {
        let backoff = ExponentialBackoff::default();
        assert_eq!(backoff.initial, Duration::from_secs(1));
        assert_eq!(backoff.max, Duration::from_secs(60));
        assert!((backoff.multiplier - 2.0).abs() < f64::EPSILON);
        assert_eq!(backoff.jitter, Some(0.5));
    }

    #[test]
    fn exponential_backoff_clone() {
        let original = ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(30))
            .with_multiplier(1.5)
            .with_jitter(Some(0.25));
        let cloned = original.clone();
        assert_eq!(cloned.initial, original.initial);
        assert_eq!(cloned.max, original.max);
        assert!((cloned.multiplier - original.multiplier).abs() < f64::EPSILON);
        assert_eq!(cloned.jitter, original.jitter);
    }

    #[test]
    fn exponential_backoff_debug() {
        let backoff = ExponentialBackoff::default();
        let debug = format!("{backoff:?}");
        assert!(debug.contains("ExponentialBackoff"));
    }

    #[test]
    fn exponential_backoff_reset_is_no_op() {
        let mut backoff = ExponentialBackoff::default().with_jitter(None);
        let d1 = backoff.next_backoff(3);
        backoff.reset();
        let d2 = backoff.next_backoff(3);
        assert_eq!(d1, d2);
    }

    #[test]
    fn exponential_backoff_clone_box() {
        let backoff = ExponentialBackoff::default().with_jitter(None);
        let mut boxed = backoff.clone_box();
        // Should produce a valid boxed strategy
        let d = boxed.next_backoff(0);
        assert!(d > Duration::ZERO);
    }

    #[test]
    fn exponential_backoff_high_attempt_capped() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);
        // Very high attempt number should not overflow, just cap at max
        let d = backoff.next_backoff(1000);
        assert_eq!(d, Duration::from_secs(60));
    }

    #[test]
    fn exponential_backoff_u32_max_attempt_caps_at_max_not_zero() {
        // Regression: `attempt as i32` wrapped negative for attempt >= 2^31,
        // making `powi` underflow to ~0 and collapsing the backoff to ~ZERO
        // (immediate retry). A saturated exponent must instead cap at `max`.
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);
        let d = backoff.next_backoff(u32::MAX);
        assert_eq!(
            d,
            Duration::from_secs(60),
            "huge attempt must cap at max, not collapse to ~zero"
        );
    }

    #[test]
    fn exponential_backoff_duration_max_cap_does_not_panic() {
        // Regression: with max == Duration::MAX, `max_secs` round-trips to
        // ~2^64 s, which `Duration::from_secs_f64` panics on. Must clamp to max.
        let mut backoff =
            ExponentialBackoff::new(Duration::from_secs(1), Duration::MAX).with_jitter(None);
        let d = backoff.next_backoff(100);
        assert_eq!(d, Duration::MAX);
    }

    #[test]
    fn decorrelated_jitter_duration_max_cap_does_not_panic() {
        // Regression: same Duration::from_secs_f64 overflow panic. A near-max
        // base makes `capped` land at ~2^64 s (the exclusive Duration bound),
        // which from_secs_f64 panics on. Must clamp to the configured max.
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(u64::MAX), Duration::MAX);
        let d = backoff.next_backoff(1);
        assert_eq!(d, Duration::MAX);
    }

    // ── DecorrelatedJitter ──────────────────────────────────────────────

    #[test]
    fn decorrelated_jitter_basic() {
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(60));

        for _ in 0..20 {
            let d = backoff.next_backoff(0);
            assert!(d >= Duration::from_secs(1), "below base");
            assert!(d <= Duration::from_secs(60), "exceeded cap");
        }
    }

    #[test]
    fn decorrelated_jitter_reset_returns_to_base() {
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(60));

        // Run a few iterations to change previous state
        for i in 0..5 {
            backoff.next_backoff(i);
        }

        backoff.reset();
        assert_eq!(backoff.previous, backoff.base);
    }

    #[test]
    fn decorrelated_jitter_clone() {
        let original = DecorrelatedJitter::new(Duration::from_secs(2), Duration::from_secs(30));
        let cloned = original.clone();
        assert_eq!(cloned.base, original.base);
        assert_eq!(cloned.max, original.max);
        assert_eq!(cloned.previous, original.previous);
    }

    #[test]
    fn decorrelated_jitter_clone_box() {
        let backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(10));
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn decorrelated_jitter_debug() {
        let backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(10));
        let debug = format!("{backoff:?}");
        assert!(debug.contains("DecorrelatedJitter"));
    }

    #[test]
    fn decorrelated_jitter_small_base_large_max() {
        let mut backoff =
            DecorrelatedJitter::new(Duration::from_millis(10), Duration::from_secs(100));
        for i in 0..50 {
            let d = backoff.next_backoff(i);
            assert!(d >= Duration::from_millis(10));
            assert!(d <= Duration::from_secs(100));
        }
    }

    // ── LinearBackoff ───────────────────────────────────────────────────

    #[test]
    fn test_linear_backoff() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(10),
        );

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(3));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(10)); // Capped
    }

    #[test]
    fn linear_backoff_exact_cap_hit() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(10),
        );
        // attempt=3: 1 + 3*3 = 10, exactly at cap
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(10));
    }

    #[test]
    fn linear_backoff_zero_increment() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(5),
            Duration::ZERO,
            Duration::from_secs(10),
        );
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(100), Duration::from_secs(5));
    }

    #[test]
    fn linear_backoff_reset_is_no_op() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let d1 = backoff.next_backoff(2);
        backoff.reset();
        let d2 = backoff.next_backoff(2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn linear_backoff_clone() {
        let original = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(10),
        );
        let cloned = original.clone();
        assert_eq!(cloned.initial, original.initial);
        assert_eq!(cloned.increment, original.increment);
        assert_eq!(cloned.max, original.max);
    }

    #[test]
    fn linear_backoff_clone_box() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn linear_backoff_debug() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        let debug = format!("{backoff:?}");
        assert!(debug.contains("LinearBackoff"));
    }

    // ── ConstantBackoff ─────────────────────────────────────────────────

    #[test]
    fn test_constant_backoff() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(5));

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(100), Duration::from_secs(5));
    }

    #[test]
    fn constant_backoff_zero_delay() {
        let mut backoff = ConstantBackoff::new(Duration::ZERO);
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(99), Duration::ZERO);
    }

    #[test]
    fn constant_backoff_clone() {
        let original = ConstantBackoff::new(Duration::from_secs(3));
        let cloned = original.clone();
        assert_eq!(cloned.delay, original.delay);
    }

    #[test]
    fn constant_backoff_clone_box() {
        let backoff = ConstantBackoff::new(Duration::from_secs(1));
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn constant_backoff_reset_is_no_op() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(1));
        backoff.reset();
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
    }

    #[test]
    fn constant_backoff_debug() {
        let backoff = ConstantBackoff::new(Duration::from_secs(1));
        let debug = format!("{backoff:?}");
        assert!(debug.contains("ConstantBackoff"));
    }

    // ── NoBackoff ───────────────────────────────────────────────────────

    #[test]
    fn test_no_backoff() {
        let mut backoff = NoBackoff;

        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(100), Duration::ZERO);
    }

    #[test]
    fn no_backoff_default() {
        let mut backoff = NoBackoff;
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn no_backoff_copy() {
        let original = NoBackoff;
        let mut copied = original;
        assert_eq!(copied.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn no_backoff_clone_box() {
        let backoff = NoBackoff;
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn no_backoff_debug() {
        let backoff = NoBackoff;
        let debug = format!("{backoff:?}");
        assert!(debug.contains("NoBackoff"));
    }

    // ── RetryConfig ─────────────────────────────────────────────────────

    #[test]
    fn test_retry_config() {
        let mut config = RetryConfig::new(3, ExponentialBackoff::default().with_jitter(None));

        assert_eq!(config.max_retries, 3);

        let d1 = config.next_backoff(0);
        let d2 = config.next_backoff(1);
        assert!(d2 > d1);
    }

    #[test]
    fn retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(config.max_total_time.is_none());
    }

    #[test]
    fn retry_config_with_max_total_time() {
        let config = RetryConfig::new(5, ConstantBackoff::new(Duration::from_secs(1)))
            .with_max_total_time(Duration::from_secs(30));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.max_total_time, Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_config_clone() {
        let original = RetryConfig::new(5, ExponentialBackoff::default().with_jitter(None))
            .with_max_total_time(Duration::from_secs(10));
        let cloned = original.clone();
        assert_eq!(cloned.max_retries, original.max_retries);
        assert_eq!(cloned.max_total_time, original.max_total_time);
    }

    #[test]
    fn retry_config_reset() {
        let mut config = RetryConfig::new(3, ConstantBackoff::new(Duration::from_secs(1)));
        let d1 = config.next_backoff(0);
        config.reset();
        let d2 = config.next_backoff(0);
        assert_eq!(d1, d2);
    }

    #[test]
    fn retry_config_debug() {
        let config = RetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RetryConfig"));
        assert!(debug.contains("max_retries"));
        assert!(debug.contains("<BackoffStrategy>"));
    }

    #[test]
    fn retry_config_with_no_backoff() {
        let mut config = RetryConfig::new(10, NoBackoff);
        for attempt in 0..10 {
            assert_eq!(config.next_backoff(attempt), Duration::ZERO);
        }
    }

    #[test]
    fn retry_config_with_linear_backoff() {
        let mut config = RetryConfig::new(
            5,
            LinearBackoff::new(
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_secs(1),
            ),
        );
        assert_eq!(config.next_backoff(0), Duration::from_millis(100));
        assert_eq!(config.next_backoff(1), Duration::from_millis(200));
    }

    // ── RateLimitConfig ─────────────────────────────────────────────────

    #[test]
    fn rate_limit_config_new() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60));
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.burst_size.is_none());
        assert!(!config.enable_queue);
        assert!(config.max_queue_size.is_none());
    }

    #[test]
    fn rate_limit_config_with_burst() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_burst(150);
        assert_eq!(config.burst_size, Some(150));
    }

    #[test]
    fn rate_limit_config_with_queue() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_queue(50);
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(50));
    }

    #[test]
    fn rate_limit_config_presets() {
        let one = RateLimitConfig::one_per_second();
        assert_eq!(one.requests_per_window, 1);
        assert_eq!(one.window, Duration::from_secs(1));

        let ten = RateLimitConfig::ten_per_second();
        assert_eq!(ten.requests_per_window, 10);
        assert_eq!(ten.window, Duration::from_secs(1));

        let sixty = RateLimitConfig::sixty_per_minute();
        assert_eq!(sixty.requests_per_window, 60);
        assert_eq!(sixty.window, Duration::from_secs(60));

        let thousand = RateLimitConfig::thousand_per_minute();
        assert_eq!(thousand.requests_per_window, 1000);
        assert_eq!(thousand.window, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_window, 60);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_config_serde_roundtrip() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60))
            .with_burst(200)
            .with_queue(10);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.requests_per_window, 100);
        assert_eq!(deserialized.burst_size, Some(200));
        assert!(deserialized.enable_queue);
        assert_eq!(deserialized.max_queue_size, Some(10));
    }

    #[test]
    fn rate_limit_config_debug() {
        let config = RateLimitConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RateLimitConfig"));
    }

    #[test]
    fn rate_limit_config_clone() {
        let original = RateLimitConfig::new(50, Duration::from_secs(30)).with_burst(100);
        let cloned = original.clone();
        assert_eq!(cloned.requests_per_window, original.requests_per_window);
        assert_eq!(cloned.burst_size, original.burst_size);
    }

    // ── RateLimitState ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_state_serialize() {
        let state = RateLimitState {
            limit: 100,
            remaining: 42,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"limit\":100"));
        assert!(json.contains("\"remaining\":42"));
        assert!(json.contains("\"is_limited\":false"));
    }

    #[test]
    fn rate_limit_state_debug_and_clone() {
        let state = RateLimitState {
            limit: 10,
            remaining: 0,
            reset_after: Duration::from_millis(500),
            is_limited: true,
        };
        let cloned = state.clone();
        assert_eq!(cloned.limit, 10);
        assert_eq!(cloned.remaining, 0);
        assert!(cloned.is_limited);
        let debug = format!("{state:?}");
        assert!(debug.contains("RateLimitState"));
    }

    // ── RateLimitError ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_error_exceeded_display() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(30),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Rate limit exceeded"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn rate_limit_error_wait_exceeded_display() {
        let err = RateLimitError::WaitExceeded {
            wait_time: Duration::from_secs(60),
            max_wait: Duration::from_secs(10),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Wait time"));
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn rate_limit_error_invalid_config_display() {
        let err = RateLimitError::InvalidConfig("bad value".into());
        let msg = format!("{err}");
        assert!(msg.contains("Invalid rate limit configuration"));
        assert!(msg.contains("bad value"));
    }

    #[test]
    fn rate_limit_error_is_std_error() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(1),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ── Builder chain tests ─────────────────────────────────────────────

    #[test]
    fn rate_limit_config_builder_chain() {
        let config = RateLimitConfig::new(200, Duration::from_secs(120))
            .with_burst(300)
            .with_queue(25);
        assert_eq!(config.requests_per_window, 200);
        assert_eq!(config.window, Duration::from_secs(120));
        assert_eq!(config.burst_size, Some(300));
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(25));
    }

    #[test]
    fn exponential_backoff_builder_chain() {
        let backoff = ExponentialBackoff::new(Duration::from_millis(200), Duration::from_secs(30))
            .with_multiplier(1.5)
            .with_jitter(Some(0.3));
        assert_eq!(backoff.initial, Duration::from_millis(200));
        assert_eq!(backoff.max, Duration::from_secs(30));
        assert!((backoff.multiplier - 1.5).abs() < f64::EPSILON);
        assert_eq!(backoff.jitter, Some(0.3));
    }

    // ── Additional ExponentialBackoff tests ──────────────────────────────

    #[test]
    fn exponential_backoff_no_jitter_deterministic() {
        let mut b1 = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10))
            .with_jitter(None);
        let mut b2 = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10))
            .with_jitter(None);
        for attempt in 0..8 {
            assert_eq!(b1.next_backoff(attempt), b2.next_backoff(attempt));
        }
    }

    #[test]
    fn exponential_backoff_multiplier_one_stays_constant() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(2), Duration::from_secs(60))
            .with_multiplier(1.0)
            .with_jitter(None);
        for attempt in 0..10 {
            assert_eq!(backoff.next_backoff(attempt), Duration::from_secs(2));
        }
    }

    #[test]
    fn exponential_backoff_initial_equals_max() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(5), Duration::from_secs(5))
            .with_jitter(None);
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(5));
    }

    #[test]
    fn exponential_backoff_initial_greater_than_max() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(10), Duration::from_secs(5))
            .with_jitter(None);
        // Initial exceeds max, but we only cap the computed value; at attempt=0 it's 10s but capped to 5s
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
    }

    #[test]
    fn exponential_backoff_jitter_none_vs_some() {
        let backoff_none = ExponentialBackoff::default().with_jitter(None);
        let backoff_some = ExponentialBackoff::default().with_jitter(Some(0.5));
        assert!(backoff_none.jitter.is_none());
        assert_eq!(backoff_some.jitter, Some(0.5));
    }

    // ── Additional DecorrelatedJitter tests ─────────────────────────────

    #[test]
    fn decorrelated_jitter_initial_previous_equals_base() {
        let backoff = DecorrelatedJitter::new(Duration::from_secs(2), Duration::from_secs(30));
        assert_eq!(backoff.previous, backoff.base);
    }

    #[test]
    fn decorrelated_jitter_max_less_than_base_stays_at_base() {
        // If max < base, next_backoff should clamp to max
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(10), Duration::from_secs(5));
        let d = backoff.next_backoff(0);
        assert!(d <= Duration::from_secs(10));
    }

    #[test]
    fn decorrelated_jitter_many_iterations_bounded() {
        let mut backoff =
            DecorrelatedJitter::new(Duration::from_millis(100), Duration::from_secs(10));
        for i in 0..100 {
            let d = backoff.next_backoff(i);
            assert!(d >= Duration::from_millis(100));
            assert!(d <= Duration::from_secs(10));
        }
    }

    // ── Additional LinearBackoff tests ──────────────────────────────────

    #[test]
    fn linear_backoff_initial_zero() {
        let mut backoff = LinearBackoff::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(5), Duration::from_secs(5));
    }

    #[test]
    fn linear_backoff_all_zero() {
        let mut backoff = LinearBackoff::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(100), Duration::ZERO);
    }

    #[test]
    fn linear_backoff_debug_contains_fields() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_secs(30),
        );
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("initial"));
        assert!(dbg.contains("increment"));
        assert!(dbg.contains("max"));
    }

    // ── Additional ConstantBackoff tests ────────────────────────────────

    #[test]
    fn constant_backoff_large_delay() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(3600));
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(3600));
        assert_eq!(backoff.next_backoff(99), Duration::from_secs(3600));
    }

    #[test]
    fn constant_backoff_debug_contains_delay() {
        let backoff = ConstantBackoff::new(Duration::from_millis(250));
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("delay"));
    }

    // ── Additional NoBackoff tests ──────────────────────────────────────

    #[test]
    fn no_backoff_reset_is_no_op() {
        let mut backoff = NoBackoff;
        backoff.reset();
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn no_backoff_default_trait() {
        let backoff = NoBackoff;
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("NoBackoff"));
    }

    // ── Additional RetryConfig tests ────────────────────────────────────

    #[test]
    fn retry_config_with_decorrelated_jitter() {
        let mut config = RetryConfig::new(
            5,
            DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(30)),
        );
        for attempt in 0..5 {
            let d = config.next_backoff(attempt);
            assert!(d >= Duration::from_secs(1));
            assert!(d <= Duration::from_secs(30));
        }
    }

    #[test]
    fn retry_config_with_constant_backoff() {
        let mut config = RetryConfig::new(3, ConstantBackoff::new(Duration::from_millis(500)));
        for attempt in 0..3 {
            assert_eq!(config.next_backoff(attempt), Duration::from_millis(500));
        }
    }

    #[test]
    fn retry_config_clone_preserves_max_total_time() {
        let config = RetryConfig::new(10, NoBackoff).with_max_total_time(Duration::from_secs(120));
        let cloned = config.clone();
        assert_eq!(cloned.max_total_time, Some(Duration::from_secs(120)));
        assert_eq!(cloned.max_retries, 10);
        // Original is still valid after clone
        assert_eq!(config.max_retries, 10);
    }

    #[test]
    fn retry_config_debug_contains_max_total_time() {
        let config = RetryConfig::new(3, NoBackoff).with_max_total_time(Duration::from_secs(60));
        let dbg = format!("{config:?}");
        assert!(dbg.contains("max_total_time"));
    }

    #[test]
    fn retry_config_default_no_max_total_time() {
        let config = RetryConfig::default();
        assert!(config.max_total_time.is_none());
    }

    #[test]
    fn retry_config_zero_retries() {
        let config = RetryConfig::new(0, NoBackoff);
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn retry_config_reset_with_decorrelated_jitter() {
        let mut config = RetryConfig::new(
            3,
            DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(10)),
        );
        // Run some iterations
        for i in 0..5 {
            config.next_backoff(i);
        }
        config.reset();
        // After reset, the decorrelated jitter should return to base behavior
        let d = config.next_backoff(0);
        assert!(d >= Duration::from_secs(1));
        assert!(d <= Duration::from_secs(10));
    }

    // ── Additional ExponentialBackoff edge cases ─────────────────────────

    #[test]
    fn exponential_backoff_zero_initial() {
        let mut backoff =
            ExponentialBackoff::new(Duration::ZERO, Duration::from_secs(60)).with_jitter(None);
        // 0 * 2^n = 0 for any n
        for attempt in 0..10 {
            assert_eq!(backoff.next_backoff(attempt), Duration::ZERO);
        }
    }

    #[test]
    fn exponential_backoff_zero_max() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_secs(1), Duration::ZERO).with_jitter(None);
        // Everything is capped to 0
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(5), Duration::ZERO);
    }

    #[test]
    fn exponential_backoff_fractional_multiplier() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_secs(10), Duration::from_secs(100))
                .with_multiplier(0.5)
                .with_jitter(None);
        // 10 * 0.5^1 = 5, 10 * 0.5^2 = 2.5, etc — decreasing
        let d0 = backoff.next_backoff(0);
        let d1 = backoff.next_backoff(1);
        let d2 = backoff.next_backoff(2);
        assert_eq!(d0, Duration::from_secs(10));
        assert_eq!(d1, Duration::from_secs(5));
        assert!(d2 < d1);
    }

    #[test]
    fn exponential_backoff_debug_contains_multiplier() {
        let backoff = ExponentialBackoff::default();
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("multiplier"));
        assert!(dbg.contains("jitter"));
    }

    #[test]
    fn exponential_backoff_jitter_zero_means_no_jitter_effect() {
        // jitter=0.0 means factor is in [1.0, 1.0), so deterministic
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(Some(0.0));
        let d = backoff.next_backoff(0);
        assert_eq!(d, Duration::from_secs(1));
    }

    #[test]
    fn exponential_backoff_clone_box_produces_same_deterministic_results() {
        let backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);
        let mut boxed = backoff.clone_box();
        // Should produce same deterministic results
        assert_eq!(boxed.next_backoff(0), Duration::from_secs(1));
        assert_eq!(boxed.next_backoff(1), Duration::from_secs(2));
    }

    // ── Additional DecorrelatedJitter tests ──────────────────────────────

    #[test]
    fn decorrelated_jitter_equal_base_and_max() {
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(5), Duration::from_secs(5));
        for i in 0..10 {
            let d = backoff.next_backoff(i);
            assert_eq!(d, Duration::from_secs(5));
        }
    }

    #[test]
    fn decorrelated_jitter_clone_box_independent_state() {
        let mut original = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(30));
        original.next_backoff(0);
        let mut boxed = original.clone_box();
        // boxed should produce valid results independently
        let d = boxed.next_backoff(0);
        assert!(d >= Duration::from_secs(1));
        assert!(d <= Duration::from_secs(30));
    }

    #[test]
    fn decorrelated_jitter_debug_contains_base() {
        let backoff = DecorrelatedJitter::new(Duration::from_millis(100), Duration::from_secs(10));
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("base"));
        assert!(dbg.contains("max"));
    }

    // ── Additional LinearBackoff tests ───────────────────────────────────

    #[test]
    fn linear_backoff_large_increment() {
        let mut backoff = LinearBackoff::new(
            Duration::from_millis(100),
            Duration::from_secs(100),
            Duration::from_secs(50),
        );
        // attempt=0: 100ms, attempt=1: 100ms + 100s = capped at 50s
        assert_eq!(backoff.next_backoff(0), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(50));
    }

    #[test]
    fn linear_backoff_max_equals_initial() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(5)); // capped
    }

    #[test]
    fn linear_backoff_overflow_caps_at_max() {
        let max = Duration::MAX.saturating_sub(Duration::from_millis(1));
        let mut backoff = LinearBackoff::new(
            Duration::MAX.saturating_sub(Duration::from_secs(1)),
            Duration::from_secs(2),
            max,
        );

        assert_eq!(backoff.next_backoff(1), max);
        assert_eq!(backoff.next_backoff(u32::MAX), max);
    }

    #[test]
    fn linear_backoff_clone_box_works() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let mut boxed = backoff.clone_box();
        assert_eq!(boxed.next_backoff(0), Duration::from_secs(1));
        assert_eq!(boxed.next_backoff(2), Duration::from_secs(3));
    }

    // ── Additional ConstantBackoff tests ─────────────────────────────────

    #[test]
    fn constant_backoff_millis_precision() {
        let mut backoff = ConstantBackoff::new(Duration::from_millis(250));
        assert_eq!(backoff.next_backoff(0), Duration::from_millis(250));
        assert_eq!(backoff.next_backoff(99), Duration::from_millis(250));
    }

    #[test]
    fn constant_backoff_clone_box_returns_same_delay() {
        let backoff = ConstantBackoff::new(Duration::from_secs(7));
        let mut boxed = backoff.clone_box();
        assert_eq!(boxed.next_backoff(0), Duration::from_secs(7));
    }

    // ── Additional NoBackoff tests ──────────────────────────────────────

    #[test]
    fn no_backoff_is_default() {
        let backoff = NoBackoff;
        let dbg = format!("{backoff:?}");
        assert!(dbg.contains("NoBackoff"));
    }

    #[test]
    fn no_backoff_clone_box_returns_zero() {
        let backoff = NoBackoff;
        let mut boxed = backoff.clone_box();
        assert_eq!(boxed.next_backoff(0), Duration::ZERO);
        assert_eq!(boxed.next_backoff(u32::MAX), Duration::ZERO);
    }

    // ── Additional RetryConfig tests ────────────────────────────────────

    #[test]
    fn retry_config_clone_with_linear_backoff() {
        let original = RetryConfig::new(
            5,
            LinearBackoff::new(
                Duration::from_millis(100),
                Duration::from_millis(50),
                Duration::from_secs(1),
            ),
        )
        .with_max_total_time(Duration::from_secs(30));
        let mut cloned = original.clone();
        assert_eq!(cloned.max_retries, 5);
        assert_eq!(cloned.max_total_time, Some(Duration::from_secs(30)));
        // Linear backoff should work through cloned box
        assert_eq!(cloned.next_backoff(0), Duration::from_millis(100));
        assert_eq!(cloned.next_backoff(1), Duration::from_millis(150));
        // Original is still accessible after clone
        assert_eq!(original.max_retries, 5);
    }

    #[test]
    fn retry_config_max_retries_u32_max() {
        let config = RetryConfig::new(u32::MAX, NoBackoff);
        assert_eq!(config.max_retries, u32::MAX);
    }

    #[test]
    fn retry_config_max_total_time_zero() {
        let config = RetryConfig::new(3, NoBackoff).with_max_total_time(Duration::ZERO);
        assert_eq!(config.max_total_time, Some(Duration::ZERO));
    }

    #[test]
    fn retry_config_debug_without_max_total_time() {
        let config = RetryConfig::new(5, ConstantBackoff::new(Duration::from_secs(1)));
        let dbg = format!("{config:?}");
        assert!(dbg.contains("max_retries"));
        assert!(dbg.contains("max_total_time"));
    }

    #[test]
    fn retry_config_reset_with_no_backoff() {
        let mut config = RetryConfig::new(3, NoBackoff);
        config.reset();
        assert_eq!(config.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn retry_config_next_backoff_respects_attempt_number() {
        let mut config = RetryConfig::new(
            10,
            LinearBackoff::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(20),
            ),
        );
        // Linear: initial + increment * attempt
        assert_eq!(config.next_backoff(0), Duration::from_secs(1));
        assert_eq!(config.next_backoff(4), Duration::from_secs(5));
        assert_eq!(config.next_backoff(9), Duration::from_secs(10));
    }
}
