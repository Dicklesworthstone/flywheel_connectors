//! Token bucket rate limiter implementation.
//!
//! Classic token bucket algorithm with burst support.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::time::sleep;
use parking_lot::Mutex;

use async_trait::async_trait;

use crate::{RateLimitConfig, RateLimitError, RateLimitState, RateLimiter};

/// Token bucket rate limiter.
///
/// Tokens are added at a fixed rate up to a maximum bucket size.
/// Each request consumes one token.
pub struct TokenBucket {
    /// Maximum tokens (bucket capacity).
    capacity: u32,

    /// Tokens added per refill.
    refill_amount: u32,

    /// Time between refills.
    refill_interval: Duration,

    /// Current token count.
    tokens: AtomicU32,

    /// Last refill time.
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    /// Create a new token bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `requests_per_window` - Maximum requests allowed per window
    /// * `window` - Duration of the rate limit window
    #[must_use]
    pub fn new(requests_per_window: u32, window: Duration) -> Self {
        // Ensure refill interval is never zero to prevent division by zero
        let refill_interval = if window.is_zero() {
            Duration::from_nanos(1)
        } else {
            window
        };

        Self {
            capacity: requests_per_window,
            refill_amount: requests_per_window,
            refill_interval,
            tokens: AtomicU32::new(requests_per_window),
            last_refill: Mutex::new(Self::phase_preserved_anchor(
                Instant::now(),
                Duration::ZERO,
                refill_interval,
            )),
        }
    }

    /// Create from configuration.
    #[must_use]
    pub fn from_config(config: &RateLimitConfig) -> Self {
        let capacity = config.burst_size.unwrap_or(config.requests_per_window);

        // Normalize rate for smoothness (avoid "burst-then-wait" behavior).
        // Instead of adding N tokens every T seconds, add 1 token every T/N seconds.
        let (refill_amount, refill_interval) = if config.requests_per_window > 0 {
            let window_nanos = config.window.as_nanos();
            let nanos_per_request = window_nanos / u128::from(config.requests_per_window);

            if nanos_per_request > 0 {
                // Smooth rate: 1 token per calculated interval
                (
                    1,
                    Duration::from_nanos(u64::try_from(nanos_per_request).unwrap_or(u64::MAX)),
                )
            } else {
                // Rate too high for smooth 1-token refilling (e.g. > 1 req/ns),
                // or window is zero. Fallback to window-based.
                (config.requests_per_window, config.window)
            }
        } else {
            (0, config.window)
        };

        // Ensure refill interval is never zero
        let refill_interval = if refill_interval.is_zero() {
            Duration::from_nanos(1)
        } else {
            refill_interval
        };

        Self {
            capacity,
            refill_amount,
            refill_interval,
            tokens: AtomicU32::new(capacity),
            last_refill: Mutex::new(Self::phase_preserved_anchor(
                Instant::now(),
                Duration::ZERO,
                refill_interval,
            )),
        }
    }

    /// Create with burst capacity.
    #[must_use]
    pub fn with_burst(requests_per_window: u32, window: Duration, burst: u32) -> Self {
        // Ensure refill interval is never zero
        let refill_interval = if window.is_zero() {
            Duration::from_nanos(1)
        } else {
            window
        };

        Self {
            capacity: burst,
            refill_amount: requests_per_window,
            refill_interval,
            tokens: AtomicU32::new(burst),
            last_refill: Mutex::new(Self::phase_preserved_anchor(
                Instant::now(),
                Duration::ZERO,
                refill_interval,
            )),
        }
    }

    /// Compute a phase-preserved anchor time for the refill clock.
    ///
    /// This implements the phase-preserving refill anchor documented for
    /// `TokenBucket::from_config` (the path used by `config_from_core` for
    /// manifest-backed connector rate limits): `now - (elapsed % interval)`.
    /// Constructors pass zero elapsed, so fresh buckets start exactly at the
    /// current phase boundary; refill passes observed elapsed to preserve the
    /// fractional remainder and avoid drift.
    fn phase_preserved_anchor(now: Instant, elapsed: Duration, interval: Duration) -> Instant {
        if interval.is_zero() {
            return now;
        }

        let remainder = elapsed.as_nanos() % interval.as_nanos();
        let rem_secs = u64::try_from(remainder / 1_000_000_000).unwrap_or(u64::MAX);
        let rem_nanos = (remainder % 1_000_000_000) as u32;

        now.checked_sub(Duration::new(rem_secs, rem_nanos))
            .unwrap_or(now)
    }

    /// Refill tokens based on elapsed time.
    ///
    /// When the bucket is already full, refresh the refill anchor so idle time does not
    /// accrue extra burst credit past capacity.
    fn refill(&self) {
        let mut last_refill = self.last_refill.lock();
        let current = self.tokens.load(Ordering::Acquire);
        let now = Instant::now();

        if current >= self.capacity {
            *last_refill = now;
            return;
        }

        let elapsed = now.saturating_duration_since(*last_refill);

        if elapsed >= self.refill_interval {
            // Calculate how many refill periods have passed
            let periods_u128 = elapsed.as_nanos() / self.refill_interval.as_nanos();
            let tokens_to_add_u128 = periods_u128.saturating_mul(u128::from(self.refill_amount));
            let tokens_to_add = u32::try_from(tokens_to_add_u128).unwrap_or(u32::MAX);

            // Add tokens up to capacity using compare_exchange to avoid race with try_acquire
            loop {
                let current = self.tokens.load(Ordering::Acquire);
                let new_tokens = current.saturating_add(tokens_to_add).min(self.capacity);

                // If already at or above capacity after adding, just break
                if new_tokens == current {
                    break;
                }

                if self
                    .tokens
                    .compare_exchange(current, new_tokens, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
                // CAS failed, retry with fresh value
            }

            // Update last refill time, preserving phase (remainder) to avoid drift.
            // By setting last_refill to (now - remainder), we correctly advance the
            // timestamp by exactly the number of elapsed periods, avoiding both
            // fractional drift and ancient history burst issues.
            *last_refill = Self::phase_preserved_anchor(now, elapsed, self.refill_interval);
        }
    }

    /// Try to consume `amount` tokens atomically.
    fn try_consume(&self, amount: u32) -> bool {
        if amount == 0 {
            return true;
        }
        if amount > self.capacity {
            return false;
        }

        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < amount {
                return false;
            }

            if self
                .tokens
                .compare_exchange(
                    current,
                    current - amount,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Calculate time until next token is available.
    fn time_until_token(&self) -> Duration {
        let last_refill = *self.last_refill.lock();
        let elapsed = Instant::now().saturating_duration_since(last_refill);

        self.refill_interval
            .checked_sub(elapsed)
            .unwrap_or(Duration::ZERO)
    }
}

#[async_trait]
impl RateLimiter for TokenBucket {
    async fn try_acquire(&self) -> bool {
        self.try_consume(1)
    }

    async fn try_acquire_n(&self, permits: u32) -> bool {
        self.try_consume(permits)
    }

    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError> {
        let start = Instant::now();

        loop {
            if self.try_acquire().await {
                return Ok(start.elapsed());
            }

            let wait_time = self.wait_time().await;
            let total_waited = start.elapsed();
            let projected = total_waited.checked_add(wait_time).unwrap_or(Duration::MAX);

            if projected > max_wait {
                return Err(RateLimitError::WaitExceeded {
                    wait_time: projected,
                    max_wait,
                });
            }

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.refill();
        self.tokens.load(Ordering::Acquire)
    }

    async fn wait_time(&self) -> Duration {
        if self.capacity == 0 {
            return Duration::MAX;
        }

        if self.tokens.load(Ordering::Acquire) > 0 {
            Duration::ZERO
        } else {
            self.time_until_token()
        }
    }

    async fn reset(&self) {
        self.tokens.store(self.capacity, Ordering::Release);
        *self.last_refill.lock() = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.refill();
        let remaining = self.tokens.load(Ordering::Acquire);

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_token(),
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic behavior ──────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_basic() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // 6th should fail
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_refill() {
        let limiter = TokenBucket::new(2, Duration::from_millis(100));

        // Consume all tokens
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for refill
        sleep(Duration::from_millis(150)).await;

        // Should have tokens again
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_state() {
        let limiter = TokenBucket::new(10, Duration::from_secs(1));

        let state = limiter.state();
        assert_eq!(state.limit, 10);
        assert_eq!(state.remaining, 10);
        assert!(!state.is_limited);

        // Consume some tokens
        for _ in 0..7 {
            limiter.try_acquire().await;
        }

        let state = limiter.state();
        assert_eq!(state.remaining, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_acquire_with_wait() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        // First request succeeds immediately
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(10));

        // Second request should wait
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(40));
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_try_acquire_n_is_atomic() {
        let limiter = TokenBucket::new(2, Duration::from_secs(1));

        // Cannot atomically take 3 tokens from a bucket of 2; must not partially consume.
        assert!(!limiter.try_acquire_n(3).await);
        assert_eq!(limiter.remaining(), 2);

        // Taking 2 works.
        assert!(limiter.try_acquire_n(2).await);
        assert_eq!(limiter.remaining(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_zero_window_safety() {
        // Ensure we don't panic if window is zero (e.g. from bad config)
        let config = RateLimitConfig {
            requests_per_window: 100,
            window: Duration::ZERO,
            ..Default::default()
        };

        // Should not panic
        let limiter = TokenBucket::from_config(&config);

        // Should work safely (likely using fallback 1ns interval or similar logic)
        assert!(limiter.try_acquire().await);

        // Direct constructor safety
        let limiter_direct = TokenBucket::new(100, Duration::ZERO);
        assert!(limiter_direct.try_acquire().await);
    }

    // ── from_config ─────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn from_config_basic() {
        let config = RateLimitConfig::new(60, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 60);
        assert_eq!(limiter.remaining(), 60);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_with_burst() {
        let config = RateLimitConfig::new(60, Duration::from_secs(60)).with_burst(120);
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 120);
        assert_eq!(limiter.remaining(), 120);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_zero_requests() {
        let config = RateLimitConfig::new(0, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 0);
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_smooth_rate() {
        // 100 requests per second → refill_amount=1, interval=10ms
        let config = RateLimitConfig::new(100, Duration::from_secs(1));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.refill_amount, 1);
        // Interval should be 10ms (1_000_000_000 / 100 = 10_000_000 ns)
        assert_eq!(limiter.refill_interval, Duration::from_millis(10));
    }

    // ── with_burst constructor ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn with_burst_constructor() {
        let limiter = TokenBucket::with_burst(10, Duration::from_secs(1), 20);
        assert_eq!(limiter.capacity, 20);
        assert_eq!(limiter.refill_amount, 10);
        assert_eq!(limiter.remaining(), 20);

        // Should allow 20 initial requests (burst capacity)
        for _ in 0..20 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn with_burst_zero_window() {
        let limiter = TokenBucket::with_burst(10, Duration::ZERO, 20);
        assert_eq!(limiter.capacity, 20);
        // refill_interval should be clamped to 1ns
        assert_eq!(limiter.refill_interval, Duration::from_nanos(1));
    }

    // ── try_acquire_n edge cases ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_zero_permits() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        // Zero permits should always succeed
        assert!(limiter.try_acquire_n(0).await);
        assert_eq!(limiter.remaining(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_exceeds_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert!(!limiter.try_acquire_n(6).await);
        assert_eq!(limiter.remaining(), 5); // No tokens consumed
    }

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_exact_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert!(limiter.try_acquire_n(5).await);
        assert_eq!(limiter.remaining(), 0);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn reset_restores_full_capacity() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));

        for _ in 0..10 {
            limiter.try_acquire().await;
        }
        assert_eq!(limiter.remaining(), 0);

        limiter.reset().await;
        assert_eq!(limiter.remaining(), 10);
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn state_after_reset() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        for _ in 0..5 {
            limiter.try_acquire().await;
        }

        let state_before = limiter.state();
        assert_eq!(state_before.remaining, 0);
        assert!(state_before.is_limited);

        limiter.reset().await;

        let state_after = limiter.state();
        assert_eq!(state_after.remaining, 5);
        assert!(!state_after.is_limited);
    }

    // ── wait_time ───────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn wait_time_zero_when_tokens_available() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn wait_time_positive_when_exhausted() {
        let limiter = TokenBucket::new(1, Duration::from_millis(100));
        limiter.try_acquire().await;
        let wait = limiter.wait_time().await;
        assert!(wait > Duration::ZERO);
        assert!(wait <= Duration::from_millis(100));
    }

    #[fcp_async_core::runtime::test]
    async fn wait_time_max_when_zero_capacity() {
        let limiter = TokenBucket::new(0, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::MAX);
    }

    // ── acquire error paths ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn acquire_exceeds_max_wait() {
        let limiter = TokenBucket::new(1, Duration::from_secs(60));
        limiter.try_acquire().await;

        let result = limiter.acquire(Duration::from_millis(5)).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WaitExceeded { max_wait, .. })
                if max_wait == Duration::from_millis(5)
        ));
    }

    // ── State snapshot details ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn state_reset_after_bounded_when_tokens_available() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        let state = limiter.state();
        // reset_after reflects time until next refill, bounded by the refill interval
        assert!(state.reset_after <= Duration::from_secs(1));
    }

    #[fcp_async_core::runtime::test]
    async fn state_is_limited_when_exhausted() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert!(state.is_limited);
        assert_eq!(state.remaining, 0);
    }

    // ── Single token capacity ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn single_token_bucket() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(60)).await;

        assert!(limiter.try_acquire().await);
    }

    // ── Zero capacity ──────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn zero_capacity_rejects_all() {
        let limiter = TokenBucket::new(0, Duration::from_secs(1));
        assert!(!limiter.try_acquire().await);
        assert_eq!(limiter.remaining(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn zero_capacity_state() {
        let limiter = TokenBucket::new(0, Duration::from_secs(1));
        let state = limiter.state();
        assert_eq!(state.limit, 0);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
    }

    // ── from_config edge cases ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn from_config_one_per_second_smooth_rate() {
        let config = RateLimitConfig::one_per_second();
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 1);
        assert_eq!(limiter.refill_amount, 1);
        assert_eq!(limiter.refill_interval, Duration::from_secs(1));
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_thousand_per_minute_smooth_rate() {
        // 1000/60s → 1 token per 60ms
        let config = RateLimitConfig::thousand_per_minute();
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 1000);
        assert_eq!(limiter.refill_amount, 1);
        assert_eq!(limiter.refill_interval, Duration::from_millis(60));
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_burst_overrides_capacity() {
        let config = RateLimitConfig::new(10, Duration::from_secs(1)).with_burst(50);
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 50);
        // Initial tokens should match burst capacity
        assert_eq!(limiter.remaining(), 50);
    }

    // ── Refill behavior ────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn refill_does_not_exceed_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_millis(50));
        // Start full, consume none, wait for multiple refill periods
        sleep(Duration::from_millis(200)).await;
        // Remaining should still be capped at capacity
        assert_eq!(limiter.remaining(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn partial_refill_after_consume() {
        // Use from_config for smooth rate: 3 per 90ms → 1 token per 30ms
        let config = RateLimitConfig::new(3, Duration::from_millis(90));
        let limiter = TokenBucket::from_config(&config);
        // Consume all
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for ~1.5 refill periods (45ms, period is 30ms)
        sleep(Duration::from_millis(45)).await;

        // Should have at least 1 token back
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn full_bucket_does_not_bank_extra_burst_after_idle() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        // Let the bucket sit full longer than its refill interval.
        sleep(Duration::from_millis(120)).await;

        assert!(limiter.try_acquire().await);
        assert!(
            !limiter.try_acquire().await,
            "idle time while full must not mint an extra token"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn remaining_refreshes_after_elapsed_refill() {
        let config = RateLimitConfig::new(2, Duration::from_millis(100));
        let limiter = TokenBucket::from_config(&config);

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert_eq!(limiter.remaining(), 0);

        sleep(Duration::from_millis(60)).await;

        assert_eq!(limiter.remaining(), 1);
    }

    // ── try_acquire_n additional ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_partial_capacity() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        // Consume 7, leaving 3
        assert!(limiter.try_acquire_n(7).await);
        assert_eq!(limiter.remaining(), 3);
        // Can't take 4 from 3
        assert!(!limiter.try_acquire_n(4).await);
        assert_eq!(limiter.remaining(), 3); // Unchanged
        // Can take exactly 3
        assert!(limiter.try_acquire_n(3).await);
        assert_eq!(limiter.remaining(), 0);
    }

    // ── Metamorphic relations ──────────────────────────────────────────

    /// Metamorphic: `try_acquire_n(0)` is a no-op on state. Any number of
    /// zero-permit requests must leave `remaining()` unchanged from the
    /// pre-call value. This is the adjoint of the "permit-then-refund"
    /// idempotency relation — the bucket has no refund API, but a
    /// zero-cost permit must behave as a refund-after-acquire so that
    /// callers can cheaply probe availability.
    #[fcp_async_core::runtime::test]
    async fn try_acquire_zero_permits_is_state_neutral() {
        let limiter = TokenBucket::new(5, Duration::from_secs(60));
        // Partially drain so "full and idle" isn't the only case exercised.
        assert!(limiter.try_acquire_n(2).await);
        let before = limiter.remaining();

        for _ in 0..16 {
            assert!(
                limiter.try_acquire_n(0).await,
                "zero-permit acquire must always succeed"
            );
        }

        assert_eq!(
            limiter.remaining(),
            before,
            "zero-permit calls must not mutate bucket state"
        );
    }

    /// Metamorphic: `remaining()` is monotonically non-decreasing under
    /// pure idle (no concurrent acquire). The refill hardening in
    /// 50f9e9d8 changed `remaining()` to actively pull refill credit;
    /// this test pins the invariant that back-to-back reads without
    /// any `try_acquire` between them never regress the observable
    /// token count — a refill-accounting regression that dropped
    /// tokens would surface here.
    #[fcp_async_core::runtime::test]
    async fn remaining_is_monotonic_under_idle() {
        let limiter = TokenBucket::new(3, Duration::from_millis(30));
        // Drain so refill has something to do.
        assert!(limiter.try_acquire_n(3).await);
        assert_eq!(limiter.remaining(), 0);

        let mut prev = limiter.remaining();
        for _ in 0..10 {
            sleep(Duration::from_millis(5)).await;
            let now = limiter.remaining();
            assert!(
                now >= prev,
                "remaining() regressed under idle: prev={prev} now={now}"
            );
            prev = now;
        }
        // After >= one refill interval of cumulative sleep, must see at
        // least one replenished token.
        assert!(prev >= 1, "at least one token must refill under idle");
    }

    // ── with_burst edge cases ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn with_burst_lower_than_rate() {
        // burst < requests_per_window is valid: bucket starts with burst tokens
        let limiter = TokenBucket::with_burst(100, Duration::from_secs(1), 5);
        assert_eq!(limiter.capacity, 5);
        assert_eq!(limiter.refill_amount, 100);
        assert_eq!(limiter.remaining(), 5);
    }

    // ── State consistency ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn state_limit_matches_capacity() {
        let limiter = TokenBucket::new(42, Duration::from_secs(1));
        assert_eq!(limiter.state().limit, 42);

        let limiter_burst = TokenBucket::with_burst(10, Duration::from_secs(1), 99);
        assert_eq!(limiter_burst.state().limit, 99);
    }

    #[fcp_async_core::runtime::test]
    async fn remaining_matches_state_remaining() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        limiter.try_acquire_n(3).await;
        assert_eq!(limiter.remaining(), limiter.state().remaining);
    }

    // ── Sync-only tests ──────────────────────────────────────────────────

    #[test]
    fn new_sets_capacity_and_tokens() {
        let limiter = TokenBucket::new(42, Duration::from_secs(10));
        assert_eq!(limiter.capacity, 42);
        assert_eq!(limiter.remaining(), 42);
    }

    #[test]
    fn new_with_zero_window_clamps_interval() {
        let limiter = TokenBucket::new(10, Duration::ZERO);
        assert_eq!(limiter.refill_interval, Duration::from_nanos(1));
        assert_eq!(limiter.capacity, 10);
    }

    #[test]
    fn new_preserves_window_as_refill_interval() {
        let limiter = TokenBucket::new(5, Duration::from_secs(30));
        assert_eq!(limiter.refill_interval, Duration::from_secs(30));
        assert_eq!(limiter.refill_amount, 5);
    }

    #[test]
    fn with_burst_sets_correct_fields() {
        let limiter = TokenBucket::with_burst(10, Duration::from_secs(1), 50);
        assert_eq!(limiter.capacity, 50);
        assert_eq!(limiter.refill_amount, 10);
        assert_eq!(limiter.refill_interval, Duration::from_secs(1));
        assert_eq!(limiter.remaining(), 50);
    }

    #[test]
    fn with_burst_zero_window_clamps_interval() {
        let limiter = TokenBucket::with_burst(5, Duration::ZERO, 10);
        assert_eq!(limiter.refill_interval, Duration::from_nanos(1));
    }

    #[test]
    fn from_config_default_uses_sixty_per_minute() {
        let config = RateLimitConfig::default();
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 60);
        assert_eq!(limiter.remaining(), 60);
    }

    #[test]
    fn from_config_zero_requests_yields_zero_capacity() {
        let config = RateLimitConfig::new(0, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 0);
        assert_eq!(limiter.refill_amount, 0);
    }

    #[test]
    fn from_config_burst_overrides_capacity_sync() {
        let config = RateLimitConfig::new(100, Duration::from_secs(1)).with_burst(200);
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 200);
        assert_eq!(limiter.remaining(), 200);
    }

    #[test]
    fn from_config_smooth_rate_calculation() {
        // 60 per minute -> 1 token per second
        let config = RateLimitConfig::new(60, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.refill_amount, 1);
        assert_eq!(limiter.refill_interval, Duration::from_secs(1));
    }

    #[test]
    fn from_config_ten_per_second_smooth_rate() {
        let config = RateLimitConfig::ten_per_second();
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.refill_amount, 1);
        // 1_000_000_000 / 10 = 100_000_000 ns = 100ms
        assert_eq!(limiter.refill_interval, Duration::from_millis(100));
    }

    #[test]
    fn phase_preserved_anchor_subtracts_elapsed_remainder() {
        let now = Instant::now();
        let anchor = TokenBucket::phase_preserved_anchor(
            now,
            Duration::from_millis(42),
            Duration::from_millis(10),
        );

        assert_eq!(
            now.saturating_duration_since(anchor),
            Duration::from_millis(2)
        );
    }

    #[test]
    fn phase_preserved_anchor_zero_elapsed_uses_current_instant() {
        let now = Instant::now();
        let anchor =
            TokenBucket::phase_preserved_anchor(now, Duration::ZERO, Duration::from_millis(10));

        assert_eq!(anchor, now);
    }

    #[test]
    fn phase_preserved_anchor_zero_interval_uses_current_instant() {
        let now = Instant::now();
        let anchor =
            TokenBucket::phase_preserved_anchor(now, Duration::from_millis(42), Duration::ZERO);

        assert_eq!(anchor, now);
    }

    #[test]
    fn try_consume_zero_always_succeeds() {
        let limiter = TokenBucket::new(5, Duration::from_secs(60));
        assert!(limiter.try_consume(0));
        assert_eq!(limiter.remaining(), 5);
    }

    #[test]
    fn try_consume_exceeding_capacity_fails() {
        let limiter = TokenBucket::new(5, Duration::from_secs(60));
        assert!(!limiter.try_consume(6));
        assert_eq!(limiter.remaining(), 5);
    }

    #[test]
    fn try_consume_exact_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_secs(60));
        assert!(limiter.try_consume(5));
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn try_consume_sequential_depletion() {
        let limiter = TokenBucket::new(3, Duration::from_secs(60));
        assert!(limiter.try_consume(1));
        assert_eq!(limiter.remaining(), 2);
        assert!(limiter.try_consume(1));
        assert_eq!(limiter.remaining(), 1);
        assert!(limiter.try_consume(1));
        assert_eq!(limiter.remaining(), 0);
        assert!(!limiter.try_consume(1));
    }

    #[test]
    fn state_fresh_limiter() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        let state = limiter.state();
        assert_eq!(state.limit, 10);
        assert_eq!(state.remaining, 10);
        assert!(!state.is_limited);
    }

    #[test]
    fn state_exhausted_limiter() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        limiter.try_consume(2);
        let state = limiter.state();
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
    }

    #[test]
    fn remaining_reflects_consumption() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        assert_eq!(limiter.remaining(), 10);
        limiter.try_consume(3);
        assert_eq!(limiter.remaining(), 7);
        limiter.try_consume(7);
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn time_until_token_returns_bounded_value() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        let wait = limiter.time_until_token();
        // Should be within the refill interval
        assert!(wait <= Duration::from_secs(1));
    }

    // ── Additional sync tests ───────────────────────────────────────────

    #[test]
    fn try_consume_one_at_a_time() {
        let limiter = TokenBucket::new(5, Duration::from_secs(60));
        for i in 0..5 {
            assert!(limiter.try_consume(1), "failed at iteration {i}");
        }
        assert!(!limiter.try_consume(1));
    }

    #[test]
    fn try_consume_various_amounts() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        assert!(limiter.try_consume(3));
        assert_eq!(limiter.remaining(), 7);
        assert!(limiter.try_consume(4));
        assert_eq!(limiter.remaining(), 3);
        assert!(!limiter.try_consume(4));
        assert_eq!(limiter.remaining(), 3);
        assert!(limiter.try_consume(3));
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn new_large_capacity() {
        let limiter = TokenBucket::new(1_000_000, Duration::from_secs(3600));
        assert_eq!(limiter.capacity, 1_000_000);
        assert_eq!(limiter.remaining(), 1_000_000);
    }

    #[test]
    fn new_millis_window() {
        let limiter = TokenBucket::new(10, Duration::from_millis(500));
        assert_eq!(limiter.refill_interval, Duration::from_millis(500));
        assert_eq!(limiter.capacity, 10);
    }

    #[test]
    fn with_burst_equal_to_rate() {
        let limiter = TokenBucket::with_burst(10, Duration::from_secs(1), 10);
        assert_eq!(limiter.capacity, 10);
        assert_eq!(limiter.refill_amount, 10);
    }

    #[test]
    fn from_config_with_nanos_window() {
        let config = RateLimitConfig::new(1, Duration::from_nanos(100));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 1);
        // refill_interval = 100ns / 1 = 100ns
        assert_eq!(limiter.refill_interval, Duration::from_nanos(100));
    }

    #[test]
    fn state_remaining_plus_consumed_equals_capacity() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));
        limiter.try_consume(4);
        let state = limiter.state();
        assert_eq!(state.remaining, 6);
        assert_eq!(state.limit, 10);
    }

    #[test]
    fn try_consume_zero_on_empty_bucket() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        limiter.try_consume(2);
        assert_eq!(limiter.remaining(), 0);
        // Zero permits should still succeed even on empty bucket
        assert!(limiter.try_consume(0));
    }

    // ── Property-based burst/capacity invariants ─────────────────────
    //
    // These props lock down the time-independent part of the
    // `count ≤ burst + window*rate` guarantee. They exercise
    // try_consume directly (a sync private fn accessible from the
    // same-module test submodule) so no runtime / clock mocking is
    // needed — we verify the bucket's burst-phase behavior before
    // any refill period elapses.
    //
    // Time-dependent invariants (refill arithmetic under real
    // wall-clock) are covered by the existing async tests in this
    // module; they can't be lifted to proptest without a mock clock.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Burst cap: a fresh bucket of capacity C permits EXACTLY C
        /// immediate try_consume(1) successes before the first refill
        /// interval elapses. The (C+1)th attempt must fail.
        ///
        /// Window is set to 10 minutes so no refill can occur during
        /// the tight consume loop below, even under extreme CI
        /// scheduling. Capacity is capped at 10_000 to keep runtime
        /// bounded across 64 proptest cases.
        #[test]
        fn prop_burst_cap_is_exactly_capacity(
            capacity in 1u32..10_000,
        ) {
            let bucket = TokenBucket::new(capacity, std::time::Duration::from_secs(600));

            for i in 0..capacity {
                proptest::prop_assert!(
                    bucket.try_consume(1),
                    "try_consume(1) #{i} must succeed (bucket has {capacity} tokens)"
                );
            }
            proptest::prop_assert!(
                !bucket.try_consume(1),
                "try_consume(1) #{capacity}+1 must fail — burst exceeded capacity"
            );
        }

        /// Overflow rejection: any request for more permits than
        /// `capacity` must fail, regardless of current token count.
        /// This is a strict bound that prevents a single over-sized
        /// request from silently consuming the entire bucket.
        #[test]
        fn prop_permits_exceeding_capacity_always_fail(
            capacity in 1u32..10_000,
            requested in 1u32..u32::MAX,
        ) {
            proptest::prop_assume!(requested > capacity);
            let bucket = TokenBucket::new(capacity, std::time::Duration::from_secs(600));
            proptest::prop_assert!(
                !bucket.try_consume(requested),
                "try_consume({requested}) with capacity {capacity} must fail"
            );
            // Bucket state unchanged — full capacity should still be usable.
            proptest::prop_assert_eq!(bucket.remaining(), capacity);
        }

        /// Zero-permit neutrality: try_consume(0) always succeeds and
        /// does not change the token count, even on an empty bucket.
        /// This is load-bearing for callers that conditionally
        /// acquire and need to probe without paying.
        #[test]
        fn prop_zero_permits_is_state_neutral(
            capacity in 1u32..10_000,
            pre_drain in 0u32..10_000,
        ) {
            let bucket = TokenBucket::new(capacity, std::time::Duration::from_secs(600));
            let pre_drain = pre_drain.min(capacity);
            for _ in 0..pre_drain {
                bucket.try_consume(1);
            }
            let before = bucket.remaining();
            proptest::prop_assert!(bucket.try_consume(0));
            proptest::prop_assert_eq!(
                bucket.remaining(),
                before,
                "try_consume(0) must not change token count"
            );
        }

        /// Partial consumption: after consuming `k ≤ capacity` tokens
        /// from a full bucket, exactly `capacity - k` tokens remain
        /// accessible via subsequent try_consume(1) calls before the
        /// (capacity - k + 1)th fails.
        #[test]
        fn prop_partial_consume_leaves_exact_remaining(
            capacity in 2u32..5_000,
            k in 1u32..5_000,
        ) {
            proptest::prop_assume!(k < capacity);
            let bucket = TokenBucket::new(capacity, std::time::Duration::from_secs(600));
            proptest::prop_assert!(bucket.try_consume(k));

            let remaining = capacity - k;
            for i in 0..remaining {
                proptest::prop_assert!(
                    bucket.try_consume(1),
                    "try_consume(1) #{i} after partial drain must succeed"
                );
            }
            proptest::prop_assert!(
                !bucket.try_consume(1),
                "try_consume(1) past remaining must fail (capacity={capacity}, k={k})"
            );
        }
    }
}
