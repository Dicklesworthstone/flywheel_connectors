//! Leaky bucket rate limiter implementation.
//!
//! Provides smooth request pacing with queue support.

use std::time::{Duration, Instant};

use fcp_async_core::time::sleep;
use parking_lot::Mutex;

use async_trait::async_trait;

use crate::{RateLimitError, RateLimitState, RateLimiter};

fn sanitize_leak_rate(leak_rate: f64) -> f64 {
    if leak_rate.is_nan() || leak_rate <= 0.0 {
        0.0
    } else if leak_rate.is_infinite() {
        f64::MAX
    } else {
        leak_rate
    }
}

fn ceil_positive_duration(secs: f64) -> Duration {
    match Duration::try_from_secs_f64(secs) {
        Ok(duration) if duration.is_zero() && secs > 0.0 => Duration::from_nanos(1),
        Ok(duration) => duration,
        Err(_) => Duration::MAX,
    }
}

/// Leaky bucket rate limiter.
///
/// Requests "leak" out at a constant rate. New requests are added to the bucket.
/// If the bucket is full, requests are rejected or queued.
///
/// Between consecutive `try_acquire` calls, real time passes and the bucket
/// leaks `leak_rate * elapsed` units.  With high leak rates (e.g. 100/s)
/// even a 1 ms scheduling gap drains 0.1 units, making a full bucket
/// appear to have room. To prevent timing artifacts from creating false capacity
/// while still allowing the bucket to fill to its declared capacity,
/// we wait until there is room for a full permit (1.0 - epsilon) before waking up.
pub struct LeakyBucket {
    /// Bucket capacity.
    capacity: u32,

    /// Leak rate (requests per second).
    leak_rate: f64,

    /// Current water level.
    level: Mutex<f64>,

    /// Last leak time.
    last_leak: Mutex<Instant>,
}

impl LeakyBucket {
    /// Create a new leaky bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum bucket size
    /// * `leak_rate` - Requests leaked per second
    #[must_use]
    pub fn new(capacity: u32, leak_rate: f64) -> Self {
        Self {
            capacity,
            leak_rate: sanitize_leak_rate(leak_rate),
            level: Mutex::new(0.0),
            last_leak: Mutex::new(Instant::now()),
        }
    }

    /// Create from requests per window.
    #[must_use]
    pub fn from_window(requests_per_window: u32, window: Duration) -> Self {
        let window = if window.is_zero() {
            Duration::from_nanos(1)
        } else {
            window
        };
        let secs = window.as_secs_f64();
        let leak_rate = f64::from(requests_per_window) / secs;
        Self::new(requests_per_window, leak_rate)
    }

    /// Leak water based on elapsed time.
    fn leak(&self) {
        let now = Instant::now();
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();

        let elapsed = now.saturating_duration_since(*last_leak);
        let leaked = elapsed.as_secs_f64() * self.leak_rate;

        if leaked > 0.0 {
            let new_level = (*level - leaked).max(0.0);

            // Only update the anchor if the level actually changed, or if the bucket
            // is fully empty. This prevents tiny time increments from being absorbed
            // by f64 truncation without actually leaking any capacity.
            if (new_level - *level).abs() > f64::EPSILON || *level < f64::EPSILON {
                *level = new_level;
                drop(level);
                *last_leak = now;
            }
        }
    }

    /// Calculate time until bucket has room.
    fn time_until_room(&self) -> Duration {
        if self.capacity == 0 {
            return Duration::MAX;
        }

        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        let room_needed = 1.0 - 1e-9;

        if level + room_needed <= capacity {
            Duration::ZERO
        } else if self.leak_rate <= 0.0 {
            Duration::MAX
        } else {
            let overflow = (level + room_needed) - capacity;
            let secs = overflow / self.leak_rate;
            // Cap at Duration::MAX representable seconds to avoid panic in
            // from_secs_f64 for extremely small leak rates.
            if secs.is_finite() && secs >= 0.0 {
                ceil_positive_duration(secs)
            } else {
                Duration::MAX
            }
        }
    }
}

#[async_trait]
impl RateLimiter for LeakyBucket {
    async fn try_acquire(&self) -> bool {
        self.try_acquire_n(1).await
    }

    async fn try_acquire_n(&self, permits: u32) -> bool {
        self.leak();

        let mut level = self.level.lock();
        let capacity = f64::from(self.capacity);
        let amount = f64::from(permits);

        // Use a tiny epsilon to prevent floating-point inaccuracies
        // from incorrectly rejecting requests exactly on the boundary.
        if *level + amount <= capacity + 1e-9 {
            *level += amount;
            true
        } else {
            false
        }
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

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn remaining(&self) -> u32 {
        self.leak();
        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        (capacity - level).max(0.0) as u32
    }

    async fn wait_time(&self) -> Duration {
        self.leak();
        self.time_until_room()
    }

    async fn reset(&self) {
        // Acquire locks in same order as leak() to prevent deadlock: last_leak then level
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();
        *level = 0.0;
        drop(level);
        *last_leak = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.leak();

        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (capacity - level).max(0.0) as u32;

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_room(),
            is_limited: level + 1.0 > capacity + 1e-9,
        }
    }
}

/// Smooth rate limiter for pacing requests.
///
/// Ensures minimum delay between requests.
pub struct SmoothPacer {
    /// Minimum interval between requests.
    min_interval: Duration,

    /// Last request time.
    last_request: Mutex<Option<Instant>>,
}

impl SmoothPacer {
    /// Create a new smooth pacer.
    #[must_use]
    pub const fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_request: Mutex::new(None),
        }
    }

    /// Create from requests per second.
    #[must_use]
    pub fn from_rate(requests_per_second: f64) -> Self {
        if requests_per_second.is_nan() || requests_per_second <= 0.0 {
            Self::new(Duration::MAX)
        } else if requests_per_second.is_infinite() {
            Self::new(Duration::ZERO)
        } else {
            // `ceil_positive_duration` avoids the panic `Duration::from_secs_f64`
            // raises when `1.0 / rps` overflows the `Duration` range (extremely
            // small positive rates, e.g. 1e-20 req/s): it maps the overflow to
            // `Duration::MAX`, matching the `rps <= 0` "effectively never" arm.
            Self::new(ceil_positive_duration(1.0 / requests_per_second))
        }
    }
}

#[async_trait]
impl RateLimiter for SmoothPacer {
    async fn try_acquire(&self) -> bool {
        let mut last = self.last_request.lock();
        let now = Instant::now();

        let last_time_val = *last;
        if let Some(last_time) = last_time_val {
            if now.saturating_duration_since(last_time) < self.min_interval {
                return false;
            }
        }

        *last = Some(now);
        true
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
        (*self.last_request.lock()).map_or(1, |last| {
            u32::from(Instant::now().saturating_duration_since(last) >= self.min_interval)
        })
    }

    async fn wait_time(&self) -> Duration {
        let snapshot = *self.last_request.lock();
        if let Some(last) = snapshot {
            let elapsed = Instant::now().saturating_duration_since(last);
            if elapsed < self.min_interval {
                return self
                    .min_interval
                    .checked_sub(elapsed)
                    .unwrap_or(Duration::ZERO);
            }
        }
        Duration::ZERO
    }

    async fn reset(&self) {
        *self.last_request.lock() = None;
    }

    fn state(&self) -> RateLimitState {
        let snapshot = *self.last_request.lock();

        let (remaining, reset_after) = snapshot.map_or((1, Duration::ZERO), |last| {
            let elapsed = Instant::now().saturating_duration_since(last);
            if elapsed < self.min_interval {
                let wait = self
                    .min_interval
                    .checked_sub(elapsed)
                    .unwrap_or(Duration::ZERO);
                (0, wait)
            } else {
                (1, Duration::ZERO)
            }
        });

        RateLimitState {
            limit: 1,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    // ── LeakyBucket tests ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_leaky_bucket_basic() {
        let limiter = LeakyBucket::new(5, 10.0); // 5 capacity, 10/sec leak

        // Fill bucket
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // Should be nearly full (may have leaked slightly during test execution)
        let level = *limiter.level.lock();
        assert!(level >= 4.5, "bucket should be nearly full, level={level}");

        // Wait for leak (10/sec means 2 leak in 200ms)
        sleep(Duration::from_millis(200)).await;

        // Should have room after leaking
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_from_window() {
        // 60 requests per 60 seconds → leak_rate = 1.0/sec, capacity = 60
        let limiter = LeakyBucket::from_window(60, Duration::from_secs(60));
        assert_eq!(limiter.capacity, 60);
        assert!((limiter.leak_rate - 1.0).abs() < f64::EPSILON);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_rejects_when_full() {
        let limiter = LeakyBucket::new(3, 0.001); // very slow leak

        // Fill to capacity
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);

        // 4th request should be rejected
        assert!(!limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_remaining_reflects_level() {
        let limiter = LeakyBucket::new(10, 0.001); // very slow leak

        assert_eq!(limiter.remaining(), 10);

        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 9);

        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 7);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_state_not_limited_when_empty() {
        let limiter = LeakyBucket::new(5, 1.0);
        let state = limiter.state();

        assert_eq!(state.limit, 5);
        assert_eq!(state.remaining, 5);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_state_limited_when_full() {
        let limiter = LeakyBucket::new(2, 0.001);

        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert_eq!(state.limit, 2);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_reset_clears_level() {
        let limiter = LeakyBucket::new(5, 0.001);

        // Fill up
        for _ in 0..5 {
            limiter.try_acquire().await;
        }
        assert!(!limiter.try_acquire().await);

        // Reset
        limiter.reset().await;

        // Should have full capacity again
        assert_eq!(limiter.remaining(), 5);
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_wait_time_zero_when_room() {
        let limiter = LeakyBucket::new(5, 1.0);
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_wait_time_positive_when_full() {
        let limiter = LeakyBucket::new(2, 0.001);

        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let wait = limiter.wait_time().await;
        assert!(
            wait > Duration::ZERO,
            "expected positive wait, got {wait:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_acquire_succeeds_within_limit() {
        let limiter = LeakyBucket::new(5, 1.0);
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        // Should return almost instantly
        assert!(waited < Duration::from_millis(50));
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_acquire_waits_and_succeeds() {
        // Capacity 1, leak rate 100/sec → refills in ~10ms
        let limiter = LeakyBucket::new(1, 100.0);

        // Fill it
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // acquire() should wait for leak and then succeed
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(200));
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_acquire_exceeds_max_wait() {
        let limiter = LeakyBucket::new(1, 0.001); // very slow leak

        limiter.try_acquire().await;

        let result = limiter.acquire(Duration::from_millis(5)).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WaitExceeded { max_wait, .. })
                if max_wait == Duration::from_millis(5)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_try_acquire_n_supports_batch_permits() {
        let limiter = LeakyBucket::new(3, 0.001);

        // Batch acquisition succeeds when there is enough room.
        assert!(limiter.try_acquire_n(2).await);

        // A second batch requiring 2 permits should fail (only 1 remaining).
        assert!(!limiter.try_acquire_n(2).await);

        // Single permit still succeeds.
        assert!(limiter.try_acquire_n(1).await);

        // Bucket is full now.
        assert!(!limiter.try_acquire_n(1).await);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_leak_recovers_capacity() {
        // High leak rate so test is fast: 100/sec
        let limiter = LeakyBucket::new(3, 100.0);

        // Fill completely
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for rapid leak
        sleep(Duration::from_millis(20)).await;

        // Should have room again
        assert!(limiter.try_acquire().await);
    }

    // ── SmoothPacer tests ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_smooth_pacer() {
        let pacer = SmoothPacer::new(Duration::from_millis(50));

        // First request succeeds
        assert!(pacer.try_acquire().await);

        // Immediate second request fails
        assert!(!pacer.try_acquire().await);

        // Wait and try again
        sleep(Duration::from_millis(60)).await;
        assert!(pacer.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_from_rate() {
        // 10 requests/sec → 100ms min interval
        let pacer = SmoothPacer::from_rate(10.0);

        assert!(pacer.try_acquire().await);
        assert!(!pacer.try_acquire().await);

        sleep(Duration::from_millis(110)).await;
        assert!(pacer.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_remaining_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        // No request made yet → remaining should be 1
        assert_eq!(pacer.remaining(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_remaining_zero_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;
        // Immediately after → remaining should be 0
        assert_eq!(pacer.remaining(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_remaining_recovers_after_interval() {
        let pacer = SmoothPacer::new(Duration::from_millis(20));
        pacer.try_acquire().await;
        sleep(Duration::from_millis(30)).await;
        assert_eq!(pacer.remaining(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_state_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let state = pacer.state();

        assert_eq!(state.limit, 1);
        assert_eq!(state.remaining, 1);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_state_limited_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;

        let state = pacer.state();
        assert_eq!(state.limit, 1);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_reset_allows_immediate_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));

        pacer.try_acquire().await;
        assert!(!pacer.try_acquire().await);

        pacer.reset().await;

        // After reset, should succeed immediately
        assert!(pacer.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_wait_time_zero_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        assert_eq!(pacer.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_wait_time_positive_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;
        let wait = pacer.wait_time().await;
        assert!(
            wait > Duration::ZERO,
            "expected positive wait, got {wait:?}"
        );
        assert!(wait <= Duration::from_millis(500));
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_acquire_succeeds_immediately_when_fresh() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let waited = pacer.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(50));
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_acquire_waits_for_interval() {
        let pacer = SmoothPacer::new(Duration::from_millis(30));
        pacer.try_acquire().await;

        // Second acquire waits for interval
        let waited = pacer.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(10));
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_acquire_exceeds_max_wait() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;

        let result = pacer.acquire(Duration::from_millis(5)).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WaitExceeded { max_wait, .. })
                if max_wait == Duration::from_millis(5)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_try_acquire_n_only_supports_one() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));

        assert!(pacer.try_acquire_n(1).await);
        assert!(!pacer.try_acquire_n(2).await);
    }

    // ── LeakyBucket edge cases ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_from_window_zero_duration() {
        let limiter = LeakyBucket::from_window(10, Duration::ZERO);
        assert_eq!(limiter.capacity, 10);
        let expected = f64::from(10) / Duration::from_nanos(1).as_secs_f64();
        assert!((limiter.leak_rate - expected).abs() < f64::EPSILON);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_zero_capacity() {
        let limiter = LeakyBucket::new(0, 10.0);
        assert!(!limiter.try_acquire().await);
        assert_eq!(limiter.remaining(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_zero_leak_rate() {
        let limiter = LeakyBucket::new(2, 0.0);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
        // With zero leak rate, time_until_room should be MAX
        let wait = limiter.wait_time().await;
        assert_eq!(wait, Duration::MAX);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_state_is_limited_uses_guard_band() {
        // Fill to capacity → is_limited should be true due to room requirements
        let limiter = LeakyBucket::new(3, 0.001);
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        let state = limiter.state();
        assert!(state.is_limited);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_try_acquire_n_zero_permits() {
        let limiter = LeakyBucket::new(3, 0.001);
        // Zero permits should fill to exactly 0, which is within capacity
        // The level stays at 0, so next try_acquire works
        limiter.try_acquire_n(0).await;
        assert_eq!(limiter.remaining(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_try_acquire_n_exceeds_capacity() {
        let limiter = LeakyBucket::new(3, 0.001);
        assert!(!limiter.try_acquire_n(4).await);
        assert_eq!(limiter.remaining(), 3); // Nothing consumed
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_try_acquire_n_exact_capacity() {
        let limiter = LeakyBucket::new(5, 0.001);
        assert!(limiter.try_acquire_n(5).await);
        assert_eq!(limiter.remaining(), 0);
        assert!(!limiter.try_acquire_n(1).await);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_time_until_room_zero_capacity() {
        let limiter = LeakyBucket::new(0, 10.0);
        let wait = limiter.wait_time().await;
        assert_eq!(wait, Duration::MAX);
    }

    #[fcp_async_core::runtime::test]
    async fn leaky_bucket_remaining_after_partial_leak() {
        // High leak rate so leak is fast
        let limiter = LeakyBucket::new(10, 1000.0);
        for _ in 0..10 {
            limiter.try_acquire().await;
        }
        sleep(Duration::from_millis(10)).await;
        // Should have recovered some capacity
        assert!(limiter.remaining() > 0);
    }

    // ── SmoothPacer edge cases ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_from_rate_zero() {
        let pacer = SmoothPacer::from_rate(0.0);
        assert_eq!(pacer.min_interval, Duration::MAX);
        // First request should succeed (no previous request)
        assert!(pacer.try_acquire().await);
        // Second immediately fails
        assert!(!pacer.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_from_rate_negative() {
        let pacer = SmoothPacer::from_rate(-5.0);
        assert_eq!(pacer.min_interval, Duration::MAX);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_from_rate_tiny_positive_does_not_panic() {
        // Regression: 1.0 / 1e-20 ≈ 1e20 s overflows the Duration range, which
        // `Duration::from_secs_f64` panics on. `from_rate` must instead clamp to
        // Duration::MAX (an effectively-never pace), matching the rps<=0 arm.
        let pacer = SmoothPacer::from_rate(1e-20);
        assert_eq!(pacer.min_interval, Duration::MAX);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_state_limit_always_one() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let state = pacer.state();
        assert_eq!(state.limit, 1);

        pacer.try_acquire().await;
        let state = pacer.state();
        assert_eq!(state.limit, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_wait_time_decreases_over_time() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        pacer.try_acquire().await;

        let wait1 = pacer.wait_time().await;
        sleep(Duration::from_millis(30)).await;
        let wait2 = pacer.wait_time().await;
        assert!(wait2 < wait1);
    }

    #[fcp_async_core::runtime::test]
    async fn smooth_pacer_remaining_binary() {
        // SmoothPacer only ever has 0 or 1 remaining
        let pacer = SmoothPacer::new(Duration::from_millis(50));
        assert_eq!(pacer.remaining(), 1);
        pacer.try_acquire().await;
        assert_eq!(pacer.remaining(), 0);
        sleep(Duration::from_millis(60)).await;
        assert_eq!(pacer.remaining(), 1);
    }

    // ── Sync-only LeakyBucket tests ──────────────────────────────────

    #[test]
    fn leaky_bucket_new_sets_fields() {
        let limiter = LeakyBucket::new(10, 5.0);
        assert_eq!(limiter.capacity, 10);
        assert!((limiter.leak_rate - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_new_zero_capacity() {
        let limiter = LeakyBucket::new(0, 10.0);
        assert_eq!(limiter.capacity, 0);
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn leaky_bucket_new_zero_leak_rate() {
        let limiter = LeakyBucket::new(5, 0.0);
        assert_eq!(limiter.capacity, 5);
        assert!((limiter.leak_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_from_window_normal() {
        // 100 req / 10 sec = 10.0 per second
        let limiter = LeakyBucket::from_window(100, Duration::from_secs(10));
        assert_eq!(limiter.capacity, 100);
        assert!((limiter.leak_rate - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_from_window_one_per_second() {
        let limiter = LeakyBucket::from_window(1, Duration::from_secs(1));
        assert_eq!(limiter.capacity, 1);
        assert!((limiter.leak_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_from_window_zero_duration_clamps_window() {
        let limiter = LeakyBucket::from_window(10, Duration::ZERO);
        let expected = f64::from(10) / Duration::from_nanos(1).as_secs_f64();
        assert!((limiter.leak_rate - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_new_sanitizes_non_finite_rates() {
        let nan = LeakyBucket::new(1, f64::NAN);
        assert!(nan.leak_rate.abs() < f64::EPSILON);

        let neg_inf = LeakyBucket::new(1, f64::NEG_INFINITY);
        assert!(neg_inf.leak_rate.abs() < f64::EPSILON);

        let inf = LeakyBucket::new(1, f64::INFINITY);
        assert!((inf.leak_rate - f64::MAX).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_time_until_room_rounds_positive_subnanosecond_wait_up() {
        let limiter = LeakyBucket::from_window(10, Duration::ZERO);
        *limiter.level.lock() = 10.0;

        assert_eq!(limiter.time_until_room(), Duration::from_nanos(1));
    }

    #[test]
    fn leaky_bucket_initial_level_is_zero() {
        let limiter = LeakyBucket::new(10, 1.0);
        assert!((*limiter.level.lock()).abs() < f64::EPSILON);
    }

    #[test]
    fn leaky_bucket_remaining_starts_at_capacity() {
        let limiter = LeakyBucket::new(50, 1.0);
        assert_eq!(limiter.remaining(), 50);
    }

    #[test]
    fn leaky_bucket_state_fresh() {
        let limiter = LeakyBucket::new(20, 10.0);
        let state = limiter.state();
        assert_eq!(state.limit, 20);
        assert_eq!(state.remaining, 20);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[test]
    fn leaky_bucket_time_until_room_empty_bucket() {
        let limiter = LeakyBucket::new(5, 1.0);
        assert_eq!(limiter.time_until_room(), Duration::ZERO);
    }

    #[test]
    fn leaky_bucket_time_until_room_zero_capacity_sync() {
        let limiter = LeakyBucket::new(0, 10.0);
        assert_eq!(limiter.time_until_room(), Duration::MAX);
    }

    #[test]
    fn leaky_bucket_time_until_room_zero_leak_rate_full() {
        let limiter = LeakyBucket::new(2, 0.0);
        // Manually set level to capacity
        *limiter.level.lock() = 2.0;
        assert_eq!(limiter.time_until_room(), Duration::MAX);
    }

    #[test]
    fn leaky_bucket_time_until_room_extremely_small_leak_rate_does_not_panic() {
        let limiter = LeakyBucket::new(2, 1e-308);
        *limiter.level.lock() = 2.0;
        // With an extremely small leak rate, overflow/leak_rate would exceed
        // Duration::MAX representable seconds. The fix caps to Duration::MAX
        // instead of panicking in Duration::from_secs_f64.
        let wait = limiter.time_until_room();
        assert_eq!(wait, Duration::MAX);
    }

    // ── Sync-only SmoothPacer tests ──────────────────────────────────

    #[test]
    fn smooth_pacer_new_sets_interval() {
        let pacer = SmoothPacer::new(Duration::from_millis(250));
        assert_eq!(pacer.min_interval, Duration::from_millis(250));
    }

    #[test]
    fn smooth_pacer_new_zero_interval() {
        let pacer = SmoothPacer::new(Duration::ZERO);
        assert_eq!(pacer.min_interval, Duration::ZERO);
    }

    #[test]
    fn smooth_pacer_from_rate_one() {
        // 1 req/sec -> 1s interval
        let pacer = SmoothPacer::from_rate(1.0);
        assert_eq!(pacer.min_interval, Duration::from_secs(1));
    }

    #[test]
    fn smooth_pacer_from_rate_ten() {
        // 10 req/sec -> 100ms interval
        let pacer = SmoothPacer::from_rate(10.0);
        assert_eq!(pacer.min_interval, Duration::from_millis(100));
    }

    #[test]
    fn smooth_pacer_from_rate_zero_uses_max() {
        let pacer = SmoothPacer::from_rate(0.0);
        assert_eq!(pacer.min_interval, Duration::MAX);
    }

    #[test]
    fn smooth_pacer_from_rate_negative_uses_max() {
        let pacer = SmoothPacer::from_rate(-1.23);
        assert_eq!(pacer.min_interval, Duration::MAX);
    }

    #[test]
    fn smooth_pacer_from_rate_nan_uses_max() {
        let pacer = SmoothPacer::from_rate(f64::NAN);
        assert_eq!(pacer.min_interval, Duration::MAX);
    }

    #[test]
    fn smooth_pacer_from_rate_infinite_uses_zero() {
        let pacer = SmoothPacer::from_rate(f64::INFINITY);
        assert_eq!(pacer.min_interval, Duration::ZERO);
    }

    #[test]
    fn smooth_pacer_remaining_fresh() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        assert_eq!(pacer.remaining(), 1);
    }

    #[test]
    fn smooth_pacer_state_fresh() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let state = pacer.state();
        assert_eq!(state.limit, 1);
        assert_eq!(state.remaining, 1);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[test]
    fn smooth_pacer_last_request_initially_none() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        assert!(pacer.last_request.lock().is_none());
    }
}
