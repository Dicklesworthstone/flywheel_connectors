//! Cross-crate conformance tests for `fcp-ratelimit`'s token bucket invariants.
//!
//! These tests pin the public `RateLimiter` contract that downstream
//! connectors rely on:
//! - multi-permit acquisition is atomic
//! - refill phase is preserved across partial intervals
//! - refill is monotonic and capped by configured burst capacity
//! - drained buckets refill at the configured smooth rate
//! - zero-rate buckets remain unavailable
//! - zero-permit requests are a no-op
//! - `reset()` restores full burst capacity

use std::time::Duration;

use fcp_async_core::time::sleep;
use fcp_ratelimit::{RateLimitConfig, RateLimiter, TokenBucket};

#[fcp_async_core::runtime::test]
async fn token_bucket_multi_permit_acquire_is_atomic() {
    let limiter = TokenBucket::new(2, Duration::from_secs(1));

    assert!(
        !limiter.try_acquire_n(3).await,
        "oversized acquisition must fail"
    );
    assert_eq!(
        limiter.remaining(),
        2,
        "failed oversized acquisition must not partially consume tokens"
    );

    assert!(
        limiter.try_acquire_n(2).await,
        "exact-capacity acquisition should succeed"
    );
    assert_eq!(limiter.remaining(), 0);
}

#[fcp_async_core::runtime::test]
async fn token_bucket_refill_preserves_elapsed_phase() {
    let limiter = TokenBucket::new(1, Duration::from_millis(100));

    assert!(
        limiter.try_acquire().await,
        "initial token should be available"
    );

    sleep(Duration::from_millis(150)).await;
    assert!(
        limiter.try_acquire().await,
        "first elapsed refill should restore one token"
    );

    sleep(Duration::from_millis(50)).await;
    assert!(
        limiter.try_acquire().await,
        "remainder from the first refill window must be preserved"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_zero_permit_acquire_is_a_no_op() {
    let limiter = TokenBucket::new(3, Duration::from_secs(1));

    assert!(limiter.try_acquire_n(0).await);
    assert_eq!(
        limiter.remaining(),
        3,
        "zero-permit acquisition must not mutate bucket state"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_reset_restores_burst_capacity() {
    let limiter =
        TokenBucket::from_config(&RateLimitConfig::new(2, Duration::from_secs(1)).with_burst(4));

    assert!(limiter.try_acquire_n(4).await);
    let exhausted = limiter.state();
    assert_eq!(exhausted.limit, 4);
    assert_eq!(exhausted.remaining, 0);
    assert!(exhausted.is_limited);

    limiter.reset().await;

    let reset = limiter.state();
    assert_eq!(reset.limit, 4);
    assert_eq!(reset.remaining, 4);
    assert!(!reset.is_limited);
    assert_eq!(limiter.wait_time().await, Duration::ZERO);
}

#[fcp_async_core::runtime::test]
async fn token_bucket_refill_remaining_is_monotonic_until_capacity() {
    let limiter =
        TokenBucket::from_config(&RateLimitConfig::new(4, Duration::from_millis(80)).with_burst(4));

    assert!(limiter.try_acquire_n(4).await);
    assert_eq!(limiter.remaining(), 0);

    sleep(Duration::from_millis(25)).await;
    let after_first_interval = limiter.remaining();
    assert!(
        (1..=4).contains(&after_first_interval),
        "first refill should add tokens without exceeding capacity; got {after_first_interval}"
    );

    sleep(Duration::from_millis(25)).await;
    let after_second_interval = limiter.remaining();
    assert!(
        after_second_interval >= after_first_interval,
        "token count must be monotonic between acquisitions"
    );
    assert!(
        after_second_interval <= 4,
        "token count must stay capped by bucket capacity"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_refill_is_capped_by_burst_allowance() {
    let limiter =
        TokenBucket::from_config(&RateLimitConfig::new(2, Duration::from_millis(40)).with_burst(5));

    assert!(limiter.try_acquire_n(5).await);
    assert_eq!(limiter.remaining(), 0);

    sleep(Duration::from_millis(150)).await;
    let refilled = limiter.state();
    assert_eq!(refilled.limit, 5);
    assert_eq!(
        refilled.remaining, 5,
        "idle refill must restore, but not exceed, burst capacity"
    );
    assert!(!refilled.is_limited);

    sleep(Duration::from_millis(80)).await;
    assert_eq!(
        limiter.remaining(),
        5,
        "additional idle time must not accumulate tokens beyond burst capacity"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_drain_then_refill_restores_tokens_at_smooth_rate() {
    let limiter = TokenBucket::from_config(&RateLimitConfig::new(2, Duration::from_millis(100)));

    assert!(limiter.try_acquire_n(2).await);
    assert_eq!(limiter.remaining(), 0);
    assert!(!limiter.try_acquire().await);

    sleep(Duration::from_millis(60)).await;
    assert!(
        limiter.try_acquire().await,
        "one smooth refill interval should restore one token"
    );
    assert_eq!(
        limiter.remaining(),
        0,
        "consuming the first refilled token should drain the bucket again"
    );

    sleep(Duration::from_millis(60)).await;
    assert!(
        limiter.try_acquire().await,
        "the next smooth refill interval should restore the next token"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_zero_rate_remains_unavailable() {
    let limiter = TokenBucket::from_config(&RateLimitConfig::new(0, Duration::from_millis(20)));

    let initial = limiter.state();
    assert_eq!(initial.limit, 0);
    assert_eq!(initial.remaining, 0);
    assert!(initial.is_limited);
    assert_eq!(limiter.wait_time().await, Duration::MAX);
    assert!(!limiter.try_acquire().await);

    sleep(Duration::from_millis(40)).await;
    let after_wait = limiter.state();
    assert_eq!(after_wait.limit, 0);
    assert_eq!(after_wait.remaining, 0);
    assert!(after_wait.is_limited);
    assert_eq!(limiter.wait_time().await, Duration::MAX);
    assert!(!limiter.try_acquire().await);
}
