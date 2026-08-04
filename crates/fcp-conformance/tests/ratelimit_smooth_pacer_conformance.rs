//! `SmoothPacer` minimum-interval pacing conformance.
//!
//! `fcp_ratelimit::SmoothPacer` enforces a minimum wall-clock
//! interval between requests. It is distinct from the other two
//! `RateLimiter` impls already pinned at conformance level:
//!
//! - `TokenBucket` (br already covers): burst capacity + continuous
//!   refill rate.
//! - `LeakyBucket` (br-ilmri): bucket capacity + leak rate.
//! - `SmoothPacer` (THIS FILE): pure inter-request spacing — no
//!   capacity, no burst, just "wait at least N between requests".
//!
//! Unique invariants pinned here:
//!
//! 1. **First acquire always succeeds.** No prior request → nothing
//!    to wait for, regardless of how short `min_interval` is.
//! 2. **Acquire within `min_interval` is rejected.**
//! 3. **Acquire after `min_interval` succeeds.**
//! 4. **`from_rate(NaN | <=0)` → never-acquirable pacer.** The
//!    saturating `Duration::MAX` construction prevents a misconfigured
//!    rate from collapsing to "always allow".
//! 5. **`from_rate(infinite)` → no-delay pacer.**
//! 6. **`wait_time` decreases as elapsed time approaches
//!    `min_interval`.**
//! 7. **`reset()` clears the last-request timestamp.**
//! 8. **`acquire(max_wait)` honours the deadline contract** —
//!    surfaces `WaitExceeded` when the projected wait > `max_wait`.

use std::time::Duration;

use fcp_async_core::time::sleep;
use fcp_ratelimit::{RateLimitError, RateLimiter, SmoothPacer};

#[fcp_async_core::runtime::test]
async fn first_acquire_always_succeeds_regardless_of_interval() {
    // Even with a 1-second min_interval, the FIRST acquire has
    // nothing to wait for and must succeed immediately.
    let pacer = SmoothPacer::new(Duration::from_secs(1));
    assert!(
        pacer.try_acquire().await,
        "first acquire on a fresh pacer must always succeed"
    );
}

#[fcp_async_core::runtime::test]
async fn second_acquire_within_min_interval_is_rejected() {
    let pacer = SmoothPacer::new(Duration::from_millis(200));
    assert!(pacer.try_acquire().await, "first acquire");
    assert!(
        !pacer.try_acquire().await,
        "second acquire within 200 ms min_interval must reject"
    );
}

#[fcp_async_core::runtime::test]
async fn acquire_after_min_interval_succeeds() {
    let pacer = SmoothPacer::new(Duration::from_millis(40));
    assert!(pacer.try_acquire().await, "first acquire");

    sleep(Duration::from_millis(60)).await;
    assert!(
        pacer.try_acquire().await,
        "after sleeping past min_interval, acquire must succeed"
    );
}

#[fcp_async_core::runtime::test]
async fn from_rate_zero_yields_never_acquirable_pacer() {
    // NORMATIVE: requests_per_second = 0 maps to Duration::MAX, so
    // the second acquire never succeeds within a reasonable wait.
    // Pinning this prevents a misconfigured rate from silently
    // collapsing to "always allow".
    let pacer = SmoothPacer::from_rate(0.0);
    assert!(pacer.try_acquire().await, "first acquire still works");
    // The wait_time must be the saturating max — no point sleeping;
    // we just check it is far above any reasonable cap.
    let w = pacer.wait_time().await;
    assert!(
        w >= Duration::from_secs(60 * 60),
        "from_rate(0.0) must yield a never-acquirable pacer (wait_time = Duration::MAX); \
         got {w:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn from_rate_negative_yields_never_acquirable_pacer() {
    // Same defensive treatment for negative rates.
    let pacer = SmoothPacer::from_rate(-5.0);
    assert!(pacer.try_acquire().await);
    let w = pacer.wait_time().await;
    assert!(
        w >= Duration::from_secs(60 * 60),
        "from_rate(-5.0) must yield a never-acquirable pacer; got {w:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn from_rate_nan_yields_never_acquirable_pacer() {
    let pacer = SmoothPacer::from_rate(f64::NAN);
    assert!(pacer.try_acquire().await);
    let w = pacer.wait_time().await;
    assert!(
        w >= Duration::from_secs(60 * 60),
        "from_rate(NaN) must yield a never-acquirable pacer; got {w:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn from_rate_infinite_yields_no_delay_pacer() {
    // Symmetric to the never-acquirable case: an infinite rate
    // means "no minimum spacing", so back-to-back acquires must
    // succeed.
    let pacer = SmoothPacer::from_rate(f64::INFINITY);
    assert!(pacer.try_acquire().await, "first acquire");
    assert!(
        pacer.try_acquire().await,
        "from_rate(inf) must allow consecutive acquires with no spacing"
    );
    assert!(
        pacer.try_acquire().await,
        "third consecutive acquire must also succeed"
    );
}

#[fcp_async_core::runtime::test]
async fn wait_time_decreases_as_elapsed_time_grows() {
    let pacer = SmoothPacer::new(Duration::from_millis(200));
    assert!(pacer.try_acquire().await);

    let w1 = pacer.wait_time().await;
    sleep(Duration::from_millis(50)).await;
    let w2 = pacer.wait_time().await;
    assert!(
        w2 < w1,
        "wait_time must decrease as time advances toward min_interval; got w1={w1:?}, w2={w2:?}"
    );
    assert!(
        w2 > Duration::ZERO,
        "we still have ~150 ms left; wait_time must remain positive"
    );
}

#[fcp_async_core::runtime::test]
async fn reset_clears_last_request_so_next_acquire_succeeds_immediately() {
    let pacer = SmoothPacer::new(Duration::from_secs(1));
    assert!(pacer.try_acquire().await, "first acquire");
    assert!(
        !pacer.try_acquire().await,
        "fixture sanity: rate-limited at the second acquire"
    );

    pacer.reset().await;

    assert!(
        pacer.try_acquire().await,
        "after reset(), the pacer must behave like a fresh instance — \
         next acquire succeeds immediately even within the original min_interval"
    );
}

#[fcp_async_core::runtime::test]
async fn acquire_returns_wait_exceeded_when_max_wait_too_short() {
    // The deadline contract: acquire(max_wait) with max_wait <
    // remaining min_interval must surface WaitExceeded.
    let pacer = SmoothPacer::new(Duration::from_secs(10));
    assert!(pacer.try_acquire().await, "first acquire");

    let result = pacer.acquire(Duration::from_millis(10)).await;
    match result {
        Err(RateLimitError::WaitExceeded {
            wait_time,
            max_wait,
        }) => {
            assert_eq!(
                max_wait,
                Duration::from_millis(10),
                "max_wait must be reported back unchanged"
            );
            assert!(
                wait_time > max_wait,
                "wait_time must exceed max_wait when WaitExceeded is returned"
            );
        }
        other => panic!("expected WaitExceeded, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn consecutive_paced_requests_honour_min_interval() {
    // After a paced wait, the next request succeeds and resets
    // the spacing window for the request AFTER that.
    let pacer = SmoothPacer::new(Duration::from_millis(40));
    assert!(pacer.try_acquire().await, "first acquire");

    sleep(Duration::from_millis(60)).await;
    assert!(pacer.try_acquire().await, "second acquire after wait");

    // Immediately after the second acquire, the third within the
    // window must reject.
    assert!(
        !pacer.try_acquire().await,
        "third acquire immediately after the second must reject — pacing is per-pair, \
         not just from the very first request"
    );
}
