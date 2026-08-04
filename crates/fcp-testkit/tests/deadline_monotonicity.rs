//! Deadline monotonicity and timeout edge-case test suite.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.3.2`.
//!
//! Proves deterministic deadline budgeting and timeout handling:
//! - Monotonic budget consumption (remaining never increases)
//! - Zero and near-zero deadline edge cases
//! - Nested deadline composition
//! - Retry loop budget exhaustion
//! - Timeout error semantics consistency
//! - Deadline vs cancellation precedence

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::time;
use fcp_async_core::{AsyncError, Deadline, ExecutionContext};

// ============================================================================
// Deadline budget monotonicity
// ============================================================================

#[fcp_async_core::runtime::test]
async fn remaining_budget_decreases_monotonically() {
    let deadline = Deadline::after(Duration::from_millis(200));

    let mut prev = deadline.remaining();
    for _ in 0..10 {
        time::sleep(Duration::from_millis(10)).await;
        // Deadline is Copy, so .remaining() recalculates from the same absolute instant
        let current = deadline.remaining();
        assert!(
            current <= prev,
            "budget must decrease monotonically: prev={prev:?} current={current:?}"
        );
        prev = current;
    }
}

#[fcp_async_core::runtime::test]
async fn context_remaining_budget_shrinks_over_time() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(200));

    let initial = context.remaining_budget().expect("has deadline");
    time::sleep(Duration::from_millis(50)).await;
    let after = context.remaining_budget().expect("has deadline");

    assert!(
        after < initial,
        "budget must shrink: initial={initial:?} after={after:?}"
    );
}

// ============================================================================
// Zero and near-zero deadline edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn zero_deadline_times_out_before_polling_work() {
    // fcp-async-core deadlines are fail-closed: an already-expired deadline is
    // observed before polling user work, even when that work is synchronous.
    let deadline = Deadline::after(Duration::ZERO);
    assert!(deadline.is_expired());

    let result = deadline.run(async { 42 }).await;
    assert!(matches!(result, Err(AsyncError::Timeout { timeout_ms: 0 })));
}

#[fcp_async_core::runtime::test]
async fn zero_deadline_times_out_async_work() {
    // But async work that needs a second poll will timeout
    let deadline = Deadline::after(Duration::ZERO);

    let result = deadline
        .run(async { time::sleep(Duration::from_millis(10)).await })
        .await;
    assert!(
        matches!(result, Err(AsyncError::Timeout { .. })),
        "async work should timeout with zero deadline: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn expired_context_times_out_async_work() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(1));

    // Let deadline expire
    time::sleep(Duration::from_millis(5)).await;

    let result = context
        .run(async { time::sleep(Duration::from_millis(10)).await })
        .await;
    assert!(
        matches!(
            result,
            Err(AsyncError::Timeout { .. } | AsyncError::Cancelled)
        ),
        "expired context should fail: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn very_short_deadline_completes_fast_work() {
    let deadline = Deadline::after(Duration::from_millis(100));

    // Work that completes almost instantly
    let result = deadline.run(async { 42 }).await;
    assert_eq!(result.unwrap(), 42);
}

#[fcp_async_core::runtime::test]
async fn expired_deadline_is_detected() {
    let deadline = Deadline::after(Duration::from_millis(10));
    time::sleep(Duration::from_millis(20)).await;

    assert!(deadline.is_expired());
    assert_eq!(deadline.remaining(), Duration::ZERO);
}

// ============================================================================
// Nested deadline composition
// ============================================================================

#[fcp_async_core::runtime::test]
async fn child_context_inherits_deadline() {
    let parent = ExecutionContext::request_scoped(Duration::from_millis(200));
    let child = parent.child();

    let parent_budget = parent.remaining_budget().expect("has deadline");
    let child_budget = child.remaining_budget().expect("has deadline");

    // Child should have approximately the same budget (shared deadline)
    let diff = parent_budget
        .checked_sub(child_budget)
        .unwrap_or_else(|| child_budget.saturating_sub(parent_budget));
    assert!(
        diff < Duration::from_millis(5),
        "budgets should be close: diff={diff:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn child_with_shorter_deadline_uses_shorter() {
    let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
    let child = parent.child().with_deadline(Duration::from_millis(50));

    // Child has its own shorter deadline
    let child_budget = child.remaining_budget().expect("has deadline");
    assert!(
        child_budget < Duration::from_millis(100),
        "child should use shorter deadline: {child_budget:?}"
    );

    // Child should timeout on slow work
    let result = child
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;
    assert!(matches!(result, Err(AsyncError::Timeout { .. })));
}

#[fcp_async_core::runtime::test]
async fn no_deadline_context_runs_without_timeout() {
    let context = ExecutionContext::background();

    assert!(context.remaining_budget().is_none());

    // Should complete without timeout
    let result = context
        .run(async {
            time::sleep(Duration::from_millis(10)).await;
            42
        })
        .await;
    assert_eq!(result.unwrap(), 42);
}

// ============================================================================
// Retry loop budget exhaustion
// ============================================================================

#[fcp_async_core::runtime::test]
async fn retry_loop_exhausts_deadline_budget() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(100));
    let attempts = Arc::new(AtomicUsize::new(0));

    let mut last_err = None;
    for _ in 0..100 {
        attempts.fetch_add(1, Ordering::SeqCst);
        match context
            .run(async { time::sleep(Duration::from_millis(20)).await })
            .await
        {
            Ok(()) => {}
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }

    let total_attempts = attempts.load(Ordering::SeqCst);
    assert!(
        (2..=7).contains(&total_attempts),
        "expected 2-7 attempts in 100ms with 20ms sleeps, got {total_attempts}"
    );
    assert!(
        matches!(last_err, Some(AsyncError::Timeout { .. })),
        "should exhaust deadline: {last_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn retry_loop_remaining_budget_decreases_each_iteration() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(200));
    let mut budgets = Vec::new();

    for _ in 0..5 {
        if let Some(budget) = context.remaining_budget() {
            if budget.is_zero() {
                break;
            }
            budgets.push(budget);
        }
        let _ = context
            .run(async { time::sleep(Duration::from_millis(20)).await })
            .await;
    }

    // Verify monotonic decrease
    for window in budgets.windows(2) {
        assert!(
            window[1] < window[0],
            "budget must decrease monotonically: {:?} -> {:?}",
            window[0],
            window[1]
        );
    }
}

// ============================================================================
// Timeout error semantics
// ============================================================================

#[fcp_async_core::runtime::test]
async fn timeout_error_contains_timeout_ms() {
    let result = time::timeout(
        Duration::from_millis(10),
        time::sleep(Duration::from_secs(5)),
    )
    .await;
    match result {
        Err(AsyncError::Timeout { timeout_ms }) => {
            assert_eq!(timeout_ms, 10);
        }
        other => panic!("expected Timeout error, got: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn timeout_does_not_fire_for_fast_work() {
    let result = time::timeout(Duration::from_millis(500), async { 42 }).await;
    assert_eq!(result.unwrap(), 42);
}

#[fcp_async_core::runtime::test]
async fn context_timeout_error_is_timeout_variant() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(10));

    let err = context
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .expect_err("should timeout");

    assert!(
        matches!(err, AsyncError::Timeout { .. }),
        "context timeout should produce Timeout error: {err:?}"
    );
}

// ============================================================================
// Deadline vs cancellation precedence
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cancellation_beats_deadline_when_both_ready() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(10));

    // Let deadline expire
    time::sleep(Duration::from_millis(20)).await;

    // Also cancel
    context.cancel();

    let err = context
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .expect_err("should fail");

    // Cancellation takes precedence (biased select in run())
    assert_eq!(err, AsyncError::Cancelled);
}

#[fcp_async_core::runtime::test]
async fn deadline_fires_when_not_cancelled() {
    let context = ExecutionContext::request_scoped(Duration::from_millis(20));

    // Don't cancel — let deadline fire naturally
    let err = context
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .expect_err("should timeout");

    assert!(
        matches!(err, AsyncError::Timeout { .. }),
        "uncancelled context should timeout: {err:?}"
    );
}

// ============================================================================
// Deadline::at absolute instant
// ============================================================================

#[fcp_async_core::runtime::test]
async fn deadline_at_past_instant_is_expired() {
    let past = Instant::now()
        .checked_sub(Duration::from_millis(100))
        .expect("100ms ago");
    let deadline = Deadline::at(past);

    assert!(deadline.is_expired());
    assert_eq!(deadline.remaining(), Duration::ZERO);
}

#[fcp_async_core::runtime::test]
async fn deadline_at_future_instant_has_budget() {
    let future_instant = Instant::now() + Duration::from_secs(10);
    let deadline = Deadline::at(future_instant);

    assert!(!deadline.is_expired());
    assert!(deadline.remaining() > Duration::from_secs(9));
}
