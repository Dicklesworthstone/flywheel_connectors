//! Parity + performance verification for fcp-async-core runtime primitives.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.2.4`.
//!
//! Validates:
//! - Timeout precision: fcp-async-core timeouts meet wall-clock accuracy thresholds
//! - Scheduling behavior: spawn ordering and yield semantics match expectations
//! - Cancellation propagation: signal latency within acceptable bounds
//! - Shutdown ordering: `TaskGroup` drains deterministically
//! - Channel throughput: bounded/unbounded channels meet baseline throughput
//! - Error/recovery behavior: error paths don't introduce unexpected latency

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::{AsyncError, CancellationToken, ExecutionContext, TaskGroup};
use fcp_async_core::{task, time};

// ============================================================================
// Timeout precision
// ============================================================================

/// Timeout fires within acceptable wall-clock tolerance.
#[fcp_async_core::runtime::test]
async fn timeout_precision_10ms() {
    let target = Duration::from_millis(10);
    let start = Instant::now();
    let _ = time::timeout(target, time::sleep(Duration::from_secs(60))).await;
    let elapsed = start.elapsed();

    // Should fire within target + 15ms tolerance (scheduler jitter)
    let upper = target + Duration::from_millis(15);
    assert!(
        elapsed >= target && elapsed <= upper,
        "10ms timeout precision: expected {target:?}..{upper:?}, got {elapsed:?}"
    );
}

/// Timeout fires within acceptable wall-clock tolerance (50ms).
#[fcp_async_core::runtime::test]
async fn timeout_precision_50ms() {
    let target = Duration::from_millis(50);
    let start = Instant::now();
    let _ = time::timeout(target, time::sleep(Duration::from_secs(60))).await;
    let elapsed = start.elapsed();

    let upper = target + Duration::from_millis(15);
    assert!(
        elapsed >= target && elapsed <= upper,
        "50ms timeout precision: expected {target:?}..{upper:?}, got {elapsed:?}"
    );
}

/// Multiple sequential timeouts maintain cumulative precision.
#[fcp_async_core::runtime::test]
async fn timeout_precision_cumulative() {
    let start = Instant::now();
    for _ in 0..5 {
        let _ = time::timeout(
            Duration::from_millis(20),
            time::sleep(Duration::from_secs(60)),
        )
        .await;
    }
    let elapsed = start.elapsed();

    // 5 * 20ms = 100ms, allow 100ms + 50ms tolerance
    assert!(
        elapsed >= Duration::from_millis(100) && elapsed <= Duration::from_millis(150),
        "cumulative timeout drift: {elapsed:?}"
    );
}

// ============================================================================
// Sleep precision
// ============================================================================

/// Sleep precision across multiple durations.
#[fcp_async_core::runtime::test]
async fn sleep_precision_sweep() {
    for target_ms in [5, 10, 25, 50, 100] {
        let target = Duration::from_millis(target_ms);
        let start = Instant::now();
        time::sleep(target).await;
        let elapsed = start.elapsed();

        let upper = target + Duration::from_millis(15);
        assert!(
            elapsed >= target && elapsed <= upper,
            "sleep {target_ms}ms: expected {target:?}..{upper:?}, got {elapsed:?}"
        );
    }
}

// ============================================================================
// Scheduling behavior
// ============================================================================

/// Spawned tasks execute and join correctly under load.
#[fcp_async_core::runtime::test]
async fn spawn_fanout_correctness() {
    let sum = Arc::new(AtomicU64::new(0));
    let count = 64;

    let mut handles = Vec::new();
    for i in 0..count {
        let s = Arc::clone(&sum);
        handles.push(task::spawn(async move {
            s.fetch_add(i, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let expected: u64 = (0..count).sum();
    assert_eq!(sum.load(Ordering::Relaxed), expected);
}

/// `yield_now` yields to other tasks in the same runtime.
#[fcp_async_core::runtime::test]
async fn yield_allows_other_tasks_progress() {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = Arc::clone(&flag);

    let setter = task::spawn(async move {
        flag_clone.store(true, Ordering::SeqCst);
    });

    // Yield to let setter run
    task::yield_now().await;
    let _ = setter.await;

    assert!(flag.load(Ordering::SeqCst));
}

/// Spawn latency: spawning + joining stays within a bounded responsiveness window.
#[fcp_async_core::runtime::test]
async fn spawn_join_latency() {
    let start = Instant::now();
    let handle = task::spawn(async { 42 });
    let _ = handle.await.unwrap();
    let elapsed = start.elapsed();

    // Shared remote workers can have millisecond-scale scheduling jitter.
    assert!(
        elapsed < Duration::from_millis(50),
        "spawn+join latency too high: {elapsed:?}"
    );
}

// ============================================================================
// Cancellation propagation latency
// ============================================================================

/// Cancellation signal propagates within acceptable latency.
#[fcp_async_core::runtime::test]
async fn cancellation_propagation_latency() {
    let token = CancellationToken::new();
    let mut listener = token.subscribe();

    let start = Instant::now();
    token.cancel();
    let _ = listener.cancelled().await;
    let elapsed = start.elapsed();

    // Propagation should be sub-millisecond
    assert!(
        elapsed < Duration::from_millis(5),
        "cancellation propagation too slow: {elapsed:?}"
    );
}

/// Cancellation propagation across spawned tasks.
#[fcp_async_core::runtime::test]
async fn cancellation_propagation_across_spawn() {
    let token = CancellationToken::new();
    let mut listener = token.subscribe();

    let start = Instant::now();
    let waiter = task::spawn(async move { listener.cancelled().await });

    task::yield_now().await;
    token.cancel();

    let result = time::timeout(Duration::from_millis(100), waiter).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "waiter should not hang");
    assert!(
        elapsed < Duration::from_millis(50),
        "cross-spawn cancellation too slow: {elapsed:?}"
    );
}

/// `ExecutionContext` cancellation propagation through hierarchy.
#[fcp_async_core::runtime::test]
async fn context_hierarchy_cancellation_latency() {
    let root = ExecutionContext::request_scoped(Duration::from_secs(10));
    let child = root.child();
    let grandchild = child.child();

    let start = Instant::now();
    root.cancel();
    let elapsed_cancel = start.elapsed();

    assert!(root.is_cancelled());
    assert!(child.is_cancelled());
    assert!(grandchild.is_cancelled());

    // All three should see cancellation in < 1ms
    assert!(
        elapsed_cancel < Duration::from_millis(5),
        "hierarchy cancellation too slow: {elapsed_cancel:?}"
    );

    // Grandchild run() should fail immediately
    let start = Instant::now();
    let err = grandchild
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .unwrap_err();
    let elapsed_run = start.elapsed();

    assert_eq!(err, AsyncError::Cancelled);
    assert!(
        elapsed_run < Duration::from_millis(10),
        "cancelled run() return too slow: {elapsed_run:?}"
    );
}

// ============================================================================
// Shutdown ordering
// ============================================================================

/// `TaskGroup` shutdown completes cooperative tasks before deadline.
#[fcp_async_core::runtime::test]
async fn shutdown_ordering_cooperative() {
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut group = TaskGroup::new();

    for i in 0..4 {
        let order = Arc::clone(&order);
        let mut listener = group.subscribe_cancellation();
        group.spawn(format!("task-{i}"), async move {
            listener.cancelled().await?;
            order.lock().unwrap().push(i);
            Ok(())
        });
    }

    task::yield_now().await;
    time::sleep(Duration::from_millis(10)).await;

    let start = Instant::now();
    let result = group.shutdown(Duration::from_secs(2)).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    let finished = order.lock().unwrap().len();
    assert_eq!(finished, 4, "all tasks should finish");

    // Shutdown of cooperative tasks should be fast (< 100ms)
    assert!(
        elapsed < Duration::from_millis(100),
        "cooperative shutdown too slow: {elapsed:?}"
    );
}

/// `TaskGroup` shutdown with timeout reports stuck tasks quickly.
#[fcp_async_core::runtime::test]
async fn shutdown_timeout_latency() {
    let mut group = TaskGroup::new();
    group.spawn("stuck", async move {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });

    let start = Instant::now();
    let result = group.shutdown(Duration::from_millis(50)).await;
    let elapsed = start.elapsed();

    assert!(matches!(result, Err(AsyncError::Timeout { .. })));
    // Should abort within timeout + small overhead
    assert!(
        elapsed < Duration::from_millis(100),
        "shutdown timeout exceeded allowance: {elapsed:?}"
    );
}

// ============================================================================
// Channel throughput
// ============================================================================

/// Bounded channel achieves minimum throughput for small messages.
#[fcp_async_core::runtime::test]
async fn bounded_channel_throughput() {
    let (tx, mut rx) = fcp_async_core::channel::bounded::<u64>("perf-q", 256);

    let count = 10_000u64;
    let sender = task::spawn(async move {
        for i in 0..count {
            tx.send(i).await.unwrap();
        }
    });

    let start = Instant::now();
    let mut received = 0u64;
    while received < count {
        if rx.recv().await.is_some() {
            received += 1;
        } else {
            break;
        }
    }
    let elapsed = start.elapsed();
    sender.await.unwrap();

    assert_eq!(received, count);
    // 10K messages should take < 500ms (conservative; usually < 50ms)
    assert!(
        elapsed < Duration::from_millis(500),
        "bounded channel too slow for {count} msgs: {elapsed:?}"
    );
}

/// Raw mpsc channel achieves comparable throughput.
#[fcp_async_core::runtime::test]
async fn mpsc_channel_throughput() {
    let (tx, mut rx) = fcp_async_core::channel::mpsc::channel::<u64>(256);

    let count = 10_000u64;
    let sender = task::spawn(async move {
        for i in 0..count {
            tx.send(i).await.unwrap();
        }
    });

    let start = Instant::now();
    let mut received = 0u64;
    while received < count {
        if rx.recv().await.is_some() {
            received += 1;
        } else {
            break;
        }
    }
    let elapsed = start.elapsed();
    sender.await.unwrap();

    assert_eq!(received, count);
    assert!(
        elapsed < Duration::from_millis(500),
        "mpsc channel too slow for {count} msgs: {elapsed:?}"
    );
}

// ============================================================================
// Error/recovery behavior
// ============================================================================

/// Timeout error path doesn't add latency beyond the timeout duration.
#[fcp_async_core::runtime::test]
async fn error_path_no_excess_latency() {
    let start = Instant::now();
    let result = time::timeout(
        Duration::from_millis(20),
        time::sleep(Duration::from_secs(60)),
    )
    .await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Error path overhead should be < 15ms
    let overhead = elapsed.saturating_sub(Duration::from_millis(20));
    assert!(
        overhead < Duration::from_millis(15),
        "timeout error overhead too high: {overhead:?}"
    );
}

/// Cancellation error path is near-instantaneous.
#[fcp_async_core::runtime::test]
async fn cancellation_error_path_latency() {
    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();

    let start = Instant::now();
    let result = ctx
        .run(async { time::sleep(Duration::from_secs(60)).await })
        .await;
    let elapsed = start.elapsed();

    assert_eq!(result.unwrap_err(), AsyncError::Cancelled);
    assert!(
        elapsed < Duration::from_millis(5),
        "cancellation error too slow: {elapsed:?}"
    );
}

/// Consecutive errors don't accumulate latency.
#[fcp_async_core::runtime::test]
async fn consecutive_errors_no_accumulation() {
    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();

    let start = Instant::now();
    for _ in 0..10 {
        let _ = ctx
            .run(async { time::sleep(Duration::from_secs(60)).await })
            .await;
    }
    let elapsed = start.elapsed();

    // 10 cancelled runs should still be < 50ms total
    assert!(
        elapsed < Duration::from_millis(50),
        "consecutive errors accumulated latency: {elapsed:?}"
    );
}

// ============================================================================
// Deadline budget tracking accuracy
// ============================================================================

/// `Deadline::remaining()` tracks real wall-clock consumption.
#[fcp_async_core::runtime::test]
async fn deadline_budget_tracks_wall_clock() {
    let deadline = fcp_async_core::Deadline::after(Duration::from_millis(200));
    let initial = deadline.remaining();

    time::sleep(Duration::from_millis(50)).await;
    let after_50 = deadline.remaining();

    time::sleep(Duration::from_millis(50)).await;
    let after_100 = deadline.remaining();

    // Budget should decrease by ~50ms each step (within 20ms tolerance)
    let consumed_first = initial.saturating_sub(after_50);
    let consumed_second = after_50.saturating_sub(after_100);

    assert!(
        consumed_first >= Duration::from_millis(30) && consumed_first <= Duration::from_millis(70),
        "first 50ms consumed {consumed_first:?}"
    );
    assert!(
        consumed_second >= Duration::from_millis(30)
            && consumed_second <= Duration::from_millis(70),
        "second 50ms consumed {consumed_second:?}"
    );
}

/// Expired deadline returns `Duration::ZERO` consistently.
#[fcp_async_core::runtime::test]
async fn expired_deadline_zero_budget_stable() {
    let deadline = fcp_async_core::Deadline::after(Duration::from_millis(10));
    time::sleep(Duration::from_millis(20)).await;

    // Multiple calls should all return ZERO
    for _ in 0..5 {
        assert_eq!(deadline.remaining(), Duration::ZERO);
    }
}

// ============================================================================
// Interval precision
// ============================================================================

/// Interval ticks maintain cadence accuracy.
#[fcp_async_core::runtime::test]
async fn interval_cadence_accuracy() {
    let period = Duration::from_millis(20);
    let mut interval = time::interval(period);
    let tick_count: u32 = 5;

    let start = Instant::now();
    for _ in 0..tick_count {
        interval.tick().await;
    }
    let elapsed = start.elapsed();

    // First tick is immediate, then 4 intervals = 80ms
    // Allow 30ms tolerance
    let expected = period * (tick_count - 1);
    let upper = expected + Duration::from_millis(30);
    assert!(
        elapsed >= expected && elapsed <= upper,
        "interval cadence: expected {expected:?}..{upper:?}, got {elapsed:?}"
    );
}

// ============================================================================
// Concurrent workload stability
// ============================================================================

/// Many concurrent contexts don't interfere with each other.
#[fcp_async_core::runtime::test]
async fn concurrent_contexts_isolation() {
    let completed = Arc::new(AtomicUsize::new(0));
    let count = 32;

    let mut handles = Vec::new();
    for _ in 0..count {
        let completed = Arc::clone(&completed);
        handles.push(task::spawn(async move {
            let ctx = ExecutionContext::request_scoped(Duration::from_millis(200));
            let result = ctx
                .run(async {
                    time::sleep(Duration::from_millis(10)).await;
                    42
                })
                .await;
            if result.is_ok() {
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        completed.load(Ordering::SeqCst),
        count,
        "all concurrent contexts should complete"
    );
}
