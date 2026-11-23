//! Cancellation race and shutdown propagation test suite.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.3.1`.
//!
//! Exercises deterministic cancellation-race and shutdown-propagation scenarios
//! against `fcp_async_core` primitives. All tests are designed to detect:
//! - Hangs from lost cancellation signals
//! - Orphaned tasks after group shutdown
//! - Race conditions between cancellation and work completion
//! - Propagation failures in nested context hierarchies
//! - Dropped-sender detection (watch channel semantics)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fcp_async_core::channel::watch;
use fcp_async_core::shutdown::{sleep_or_shutdown, wait_for_shutdown};
use fcp_async_core::{AsyncError, CancellationToken, ExecutionContext, TaskGroup};
use fcp_async_core::{task, time};

// ============================================================================
// CancellationToken races
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cancel_before_subscribe_is_immediately_visible() {
    let token = CancellationToken::new();
    token.cancel();

    let mut listener = token.subscribe();
    assert!(listener.is_cancelled());

    // cancelled() should return immediately, not hang
    let result = time::timeout(Duration::from_millis(100), listener.cancelled()).await;
    assert!(
        result.is_ok(),
        "cancelled() should resolve immediately for pre-cancelled token"
    );
}

#[fcp_async_core::runtime::test]
async fn concurrent_cancel_and_subscribe_no_lost_signals() {
    for _ in 0..100 {
        let token = CancellationToken::new();
        let token_clone = token.clone();

        let subscriber = task::spawn(async move {
            let mut listener = token_clone.subscribe();
            listener.cancelled().await
        });

        // Yield to let subscriber register, then cancel
        task::yield_now().await;
        token.cancel();

        let result = time::timeout(Duration::from_millis(500), subscriber).await;
        assert!(result.is_ok(), "subscriber should not hang");
    }
}

#[fcp_async_core::runtime::test]
async fn multiple_cancel_calls_are_idempotent() {
    let token = CancellationToken::new();
    let mut listener = token.subscribe();

    token.cancel();
    token.cancel(); // second cancel should be no-op

    assert!(listener.is_cancelled());
    let result = listener.cancelled().await;
    assert!(result.is_ok());
}

// ============================================================================
// TaskGroup shutdown races
// ============================================================================

#[fcp_async_core::runtime::test]
async fn shutdown_drains_all_tasks_with_counter_proof() {
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let mut group = TaskGroup::new();

    for i in 0..32 {
        let started = Arc::clone(&started);
        let finished = Arc::clone(&finished);
        let mut listener = group.subscribe_cancellation();

        group.spawn(format!("worker-{i}"), async move {
            started.fetch_add(1, Ordering::SeqCst);
            listener.cancelled().await?;
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
    }

    // Let all tasks start
    task::yield_now().await;
    time::sleep(Duration::from_millis(10)).await;

    let result = group.shutdown(Duration::from_secs(2)).await;
    assert!(result.is_ok());
    assert_eq!(started.load(Ordering::SeqCst), 32);
    assert_eq!(finished.load(Ordering::SeqCst), 32);
}

#[fcp_async_core::runtime::test]
async fn shutdown_with_already_completed_tasks() {
    let mut group = TaskGroup::new();

    // Spawn tasks that complete immediately
    for i in 0..8 {
        group.spawn(format!("fast-{i}"), async move { Ok(()) });
    }

    // Let tasks complete
    time::sleep(Duration::from_millis(10)).await;

    // Shutdown should succeed even though tasks already finished
    let result = group.shutdown(Duration::from_millis(100)).await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn shutdown_timeout_aborts_stuck_tasks() {
    let mut group = TaskGroup::new();

    // Spawn a task that ignores cancellation (stuck)
    group.spawn("stuck", async move {
        // Intentionally ignore cancellation and sleep forever
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });

    // Short timeout should trigger abort
    let result = group.shutdown(Duration::from_millis(50)).await;
    assert!(
        matches!(result, Err(AsyncError::Timeout { .. })),
        "stuck task should cause timeout: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn shutdown_mixed_cooperative_and_stuck_tasks() {
    let cooperative_done = Arc::new(AtomicBool::new(false));
    let cooperative_done_clone = Arc::clone(&cooperative_done);
    let mut group = TaskGroup::new();

    // Cooperative task
    let mut listener = group.subscribe_cancellation();
    group.spawn("cooperative", async move {
        listener.cancelled().await?;
        cooperative_done_clone.store(true, Ordering::SeqCst);
        Ok(())
    });

    // Stuck task (ignores cancellation)
    group.spawn("stuck", async move {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });

    let result = group.shutdown(Duration::from_millis(100)).await;
    // Cooperative task should have completed before timeout
    assert!(cooperative_done.load(Ordering::SeqCst));
    // Overall result is timeout due to stuck task
    assert!(matches!(result, Err(AsyncError::Timeout { .. })));
}

// ============================================================================
// ExecutionContext cancellation races
// ============================================================================

#[fcp_async_core::runtime::test]
async fn child_context_inherits_parent_cancellation() {
    let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
    let child = parent.child();

    parent.cancel();

    assert!(child.is_cancelled());

    let err = child
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .expect_err("child should be cancelled");

    assert_eq!(err, AsyncError::Cancelled);
}

#[fcp_async_core::runtime::test]
async fn child_cancel_preserves_parent_siblings_and_future_work() {
    let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
    let child = parent.child();
    let sibling = parent.child();
    let descendant = child.child();

    child.cancel();

    assert!(child.is_cancelled());
    assert!(descendant.is_cancelled());
    assert!(!parent.is_cancelled());
    assert!(!sibling.is_cancelled());
    assert!(!parent.child().is_cancelled());
    assert_eq!(parent.run(async { 7 }).await.expect("parent work"), 7);
    assert_eq!(sibling.run(async { 11 }).await.expect("sibling work"), 11);
    assert_eq!(
        descendant
            .run(std::future::pending::<()>())
            .await
            .expect_err("cancelled descendant"),
        AsyncError::Cancelled
    );

    // Clones remain handles to the same work, including its descendants.
    let same_parent = parent.clone();
    same_parent.cancel();
    assert!(parent.is_cancelled());
    assert!(sibling.is_cancelled());
}

#[fcp_async_core::runtime::test]
async fn nested_three_level_cancellation_propagation() {
    let root = ExecutionContext::request_scoped(Duration::from_secs(10));
    let mid = root.child();
    let leaf = mid.child();

    assert!(!root.is_cancelled());
    assert!(!mid.is_cancelled());
    assert!(!leaf.is_cancelled());

    root.cancel();

    assert!(root.is_cancelled());
    assert!(mid.is_cancelled());
    assert!(leaf.is_cancelled());

    let err = leaf
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await
        .expect_err("leaf should be cancelled");
    assert_eq!(err, AsyncError::Cancelled);
}

#[fcp_async_core::runtime::test]
async fn deadline_and_cancellation_race_cancellation_wins() {
    // Long deadline, immediate cancellation
    let context = ExecutionContext::request_scoped(Duration::from_secs(60));
    let context_clone = context.clone();

    let work = task::spawn(async move {
        context_clone
            .run(async {
                time::sleep(Duration::from_secs(60)).await;
            })
            .await
    });

    // Cancel immediately
    context.cancel();

    let result = time::timeout(Duration::from_millis(500), work).await;
    assert!(result.is_ok(), "work should not hang after cancel");
    let inner = result.unwrap().expect("join");
    assert_eq!(inner.unwrap_err(), AsyncError::Cancelled);
}

// ============================================================================
// Watch-based shutdown propagation
// ============================================================================

#[fcp_async_core::runtime::test]
async fn wait_for_shutdown_resolves_when_signaled() {
    let (tx, mut rx) = watch::channel(false);

    let waiter = task::spawn(async move { wait_for_shutdown(&mut rx).await });

    tx.send(true).expect("send shutdown signal");

    let result = time::timeout(Duration::from_millis(500), waiter).await;
    assert!(result.is_ok(), "waiter should not hang");
    let inner = result.unwrap().expect("join");
    assert!(matches!(inner, Err(AsyncError::Cancelled)));
}

#[fcp_async_core::runtime::test]
async fn wait_for_shutdown_detects_dropped_sender() {
    let (tx, mut rx) = watch::channel(false);
    drop(tx);

    let result = wait_for_shutdown(&mut rx).await;
    assert!(matches!(result, Err(AsyncError::Cancelled)));
}

#[fcp_async_core::runtime::test]
async fn wait_for_shutdown_pre_signaled_returns_immediately() {
    let (_tx, mut rx) = watch::channel(true);

    let result = time::timeout(Duration::from_millis(100), wait_for_shutdown(&mut rx)).await;
    assert!(
        result.is_ok(),
        "pre-signaled shutdown should resolve immediately"
    );
}

#[fcp_async_core::runtime::test]
async fn sleep_or_shutdown_respects_shutdown_signal() {
    let (tx, mut rx) = watch::channel(false);

    let sleeper =
        task::spawn(async move { sleep_or_shutdown(Duration::from_secs(60), &mut rx).await });

    // Signal shutdown before sleep completes
    time::sleep(Duration::from_millis(10)).await;
    tx.send(true).expect("send shutdown");

    let result = time::timeout(Duration::from_millis(500), sleeper).await;
    assert!(
        result.is_ok(),
        "sleeper should not hang after shutdown signal"
    );
    let inner = result.unwrap().expect("join");
    assert!(matches!(inner, Err(AsyncError::Cancelled)));
}

#[fcp_async_core::runtime::test]
async fn sleep_or_shutdown_completes_sleep_when_no_signal() {
    let (_tx, mut rx) = watch::channel(false);

    let result = sleep_or_shutdown(Duration::from_millis(10), &mut rx).await;
    assert!(
        result.is_ok(),
        "sleep should complete without shutdown signal"
    );
}

// ============================================================================
// Stress: concurrent cancellation + completion races
// ============================================================================

#[fcp_async_core::runtime::test]
async fn race_cancel_vs_completion_no_panic() {
    // Run many iterations to expose timing-sensitive races
    for _ in 0..50 {
        let token = CancellationToken::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);
        let mut listener = token.subscribe();

        let worker = task::spawn(async move {
            // Simulate short work that may or may not finish before cancel
            time::sleep(Duration::from_micros(100)).await;
            completed_clone.store(true, Ordering::SeqCst);
        });

        // Cancel concurrently
        token.cancel();

        // Neither should panic regardless of ordering
        let _ = listener.cancelled().await;
        let _ = worker.await;
    }
}

#[fcp_async_core::runtime::test]
async fn many_listeners_all_receive_cancel() {
    let token = CancellationToken::new();
    let received = Arc::new(AtomicUsize::new(0));
    let count = 128;

    let mut handles = Vec::new();
    for _ in 0..count {
        let mut listener = token.subscribe();
        let received = Arc::clone(&received);
        handles.push(task::spawn(async move {
            let _ = listener.cancelled().await;
            received.fetch_add(1, Ordering::SeqCst);
        }));
    }

    task::yield_now().await;
    token.cancel();

    for handle in handles {
        let result = time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "listener should not hang");
    }

    assert_eq!(received.load(Ordering::SeqCst), count);
}
