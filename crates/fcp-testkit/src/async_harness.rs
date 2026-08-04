//! Shared async test harness helpers for ASUPERSYNC migration work.
//!
//! This module centralizes common test utilities so crate and connector suites
//! can avoid ad hoc runtime setup and unstable correlation conventions.

use std::future::Future;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use fcp_async_core::{AsyncError, ExecutionContext, channel, shutdown};
use uuid::Uuid;

/// Version tag for the shared async harness contract.
pub const ASUPERSYNC_HARNESS_VERSION: &str = "asupersync-test-harness/v1";

/// Scenario-level context used to correlate logs and artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncTestContext {
    run: String,
    scenario: String,
    correlation: String,
}

impl AsyncTestContext {
    /// Build a context from explicit run/scenario IDs.
    #[must_use]
    pub fn new(run_id: impl Into<String>, scenario_id: impl Into<String>) -> Self {
        let run_id = run_id.into();
        let scenario_id = scenario_id.into();
        let correlation_id = deterministic_correlation_id(&run_id, &scenario_id);
        Self {
            run: run_id,
            scenario: scenario_id,
            correlation: correlation_id,
        }
    }

    /// Build a context with a timestamp-derived run ID.
    #[must_use]
    pub fn for_scenario(scenario_id: impl Into<String>) -> Self {
        let run_id = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
        Self::new(run_id, scenario_id)
    }

    /// Stable run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run
    }

    /// Stable scenario identifier.
    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.scenario
    }

    /// Deterministic correlation ID derived from run/scenario.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation
    }

    /// Standardized JSON fields for structured logs.
    #[must_use]
    pub fn as_log_fields(&self) -> serde_json::Value {
        serde_json::json!({
            "harness_version": ASUPERSYNC_HARNESS_VERSION,
            "run_id": self.run,
            "scenario_id": self.scenario,
            "correlation_id": self.correlation,
        })
    }
}

/// Deterministic correlation ID generator for test logs/artifacts.
#[must_use]
pub fn deterministic_correlation_id(run_id: &str, scenario_id: &str) -> String {
    let key = format!("{run_id}:{scenario_id}");
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // Preserve UUID variant/version semantics for easier downstream parsing.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

/// Create a request-scoped execution context with a fixed timeout budget.
#[must_use]
pub fn request_context(timeout: Duration) -> ExecutionContext {
    ExecutionContext::request_scoped(timeout)
}

/// Run a future with deterministic timeout behavior.
///
/// # Errors
///
/// Returns [`AsyncError::Timeout`] when the timeout budget is exhausted.
/// Returns [`AsyncError::Cancelled`] when the context is cancelled first.
pub async fn run_with_timeout<T, F>(timeout: Duration, future: F) -> Result<T, AsyncError>
where
    F: Future<Output = T>,
{
    request_context(timeout).run(future).await
}

/// Spawn a cancellation trigger for a context after the given delay.
///
/// This uses a dedicated wall-clock thread so the timer starts immediately and
/// is not delayed by async runtime scheduling jitter.
#[must_use]
pub fn spawn_cancel_after(context: ExecutionContext, delay: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(delay);
        context.cancel();
    })
}

/// Build a bounded queue pair for async backpressure tests.
#[must_use]
pub fn bounded_queue<T>(
    name: impl Into<String>,
    capacity: usize,
) -> (channel::BoundedSender<T>, channel::BoundedReceiver<T>) {
    channel::bounded(name, capacity)
}

/// Build a watch-based shutdown channel pair for shutdown/cancellation tests.
#[must_use]
pub fn shutdown_channel(
    initial_shutdown: bool,
) -> (channel::watch::Sender<bool>, channel::watch::Receiver<bool>) {
    channel::watch::channel(initial_shutdown)
}

/// Sleep unless shutdown is signaled first.
///
/// # Errors
///
/// Returns [`AsyncError::Cancelled`] when shutdown is observed before sleep completes.
pub async fn sleep_or_shutdown(
    duration: Duration,
    shutdown_rx: &mut channel::watch::Receiver<bool>,
) -> Result<(), AsyncError> {
    shutdown::sleep_or_shutdown(duration, shutdown_rx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_async_core::time;

    #[test]
    fn deterministic_correlation_id_is_stable() {
        let first = deterministic_correlation_id("run-1", "scenario-a");
        let second = deterministic_correlation_id("run-1", "scenario-a");
        let third = deterministic_correlation_id("run-2", "scenario-a");

        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn context_includes_log_fields() {
        let context = AsyncTestContext::new("run-123", "scenario-xyz");
        let fields = context.as_log_fields();

        assert_eq!(fields["harness_version"], ASUPERSYNC_HARNESS_VERSION);
        assert_eq!(fields["run_id"], "run-123");
        assert_eq!(fields["scenario_id"], "scenario-xyz");
        assert_eq!(fields["correlation_id"], context.correlation_id());
    }

    #[test]
    fn for_scenario_preserves_scenario_and_derives_correlation() {
        let context = AsyncTestContext::for_scenario("scenario-xyz");

        assert_eq!(context.scenario_id(), "scenario-xyz");
        assert!(!context.run_id().is_empty());
        assert_eq!(
            context.correlation_id(),
            deterministic_correlation_id(context.run_id(), context.scenario_id())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn request_context_runs_future_within_budget() {
        let context = request_context(Duration::from_millis(50));

        let result = context.run(async { 7_u8 }).await;

        assert_eq!(result, Ok(7_u8));
    }

    #[fcp_async_core::runtime::test]
    async fn run_with_timeout_returns_value_before_deadline() {
        let result = run_with_timeout(Duration::from_millis(50), async { "done" }).await;

        assert_eq!(result, Ok("done"));
    }

    #[fcp_async_core::runtime::test]
    async fn run_with_timeout_times_out() {
        let result = run_with_timeout(Duration::from_millis(25), async {
            time::sleep(Duration::from_millis(200)).await;
            42_u8
        })
        .await;

        assert!(matches!(result, Err(AsyncError::Timeout { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_queue_sends_and_receives() {
        let (sender, mut receiver) = bounded_queue("test-queue", 4);
        sender.send(7_u8).await.expect("send to bounded queue");
        assert_eq!(receiver.recv().await, Some(7_u8));
    }

    #[test]
    fn shutdown_channel_preserves_initial_state_and_updates() {
        let (sender, receiver) = shutdown_channel(true);

        assert!(*receiver.borrow());
        sender.send(false).expect("update shutdown signal");
        assert!(!*receiver.borrow());
    }

    #[fcp_async_core::runtime::test]
    async fn sleep_or_shutdown_completes_when_sleep_wins() {
        let (_sender, mut receiver) = shutdown_channel(false);

        let result = sleep_or_shutdown(Duration::from_millis(10), &mut receiver).await;

        assert_eq!(result, Ok(()));
    }

    #[fcp_async_core::runtime::test]
    async fn sleep_or_shutdown_returns_cancelled_when_shutdown_is_signaled() {
        let (sender, mut receiver) = shutdown_channel(false);
        sender.send(true).expect("signal shutdown");

        let result = sleep_or_shutdown(Duration::from_secs(1), &mut receiver).await;

        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    #[fcp_async_core::runtime::test]
    async fn spawn_cancel_after_triggers_cancellation() {
        let context = request_context(Duration::from_secs(1));
        let cancel_handle = spawn_cancel_after(context.clone(), Duration::from_millis(5));

        let result = context
            .run(async {
                time::sleep(Duration::from_millis(50)).await;
                "done"
            })
            .await;

        cancel_handle.join().expect("cancellation task join");
        assert!(matches!(result, Err(AsyncError::Cancelled)));
    }

    // ---- Additional AsyncTestContext tests ----

    #[test]
    fn context_debug_format() {
        let ctx = AsyncTestContext::new("run-1", "scene-1");
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("AsyncTestContext"));
        assert!(dbg.contains("run-1"));
        assert!(dbg.contains("scene-1"));
    }

    #[test]
    fn context_clone() {
        let ctx = AsyncTestContext::new("run-c", "scene-c");
        let cloned = ctx.clone();
        assert_eq!(ctx.run_id(), cloned.run_id());
        assert_eq!(ctx.scenario_id(), cloned.scenario_id());
        assert_eq!(ctx.correlation_id(), cloned.correlation_id());
    }

    #[test]
    fn context_eq() {
        let a = AsyncTestContext::new("run-eq", "scene-eq");
        let b = AsyncTestContext::new("run-eq", "scene-eq");
        assert_eq!(a, b);
    }

    #[test]
    fn context_ne_different_run() {
        let a = AsyncTestContext::new("run-1", "scene");
        let b = AsyncTestContext::new("run-2", "scene");
        assert_ne!(a, b);
    }

    #[test]
    fn context_ne_different_scenario() {
        let a = AsyncTestContext::new("run", "scene-1");
        let b = AsyncTestContext::new("run", "scene-2");
        assert_ne!(a, b);
    }

    #[test]
    fn context_log_fields_has_all_keys() {
        let ctx = AsyncTestContext::new("r", "s");
        let fields = ctx.as_log_fields();
        assert!(fields.get("harness_version").is_some());
        assert!(fields.get("run_id").is_some());
        assert!(fields.get("scenario_id").is_some());
        assert!(fields.get("correlation_id").is_some());
    }

    #[test]
    fn deterministic_correlation_id_is_uuid_format() {
        let id = deterministic_correlation_id("run", "scenario");
        // UUID format: 8-4-4-4-12 hex chars
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn deterministic_correlation_id_different_inputs_different_ids() {
        let id1 = deterministic_correlation_id("a", "b");
        let id2 = deterministic_correlation_id("c", "d");
        let id3 = deterministic_correlation_id("a", "c");
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }

    #[test]
    fn deterministic_correlation_id_empty_inputs() {
        let id = deterministic_correlation_id("", "");
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn deterministic_correlation_id_long_inputs() {
        let run = "a".repeat(1000);
        let scenario = "b".repeat(1000);
        let id = deterministic_correlation_id(&run, &scenario);
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn for_scenario_produces_non_empty_run_id() {
        let ctx = AsyncTestContext::for_scenario("test");
        assert!(!ctx.run_id().is_empty());
        // Run ID should contain a timestamp-like pattern
        assert!(ctx.run_id().contains('T'));
    }

    #[test]
    fn harness_version_is_non_empty() {
        assert!(!ASUPERSYNC_HARNESS_VERSION.is_empty());
        assert!(ASUPERSYNC_HARNESS_VERSION.contains("asupersync"));
    }

    #[test]
    fn shutdown_channel_false_initial() {
        let (_tx, rx) = shutdown_channel(false);
        assert!(!*rx.borrow());
    }

    #[test]
    fn shutdown_channel_multiple_updates() {
        let (tx, rx) = shutdown_channel(false);
        assert!(!*rx.borrow());
        tx.send(true).unwrap();
        assert!(*rx.borrow());
        tx.send(false).unwrap();
        assert!(!*rx.borrow());
    }

    // ---- Additional deterministic_correlation_id tests ----

    #[test]
    fn deterministic_correlation_id_uuid_v5_version_nibble() {
        let id = deterministic_correlation_id("run-v", "scenario-v");
        // UUID version nibble should be 5 (char at position 14)
        assert_eq!(id.chars().nth(14), Some('5'));
    }

    #[test]
    fn deterministic_correlation_id_uuid_variant_bits() {
        let id = deterministic_correlation_id("run-var", "scenario-var");
        // Variant nibble at position 19 should be 8, 9, a, or b
        let variant_char = id.chars().nth(19).unwrap();
        assert!(
            ['8', '9', 'a', 'b'].contains(&variant_char),
            "unexpected variant nibble: {variant_char}"
        );
    }

    #[test]
    fn deterministic_correlation_id_symmetry_broken() {
        // Swapping run/scenario should produce different IDs
        let id1 = deterministic_correlation_id("alpha", "beta");
        let id2 = deterministic_correlation_id("beta", "alpha");
        assert_ne!(id1, id2);
    }

    #[test]
    fn deterministic_correlation_id_special_characters() {
        let id = deterministic_correlation_id("run/with:special", "scenario@#$%");
        assert_eq!(id.len(), 36);
        // Should still be valid UUID format
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn deterministic_correlation_id_unicode_inputs() {
        let id = deterministic_correlation_id("run-\u{00e9}\u{00e8}", "\u{2603}\u{2764}");
        assert_eq!(id.len(), 36);
    }

    // ---- Additional AsyncTestContext tests ----

    #[test]
    fn context_accessors_return_expected_values() {
        let ctx = AsyncTestContext::new("my-run", "my-scenario");
        assert_eq!(ctx.run_id(), "my-run");
        assert_eq!(ctx.scenario_id(), "my-scenario");
        assert!(!ctx.correlation_id().is_empty());
    }

    #[test]
    fn context_for_scenario_run_id_has_timestamp_format() {
        let ctx = AsyncTestContext::for_scenario("ts-test");
        let run = ctx.run_id();
        // Should contain 'T' (ISO format) and 'Z' (UTC)
        assert!(run.contains('T'));
        assert!(run.contains('Z'));
    }

    #[test]
    fn context_log_fields_values_match_accessors() {
        let ctx = AsyncTestContext::new("r1", "s1");
        let fields = ctx.as_log_fields();
        assert_eq!(fields["run_id"].as_str().unwrap(), ctx.run_id());
        assert_eq!(fields["scenario_id"].as_str().unwrap(), ctx.scenario_id());
        assert_eq!(
            fields["correlation_id"].as_str().unwrap(),
            ctx.correlation_id()
        );
    }

    #[test]
    fn context_log_fields_is_object() {
        let ctx = AsyncTestContext::new("r", "s");
        let fields = ctx.as_log_fields();
        assert!(fields.is_object());
        assert_eq!(fields.as_object().unwrap().len(), 4);
    }

    #[test]
    fn context_two_for_scenario_calls_differ() {
        let a = AsyncTestContext::for_scenario("same-scenario");
        // Small delay ensures different timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = AsyncTestContext::for_scenario("same-scenario");
        // Run IDs should differ because timestamps differ
        assert_ne!(a.run_id(), b.run_id());
        // Correlation IDs should also differ since run ID is part of the key
        assert_ne!(a.correlation_id(), b.correlation_id());
    }

    // ---- Additional bounded_queue / shutdown tests ----

    #[fcp_async_core::runtime::test]
    async fn bounded_queue_capacity_respected() {
        let (tx, _rx) = bounded_queue::<u8>("cap-test", 2);
        // First two sends should succeed immediately
        tx.send(1).await.expect("send 1");
        tx.send(2).await.expect("send 2");
        // Channel is now full; verify by trying send with timeout
        let result =
            fcp_async_core::time::timeout(std::time::Duration::from_millis(25), tx.send(3)).await;
        // Should timeout because channel is full
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_queue_recv_none_after_drop_sender() {
        let (tx, mut rx) = bounded_queue::<u8>("drop-test", 4);
        tx.send(10).await.expect("send");
        drop(tx);
        // Should get the buffered item
        assert_eq!(rx.recv().await, Some(10));
        // Then None because sender is dropped
        assert_eq!(rx.recv().await, None);
    }

    #[test]
    fn shutdown_channel_true_initial() {
        let (_tx, rx) = shutdown_channel(true);
        assert!(*rx.borrow());
    }

    #[test]
    fn request_context_has_nonzero_timeout() {
        let ctx = request_context(std::time::Duration::from_millis(100));
        // Just verify it was created without panic
        let dbg = format!("{ctx:?}");
        assert!(!dbg.is_empty());
    }

    // ---- Additional AsyncTestContext edge case tests ----

    #[test]
    fn context_with_empty_strings() {
        let ctx = AsyncTestContext::new("", "");
        assert!(ctx.run_id().is_empty());
        assert!(ctx.scenario_id().is_empty());
        assert!(!ctx.correlation_id().is_empty());
    }

    #[test]
    fn context_with_unicode_ids() {
        let ctx = AsyncTestContext::new("run-\u{00e9}", "scene-\u{2603}");
        assert_eq!(ctx.run_id(), "run-\u{00e9}");
        assert_eq!(ctx.scenario_id(), "scene-\u{2603}");
        assert_eq!(ctx.correlation_id().len(), 36);
    }

    #[test]
    fn context_with_very_long_ids() {
        let long_run = "r".repeat(5000);
        let long_scene = "s".repeat(5000);
        let ctx = AsyncTestContext::new(long_run.as_str(), long_scene.as_str());
        assert_eq!(ctx.run_id(), long_run);
        assert_eq!(ctx.scenario_id(), long_scene);
        assert_eq!(ctx.correlation_id().len(), 36);
    }

    #[test]
    fn context_clone_eq_roundtrip() {
        let ctx = AsyncTestContext::new("run-rt", "scene-rt");
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
        // Verify all fields match
        assert_eq!(ctx.run_id(), cloned.run_id());
        assert_eq!(ctx.scenario_id(), cloned.scenario_id());
        assert_eq!(ctx.correlation_id(), cloned.correlation_id());
        assert_eq!(ctx.as_log_fields(), cloned.as_log_fields());
    }

    #[test]
    fn deterministic_correlation_id_whitespace_inputs() {
        let id = deterministic_correlation_id("  ", "\t\n");
        assert_eq!(id.len(), 36);
        // Different from empty string inputs
        let id_empty = deterministic_correlation_id("", "");
        assert_ne!(id, id_empty);
    }

    #[test]
    fn deterministic_correlation_id_newline_in_input() {
        let id = deterministic_correlation_id("run\nwith\nnewlines", "scene");
        assert_eq!(id.len(), 36);
    }

    #[fcp_async_core::runtime::test]
    async fn run_with_timeout_returns_string() {
        let result =
            run_with_timeout(Duration::from_millis(50), async { String::from("hello") }).await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_queue_multiple_items() {
        let (tx, mut rx) = bounded_queue::<String>("multi-test", 8);
        for i in 0..5 {
            tx.send(format!("item-{i}")).await.expect("send");
        }
        for i in 0..5 {
            assert_eq!(rx.recv().await, Some(format!("item-{i}")));
        }
    }
}
