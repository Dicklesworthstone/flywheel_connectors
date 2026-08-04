//! Tracing span contract verification for V3 operations.
//!
//! Validates that `RetryLoop::execute()` emits the structured tracing fields
//! required by the FCP3 forensics standard:
//!
//! - **Success path**: `debug!` with `attempt` field
//! - **Retry path**: `warn!` with `attempt`, `delay_ms`, `error` fields
//! - **Terminal/max-exhausted path**: no retry warning emitted
//!
//! Uses a custom `tracing_subscriber::Layer` to capture events without
//! requiring a real subscriber or network I/O.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fcp_async_core::{AsyncError, ExecutionContext};
use fcp_sdk::migration::{AttemptOutcome, RetryLoop};
use fcp_sdk::retry::RetryPolicy;
use fcp_sdk::{
    ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig, FcpError,
    map_async_to_fcp_error,
};
use tracing::Level;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

// ─────────────────────────────────────────────────────────────────────────────
// Test error type (mirrors migration.rs internal TestError for integration use)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum TestError {
    Transient(String),
    Fatal(String),
    DeadlineExceeded(String),
    Cancelled,
}

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(msg) => write!(f, "transient: {msg}"),
            Self::Fatal(msg) => write!(f, "fatal: {msg}"),
            Self::DeadlineExceeded(msg) => write!(f, "deadline: {msg}"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl ConnectorErrorMapping for TestError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::DeadlineExceeded(format!("exceeded {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Cancelled,
            other => Self::Fatal(other.to_string()),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        map_async_to_fcp_error(&match self {
            Self::Transient(msg) => AsyncError::ProtocolIo {
                message: msg.clone(),
            },
            Self::Fatal(msg) => AsyncError::Runtime {
                message: msg.clone(),
            },
            Self::DeadlineExceeded(_) => AsyncError::Timeout { timeout_ms: 0 },
            Self::Cancelled => AsyncError::Cancelled,
        })
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Captured event storage
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CapturedEvent {
    level: Level,
    message: String,
    fields: Vec<(String, String)>,
}

impl CapturedEvent {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|(k, _)| k == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture layer: records tracing events into a shared Vec
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CaptureLayer {
    fn new() -> (Self, Arc<Mutex<Vec<CapturedEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                events: events.clone(),
            },
            events,
        )
    }
}

/// Visitor that extracts field names and values from tracing events.
struct FieldVisitor {
    fields: Vec<(String, String)>,
    message: String,
}

impl FieldVisitor {
    const fn new() -> Self {
        Self {
            fields: Vec::new(),
            message: String::new(),
        }
    }
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::new();
        event.record(&mut visitor);

        let captured = CapturedEvent {
            level: *event.metadata().level(),
            message: visitor.message,
            fields: visitor.fields,
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(captured);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: run async block under a captured tracing subscriber
// ─────────────────────────────────────────────────────────────────────────────

fn run_with_tracing<F, R>(f: F) -> (R, Vec<CapturedEvent>)
where
    F: FnOnce() -> R,
{
    let (layer, events) = CaptureLayer::new();
    let subscriber = tracing_subscriber::registry().with(layer);

    let result = tracing::subscriber::with_default(subscriber, f);

    let captured = events.lock().unwrap().clone();
    (result, captured)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn success_path_emits_attempt_field() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(3));

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |_attempt| async {
                AttemptOutcome::Success("ok")
            })
            .await
        })
    });

    assert!(result.unwrap().is_ok());

    // RetryLoop emits debug!("executing retry attempt") with `attempt` field
    let attempt_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("executing retry attempt"))
        .collect();
    assert!(
        !attempt_events.is_empty(),
        "expected at least one 'executing retry attempt' event, got {events:?}"
    );
    let event = &attempt_events[0];
    assert!(
        event.has_field("attempt"),
        "expected 'attempt' field in event: {event:?}"
    );
    assert_eq!(
        event.field("attempt").unwrap(),
        "0",
        "first attempt should be 0"
    );
    assert_eq!(
        event.level,
        Level::DEBUG,
        "attempt event should be DEBUG level"
    );
}

#[test]
fn retry_path_emits_attempt_delay_ms_error_fields() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(30));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |attempt| async move {
                if attempt < 2 {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("rate limited".into()),
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Success("recovered")
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_ok());

    // Should have retry warning events with attempt, delay_ms, error
    let retry_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("retrying after transient error"))
        .collect();
    assert!(
        !retry_events.is_empty(),
        "expected retry warning events, got {events:?}"
    );

    for retry_event in &retry_events {
        assert_eq!(
            retry_event.level,
            Level::WARN,
            "retry event should be WARN level"
        );
        assert!(
            retry_event.has_field("attempt"),
            "retry event must have 'attempt' field: {retry_event:?}"
        );
        assert!(
            retry_event.has_field("delay_ms"),
            "retry event must have 'delay_ms' field: {retry_event:?}"
        );
        assert!(
            retry_event.has_field("error"),
            "retry event must have 'error' field: {retry_event:?}"
        );
    }

    // First retry event should be attempt 0
    assert_eq!(
        retry_events[0].field("attempt").unwrap(),
        "0",
        "first retry attempt should be 0"
    );

    // delay_ms should be a valid positive number
    let delay_ms: u64 = retry_events[0]
        .field("delay_ms")
        .unwrap()
        .parse()
        .expect("delay_ms should be a u64");
    assert!(delay_ms > 0, "delay_ms should be positive: {delay_ms}");

    // error field should contain the error message
    let error_field = retry_events[0].field("error").unwrap();
    assert!(
        error_field.contains("rate limited"),
        "error field should contain error message, got: {error_field}"
    );
}

#[test]
fn terminal_error_emits_no_retry_warning() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(3));

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |_attempt| async {
                AttemptOutcome::Terminal(TestError::Fatal("auth failed".into()))
            })
            .await
        })
    });

    assert!(result.unwrap().is_err());

    // Should NOT have any retry warning events (terminal errors don't retry)
    assert!(
        !events
            .iter()
            .any(|e| e.message.contains("retrying after transient error")),
        "terminal error should not emit retry warnings"
    );

    // Should still have the initial attempt debug event
    assert!(
        events
            .iter()
            .any(|e| e.message.contains("executing retry attempt")),
        "should still emit attempt debug event"
    );
}

#[test]
fn max_attempts_exhausted_emits_correct_retry_count() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(30));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |_attempt| async {
                AttemptOutcome::Retryable {
                    error: TestError::Transient("still failing".into()),
                    retry_after: None,
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_err());

    // Retry warnings are emitted for each retryable failure where the policy
    // grants another attempt. Verify they have sequentially incrementing attempt
    // numbers regardless of how many the policy allowed.
    let retry_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("retrying after transient error"))
        .collect();
    assert_eq!(
        retry_events.len(),
        2,
        "max_attempts=3 should emit exactly two retry warnings before exhaustion"
    );
    for (i, event) in retry_events.iter().enumerate() {
        let attempt: u32 = event
            .field("attempt")
            .unwrap()
            .parse()
            .expect("attempt should be u32");
        assert_eq!(
            attempt as usize, i,
            "retry attempts should increment sequentially"
        );
    }
}

#[test]
fn retry_with_explicit_retry_after_emits_delay() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(30));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(100)
                .with_jitter_enabled(false);

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |attempt| async move {
                if attempt == 0 {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("429 rate limited".into()),
                        retry_after: Some(Duration::from_millis(50)),
                    }
                } else {
                    AttemptOutcome::Success("ok after retry-after")
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_ok());

    let retry_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("retrying after transient error"))
        .collect();
    assert_eq!(retry_events.len(), 1, "should have exactly one retry event");

    // delay_ms should reflect the retry_after hint (50ms)
    let delay_ms: u64 = retry_events[0]
        .field("delay_ms")
        .unwrap()
        .parse()
        .expect("delay_ms should be u64");
    assert_eq!(
        delay_ms, 50,
        "delay_ms should match retry_after hint of 50ms"
    );

    // error should mention the rate limit
    let error_field = retry_events[0].field("error").unwrap();
    assert!(
        error_field.contains("429"),
        "error field should contain rate limit message"
    );
}

#[test]
fn cancellation_emits_no_retry_warning() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(10))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            // Cancel immediately
            ctx.cancel();

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |_attempt| async {
                AttemptOutcome::Retryable {
                    error: TestError::Transient("should not reach".into()),
                    retry_after: None,
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_err());

    // Cancelled before first attempt: no retry warnings
    assert!(
        !events
            .iter()
            .any(|e| e.message.contains("retrying after transient error")),
        "cancelled context should not emit retry warnings"
    );

    // No attempt events either (cancellation checked before attempt)
    assert!(
        !events
            .iter()
            .any(|e| e.message.contains("executing retry attempt")),
        "cancelled context should not emit attempt events"
    );
}

#[test]
fn runtime_lifecycle_tracing_contract() {
    // Verify ConnectorRuntime integrates properly with tracing context
    let (_result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let runtime = ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(5)),
            );

            let ctx = runtime.request_context();
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            // Success path through runtime context
            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Success("via runtime")
                })
                .await;

            assert_eq!(result.unwrap(), "via runtime");

            // Now test with retry through runtime context
            let ctx2 = runtime.request_context();
            let result2: Result<&str, TestError> =
                RetryLoop::execute(&ctx2, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("first try".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("second try")
                    }
                })
                .await;

            assert_eq!(result2.unwrap(), "second try");

            // Shutdown and verify cancelled context produces no retry events
            runtime.shutdown();
            assert!(runtime.is_shutting_down());
        })
    });

    // Should have attempt events for both calls
    let attempt_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("executing retry attempt"))
        .collect();
    assert!(
        attempt_events.len() >= 2,
        "expected at least 2 attempt events (one per call), got {}",
        attempt_events.len()
    );

    // Should have exactly one retry warning (from the second call's first attempt)
    let retry_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("retrying after transient error"))
        .collect();
    assert_eq!(
        retry_events.len(),
        1,
        "expected exactly 1 retry warning, got {}",
        retry_events.len()
    );

    // Verify the retry event has all required fields
    let retry = &retry_events[0];
    assert!(retry.has_field("attempt"), "missing 'attempt' field");
    assert!(retry.has_field("delay_ms"), "missing 'delay_ms' field");
    assert!(retry.has_field("error"), "missing 'error' field");
}

#[test]
fn multiple_retries_emit_incrementing_attempts() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(30));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |attempt| async move {
                if attempt < 3 {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient(format!("fail #{attempt}")),
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Success("finally")
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_ok());

    let retry_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("retrying after transient error"))
        .collect();

    // 3 retries: attempts 0, 1, 2
    assert_eq!(
        retry_events.len(),
        3,
        "expected 3 retry events, got {}",
        retry_events.len()
    );

    for (i, event) in retry_events.iter().enumerate() {
        let attempt: u32 = event
            .field("attempt")
            .unwrap()
            .parse()
            .expect("attempt should be u32");
        assert_eq!(
            attempt as usize, i,
            "attempt {i} should have attempt={i}, got {attempt}"
        );

        // Each retry should have increasing delay_ms (exponential backoff)
        let delay_ms: u64 = event
            .field("delay_ms")
            .unwrap()
            .parse()
            .expect("delay_ms should be u64");
        assert!(delay_ms > 0, "delay_ms should be positive at attempt {i}");

        // Error field should contain the attempt-specific message
        let error_field = event.field("error").unwrap();
        assert!(
            error_field.contains(&format!("fail #{i}")),
            "error should contain attempt-specific message at attempt {i}, got: {error_field}"
        );
    }

    // Verify exponential backoff: delay should increase
    let delays: Vec<u64> = retry_events
        .iter()
        .map(|e| e.field("delay_ms").unwrap().parse().unwrap())
        .collect();
    for window in delays.windows(2) {
        assert!(
            window[1] >= window[0],
            "backoff delays should be non-decreasing: {delays:?}"
        );
    }
}

#[test]
fn attempt_debug_events_count_matches_actual_attempts() {
    let (result, events) = run_with_tracing(|| {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(30));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(4))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            RetryLoop::execute::<&str, TestError, _, _>(&ctx, &policy, |attempt| async move {
                if attempt < 2 {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("retry me".into()),
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Success("done")
                }
            })
            .await
        })
    });

    assert!(result.unwrap().is_ok());

    // debug!() is emitted once per attempt
    let attempt_events: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("executing retry attempt"))
        .collect();
    assert_eq!(
        attempt_events.len(),
        3,
        "expected 3 attempt events (0, 1, 2), got {}",
        attempt_events.len()
    );

    // All attempt events should be DEBUG level
    for event in &attempt_events {
        assert_eq!(event.level, Level::DEBUG, "attempt events should be DEBUG");
    }
}
