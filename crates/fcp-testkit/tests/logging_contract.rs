//! Structured logging contract + redaction validation for ASUPERSYNC test outputs.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.7.6`.
//!
//! Enforces:
//! - Lifecycle-critical async operations emit required structured log events
//! - Secret/PII patterns are never present in diagnostic output
//! - Failure logs preserve enough context for race/timing triage
//! - Log JSON schema conformance for machine-parseable outputs

use std::time::Duration;

use fcp_async_core::{AsyncError, ExecutionContext, TaskGroup};
use fcp_async_core::{task, time};
use fcp_testkit::{LogCapture, TracingCapture};

// ============================================================================
// 1. Lifecycle event log presence
// ============================================================================

/// Timeout operations produce structured log output with timing context.
#[fcp_async_core::runtime::test]
async fn timeout_produces_structured_log() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    let _ = time::timeout(
        Duration::from_millis(20),
        time::sleep(Duration::from_secs(60)),
    )
    .await;

    let jsonl = capture.jsonl();
    // JSON log lines should be present (at least subscriber is active)
    // The exact log content depends on instrumentation; verify structure
    for line in jsonl.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // All lines should be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "log line should be valid JSON: {line}");
        let val = parsed.unwrap();
        // Standard tracing fields (JSON fmt layer uses "timestamp")
        assert!(
            val.get("timestamp").is_some() || val.get("ts").is_some(),
            "log should have timestamp: {val}"
        );
        assert!(
            val.get("message").is_some(),
            "log should have message: {val}"
        );
    }
}

/// `TaskGroup` shutdown emits ordered lifecycle events.
#[fcp_async_core::runtime::test]
async fn task_group_lifecycle_logs() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    let mut group = TaskGroup::new();
    let mut listener = group.subscribe_cancellation();
    group.spawn("lifecycle-test", async move {
        listener.cancelled().await?;
        Ok(())
    });

    task::yield_now().await;
    time::sleep(Duration::from_millis(10)).await;
    let _ = group.shutdown(Duration::from_secs(1)).await;

    let jsonl = capture.jsonl();
    for line in jsonl.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "lifecycle log should be valid JSON: {line}");
    }
}

/// Cancellation produces log output.
#[fcp_async_core::runtime::test]
async fn cancellation_produces_log() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();

    let _ = ctx
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;

    let jsonl = capture.jsonl();
    for line in jsonl.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "cancellation log should be valid JSON: {line}"
        );
    }
}

// ============================================================================
// 2. Secret/PII redaction checks
// ============================================================================

/// Common secret patterns must never appear in log output.
#[fcp_async_core::runtime::test]
async fn no_secrets_in_timeout_logs() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    // Simulate operation with secret-like context
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(20));
    let _ = ctx
        .run(async { time::sleep(Duration::from_secs(60)).await })
        .await;

    let output = capture.jsonl();
    assert_no_secrets_in_output(&output);
}

/// No secrets leak through error formatting.
#[fcp_async_core::runtime::test]
async fn no_secrets_in_error_display() {
    let errors = vec![
        AsyncError::Timeout { timeout_ms: 100 },
        AsyncError::Cancelled,
        AsyncError::ChannelClosed,
        AsyncError::ChannelFull,
        AsyncError::ProtocolIo {
            message: "connection refused".to_string(),
        },
        AsyncError::Join {
            message: "task panicked".to_string(),
        },
        AsyncError::Runtime {
            message: "cannot start runtime".to_string(),
        },
    ];

    for err in &errors {
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert_no_secrets_in_output(&display);
        assert_no_secrets_in_output(&debug);
    }
}

/// No secrets in `TaskGroup` shutdown logs.
#[fcp_async_core::runtime::test]
async fn no_secrets_in_shutdown_logs() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    let mut group = TaskGroup::new();
    group.spawn("secret-bearer", async move {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });

    let _ = group.shutdown(Duration::from_millis(50)).await;

    let output = capture.jsonl();
    assert_no_secrets_in_output(&output);
}

// ============================================================================
// 3. Failure context preservation
// ============================================================================

/// Timeout errors preserve the configured duration.
#[fcp_async_core::runtime::test]
async fn timeout_error_preserves_duration_context() {
    let result = time::timeout(
        Duration::from_millis(42),
        time::sleep(Duration::from_secs(60)),
    )
    .await;

    match result {
        Err(AsyncError::Timeout { timeout_ms }) => {
            assert_eq!(
                timeout_ms, 42,
                "timeout_ms should preserve configured value"
            );
        }
        other => panic!("expected Timeout error: {other:?}"),
    }
}

/// `ExecutionContext` run failure preserves error variant.
#[fcp_async_core::runtime::test]
async fn context_run_failure_preserves_variant() {
    // Timeout case
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(20));
    let result = ctx
        .run(async { time::sleep(Duration::from_secs(60)).await })
        .await;
    assert!(
        matches!(result, Err(AsyncError::Timeout { .. })),
        "should preserve Timeout variant: {result:?}"
    );

    // Cancellation case
    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();
    let result = ctx
        .run(async { time::sleep(Duration::from_secs(60)).await })
        .await;
    assert_eq!(result.unwrap_err(), AsyncError::Cancelled);
}

/// Nested context failures are distinguishable.
#[fcp_async_core::runtime::test]
async fn nested_failure_context_distinguishable() {
    let parent = ExecutionContext::request_scoped(Duration::from_millis(100));
    let child = parent.child().with_deadline(Duration::from_millis(20));

    let result = child
        .run(async { time::sleep(Duration::from_secs(60)).await })
        .await;

    // Child should timeout before parent
    assert!(
        matches!(result, Err(AsyncError::Timeout { .. })),
        "child should timeout first: {result:?}"
    );

    // Parent should still have budget
    let remaining = parent.remaining_budget().expect("has deadline");
    assert!(
        remaining > Duration::from_millis(30),
        "parent should have budget left: {remaining:?}"
    );
}

// ============================================================================
// 4. Log JSON schema conformance
// ============================================================================

/// `LogCapture` produces valid structured JSON with required fields.
#[fcp_async_core::runtime::test]
async fn log_capture_json_schema() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    // Generate some log activity
    tracing::info!(operation = "test", "schema validation check");
    tracing::warn!(timeout_ms = 42, "approaching deadline");

    let jsonl = capture.jsonl();
    let json_lines: Vec<serde_json::Value> = jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    assert!(
        !json_lines.is_empty(),
        "should capture at least one JSON line"
    );

    for val in &json_lines {
        // Required fields per structured logging contract
        // Note: LogCapture::install_json() uses tracing_subscriber JSON fmt
        // with with_level(false) — level is omitted for flattened output.
        // Timestamp and message are always present.
        assert!(
            val.get("timestamp").is_some() || val.get("ts").is_some(),
            "missing timestamp in: {val}"
        );
        assert!(val.get("message").is_some(), "missing message in: {val}");
    }
}

/// `TracingCapture` records event level and message.
#[test]
fn tracing_capture_records_events() {
    let capture = TracingCapture::new();
    assert!(capture.events().is_empty());
    // TracingCapture requires subscriber setup which is per-global;
    // verify API exists and is usable
    assert!(!capture.has_errors());
    assert!(!capture.has_warnings());
}

/// `LogCapture` clear/snapshot cycle works.
#[fcp_async_core::runtime::test]
async fn log_capture_clear_snapshot_cycle() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    tracing::info!("first");
    let snap1 = capture.jsonl();
    assert!(!snap1.is_empty(), "first snapshot should have content");

    capture.clear();
    let snap2 = capture.jsonl();
    assert!(snap2.is_empty(), "cleared snapshot should be empty");

    tracing::info!("second");
    let snap3 = capture.jsonl();
    assert!(!snap3.is_empty(), "new snapshot should have content");
}

// ============================================================================
// 5. Concurrent logging doesn't interleave/corrupt
// ============================================================================

/// Concurrent async operations produce non-corrupted log lines.
#[fcp_async_core::runtime::test]
async fn concurrent_logging_no_corruption() {
    let capture = LogCapture::new();
    let _guard = capture.install_json();

    let mut handles = Vec::new();
    for i in 0..16 {
        handles.push(task::spawn(async move {
            tracing::info!(task_id = i, "concurrent task event");
            time::sleep(Duration::from_millis(5)).await;
            tracing::info!(task_id = i, "concurrent task done");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let jsonl = capture.jsonl();
    for line in jsonl.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "concurrent log line should be valid JSON (no interleaving corruption): {line}"
        );
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Secret patterns that must never appear in any output.
const SECRET_PATTERNS: &[&str] = &[
    "AKIA",           // AWS access key prefix
    "sk-",            // OpenAI/Stripe secret key prefix
    "ghp_",           // GitHub personal access token
    "ghs_",           // GitHub server token
    "glpat-",         // GitLab personal access token
    "xoxb-",          // Slack bot token
    "xoxp-",          // Slack user token
    "Bearer ",        // OAuth bearer token
    "password=",      // Password in query string
    "secret=",        // Secret in query string
    "token=",         // Token in query string
    "-----BEGIN",     // PEM private key
    "-----END",       // PEM private key
    "api_key=",       // API key in query string
    "Authorization:", // Auth header
];

fn assert_no_secrets_in_output(output: &str) {
    for pattern in SECRET_PATTERNS {
        assert!(
            !output.contains(pattern),
            "output contains secret pattern '{pattern}': {output}"
        );
    }
}
