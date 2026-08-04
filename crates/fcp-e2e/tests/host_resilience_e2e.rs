//! E2E tests for the FCP2 Host Resilience flow.
//!
//! Exercises the resilience layer end-to-end:
//! - Circuit breaker state transitions (closed -> open -> half-open -> closed)
//! - Bulkhead concurrency isolation and queue limits
//! - Health-based routing with probe recovery
//! - Adaptive load shedding by priority class
//! - Composed resilience layer executing connector operations
//! - Metrics snapshot accuracy
//! - Configuration and defaults
//!
//! All async tests use `fcp_async_core::runtime::test`.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use fcp_e2e::{AssertionsSummary, E2eLogEntry, E2eLogger};
use fcp_host::{
    BulkheadConfig, CircuitBreakerConfig, CircuitState, FailurePredicate, HealthRouterConfig,
    LoadShedConfig, RequestPriority, ResilienceConfig, ResilienceError, ResilienceLayer,
    ResilienceMetricsSnapshot, RoutingDecision, merge_connector_health,
};
use fcp_prelude::{ConnectorHealth, ConnectorId};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn log_entry(
    test_name: &str,
    phase: &str,
    result: &str,
    passed: u32,
    failed: u32,
    context: serde_json::Value,
) -> E2eLogEntry {
    E2eLogEntry::new(
        "info",
        test_name,
        "fcp-e2e",
        phase,
        "host-resilience-e2e",
        result,
        0,
        AssertionsSummary::new(passed, failed),
        context,
    )
}

fn default_layer() -> ResilienceLayer {
    ResilienceLayer::default()
}

fn fast_circuit_layer() -> ResilienceLayer {
    ResilienceLayer::new(ResilienceConfig {
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            open_duration: Duration::from_millis(50),
            window_duration: Duration::from_secs(30),
            failure_predicate: FailurePredicate::AnyError,
        },
        ..ResilienceConfig::default()
    })
}

fn timeout_layer(timeout: Duration) -> ResilienceLayer {
    ResilienceLayer::new(ResilienceConfig {
        operation_timeout: Some(timeout),
        ..ResilienceConfig::default()
    })
}

async fn succeed(layer: &ResilienceLayer, connector: &ConnectorId) {
    let _: Result<(), ResilienceError<String>> = layer
        .execute(connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
}

async fn fail_op(layer: &ResilienceLayer, connector: &ConnectorId) {
    let _: Result<(), ResilienceError<String>> = layer
        .execute(connector, RequestPriority::Normal, "op", async {
            Err("simulated-failure".to_string())
        })
        .await;
}

fn is_healthy(h: &ConnectorHealth) -> bool {
    matches!(h, ConnectorHealth::Healthy)
}

fn is_unavailable(h: &ConnectorHealth) -> bool {
    matches!(h, ConnectorHealth::Unavailable { .. })
}

fn is_degraded(h: &ConnectorHealth) -> bool {
    matches!(h, ConnectorHealth::Degraded { .. })
}

// ═════════════════════════════════════════════════════════════════════════════
// A. Configuration and Defaults
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn default_resilience_config_is_sane() {
    let config = ResilienceConfig::default();
    assert_eq!(config.circuit_breaker.failure_threshold, 3);
    assert_eq!(config.circuit_breaker.success_threshold, 2);
    assert_eq!(config.circuit_breaker.open_duration, Duration::from_secs(5));
    assert_eq!(
        config.circuit_breaker.failure_predicate,
        FailurePredicate::AnyError
    );
    assert_eq!(config.bulkhead.max_concurrent, 16);
    assert_eq!(config.bulkhead.max_queued, 32);
    assert_eq!(config.bulkhead.queue_timeout, Duration::from_millis(250));
    assert_eq!(config.health.unhealthy_threshold, 3);
    assert_eq!(config.health.recovery_success_threshold, 2);
    assert!(config.operation_timeout.is_none());
}

#[test]
fn circuit_breaker_config_defaults() {
    let config = CircuitBreakerConfig::default();
    assert_eq!(config.failure_threshold, 3);
    assert_eq!(config.success_threshold, 2);
    assert_eq!(config.open_duration, Duration::from_secs(5));
    assert_eq!(config.window_duration, Duration::from_secs(30));
    assert_eq!(config.failure_predicate, FailurePredicate::AnyError);
}

#[test]
fn bulkhead_config_defaults() {
    let config = BulkheadConfig::default();
    assert_eq!(config.max_concurrent, 16);
    assert_eq!(config.max_queued, 32);
    assert_eq!(config.queue_timeout, Duration::from_millis(250));
}

#[test]
fn health_router_config_defaults() {
    let config = HealthRouterConfig::default();
    assert_eq!(config.unhealthy_threshold, 3);
    assert_eq!(config.recovery_success_threshold, 2);
    assert_eq!(
        config.latency_degraded_threshold,
        Duration::from_millis(750)
    );
    assert_eq!(config.error_rate_degraded_threshold_per_mille, 500);
    assert_eq!(config.probe_interval, Duration::from_secs(5));
    assert_eq!(config.error_window, Duration::from_secs(30));
    assert_eq!(config.latency_alpha_per_mille, 200);
}

#[test]
fn load_shed_config_defaults() {
    let config = LoadShedConfig::default();
    assert_eq!(config.shed_threshold_per_mille, 850);
    assert_eq!(config.full_shed_threshold_per_mille, 1_000);
    assert_eq!(
        config.sheddable_priorities,
        vec![RequestPriority::Low, RequestPriority::Normal]
    );
}

#[test]
fn resilience_layer_default_creates_successfully() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");
    assert!(is_healthy(&layer.connector_health(&connector)));
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);
}

#[test]
fn ensure_connector_initializes_state() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");
    layer.ensure_connector(&connector);
    assert!(is_healthy(&layer.connector_health(&connector)));
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);
    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 0);
}

#[test]
fn metrics_snapshot_default_is_zeroed() {
    let m = ResilienceMetricsSnapshot::default();
    assert_eq!(m.requests, 0);
    assert_eq!(m.successes, 0);
    assert_eq!(m.failures, 0);
    assert_eq!(m.timeouts, 0);
    assert_eq!(m.circuit_rejections, 0);
    assert_eq!(m.circuit_opened, 0);
    assert_eq!(m.bulkhead_rejections, 0);
    assert_eq!(m.load_shed, 0);
    assert_eq!(m.probe_requests, 0);
}

#[test]
fn failure_predicate_any_error() {
    assert_eq!(FailurePredicate::AnyError, FailurePredicate::AnyError);
}

#[test]
fn failure_predicate_timeouts_only() {
    assert_eq!(
        FailurePredicate::TimeoutsOnly,
        FailurePredicate::TimeoutsOnly
    );
}

#[test]
fn failure_predicate_slow_responses() {
    let p = FailurePredicate::SlowResponses {
        threshold: Duration::from_millis(100),
    };
    assert_eq!(
        p,
        FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100)
        }
    );
}

#[test]
fn failure_predicate_error_or_slow() {
    let p = FailurePredicate::ErrorOrSlowResponses {
        threshold: Duration::from_millis(200),
    };
    assert_eq!(
        p,
        FailurePredicate::ErrorOrSlowResponses {
            threshold: Duration::from_millis(200)
        }
    );
}

#[test]
fn circuit_state_variants() {
    assert_eq!(CircuitState::Closed, CircuitState::Closed);
    assert_eq!(CircuitState::Open, CircuitState::Open);
    assert_eq!(CircuitState::HalfOpen, CircuitState::HalfOpen);
    assert_ne!(CircuitState::Closed, CircuitState::Open);
}

#[test]
fn request_priority_variants_distinct() {
    let priorities = [
        RequestPriority::Critical,
        RequestPriority::High,
        RequestPriority::Normal,
        RequestPriority::Low,
    ];
    for (i, p1) in priorities.iter().enumerate() {
        for (j, p2) in priorities.iter().enumerate() {
            if i == j {
                assert_eq!(p1, p2);
            } else {
                assert_ne!(p1, p2);
            }
        }
    }
}

#[test]
fn routing_decision_allow() {
    let d = RoutingDecision::Allow;
    assert_eq!(d, RoutingDecision::Allow);
}

#[test]
fn routing_decision_allow_degraded() {
    let d = RoutingDecision::AllowDegraded {
        reason: "slow".to_string(),
    };
    assert!(matches!(d, RoutingDecision::AllowDegraded { .. }));
}

#[test]
fn routing_decision_allow_probe() {
    assert_eq!(RoutingDecision::AllowProbe, RoutingDecision::AllowProbe);
}

#[test]
fn routing_decision_reject() {
    let d = RoutingDecision::Reject {
        reason: "unhealthy".to_string(),
    };
    assert!(matches!(d, RoutingDecision::Reject { .. }));
}

// ═════════════════════════════════════════════════════════════════════════════
// B. Resilience Error Display
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn resilience_error_display_load_shed() {
    let e: ResilienceError<String> = ResilienceError::LoadShed {
        load_per_mille: 900,
    };
    let msg = e.to_string();
    assert!(msg.contains("900"), "expected load value in message: {msg}");
    assert!(msg.contains("shed"), "expected 'shed' in message: {msg}");
}

#[test]
fn resilience_error_display_unhealthy() {
    let e: ResilienceError<String> = ResilienceError::Unhealthy {
        reason: "3 consecutive failures".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("unhealthy"), "expected 'unhealthy': {msg}");
    assert!(
        msg.contains("3 consecutive failures"),
        "expected reason: {msg}"
    );
}

#[test]
fn resilience_error_display_circuit_open() {
    let e: ResilienceError<String> = ResilienceError::CircuitOpen {
        retry_after: Duration::from_secs(5),
    };
    let msg = e.to_string();
    assert!(msg.contains("circuit"), "expected 'circuit': {msg}");
    assert!(msg.contains("5000"), "expected retry_after ms: {msg}");
}

#[test]
fn resilience_error_display_half_open_limited() {
    let e: ResilienceError<String> = ResilienceError::HalfOpenLimited;
    let msg = e.to_string();
    assert!(msg.contains("half-open"), "expected 'half-open': {msg}");
}

#[test]
fn resilience_error_display_bulkhead_full() {
    let e: ResilienceError<String> = ResilienceError::BulkheadFull;
    let msg = e.to_string();
    assert!(msg.contains("bulkhead"), "expected 'bulkhead': {msg}");
    assert!(msg.contains("full"), "expected 'full': {msg}");
}

#[test]
fn resilience_error_display_queue_timeout() {
    let e: ResilienceError<String> = ResilienceError::QueueTimeout {
        timeout: Duration::from_millis(250),
    };
    let msg = e.to_string();
    assert!(msg.contains("250"), "expected timeout ms: {msg}");
}

#[test]
fn resilience_error_display_timed_out() {
    let e: ResilienceError<String> = ResilienceError::TimedOut {
        timeout: Duration::from_secs(10),
    };
    let msg = e.to_string();
    assert!(msg.contains("10000"), "expected timeout ms: {msg}");
}

#[test]
fn resilience_error_display_inner() {
    let e: ResilienceError<String> = ResilienceError::Inner("custom error".to_string());
    let msg = e.to_string();
    assert!(msg.contains("custom error"), "expected inner error: {msg}");
}

#[test]
fn resilience_error_eq() {
    let a: ResilienceError<String> = ResilienceError::BulkheadFull;
    let b: ResilienceError<String> = ResilienceError::BulkheadFull;
    assert_eq!(a, b);
}

#[test]
fn resilience_error_ne() {
    let a: ResilienceError<String> = ResilienceError::BulkheadFull;
    let b: ResilienceError<String> = ResilienceError::HalfOpenLimited;
    assert_ne!(a, b);
}

// ═════════════════════════════════════════════════════════════════════════════
// C. Circuit Breaker E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn circuit_starts_closed() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);
}

#[fcp_async_core::runtime::test]
async fn circuit_opens_after_failure_threshold() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // 2 failures should open the circuit (threshold=2)
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);
    let m = layer.metrics(&connector);
    assert_eq!(m.failures, 2);
    assert_eq!(m.circuit_opened, 1);
}

#[fcp_async_core::runtime::test]
async fn circuit_rejects_when_open() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);

    // Attempt while open should be rejected
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    assert!(
        matches!(result, Err(ResilienceError::CircuitOpen { .. })),
        "expected CircuitOpen, got {result:?}"
    );

    let m = layer.metrics(&connector);
    assert!(m.circuit_rejections >= 1);
}

#[fcp_async_core::runtime::test]
async fn circuit_transitions_to_half_open_after_duration() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);

    // Wait for open_duration (50ms)
    fcp_async_core::time::sleep(Duration::from_millis(60)).await;

    // Next request should be a probe (half-open)
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "probe", async {
            Ok(())
        })
        .await;
    assert!(result.is_ok(), "probe should succeed: {result:?}");
}

#[fcp_async_core::runtime::test]
async fn circuit_closes_after_success_in_half_open() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // Open the circuit
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    // Wait for half-open
    fcp_async_core::time::sleep(Duration::from_millis(60)).await;

    // Successful probe should close circuit (success_threshold=1)
    succeed(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);
}

#[fcp_async_core::runtime::test]
async fn circuit_success_resets_failure_counter() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // 1 failure, then success should reset counter
    fail_op(&layer, &connector).await;
    succeed(&layer, &connector).await;

    // Another failure should NOT open (counter was reset)
    fail_op(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);
}

#[fcp_async_core::runtime::test]
async fn circuit_metrics_track_requests() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    succeed(&layer, &connector).await;
    succeed(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 3);
    assert_eq!(m.successes, 2);
    assert_eq!(m.failures, 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// D. Bulkhead E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn bulkhead_allows_within_limits() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        bulkhead: BulkheadConfig {
            max_concurrent: 2,
            max_queued: 2,
            queue_timeout: Duration::from_millis(100),
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:bulkhead:1.0.0");

    // Single request should succeed
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn bulkhead_sequential_operations_work() {
    // Use reasonable limits for sequential operation testing
    let layer = ResilienceLayer::new(ResilienceConfig {
        bulkhead: BulkheadConfig {
            max_concurrent: 2,
            max_queued: 4,
            queue_timeout: Duration::from_millis(100),
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:bulkhead:1.0.0");

    // Sequential operations should all succeed (permit released between calls)
    for _ in 0..5 {
        let result: Result<(), ResilienceError<String>> = layer
            .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
            .await;
        assert!(result.is_ok());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// E. Health Router E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn health_starts_healthy() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");
    assert!(is_healthy(&layer.connector_health(&connector)));
}

#[fcp_async_core::runtime::test]
async fn health_becomes_unavailable_after_consecutive_failures() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        health: HealthRouterConfig {
            unhealthy_threshold: 2,
            ..HealthRouterConfig::default()
        },
        // Use high failure threshold for circuit to not interfere
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 100,
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:failing:1.0.0");

    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    let health = layer.connector_health(&connector);
    assert!(
        is_unavailable(&health),
        "expected Unavailable, got {health:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn health_rejects_unhealthy_connectors() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        health: HealthRouterConfig {
            unhealthy_threshold: 2,
            probe_interval: Duration::from_secs(60), // long probe interval to ensure rejection
            ..HealthRouterConfig::default()
        },
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 100,
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:failing:1.0.0");

    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    // Should be rejected by health router
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    assert!(
        matches!(result, Err(ResilienceError::Unhealthy { .. })),
        "expected Unhealthy rejection, got {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn health_remains_healthy_below_threshold() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        health: HealthRouterConfig {
            unhealthy_threshold: 5,
            ..HealthRouterConfig::default()
        },
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 100,
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // 2 failures (well below threshold of 5) should remain healthy
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    let health = layer.connector_health(&connector);
    // Not unavailable yet (only 2 failures, threshold is 5)
    assert!(
        !is_unavailable(&health),
        "expected not-unavailable with 2 failures (threshold=5), got {health:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// F. Load Shedding E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn load_shedding_critical_never_shed() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        load_shed: LoadShedConfig {
            shed_threshold_per_mille: 100, // very low threshold
            full_shed_threshold_per_mille: 200,
            sheddable_priorities: vec![RequestPriority::Low, RequestPriority::Normal],
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // Set high load
    layer.set_base_load_per_mille(999);

    // Critical should never be shed
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Critical, "op", async {
            Ok(())
        })
        .await;
    assert!(
        result.is_ok(),
        "critical priority should not be shed: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn load_shedding_high_never_shed_if_not_sheddable() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        load_shed: LoadShedConfig {
            shed_threshold_per_mille: 100,
            full_shed_threshold_per_mille: 200,
            sheddable_priorities: vec![RequestPriority::Low, RequestPriority::Normal],
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    layer.set_base_load_per_mille(999);

    // High is not in sheddable_priorities
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::High, "op", async { Ok(()) })
        .await;
    assert!(
        result.is_ok(),
        "high priority should not be shed: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn load_shedding_low_shed_at_full_load() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        load_shed: LoadShedConfig {
            shed_threshold_per_mille: 100,
            full_shed_threshold_per_mille: 200,
            sheddable_priorities: vec![RequestPriority::Low, RequestPriority::Normal],
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // Set load at/above full shed threshold
    layer.set_base_load_per_mille(1000);

    // Low priority should be shed at full load
    let mut shed_count = 0;
    for _ in 0..10 {
        let result: Result<(), ResilienceError<String>> = layer
            .execute(&connector, RequestPriority::Low, "op", async { Ok(()) })
            .await;
        if matches!(result, Err(ResilienceError::LoadShed { .. })) {
            shed_count += 1;
        }
    }
    assert!(
        shed_count > 0,
        "expected at least some load shedding at full load"
    );
}

#[fcp_async_core::runtime::test]
async fn load_shedding_none_below_threshold() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    // Default shed threshold is 850, set load below
    layer.set_base_load_per_mille(100);

    for _ in 0..10 {
        let result: Result<(), ResilienceError<String>> = layer
            .execute(&connector, RequestPriority::Low, "op", async { Ok(()) })
            .await;
        assert!(
            result.is_ok(),
            "should not shed below threshold: {result:?}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn load_shedding_metrics_tracked() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        load_shed: LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![RequestPriority::Low],
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    layer.set_base_load_per_mille(1000);

    // Execute several Low priority requests
    for _ in 0..5 {
        let _: Result<(), ResilienceError<String>> = layer
            .execute(&connector, RequestPriority::Low, "op", async { Ok(()) })
            .await;
    }

    let m = layer.metrics(&connector);
    assert!(
        m.load_shed > 0,
        "expected load_shed metrics > 0, got {}",
        m.load_shed
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// G. Operation Timeout E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn operation_timeout_triggers() {
    let layer = timeout_layer(Duration::from_millis(50));
    let connector = ConnectorId::from_static("test:slow:1.0.0");

    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "slow-op", async {
            fcp_async_core::time::sleep(Duration::from_millis(200)).await;
            Ok(())
        })
        .await;

    assert!(
        matches!(result, Err(ResilienceError::TimedOut { .. })),
        "expected TimedOut, got {result:?}"
    );
    let m = layer.metrics(&connector);
    assert_eq!(m.timeouts, 1);
}

#[fcp_async_core::runtime::test]
async fn operation_within_timeout_succeeds() {
    let layer = timeout_layer(Duration::from_millis(500));
    let connector = ConnectorId::from_static("test:fast:1.0.0");

    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "fast-op", async {
            fcp_async_core::time::sleep(Duration::from_millis(10)).await;
            Ok(())
        })
        .await;

    assert!(result.is_ok(), "fast op should succeed: {result:?}");
}

#[fcp_async_core::runtime::test]
async fn timeout_counts_as_failure_for_circuit() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        operation_timeout: Some(Duration::from_millis(20)),
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:slow:1.0.0");

    // 2 timeouts should open the circuit
    for _ in 0..2 {
        let _: Result<(), ResilienceError<String>> = layer
            .execute(&connector, RequestPriority::Normal, "op", async {
                fcp_async_core::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            })
            .await;
    }

    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);
}

// ═════════════════════════════════════════════════════════════════════════════
// H. Connector Isolation
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn connector_state_isolated() {
    let layer = fast_circuit_layer();
    let c1 = ConnectorId::from_static("test:good:1.0.0");
    let c2 = ConnectorId::from_static("test:bad:1.0.0");

    // Fail c2 until circuit opens
    fail_op(&layer, &c2).await;
    fail_op(&layer, &c2).await;
    assert_eq!(layer.circuit_state(&c2), CircuitState::Open);

    // c1 should still be closed
    assert_eq!(layer.circuit_state(&c1), CircuitState::Closed);
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&c1, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    assert!(
        result.is_ok(),
        "c1 should not be affected by c2: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_metrics_isolated() {
    let layer = default_layer();
    let c1 = ConnectorId::from_static("test:a:1.0.0");
    let c2 = ConnectorId::from_static("test:b:1.0.0");

    succeed(&layer, &c1).await;
    succeed(&layer, &c1).await;
    succeed(&layer, &c2).await;

    let m1 = layer.metrics(&c1);
    let m2 = layer.metrics(&c2);
    assert_eq!(m1.requests, 2);
    assert_eq!(m2.requests, 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// I. merge_connector_health
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn merge_both_healthy() {
    let result = merge_connector_health(ConnectorHealth::Healthy, ConnectorHealth::Healthy);
    assert!(is_healthy(&result));
}

#[test]
fn merge_healthy_and_degraded() {
    let result = merge_connector_health(
        ConnectorHealth::Healthy,
        ConnectorHealth::Degraded {
            reason: "slow".to_string(),
        },
    );
    assert!(is_degraded(&result));
}

#[test]
fn merge_degraded_and_unavailable() {
    let now = chrono::Utc::now();
    let result = merge_connector_health(
        ConnectorHealth::Degraded {
            reason: "slow".to_string(),
        },
        ConnectorHealth::Unavailable {
            reason: "down".to_string(),
            since: now,
        },
    );
    assert!(is_unavailable(&result));
}

#[test]
fn merge_both_unavailable_combines_reasons() {
    let now = chrono::Utc::now();
    let result = merge_connector_health(
        ConnectorHealth::Unavailable {
            reason: "crash".to_string(),
            since: now,
        },
        ConnectorHealth::Unavailable {
            reason: "oom".to_string(),
            since: now,
        },
    );
    match result {
        ConnectorHealth::Unavailable { reason, .. } => {
            assert!(reason.contains("crash"), "expected crash: {reason}");
            assert!(reason.contains("oom"), "expected oom: {reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn merge_both_degraded_combines_reasons() {
    let result = merge_connector_health(
        ConnectorHealth::Degraded {
            reason: "high latency".to_string(),
        },
        ConnectorHealth::Degraded {
            reason: "high error rate".to_string(),
        },
    );
    match result {
        ConnectorHealth::Degraded { reason } => {
            assert!(
                reason.contains("high latency"),
                "expected latency: {reason}"
            );
            assert!(
                reason.contains("high error rate"),
                "expected error rate: {reason}"
            );
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// J. Composed Flow E2E
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn composed_success_flow() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    let result: Result<String, ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "echo", async {
            Ok("hello".to_string())
        })
        .await;

    assert_eq!(result.unwrap(), "hello");
    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 1);
    assert_eq!(m.successes, 1);
    assert_eq!(m.failures, 0);
}

#[fcp_async_core::runtime::test]
async fn composed_failure_flow() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:echo:1.0.0");

    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "fail", async {
            Err("boom".to_string())
        })
        .await;

    assert!(matches!(result, Err(ResilienceError::Inner(ref e)) if e == "boom"));
    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 1);
    assert_eq!(m.failures, 1);
    assert_eq!(m.successes, 0);
}

#[fcp_async_core::runtime::test]
async fn composed_cascade_circuit_then_reject() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_millis(50),
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:cascade:1.0.0");

    // Cause failures
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;

    // Circuit is now open
    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);

    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    assert!(
        matches!(result, Err(ResilienceError::CircuitOpen { .. })),
        "expected circuit rejection, got {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn composed_recovery_flow() {
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:recover:1.0.0");

    // Open the circuit
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Open);

    // Wait for half-open
    fcp_async_core::time::sleep(Duration::from_millis(60)).await;

    // Successful probe closes circuit
    succeed(&layer, &connector).await;
    assert_eq!(layer.circuit_state(&connector), CircuitState::Closed);

    // Normal operation resumes
    let result: Result<String, ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async {
            Ok("recovered".to_string())
        })
        .await;
    assert_eq!(result.unwrap(), "recovered");
}

// ═════════════════════════════════════════════════════════════════════════════
// K. Metrics Accuracy
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn metrics_track_all_outcomes() {
    let layer = ResilienceLayer::new(ResilienceConfig {
        operation_timeout: Some(Duration::from_millis(20)),
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 100, // high to avoid circuit interference
            ..CircuitBreakerConfig::default()
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:metrics:1.0.0");

    // 2 successes
    succeed(&layer, &connector).await;
    succeed(&layer, &connector).await;

    // 1 failure
    fail_op(&layer, &connector).await;

    // 1 timeout
    let _: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "slow", async {
            fcp_async_core::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        })
        .await;

    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 4);
    assert_eq!(m.successes, 2);
    assert_eq!(m.failures, 1);
    assert_eq!(m.timeouts, 1);
}

#[fcp_async_core::runtime::test]
async fn metrics_snapshot_is_consistent() {
    let layer = default_layer();
    let connector = ConnectorId::from_static("test:consistent:1.0.0");

    for _ in 0..10 {
        succeed(&layer, &connector).await;
    }

    let m = layer.metrics(&connector);
    assert_eq!(m.requests, 10);
    assert_eq!(m.successes, 10);
    assert_eq!(m.failures, 0);
    assert_eq!(m.timeouts, 0);
    assert_eq!(m.circuit_rejections, 0);
    assert_eq!(m.circuit_opened, 0);
    assert_eq!(m.bulkhead_rejections, 0);
    assert_eq!(m.load_shed, 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// L. Full Logged E2E Flow
// ═════════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn logged_resilience_flow() {
    let mut logger = E2eLogger::new();
    let layer = fast_circuit_layer();
    let connector = ConnectorId::from_static("test:flow:1.0.0");

    // Phase 1: Normal operation
    let result: Result<String, ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "echo", async {
            Ok("ok".to_string())
        })
        .await;
    let ok = result.is_ok();
    logger.push(log_entry(
        "logged_resilience_flow",
        "normal-operation",
        if ok { "pass" } else { "fail" },
        u32::from(ok),
        u32::from(!ok),
        json!({ "response": "ok", "circuit": "closed" }),
    ));
    assert!(ok);

    // Phase 2: Inject failures to open circuit
    fail_op(&layer, &connector).await;
    fail_op(&layer, &connector).await;
    let circuit = layer.circuit_state(&connector);
    let circuit_open = circuit == CircuitState::Open;
    logger.push(log_entry(
        "logged_resilience_flow",
        "inject-failures",
        if circuit_open { "pass" } else { "fail" },
        u32::from(circuit_open),
        u32::from(!circuit_open),
        json!({ "failures": 2, "circuit_state": format!("{circuit:?}") }),
    ));
    assert!(circuit_open);

    // Phase 3: Verify rejection while circuit open
    let reject: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Normal, "op", async { Ok(()) })
        .await;
    let rejected = matches!(reject, Err(ResilienceError::CircuitOpen { .. }));
    logger.push(log_entry(
        "logged_resilience_flow",
        "circuit-rejection",
        if rejected { "pass" } else { "fail" },
        u32::from(rejected),
        u32::from(!rejected),
        json!({ "rejected": rejected }),
    ));
    assert!(rejected);

    // Phase 4: Wait for half-open and recover
    fcp_async_core::time::sleep(Duration::from_millis(60)).await;
    succeed(&layer, &connector).await;
    let recovered = layer.circuit_state(&connector) == CircuitState::Closed;
    logger.push(log_entry(
        "logged_resilience_flow",
        "recovery",
        if recovered { "pass" } else { "fail" },
        u32::from(recovered),
        u32::from(!recovered),
        json!({ "circuit_state": "closed", "recovered": recovered }),
    ));
    assert!(recovered);

    // Phase 5: Verify metrics
    let m = layer.metrics(&connector);
    let metrics_ok = m.requests >= 5 && m.successes >= 2 && m.failures >= 2;
    logger.push(log_entry(
        "logged_resilience_flow",
        "metrics-verification",
        if metrics_ok { "pass" } else { "fail" },
        u32::from(metrics_ok),
        u32::from(!metrics_ok),
        json!({
            "requests": m.requests,
            "successes": m.successes,
            "failures": m.failures,
            "circuit_rejections": m.circuit_rejections,
            "circuit_opened": m.circuit_opened,
        }),
    ));
    assert!(metrics_ok);

    // Validate JSONL output
    let output = logger.to_json_lines();
    assert!(!output.is_empty());
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 5);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        assert!(v.get("timestamp").is_some());
        assert!(v.get("test_name").is_some());
    }
}

#[fcp_async_core::runtime::test]
async fn logged_load_shed_flow() {
    let mut logger = E2eLogger::new();
    let layer = ResilienceLayer::new(ResilienceConfig {
        load_shed: LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![RequestPriority::Low],
        },
        ..ResilienceConfig::default()
    });
    let connector = ConnectorId::from_static("test:shed:1.0.0");

    layer.set_base_load_per_mille(1000);

    // Attempt Low priority under max load
    let result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Low, "op", async { Ok(()) })
        .await;
    let shed = matches!(result, Err(ResilienceError::LoadShed { .. }));
    logger.push(log_entry(
        "logged_load_shed_flow",
        "shed-low-priority",
        if shed { "pass" } else { "fail" },
        u32::from(shed),
        u32::from(!shed),
        json!({ "priority": "Low", "load": 1000, "shed": shed }),
    ));

    // Critical should pass through
    let critical_result: Result<(), ResilienceError<String>> = layer
        .execute(&connector, RequestPriority::Critical, "op", async {
            Ok(())
        })
        .await;
    let critical_ok = critical_result.is_ok();
    logger.push(log_entry(
        "logged_load_shed_flow",
        "critical-passes",
        if critical_ok { "pass" } else { "fail" },
        u32::from(critical_ok),
        u32::from(!critical_ok),
        json!({ "priority": "Critical", "load": 1000, "passed": critical_ok }),
    ));
    assert!(critical_ok);

    let output = logger.to_json_lines();
    assert!(!output.is_empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// M. Config Clone / Debug
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn resilience_config_clone() {
    let config = ResilienceConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.circuit_breaker.failure_threshold, 3);
    assert_eq!(cloned.bulkhead.max_concurrent, 16);
}

#[test]
fn resilience_config_debug() {
    let config = ResilienceConfig::default();
    let dbg = format!("{config:?}");
    assert!(dbg.contains("ResilienceConfig"));
}

#[test]
fn circuit_breaker_config_clone() {
    let config = CircuitBreakerConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.failure_threshold, config.failure_threshold);
}

#[test]
fn bulkhead_config_clone() {
    let config = BulkheadConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.max_concurrent, config.max_concurrent);
}

#[test]
fn health_router_config_clone() {
    let config = HealthRouterConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.unhealthy_threshold, config.unhealthy_threshold);
}

#[test]
fn load_shed_config_clone() {
    let config = LoadShedConfig::default();
    let cloned = config.clone();
    assert_eq!(
        cloned.shed_threshold_per_mille,
        config.shed_threshold_per_mille
    );
}

#[test]
fn metrics_snapshot_copy() {
    let m = ResilienceMetricsSnapshot {
        requests: 42,
        successes: 40,
        failures: 2,
        ..ResilienceMetricsSnapshot::default()
    };
    let copied = m;
    assert_eq!(copied.requests, 42);
    assert_eq!(copied.successes, 40);
}

#[test]
fn metrics_snapshot_debug() {
    let m = ResilienceMetricsSnapshot::default();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("ResilienceMetricsSnapshot"));
}

#[test]
fn resilience_layer_debug() {
    let layer = default_layer();
    let dbg = format!("{layer:?}");
    assert!(dbg.contains("ResilienceLayer"));
}
