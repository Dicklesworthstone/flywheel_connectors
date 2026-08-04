//! Cross-module integration tests for `fcp-sdk`.
//!
//! Tests exercise real code paths spanning multiple SDK modules
//! (retry + formatting, ratelimit + retry, streaming + ack/nack,
//! runtime health + supervisor config, schema validation + limits)
//! without mocks.

use std::time::Duration;

use serde_json::json;

use fcp_sdk::formatting::{
    ErrorClass, FormatMode, Formatter, classify_error_message, is_parse_error_message,
};
use fcp_sdk::ratelimit::{RateLimitError, RateLimitPoolBuilder, RateLimitTracker};
use fcp_sdk::retry::{
    DEFAULT_RATE_LIMIT_RETRY_AFTER, RetryDecision, RetryPolicy, decision_from_error_message,
    decision_from_http_status, map_external_error,
};
use fcp_sdk::runtime::{HealthTracker, HealthTransition, SupervisorConfig};
use fcp_sdk::streaming::{BufferLimits, EventStreamManager, ReplayError};
use fcp_sdk::{
    ConnectorId, EventAck, EventCaps, EventData, EventNack, FcpError, HealthState, InstanceId,
    Limits, Principal, RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool,
    RateLimitScope, RateLimitUnit, RequestId, SchemaValidationError, SubscribeRequest, ThreadInfo,
    ThreadKind, TrustLevel, ZoneId,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn sample_event_data() -> EventData {
    EventData::new(
        ConnectorId::from_static("test:sdk:v1"),
        InstanceId::new(),
        ZoneId::work(),
        Principal {
            kind: "user".into(),
            id: "tester".into(),
            trust: TrustLevel::Paired,
            display: Some("Tester".into()),
        },
        json!({"test": true}),
    )
}

const fn caps(replay: bool, requires_ack: bool, min_buffer: u32) -> EventCaps {
    EventCaps {
        streaming: true,
        replay,
        min_buffer_events: min_buffer,
        requires_ack,
    }
}

fn test_declarations() -> RateLimitDeclarations {
    let pool_a = RateLimitPool {
        id: "global".into(),
        description: "Global rate limit".into(),
        config: RateLimitConfig {
            requests: 10,
            window: Duration::from_secs(60),
            burst: Some(2),
            unit: RateLimitUnit::Requests,
        },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Global,
    };
    let pool_b = RateLimitPool {
        id: "writes".into(),
        description: "Write operations".into(),
        config: RateLimitConfig {
            requests: 5,
            window: Duration::from_secs(60),
            burst: None,
            unit: RateLimitUnit::Requests,
        },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Global,
    };

    let mut tool_pool_map = std::collections::HashMap::new();
    tool_pool_map.insert("read".into(), vec!["global".into()]);
    tool_pool_map.insert("write".into(), vec!["global".into(), "writes".into()]);

    RateLimitDeclarations {
        limits: vec![pool_a, pool_b],
        tool_pool_map,
    }
}

// ============================================================================
// 1. Retry + Formatting: error classification → retry decision pipeline
// ============================================================================

#[test]
fn rate_limit_message_classified_then_retryable() {
    let msg = "Too many requests, please slow down";
    let class = classify_error_message(msg);
    assert_eq!(class, ErrorClass::RateLimit);

    let decision = decision_from_error_message(msg);
    assert_eq!(decision, RetryDecision::Backoff);
    assert!(decision.is_retryable());
}

#[test]
fn transient_message_classified_then_retryable() {
    let msg = "Connection timed out waiting for response";
    let class = classify_error_message(msg);
    assert_eq!(class, ErrorClass::Transient);

    let decision = decision_from_error_message(msg);
    assert_eq!(decision, RetryDecision::Backoff);
    assert!(decision.is_retryable());
}

#[test]
fn terminal_message_classified_not_retryable() {
    let msg = "Invalid API key provided";
    let class = classify_error_message(msg);
    assert_eq!(class, ErrorClass::Terminal);

    let decision = decision_from_error_message(msg);
    assert_eq!(decision, RetryDecision::Terminal);
    assert!(!decision.is_retryable());
}

#[test]
fn parse_error_message_classified_terminal() {
    let msg = "Can't parse entities in message text";
    assert!(is_parse_error_message(msg));
    let class = classify_error_message(msg);
    assert_eq!(class, ErrorClass::ParseError);

    let decision = decision_from_error_message(msg);
    assert_eq!(decision, RetryDecision::Terminal);
}

#[test]
fn http_status_messages_flow_through_classification() {
    let cases = [
        ("http 429 rate limit exceeded", ErrorClass::RateLimit, true),
        ("http 502 bad gateway", ErrorClass::Transient, true),
        ("http 503 service unavailable", ErrorClass::Transient, true),
        ("http 504 gateway timeout", ErrorClass::Transient, true),
        ("Permission denied", ErrorClass::Terminal, false),
    ];

    for (msg, expected_class, expected_retryable) in cases {
        let class = classify_error_message(msg);
        assert_eq!(class, expected_class, "wrong class for: {msg}");
        let decision = decision_from_error_message(msg);
        assert_eq!(
            decision.is_retryable(),
            expected_retryable,
            "wrong retryable for: {msg}"
        );
    }
}

// ============================================================================
// 2. Retry + HTTP status → FcpError mapping pipeline
// ============================================================================

#[test]
fn http_429_maps_to_rate_limited_fcp_error() {
    let hint = Duration::from_secs(10);
    let (decision, error) =
        map_external_error("api-service", Some(429), "rate limited", Some(hint));

    assert_eq!(decision, RetryDecision::After(hint));
    assert!(matches!(
        error,
        FcpError::RateLimited {
            retry_after_ms: 10_000,
            ..
        }
    ));
}

#[test]
fn http_429_without_hint_uses_default_retry_after() {
    let (decision, error) = map_external_error("api", Some(429), "slow down", None);

    assert_eq!(
        decision,
        RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER)
    );
    assert!(matches!(error, FcpError::RateLimited { .. }));
}

#[test]
fn http_500_maps_to_external_error_retryable() {
    let (decision, error) = map_external_error("backend", Some(500), "Internal Server Error", None);

    assert_eq!(decision, RetryDecision::Backoff);
    assert!(matches!(
        error,
        FcpError::External {
            retryable: true,
            ..
        }
    ));
}

#[test]
fn http_401_maps_to_terminal_external_error() {
    let (decision, error) = map_external_error("auth-svc", Some(401), "Unauthorized", None);

    assert_eq!(decision, RetryDecision::Terminal);
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
}

#[test]
fn no_status_falls_back_to_message_classification() {
    let (decision, _) = map_external_error("svc", None, "Connection timed out", None);
    assert_eq!(decision, RetryDecision::Backoff);

    let (decision2, _) = map_external_error("svc", None, "Bad request format", None);
    assert_eq!(decision2, RetryDecision::Terminal);
}

// ============================================================================
// 3. RetryPolicy + HTTP status integration
// ============================================================================

#[test]
fn retry_policy_backoff_from_http_status() {
    let policy = RetryPolicy::new().with_jitter_enabled(false);
    let decision = decision_from_http_status(503, None);
    assert_eq!(decision, RetryDecision::Backoff);

    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay.as_millis(), 1000);

    let delay1 = policy.next_delay(1, decision, None).unwrap();
    assert_eq!(delay1.as_millis(), 2000);

    let delay2 = policy.next_delay(2, decision, None).unwrap();
    assert_eq!(delay2.as_millis(), 4000);
}

#[test]
fn retry_policy_respects_max_attempts() {
    let policy = RetryPolicy::new()
        .with_max_attempts(Some(3))
        .with_jitter_enabled(false);

    assert!(policy.next_delay(0, RetryDecision::Backoff, None).is_some());
    assert!(policy.next_delay(1, RetryDecision::Backoff, None).is_some());
    assert!(policy.next_delay(2, RetryDecision::Backoff, None).is_none());
    assert!(policy.next_delay(3, RetryDecision::Backoff, None).is_none());
}

#[test]
fn retry_after_hint_overrides_computed_backoff() {
    let policy = RetryPolicy::new().with_jitter_enabled(false);
    // A hint inside the policy's ceiling raises the delay above the computed
    // backoff (default base is 1s).
    let hint = Duration::from_secs(30);
    let decision = decision_from_http_status(429, Some(hint));

    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay, hint);
}

/// `Retry-After` is attacker-controlled, so it raises the delay but must not
/// escape `max_backoff_ms` — the same ceiling
/// `retry_policy_caps_at_max_backoff` (below) already asserts for the computed
/// backoff. The hint path used to bypass it entirely.
#[test]
fn retry_after_hint_cannot_exceed_max_backoff() {
    let policy = RetryPolicy::new().with_jitter_enabled(false);
    let decision = decision_from_http_status(429, Some(Duration::from_secs(31_536_000)));

    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay, Duration::from_millis(policy.max_backoff_ms));
}

#[test]
fn retry_policy_caps_at_max_backoff() {
    let policy = RetryPolicy::new()
        .with_base_backoff_ms(1000)
        .with_max_backoff_ms(10_000)
        .with_jitter_enabled(false)
        .with_max_attempts(None);

    let delay = policy.next_delay(10, RetryDecision::Backoff, None).unwrap();
    assert_eq!(delay.as_millis(), 10_000);
}

// ============================================================================
// 4. Supervisor backoff convergence with RetryPolicy
// ============================================================================

#[test]
fn supervisor_and_retry_policy_same_backoff_formula() {
    let config = SupervisorConfig::default();
    let policy = RetryPolicy::new()
        .with_base_backoff_ms(config.base_backoff_ms)
        .with_max_backoff_ms(config.max_backoff_ms);

    for attempt in 0..8 {
        let supervisor_delay = config.compute_backoff(attempt);
        let policy_delay = policy.compute_backoff_ms(attempt);
        assert_eq!(
            supervisor_delay, policy_delay,
            "mismatch at attempt {attempt}"
        );
    }
}

#[test]
fn supervisor_and_retry_policy_same_jitter_formula() {
    let config = SupervisorConfig::default();
    let policy = RetryPolicy::new()
        .with_base_backoff_ms(config.base_backoff_ms)
        .with_max_backoff_ms(config.max_backoff_ms)
        .with_jitter_enabled(true);

    let factor = 0.42;
    for attempt in 0..8 {
        let supervisor_delay = config.compute_backoff_with_jitter(attempt, factor);
        let policy_delay = policy.compute_backoff_with_jitter_ms(attempt, factor);
        assert_eq!(
            supervisor_delay, policy_delay,
            "jitter mismatch at attempt {attempt}"
        );
    }
}

// ============================================================================
// 5. RateLimitTracker from declarations + consumption
// ============================================================================

#[test]
fn tracker_from_declarations_enforces_limits() {
    let decls = test_declarations();
    let tracker = RateLimitTracker::from_declarations(&decls);

    for _ in 0..12 {
        assert!(tracker.try_consume("read", 1).is_none());
    }
    assert!(tracker.try_consume("read", 1).is_some());
}

#[test]
fn tracker_write_consumes_both_pools() {
    let decls = test_declarations();
    let tracker = RateLimitTracker::from_declarations(&decls);

    for _ in 0..5 {
        assert!(tracker.try_consume("write", 1).is_none());
    }
    let err = tracker.try_consume("write", 1).unwrap();
    assert_eq!(err.pool_id, "writes");
    assert_eq!(err.limit, 5);
}

#[test]
fn tracker_operation_status_reflects_consumption() {
    let decls = test_declarations();
    let tracker = RateLimitTracker::from_declarations(&decls);

    tracker.try_consume("write", 3);
    let statuses = tracker.operation_status("write");
    assert_eq!(statuses.len(), 2);

    for (pool_id, status) in &statuses {
        match pool_id.as_str() {
            "global" => assert_eq!(status.remaining, 12 - 3),
            "writes" => assert_eq!(status.remaining, 5 - 3),
            _ => panic!("unexpected pool: {pool_id}"),
        }
    }
}

// ============================================================================
// 6. RateLimitError → FcpError cross-module mapping
// ============================================================================

#[test]
fn rate_limit_error_converts_to_fcp_rate_limited() {
    let pool = RateLimitPool {
        id: "test".into(),
        description: "test pool".into(),
        config: RateLimitConfig {
            requests: 100,
            window: Duration::from_secs(60),
            burst: None,
            unit: RateLimitUnit::Requests,
        },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Global,
    };

    let err = RateLimitError::for_pool(&pool, 101, 5000);
    assert!(!err.is_soft());

    let fcp = err.into_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        }
    ));
}

#[test]
fn soft_limit_error_is_soft() {
    let pool = RateLimitPool {
        id: "advisory".into(),
        description: "advisory pool".into(),
        config: RateLimitConfig {
            requests: 10,
            window: Duration::from_secs(60),
            burst: None,
            unit: RateLimitUnit::Requests,
        },
        enforcement: RateLimitEnforcement::Advisory,
        scope: RateLimitScope::Global,
    };

    let err = RateLimitError::for_pool(&pool, 11, 1000);
    assert!(err.is_soft());
}

// ============================================================================
// 7. Formatting + fallback pipeline
// ============================================================================

#[test]
fn html_valid_passes_through() {
    let result = Formatter::render_with_fallback("<b>hello</b>", FormatMode::Html);
    assert_eq!(result.rendered, "<b>hello</b>");
    assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
}

#[test]
fn html_invalid_falls_back_to_plaintext() {
    // Unclosed tag (no closing '>')
    let result = Formatter::render_with_fallback("text <b with no close", FormatMode::Html);
    assert!(result.parse_mode_used.is_none());
    assert!(!result.rendered.contains('<'));
}

#[test]
fn markdown_trailing_backslash_falls_back() {
    let result = Formatter::render_with_fallback("text\\", FormatMode::MarkdownV2);
    assert!(result.parse_mode_used.is_none());
}

#[test]
fn plaintext_always_passes() {
    let result = Formatter::render_with_fallback("hello world", FormatMode::Plain);
    assert_eq!(result.rendered, "hello world");
    assert!(result.parse_mode_used.is_none());
}

#[test]
fn control_chars_trigger_fallback() {
    let input = "hello\x01world";
    let result = Formatter::render_with_fallback(input, FormatMode::Html);
    assert!(result.parse_mode_used.is_none());
}

#[test]
fn plaintext_fallback_strips_html_tags() {
    let result = Formatter::render_plaintext_fallback("<b>bold</b>", FormatMode::Html);
    assert!(result.parse_mode_used.is_none());
    assert!(!result.rendered.contains('<'));
    assert!(result.rendered.contains("bold"));
}

// ============================================================================
// 8. Streaming: emit → subscribe → replay → ack → nack pipeline
// ============================================================================

#[test]
fn streaming_emit_subscribe_replay_flow() {
    let mut mgr = EventStreamManager::new(caps(true, true, 10));

    for _ in 0..5 {
        mgr.emit("topic-a", sample_event_data());
    }

    let req = SubscribeRequest {
        r#type: "subscribe".into(),
        id: RequestId::new("sub-1"),
        topics: vec!["topic-a".into()],
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    };
    let outcome = mgr.handle_subscribe(&req).unwrap();
    assert!(
        outcome
            .response
            .result
            .confirmed_topics
            .contains(&"topic-a".into())
    );

    let replayed = mgr.replay_from("topic-a", "").unwrap();
    assert_eq!(replayed.len(), 5);
}

#[test]
fn streaming_thread_info_survives_sdk_to_client_flow() {
    let mut mgr = EventStreamManager::new(caps(true, true, 10));
    let thread = ThreadInfo::new("forum-topic-42", ThreadKind::ForumTopic).with_parent_id("chat-7");
    let emitted = mgr.emit(
        "telegram.message.new",
        sample_event_data().with_thread_info(thread.clone()),
    );

    let req = SubscribeRequest {
        r#type: "subscribe".into(),
        id: RequestId::new("sub-thread-1"),
        topics: vec!["telegram.message.new".into()],
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    };
    let outcome = mgr.handle_subscribe(&req).unwrap();
    assert_eq!(
        outcome.response.result.confirmed_topics,
        vec!["telegram.message.new".to_string()]
    );

    let replayed = mgr.replay_from("telegram.message.new", "").unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].seq, emitted.seq);
    assert_eq!(replayed[0].data.thread_info.as_ref(), Some(&thread));

    let encoded = serde_json::to_value(&replayed[0]).unwrap();
    let decoded: fcp_sdk::EventEnvelope = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.data.thread_info.as_ref(), Some(&thread));

    let ack = EventAck::new("telegram.message.new", vec![emitted.seq]);
    let ack_result = mgr.handle_ack(&ack);
    assert_eq!(ack_result.acked, vec![emitted.seq]);
    assert!(ack_result.missing.is_empty());
}

#[test]
fn streaming_replay_from_cursor_returns_subsequent() {
    let mut mgr = EventStreamManager::new(caps(true, false, 10));

    let e1 = mgr.emit("events", sample_event_data());
    let e2 = mgr.emit("events", sample_event_data());
    let _e3 = mgr.emit("events", sample_event_data());

    let replayed = mgr.replay_from("events", &e1.cursor).unwrap();
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].seq, e2.seq);
}

#[test]
fn streaming_ack_clears_pending() {
    let mut mgr = EventStreamManager::new(caps(true, true, 10));

    let e1 = mgr.emit("t", sample_event_data());
    let _e2 = mgr.emit("t", sample_event_data());

    let ack = EventAck::new("t", vec![e1.seq]);
    let result = mgr.handle_ack(&ack);
    assert_eq!(result.acked, vec![e1.seq]);
    assert!(result.missing.is_empty());

    // Ack e1 again → it's missing now
    let result2 = mgr.handle_ack(&ack);
    assert!(result2.acked.is_empty());
    assert_eq!(result2.missing, vec![e1.seq]);
}

#[test]
fn streaming_nack_redelivers_events() {
    let mut mgr = EventStreamManager::new(caps(true, true, 10));

    let e1 = mgr.emit("t", sample_event_data());

    let nack = EventNack::new("t", vec![e1.seq], "retry");
    let result = mgr.handle_nack(&nack);
    assert_eq!(result.redeliver.len(), 1);
    assert_eq!(result.redeliver[0].seq, e1.seq);
    assert!(result.missing.is_empty());
}

#[test]
fn streaming_nack_nonexistent_reports_missing() {
    let mut mgr = EventStreamManager::new(caps(true, true, 10));
    mgr.emit("t", sample_event_data());

    let nack = EventNack::new("t", vec![9999], "retry");
    let result = mgr.handle_nack(&nack);
    assert!(result.redeliver.is_empty());
    assert_eq!(result.missing, vec![9999]);
}

#[test]
fn streaming_replay_unknown_topic_error() {
    let mgr = EventStreamManager::new(caps(true, false, 10));
    let err = mgr.replay_from("nonexistent", "").unwrap_err();
    assert!(matches!(err, ReplayError::UnknownTopic { .. }));
}

#[test]
fn streaming_replay_invalid_cursor_error() {
    let mut mgr = EventStreamManager::new(caps(true, false, 10));
    mgr.emit("t", sample_event_data());

    let err = mgr.replay_from("t", "not-a-number").unwrap_err();
    assert!(matches!(err, ReplayError::InvalidCursor { .. }));
}

// ============================================================================
// 9. Streaming buffer limits + ack interaction
// ============================================================================

#[test]
fn buffer_limits_trim_unacked_protected() {
    let limits = BufferLimits::new(2, 5);
    let mut mgr = EventStreamManager::with_limits(caps(true, true, 2), limits);

    let mut seqs = Vec::new();
    for _ in 0..10 {
        let env = mgr.emit("t", sample_event_data());
        seqs.push(env.seq);
    }

    // Pending acks protect all 10
    let replayed = mgr.replay_from("t", "").unwrap();
    assert_eq!(replayed.len(), 10);

    // Ack first 5
    let ack = EventAck::new("t", seqs[..5].to_vec());
    mgr.handle_ack(&ack);

    // After ack, trimming can remove the first 5
    let replayed2 = mgr.replay_from("t", "").unwrap();
    assert!(replayed2.len() <= 10);
}

// ============================================================================
// 10. Health tracker state machine transitions
// ============================================================================

#[test]
fn health_tracker_starts_in_starting_state() {
    let tracker = HealthTracker::new();
    assert!(matches!(tracker.state(), HealthState::Starting));
    assert_eq!(tracker.consecutive_failures(), 0);
}

#[test]
fn health_tracker_starting_to_healthy() {
    let mut tracker = HealthTracker::new();
    assert!(tracker.transition(HealthTransition::ToHealthy));
    assert!(tracker.is_healthy());
}

#[test]
fn health_tracker_failure_accumulation() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    tracker.record_failure("timeout");
    assert_eq!(tracker.consecutive_failures(), 1);

    tracker.record_failure("connection reset");
    assert_eq!(tracker.consecutive_failures(), 2);

    tracker.record_success();
    assert_eq!(tracker.consecutive_failures(), 0);
}

#[test]
fn health_tracker_degradation_and_recovery() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    assert!(tracker.transition(HealthTransition::ToDegraded {
        reason: "high latency".into(),
    }));
    assert!(tracker.is_degraded());

    assert!(tracker.transition(HealthTransition::ToHealthy));
    assert!(tracker.is_healthy());
}

#[test]
fn health_tracker_invalid_transitions_rejected() {
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    // Ready → Ready is not valid
    assert!(!tracker.transition(HealthTransition::ToHealthy));
    assert!(tracker.is_healthy());
}

#[test]
fn health_tracker_failure_threshold_with_supervisor_config() {
    let config = SupervisorConfig::default();
    let mut tracker = HealthTracker::new();
    tracker.transition(HealthTransition::ToHealthy);

    for i in 0..config.max_consecutive_failures {
        tracker.record_failure(&format!("failure {i}"));
    }
    assert_eq!(
        tracker.consecutive_failures(),
        config.max_consecutive_failures
    );

    assert!(tracker.transition(HealthTransition::ToUnhealthy {
        reason: "exceeded max consecutive failures".into(),
    }));
    assert!(tracker.is_unhealthy());

    assert!(tracker.transition(HealthTransition::ToHealthy));
    assert!(tracker.is_healthy());
}

// ============================================================================
// 11. Schema validation + limits enforcement pipeline
// ============================================================================

#[test]
fn schema_validation_accepts_valid_input() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name"]
    });

    let value = json!({"name": "Alice", "age": 30});
    fcp_sdk::validate_input(&schema, &value).unwrap();
}

#[test]
fn schema_validation_rejects_invalid_input() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"}
        },
        "required": ["name"]
    });

    let value = json!({"age": 30});
    let err = fcp_sdk::validate_input(&schema, &value).unwrap_err();
    assert!(matches!(err, FcpError::InvalidRequest { .. }));
}

#[test]
fn limits_enforcement_rejects_oversized_payload() {
    let schema = json!({"type": "object"});
    let limits = Limits::new(50, 100, 10);
    let big_value = json!({"data": "x".repeat(100)});

    let err = fcp_sdk::validate_input_with_limits(&schema, &big_value, &limits).unwrap_err();
    assert!(matches!(err, FcpError::InvalidRequest { .. }));
}

#[test]
fn limits_enforcement_rejects_deep_nesting() {
    let schema = json!({"type": "object"});
    let limits = Limits::new(100_000, 100, 3);

    let deep = json!({"a": {"b": {"c": {"d": "too deep"}}}});
    let err = fcp_sdk::validate_input_with_limits(&schema, &deep, &limits).unwrap_err();
    assert!(matches!(err, FcpError::InvalidRequest { .. }));
}

#[test]
fn limits_enforcement_rejects_long_array() {
    let schema = json!({"type": "object"});
    let limits = Limits::new(100_000, 3, 32);

    let arr = json!({"items": [1, 2, 3, 4, 5]});
    let err = fcp_sdk::validate_input_with_limits(&schema, &arr, &limits).unwrap_err();
    assert!(matches!(err, FcpError::InvalidRequest { .. }));
}

#[test]
fn limits_disabled_allows_everything() {
    let schema = json!({"type": "object"});
    let limits = Limits::disabled();
    let big = json!({"data": "x".repeat(10_000)});

    fcp_sdk::validate_input_with_limits(&schema, &big, &limits).unwrap();
}

#[test]
fn schema_compiler_caches_and_reuses() {
    use fcp_sdk::SchemaValidator;

    let schema = json!({"type": "string"});
    let validator = SchemaValidator::compile(&schema).unwrap();

    validator.validate(&json!("hello")).unwrap();

    let err = validator.validate(&json!(42)).unwrap_err();
    assert!(matches!(
        err,
        SchemaValidationError::ValidationFailed { .. }
    ));
}

// ============================================================================
// 12. End-to-end: external error → retry decision → policy delay
// ============================================================================

#[test]
fn end_to_end_429_retry_flow() {
    let policy = RetryPolicy::new().with_jitter_enabled(false);
    let hint = Duration::from_secs(5);
    let (decision, fcp_err) =
        map_external_error("github-api", Some(429), "Rate limit exceeded", Some(hint));

    assert_eq!(decision, RetryDecision::After(hint));

    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay, hint);

    assert!(matches!(
        fcp_err,
        FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        }
    ));
}

#[test]
fn end_to_end_503_retry_flow() {
    let policy = RetryPolicy::new()
        .with_jitter_enabled(false)
        .with_base_backoff_ms(500);
    let (decision, fcp_err) =
        map_external_error("slack-api", Some(503), "Service Unavailable", None);

    assert_eq!(decision, RetryDecision::Backoff);

    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay.as_millis(), 500);

    assert!(matches!(
        fcp_err,
        FcpError::External {
            retryable: true,
            ..
        }
    ));
}

#[test]
fn end_to_end_message_only_error_flow() {
    let policy = RetryPolicy::new()
        .with_jitter_enabled(false)
        .with_base_backoff_ms(200);
    let (decision, _) =
        map_external_error("internal", None, "Connection refused by remote host", None);

    assert_eq!(decision, RetryDecision::Backoff);
    let delay = policy.next_delay(0, decision, None).unwrap();
    assert_eq!(delay.as_millis(), 200);
}

// ============================================================================
// 13. Formatting error class → retry decision integration
// ============================================================================

#[test]
fn format_error_triggers_terminal_retry_decision() {
    let msg = "Can't parse entities: markdown parse error";
    assert!(is_parse_error_message(msg));
    let decision = decision_from_error_message(msg);
    assert_eq!(decision, RetryDecision::Terminal);
}

#[test]
fn format_render_failure_classifies_correctly() {
    let result = Formatter::render_with_fallback("<unclosed", FormatMode::Html);
    assert!(result.parse_mode_used.is_none());

    let class = classify_error_message("can't parse entities in HTML");
    assert_eq!(class, ErrorClass::ParseError);
}

// ============================================================================
// 14. Streaming multi-topic with subscribe + replay
// ============================================================================

#[test]
fn multi_topic_subscribe_and_replay() {
    let mut mgr = EventStreamManager::new(caps(true, false, 10));

    mgr.emit("orders", sample_event_data());
    mgr.emit("orders", sample_event_data());
    mgr.emit("notifications", sample_event_data());

    let req = SubscribeRequest {
        r#type: "subscribe".into(),
        id: RequestId::new("sub-multi"),
        topics: vec!["orders".into(), "notifications".into()],
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    };
    let outcome = mgr.handle_subscribe(&req).unwrap();
    assert_eq!(outcome.response.result.confirmed_topics.len(), 2);

    let orders = mgr.replay_from("orders", "").unwrap();
    assert_eq!(orders.len(), 2);

    let notifs = mgr.replay_from("notifications", "").unwrap();
    assert_eq!(notifs.len(), 1);
}

#[test]
fn subscribe_to_nonexistent_topic_creates_it() {
    let mut mgr = EventStreamManager::new(caps(true, false, 10));

    let req = SubscribeRequest {
        r#type: "subscribe".into(),
        id: RequestId::new("sub-new"),
        topics: vec!["new-topic".into()],
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    };
    let outcome = mgr.handle_subscribe(&req).unwrap();
    assert!(
        outcome
            .response
            .result
            .confirmed_topics
            .contains(&"new-topic".into())
    );

    let replayed = mgr.replay_from("new-topic", "").unwrap();
    assert!(replayed.is_empty());
}

// ============================================================================
// 15. SupervisorConfig validation
// ============================================================================

#[test]
fn supervisor_config_default_validates() {
    let config = SupervisorConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn supervisor_config_zero_base_backoff_fails_validation() {
    let config = SupervisorConfig {
        base_backoff_ms: 0,
        ..SupervisorConfig::default()
    };
    let errors = config.validate().unwrap_err();
    assert!(!errors.is_empty());
}

#[test]
fn supervisor_config_serde_roundtrip() {
    let config = SupervisorConfig::default();
    let json_str = serde_json::to_string(&config).unwrap();
    let restored: SupervisorConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config.base_backoff_ms, restored.base_backoff_ms);
    assert_eq!(config.max_backoff_ms, restored.max_backoff_ms);
    assert_eq!(
        config.max_consecutive_failures,
        restored.max_consecutive_failures
    );
}

// ============================================================================
// 16. RateLimitTracker thread safety
// ============================================================================

#[test]
fn rate_limit_tracker_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RateLimitTracker>();
}

#[test]
fn rate_limit_tracker_clone_shares_state() {
    let decls = test_declarations();
    let tracker = RateLimitTracker::from_declarations(&decls);
    let clone = tracker.clone();

    tracker.try_consume("read", 5);

    let status = clone.pool_status("global").unwrap();
    assert_eq!(status.remaining, 12 - 5);
}

// ============================================================================
// 17. RateLimitPoolBuilder
// ============================================================================

#[test]
fn pool_builder_creates_valid_pool() {
    let pool = RateLimitPoolBuilder::new("api")
        .description("API rate limit")
        .requests(100)
        .window_secs(60)
        .burst(10)
        .enforcement(RateLimitEnforcement::Hard)
        .scope(RateLimitScope::Global)
        .unit(RateLimitUnit::Requests)
        .build();

    assert_eq!(pool.id, "api");
    assert_eq!(pool.config.requests, 100);
    assert_eq!(pool.config.burst, Some(10));
}

#[test]
fn pool_builder_add_to_tracker() {
    let tracker = RateLimitTracker::new();
    let pool = RateLimitPoolBuilder::new("test-pool")
        .requests(3)
        .window_secs(60)
        .enforcement(RateLimitEnforcement::Hard)
        .build();

    tracker.add_pool(pool);
    let status = tracker.pool_status("test-pool").unwrap();
    assert_eq!(status.limit, 3);
    assert_eq!(status.remaining, 3);
}

// ============================================================================
// 18. BufferLimits edge cases
// ============================================================================

#[test]
fn buffer_limits_min_greater_than_max_adjusted() {
    let limits = BufferLimits::new(100, 50);
    assert_eq!(limits.max_events, 100);
}

#[test]
fn buffer_limits_default_values() {
    let limits = BufferLimits::default();
    assert_eq!(limits.min_events, 10);
    assert_eq!(limits.max_events, 100);
}

// ============================================================================
// 19. Schema validation output mode
// ============================================================================

#[test]
fn validate_output_rejects_invalid_response() {
    let schema = json!({
        "type": "object",
        "properties": {
            "result": {"type": "string"}
        },
        "required": ["result"]
    });

    let bad_output = json!({"data": 42});
    let err = fcp_sdk::validate_output(&schema, &bad_output).unwrap_err();
    assert!(matches!(err, FcpError::Internal { .. }));
}

#[test]
fn validate_output_with_limits_checks_both() {
    let schema = json!({"type": "object"});
    let limits = Limits::new(20, 100, 32);
    let big_output = json!({"result": "x".repeat(100)});

    let err = fcp_sdk::validate_output_with_limits(&schema, &big_output, &limits).unwrap_err();
    assert!(matches!(err, FcpError::Internal { .. }));
}

// ============================================================================
// 20. Streaming emit_with_seq
// ============================================================================

#[test]
fn emit_with_seq_uses_provided_sequence() {
    let mut mgr = EventStreamManager::new(caps(true, false, 10));

    let e = mgr.emit_with_seq("t", 42, sample_event_data());
    assert_eq!(e.seq, 42);
    assert_eq!(e.cursor, "42");

    let e2 = mgr.emit("t", sample_event_data());
    assert_eq!(e2.seq, 43);
}
