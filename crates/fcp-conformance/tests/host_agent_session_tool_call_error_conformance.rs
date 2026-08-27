//! `fcp_host` `AgentSessionConfig` + `ToolCallError` + helpful error
//! response builders conformance.
//!
//! Three tightly-coupled agent-facing primitives:
//!
//! 1. **`AgentSessionConfig`** — session lifecycle bounds
//!    (`idle_timeout`, `max_lifetime`, `max_concurrent_calls`,
//!    `rate_limit_per_minute`). The `validate()` method gates a session
//!    config before use; documented defaults define how aggressively
//!    sessions auto-expire and how much concurrent work an agent can
//!    drive.
//! 2. **`ToolCallError`** — host-side error that converts to a
//!    JSON-RPC `error` payload via `to_jsonrpc_error()`.
//! 3. **`build_error_response` / `build_error_response_with_data`**
//!    — the two helpers every tool-call dispatcher uses to format
//!    a JSON-RPC error response.
//!
//! Properties pinned (NORMATIVE):
//!
//! - `AgentSessionConfig::default` documented values:
//!   `idle_timeout=5min`, `max_lifetime=1h`, `max_concurrent_calls=10`,
//!   `rate_limit_per_minute=60`.
//! - `validate()` returns documented error strings for each invalid
//!   condition (zero `idle_timeout`, zero `max_lifetime`, max < idle,
//!   zero `concurrent_calls`, zero `rate_limit`).
//! - `is_valid()` ⇔ `validate().is_empty()`.
//! - `ToolCallError::new` constructs with code+message, data=None.
//! - `ToolCallError::with_data` adds structured data.
//! - `to_jsonrpc_error()` extracts numeric code + message + data
//!   into the `McpJsonRpcError` envelope.
//! - `Display` is `"[{code}] {message}"` exact format.
//! - `build_error_response` produces jsonrpc="2.0", preserved id,
//!   error with code+message and data=None.
//! - `build_error_response_with_data` includes the data payload.

use fcp_host::{
    AgentSessionConfig, McpErrorCode, ToolCallError, build_error_response,
    build_error_response_with_data,
};
use serde_json::json;
use std::time::Duration;

// ─── AgentSessionConfig::default ──────────────────────────────────

#[test]
fn agent_session_config_default_idle_timeout_is_five_minutes() {
    assert_eq!(
        AgentSessionConfig::default().idle_timeout,
        Duration::from_secs(5 * 60),
        "default idle_timeout MUST be 5 minutes"
    );
}

#[test]
fn agent_session_config_default_max_lifetime_is_one_hour() {
    assert_eq!(
        AgentSessionConfig::default().max_lifetime,
        Duration::from_secs(60 * 60),
        "default max_lifetime MUST be 1 hour"
    );
}

#[test]
fn agent_session_config_default_max_concurrent_calls_is_ten() {
    assert_eq!(AgentSessionConfig::default().max_concurrent_calls, 10);
}

#[test]
fn agent_session_config_default_rate_limit_per_minute_is_sixty() {
    assert_eq!(AgentSessionConfig::default().rate_limit_per_minute, 60);
}

#[test]
fn agent_session_config_default_is_valid() {
    let c = AgentSessionConfig::default();
    assert!(
        c.is_valid(),
        "default config MUST be self-valid; got errors: {:?}",
        c.validate()
    );
}

// ─── AgentSessionConfig::validate ─────────────────────────────────

#[test]
fn validate_rejects_zero_idle_timeout() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::ZERO,
        max_lifetime: Duration::from_secs(60),
        max_concurrent_calls: 5,
        rate_limit_per_minute: 30,
    };
    let errs = c.validate();
    assert!(
        errs.iter().any(|e| e.contains("idle_timeout must be > 0")),
        "MUST reject zero idle_timeout; got {errs:?}"
    );
    assert!(!c.is_valid());
}

#[test]
fn validate_rejects_zero_max_lifetime() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(60),
        max_lifetime: Duration::ZERO,
        max_concurrent_calls: 5,
        rate_limit_per_minute: 30,
    };
    let errs = c.validate();
    assert!(
        errs.iter().any(|e| e.contains("max_lifetime must be > 0")),
        "MUST reject zero max_lifetime; got {errs:?}"
    );
}

#[test]
fn validate_rejects_max_lifetime_below_idle_timeout() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(600),
        max_lifetime: Duration::from_secs(60),
        max_concurrent_calls: 5,
        rate_limit_per_minute: 30,
    };
    let errs = c.validate();
    assert!(
        errs.iter()
            .any(|e| e.contains("max_lifetime must be >= idle_timeout")),
        "MUST reject max < idle (session would expire before becoming idle); got {errs:?}"
    );
}

#[test]
fn validate_rejects_zero_max_concurrent_calls() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(120),
        max_concurrent_calls: 0,
        rate_limit_per_minute: 30,
    };
    let errs = c.validate();
    assert!(
        errs.iter()
            .any(|e| e.contains("max_concurrent_calls must be > 0"))
    );
}

#[test]
fn validate_rejects_zero_rate_limit_per_minute() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(120),
        max_concurrent_calls: 5,
        rate_limit_per_minute: 0,
    };
    let errs = c.validate();
    assert!(
        errs.iter()
            .any(|e| e.contains("rate_limit_per_minute must be > 0"))
    );
}

#[test]
fn validate_accumulates_multiple_errors() {
    // All four invalid conditions at once.
    let c = AgentSessionConfig {
        idle_timeout: Duration::ZERO,
        max_lifetime: Duration::ZERO,
        max_concurrent_calls: 0,
        rate_limit_per_minute: 0,
    };
    let errs = c.validate();
    assert!(
        errs.len() >= 4,
        "all 4 invariant violations MUST yield ≥4 errors; got {errs:?}"
    );
    assert!(!c.is_valid());
}

#[test]
fn validate_returns_empty_for_legal_config() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(120),
        max_concurrent_calls: 5,
        rate_limit_per_minute: 30,
    };
    assert_eq!(c.validate(), [] as [std::string::String; 0]);
    assert!(c.is_valid());
}

// ─── AgentSessionConfig serde ─────────────────────────────────────

#[test]
fn agent_session_config_serializes_durations_as_seconds() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(300),
        max_lifetime: Duration::from_secs(3600),
        max_concurrent_calls: 10,
        rate_limit_per_minute: 60,
    };
    let v = serde_json::to_value(&c).expect("serialize");
    // duration_secs serde: u64 seconds.
    assert_eq!(v["idle_timeout"], 300);
    assert_eq!(v["max_lifetime"], 3600);
}

#[test]
fn agent_session_config_serde_roundtrip() {
    let c = AgentSessionConfig {
        idle_timeout: Duration::from_secs(120),
        max_lifetime: Duration::from_secs(600),
        max_concurrent_calls: 7,
        rate_limit_per_minute: 42,
    };
    let json_str = serde_json::to_string(&c).expect("serialize");
    let parsed: AgentSessionConfig = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.idle_timeout, c.idle_timeout);
    assert_eq!(parsed.max_lifetime, c.max_lifetime);
    assert_eq!(parsed.max_concurrent_calls, c.max_concurrent_calls);
    assert_eq!(parsed.rate_limit_per_minute, c.rate_limit_per_minute);
}

// ─── ToolCallError ────────────────────────────────────────────────

#[test]
fn tool_call_error_new_constructs_with_data_none() {
    let e = ToolCallError::new(McpErrorCode::ToolNotFound, "no such tool");
    assert_eq!(e.code, McpErrorCode::ToolNotFound);
    assert_eq!(e.message, "no such tool");
    assert!(e.data.is_none());
}

#[test]
fn tool_call_error_with_data_carries_structured_payload() {
    let e = ToolCallError::with_data(
        McpErrorCode::InvalidParams,
        "bad shape",
        json!({"missing": ["arg1"]}),
    );
    assert_eq!(e.code, McpErrorCode::InvalidParams);
    assert_eq!(e.message, "bad shape");
    assert!(e.data.is_some());
    assert_eq!(e.data.as_ref().unwrap()["missing"][0], "arg1");
}

#[test]
fn to_jsonrpc_error_extracts_numeric_code_message_and_data() {
    let e = ToolCallError::with_data(
        McpErrorCode::RateLimited,
        "slow down",
        json!({"retry_after_ms": 1500}),
    );
    let r = e.to_jsonrpc_error();
    assert_eq!(r.code, -32006, "RateLimited numeric code MUST be -32006");
    assert_eq!(r.message, "slow down");
    assert!(r.data.is_some());
    assert_eq!(r.data.unwrap()["retry_after_ms"], 1500);
}

#[test]
fn to_jsonrpc_error_passes_through_none_data() {
    let e = ToolCallError::new(McpErrorCode::InternalError, "oops");
    let r = e.to_jsonrpc_error();
    assert_eq!(r.code, -32603);
    assert!(r.data.is_none());
}

#[test]
fn tool_call_error_display_is_bracketed_code_then_message() {
    let e = ToolCallError::new(McpErrorCode::ToolNotFound, "no such tool");
    let s = format!("{e}");
    // Display passes through McpErrorCode's Display: "{message} ({code})".
    // Then ToolCallError prepends "[{}] {}", so the final form is
    // "[Tool not found (-32001)] no such tool".
    assert_eq!(
        s, "[Tool not found (-32001)] no such tool",
        "ToolCallError Display MUST be '[{{McpErrorCode-Display}}] {{message}}'"
    );
}

// ─── build_error_response ─────────────────────────────────────────

#[test]
fn build_error_response_sets_jsonrpc_2_0_and_preserves_id() {
    let r = build_error_response(json!(7), McpErrorCode::ToolNotFound, "no");
    assert_eq!(r.jsonrpc, "2.0");
    assert_eq!(r.id, json!(7));
    assert_eq!(r.error.code, -32001, "ToolNotFound = -32001");
    assert_eq!(r.error.message, "no");
    assert!(r.error.data.is_none());
}

#[test]
fn build_error_response_handles_string_id() {
    let r = build_error_response(json!("req-abc"), McpErrorCode::InvalidParams, "bad");
    assert_eq!(r.id, json!("req-abc"));
    assert_eq!(r.error.code, -32602);
}

#[test]
fn build_error_response_with_data_includes_payload() {
    let r = build_error_response_with_data(
        json!(1),
        McpErrorCode::ToolExecutionError,
        "boom",
        json!({"trace": ["a", "b"]}),
    );
    assert_eq!(r.jsonrpc, "2.0");
    assert_eq!(r.id, json!(1));
    assert_eq!(r.error.code, -32002);
    assert_eq!(r.error.message, "boom");
    assert!(r.error.data.is_some());
    assert_eq!(r.error.data.as_ref().unwrap()["trace"][0], "a");
}

#[test]
fn build_error_response_serialized_form_matches_jsonrpc_2_0_envelope() {
    let r = build_error_response(json!(99), McpErrorCode::PermissionDenied, "nope");
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 99);
    assert_eq!(v["error"]["code"], -32005);
    assert_eq!(v["error"]["message"], "nope");
    assert!(v["error"].get("data").is_none()); // None → omitted.
}

#[test]
fn build_error_response_with_data_serializes_data_field() {
    let r = build_error_response_with_data(
        json!(2),
        McpErrorCode::AuthenticationRequired,
        "auth needed",
        json!({"realm": "host"}),
    );
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(v["error"]["code"], -32004);
    assert_eq!(v["error"]["data"]["realm"], "host");
}
