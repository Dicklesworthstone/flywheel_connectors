//! Structured logging with JSON output and sensitive data redaction.

use std::fmt as std_fmt;

use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    prelude::*,
};

#[cfg(feature = "otlp")]
use crate::export::otlp_logger_provider;
use crate::{TelemetryConfig, TelemetryError};

/// Initialize the logging subsystem.
///
/// # Errors
/// Returns `TelemetryError::LoggingInit` if the subscriber cannot be installed.
pub fn init_logging(config: &TelemetryConfig) -> Result<(), TelemetryError> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    if config.json_logs {
        #[cfg(feature = "otlp")]
        {
            match otlp_logger_provider() {
                Some(otlp_layer) => subscriber
                    .with(
                        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                            &otlp_layer,
                        ),
                    )
                    .with(json_logging_layer())
                    .try_init()
                    .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?,
                None => subscriber
                    .with(json_logging_layer())
                    .try_init()
                    .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?,
            }
        }
        #[cfg(not(feature = "otlp"))]
        {
            subscriber
                .with(json_logging_layer())
                .try_init()
                .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
        }
    } else {
        #[cfg(feature = "otlp")]
        {
            match otlp_logger_provider() {
                Some(otlp_layer) => subscriber
                    .with(
                        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                            &otlp_layer,
                        ),
                    )
                    .with(pretty_logging_layer())
                    .try_init()
                    .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?,
                None => subscriber
                    .with(pretty_logging_layer())
                    .try_init()
                    .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?,
            }
        }
        #[cfg(not(feature = "otlp"))]
        {
            subscriber
                .with(pretty_logging_layer())
                .try_init()
                .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
        }
    }

    Ok(())
}

/// Diagnostics go to STDERR, leaving stdout free as a data channel.
///
/// `fmt::layer()` writes to stdout by default, which is the wrong stream for logs
/// and was the wrong stream here: MEASURED on the `fcp-host` binary, 16 structured
/// log lines arrived on stdout and 0 on stderr. That silently defeated every
/// consumer that reads diagnostics off stderr — `host_connector_integration`
/// spawns the host with `.stdout(Stdio::null())` and `.stderr(Stdio::piped())`, so
/// 12 tests timed out waiting for events that were being discarded (br-050la).
///
/// The convention is the repository's own, stated in README.md: "Stdout is
/// data-only. Every diagnostic (progress, warnings, retry notices, lint output)
/// goes to stderr." Keeping logs on stdout also means any binary later run as a
/// subprocess with a protocol on its stdout would have that channel corrupted by
/// its own logging — the exact hazard the convention exists to prevent.
///
/// This has never been otherwise: `git log -S with_writer` on this file is empty,
/// so the stdout default was inherited rather than chosen.
fn json_logging_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fmt::layer()
        .with_writer(std::io::stderr)
        .json()
        // Event fields at the TOP level, not nested under `"fields"`.
        //
        // `.json()` alone nests every custom field, so a line reads
        // `{"level":..,"fields":{"message":..,"event":"invoke_request"},..}`. Every
        // consumer in this repo reads them flat — README documents the per-event
        // schema as `timestamp`, `level`, `target`, `trace_id`/`span_id`,
        // `connector_id`, `audit_seq`, `message` plus event-specific fields, all as
        // peers — and `host_connector_integration`'s log matcher looks up
        // `entry["event"]` directly.
        //
        // Nesting is why 12 of those tests timed out even once the stream was
        // fixed: MEASURED, every event they waited for WAS emitted, so the events
        // were never missing — they were one level deeper than anything reading
        // them looked (br-050la).
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
}

/// Same stderr discipline as [`json_logging_layer`]; see its comment.
fn pretty_logging_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
}

const MAX_REDACTION_DEPTH: usize = 128;

/// Redact sensitive fields from a JSON value.
#[must_use]
pub fn redact_sensitive(value: &serde_json::Value, fields: &[String]) -> serde_json::Value {
    redact_sensitive_with_depth(value, fields, 0)
}

fn redact_sensitive_with_depth(
    value: &serde_json::Value,
    fields: &[String],
    depth: usize,
) -> serde_json::Value {
    if depth > MAX_REDACTION_DEPTH {
        return serde_json::Value::String("[MAX_DEPTH_EXCEEDED]".to_string());
    }

    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                if fields
                    .iter()
                    .any(|f| key.to_lowercase().contains(&f.to_lowercase()))
                {
                    result.insert(
                        key.clone(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                } else {
                    result.insert(
                        key.clone(),
                        redact_sensitive_with_depth(val, fields, depth + 1),
                    );
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_sensitive_with_depth(v, fields, depth + 1))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Escape control characters so attacker-controlled values cannot inject
/// multi-line or terminal-control sequences into pretty span/log output.
#[must_use]
pub fn sanitize_log_value(value: &impl std_fmt::Display) -> String {
    let rendered = value.to_string();
    let mut sanitized = String::with_capacity(rendered.len());

    for ch in rendered.chars() {
        if ch.is_control() {
            sanitized.extend(ch.escape_default());
        } else {
            sanitized.push(ch);
        }
    }

    sanitized
}

/// Log a structured event with automatic field injection.
#[macro_export]
macro_rules! log_event {
    ($level:ident, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::$level!(
            message = %$crate::sanitize_log_value(&$message),
            $($key = %$crate::sanitize_log_value(&$value),)*
        );
    };
}

/// Log an error with context.
#[macro_export]
macro_rules! log_error {
    ($err:expr, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::error!(
            error = %$crate::sanitize_log_value(&$err),
            error_type = %std::any::type_name_of_val(&$err),
            message = %$crate::sanitize_log_value(&$message),
            $($key = %$crate::sanitize_log_value(&$value),)*
        );
    };
}

/// Log a request/response pair.
pub fn log_request_response(
    operation: &str,
    request: &serde_json::Value,
    response: &serde_json::Value,
    duration_ms: u64,
    success: bool,
) {
    // Substring-matched against JSON field names. Keep this list
    // aligned with the sensitive-header allowlist in
    // `fcp_webhook::provider::is_sensitive_header_name` and the PII
    // conventions codified by connectors. Adding a field here is
    // backward-compatible: worst case it hides a value that was
    // previously being logged.
    let redact_fields = vec![
        "password".to_string(),
        "api_key".to_string(),
        // Hyphenated form: JSON maps surfaced from HTTP headers preserve
        // "X-API-Key" / "X-Api-Key" as-is — underscore-only substrings
        // silently miss them.
        "api-key".to_string(),
        "apikey".to_string(),
        // AWS-style: access_key / access_key_id / aws_access_key_id never
        // contained any of the prior substrings and were being logged raw.
        "access_key".to_string(),
        "access-key".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "authorization".to_string(),
        "bearer".to_string(),
        "cookie".to_string(),
        "credential".to_string(),
        "private_key".to_string(),
        // Hyphenated form for headers such as "X-Private-Key".
        "private-key".to_string(),
        "session".to_string(),
    ];

    let redacted_request = redact_sensitive(request, &redact_fields);
    let redacted_response = redact_sensitive(response, &redact_fields);
    let operation = sanitize_log_value(&operation);
    let request = sanitize_log_value(&redacted_request);
    let response = sanitize_log_value(&redacted_response);

    if success {
        tracing::info!(
            operation = operation,
            request = %request,
            response = %response,
            duration_ms = duration_ms,
            "Request completed successfully"
        );
    } else {
        tracing::warn!(
            operation = operation,
            request = %request,
            response = %response,
            duration_ms = duration_ms,
            "Request completed with error"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_sensitive() {
        let value = json!({
            "user": "john",
            "password": "secret123",
            "api_key": "key-abc",
            "data": {
                "token": "tok-xyz",
                "name": "test"
            }
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "password".to_string(),
                "api_key".to_string(),
                "token".to_string(),
            ],
        );

        assert_eq!(redacted["user"], "john");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["data"]["token"], "[REDACTED]");
        assert_eq!(redacted["data"]["name"], "test");
    }

    #[test]
    fn test_redact_nested_array() {
        let value = json!({
            "users": [
                {"name": "john", "password": "pass1"},
                {"name": "jane", "password": "pass2"}
            ]
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["users"][0]["name"], "john");
        assert_eq!(redacted["users"][0]["password"], "[REDACTED]");
        assert_eq!(redacted["users"][1]["name"], "jane");
        assert_eq!(redacted["users"][1]["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_case_insensitive() {
        let value = json!({
            "PASSWORD": "secret1",
            "Password": "secret2",
            "password": "secret3",
            "user_password": "secret4"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // All variations should be redacted due to case-insensitive contains check
        assert_eq!(redacted["PASSWORD"], "[REDACTED]");
        assert_eq!(redacted["Password"], "[REDACTED]");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["user_password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_partial_match() {
        let value = json!({
            "api_key_id": "key-123",
            "secret_token": "tok-456",
            "authorization_header": "Bearer xyz"
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "key".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        );

        assert_eq!(redacted["api_key_id"], "[REDACTED]");
        assert_eq!(redacted["secret_token"], "[REDACTED]");
        assert_eq!(redacted["authorization_header"], "[REDACTED]");
    }

    #[test]
    fn test_redact_deeply_nested() {
        let value = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "password": "deep-secret"
                        }
                    }
                }
            }
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(
            redacted["level1"]["level2"]["level3"]["level4"]["password"],
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_array_of_arrays() {
        let value = json!({
            "matrix": [
                [{"password": "p1"}, {"password": "p2"}],
                [{"password": "p3"}, {"safe": "data"}]
            ]
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["matrix"][0][0]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][0][1]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][1][0]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][1][1]["safe"], "data");
    }

    #[test]
    fn test_redact_preserves_primitives() {
        let value = json!({
            "string": "hello",
            "number": 42,
            "float": 1.234,
            "boolean": true,
            "null_value": null
        });

        let redacted = redact_sensitive(&value, &["nonexistent".to_string()]);

        assert_eq!(redacted["string"], "hello");
        assert_eq!(redacted["number"], 42);
        assert_eq!(redacted["float"], 1.234);
        assert_eq!(redacted["boolean"], true);
        assert!(redacted["null_value"].is_null());
    }

    #[test]
    fn test_redact_empty_object() {
        let value = json!({});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!({}));
    }

    #[test]
    fn test_redact_empty_array() {
        let value = json!([]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!([]));
    }

    #[test]
    fn test_redact_no_fields() {
        let value = json!({"safe": "data", "also_safe": "more data"});
        let redacted = redact_sensitive(&value, &[]);
        assert_eq!(redacted["safe"], "data");
        assert_eq!(redacted["also_safe"], "more data");
    }

    #[test]
    fn test_redact_multiple_sensitive_fields() {
        let value = json!({
            "credentials": {
                "password": "pass123",
                "api_key": "key456",
                "secret": "sec789",
                "token": "tok012",
                "authorization": "auth345"
            }
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "password".to_string(),
                "api_key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        );

        assert_eq!(redacted["credentials"]["password"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["api_key"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["secret"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["token"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["authorization"], "[REDACTED]");
    }

    #[test]
    fn test_redact_primitive_value() {
        // Redacting a primitive should return it unchanged
        let value = json!("just a string");
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, "just a string");

        let number = json!(42);
        let redacted_num = redact_sensitive(&number, &["password".to_string()]);
        assert_eq!(redacted_num, 42);
    }

    #[test]
    fn test_redact_array_of_primitives() {
        let value = json!(["one", "two", "three"]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!(["one", "two", "three"]));
    }

    #[test]
    fn test_redact_mixed_array() {
        let value = json!([
            "string",
            42,
            {"password": "secret"},
            null,
            true
        ]);

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted[0], "string");
        assert_eq!(redacted[1], 42);
        assert_eq!(redacted[2]["password"], "[REDACTED]");
        assert!(redacted[3].is_null());
        assert_eq!(redacted[4], true);
    }

    #[test]
    fn test_redact_fcp_standard_fields() {
        // Test with the default FCP redaction fields
        let fcp_redact_fields = vec![
            "password".to_string(),
            "api_key".to_string(),
            "secret".to_string(),
            "token".to_string(),
            "authorization".to_string(),
        ];

        let value = json!({
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                },
                "body": {
                    "user": "admin",
                    "password": "admin123",
                    "api_key": "sk-1234567890"
                }
            },
            "response": {
                "access_token": "at_abc123",
                "refresh_token": "rt_xyz789"
            }
        });

        let redacted = redact_sensitive(&value, &fcp_redact_fields);

        // Headers with Authorization
        assert_eq!(
            redacted["request"]["headers"]["Authorization"],
            "[REDACTED]"
        );
        // Body fields
        assert_eq!(redacted["request"]["body"]["user"], "admin");
        assert_eq!(redacted["request"]["body"]["password"], "[REDACTED]");
        assert_eq!(redacted["request"]["body"]["api_key"], "[REDACTED]");
        // Response tokens
        assert_eq!(redacted["response"]["access_token"], "[REDACTED]");
        assert_eq!(redacted["response"]["refresh_token"], "[REDACTED]");
    }

    // ============ Unicode and edge case tests ============

    #[test]
    fn test_redact_unicode_field_names() {
        let value = json!({
            "密码": "secret123",  // Chinese for "password"
            "パスワード": "secret456",  // Japanese for "password"
            "пароль": "secret789",  // Russian for "password"
            "normal_field": "visible"
        });

        // Should not redact these since our patterns are ASCII
        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["密码"], "secret123");
        assert_eq!(redacted["パスワード"], "secret456");
        assert_eq!(redacted["пароль"], "secret789");
        assert_eq!(redacted["normal_field"], "visible");
    }

    #[test]
    fn test_redact_unicode_field_values() {
        let value = json!({
            "password": "密码🔐secure",  // Unicode value with emoji
            "message": "Hello 世界 🌍"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["message"], "Hello 世界 🌍");
    }

    #[test]
    fn test_redact_empty_string_value() {
        let value = json!({
            "password": "",
            "api_key": ""
        });

        let redacted = redact_sensitive(&value, &["password".to_string(), "api_key".to_string()]);

        // Empty strings in sensitive fields should still be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
    }

    #[test]
    fn test_redact_numeric_sensitive_values() {
        let value = json!({
            "password": 12345,  // Numeric password (bad practice but possible)
            "token": 999_999,
            "user_id": 42
        });

        let redacted = redact_sensitive(&value, &["password".to_string(), "token".to_string()]);

        // Numeric values in sensitive fields should be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["user_id"], 42);
    }

    #[test]
    fn test_redact_boolean_sensitive_values() {
        let value = json!({
            "has_secret": true,  // Field name contains "secret"
            "is_active": true
        });

        let redacted = redact_sensitive(&value, &["secret".to_string()]);

        assert_eq!(redacted["has_secret"], "[REDACTED]");
        assert_eq!(redacted["is_active"], true);
    }

    #[test]
    fn test_redact_null_sensitive_values() {
        let value = json!({
            "password": null,
            "name": null
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // Null values in sensitive fields should be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert!(redacted["name"].is_null());
    }

    #[test]
    fn test_redact_object_in_sensitive_field() {
        let value = json!({
            "secret_config": {
                "key": "value",
                "nested": "data"
            },
            "public_config": {
                "setting": "visible"
            }
        });

        let redacted = redact_sensitive(&value, &["secret".to_string()]);

        // Entire object should be redacted when field name matches
        assert_eq!(redacted["secret_config"], "[REDACTED]");
        assert_eq!(redacted["public_config"]["setting"], "visible");
    }

    #[test]
    fn test_redact_array_in_sensitive_field() {
        let value = json!({
            "api_keys": ["key1", "key2", "key3"],
            "names": ["alice", "bob"]
        });

        let redacted = redact_sensitive(&value, &["key".to_string()]);

        // Entire array should be redacted when field name matches
        assert_eq!(redacted["api_keys"], "[REDACTED]");
        assert_eq!(redacted["names"], json!(["alice", "bob"]));
    }

    #[test]
    fn test_redact_very_long_field_name() {
        let long_key = format!("password_{}", "x".repeat(1000));
        let value = json!({
            long_key.clone(): "secret"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted[&long_key], "[REDACTED]");
    }

    #[test]
    fn test_redact_very_long_value() {
        let long_value = "secret".repeat(10000);
        let value = json!({
            "password": long_value
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_special_json_characters() {
        let value = json!({
            "password": "secret\"with\\special\nchars\t",
            "message": "normal\"text"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["message"], "normal\"text");
    }

    #[test]
    fn test_redact_preserves_object_key_order() {
        // Note: serde_json uses BTreeMap internally, so order is alphabetical
        let value = json!({
            "zebra": "last",
            "apple": "first",
            "password": "secret",
            "middle": "middle"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // All keys should still be present
        assert!(redacted.get("zebra").is_some());
        assert!(redacted.get("apple").is_some());
        assert!(redacted.get("middle").is_some());
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_with_regex_like_patterns() {
        // Field patterns that look like regex but should be treated literally
        let value = json!({
            "pass.*word": "should_not_match",
            "password": "should_match"
        });

        // The pattern should match literally, not as regex
        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["pass.*word"], "should_not_match");
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_concurrent_field_matches() {
        // Field that matches multiple patterns
        let value = json!({
            "api_key_token_secret": "ultra_sensitive"
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "api".to_string(),
                "key".to_string(),
                "token".to_string(),
                "secret".to_string(),
            ],
        );

        // Should be redacted (matches all patterns, but only needs one)
        assert_eq!(redacted["api_key_token_secret"], "[REDACTED]");
    }

    #[test]
    fn test_redact_whitespace_in_field_names() {
        let value = json!({
            "pass word": "with space",
            "password": "no space"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // "pass word" should not match "password" pattern
        assert_eq!(redacted["pass word"], "with space");
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_max_depth_exceeded() {
        // Build a deeply nested structure exceeding MAX_REDACTION_DEPTH
        let mut value = json!({"password": "deep"});
        for _ in 0..150 {
            value = json!({"nested": value});
        }
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        let redacted_str = serde_json::to_string(&redacted).unwrap();
        assert!(redacted_str.contains("[MAX_DEPTH_EXCEEDED]"));
    }

    #[test]
    fn test_redact_single_key_object() {
        let value = json!({"password": "secret"});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_with_empty_field_list() {
        let value = json!({"password": "not_redacted"});
        let redacted = redact_sensitive(&value, &[]);
        assert_eq!(redacted["password"], "not_redacted");
    }

    #[test]
    fn test_redact_null_top_level() {
        let value = json!(null);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert!(redacted.is_null());
    }

    #[test]
    fn test_redact_boolean_top_level() {
        let value = json!(true);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, true);
    }

    #[test]
    fn test_redact_number_top_level() {
        let value = json!(42);
        let redacted = redact_sensitive(&value, &["anything".to_string()]);
        assert_eq!(redacted, 42);
    }

    #[test]
    fn test_redact_large_array_of_objects() {
        let arr: Vec<serde_json::Value> = (0..100)
            .map(|i| json!({"id": i, "token": format!("tok_{i}")}))
            .collect();
        let value = serde_json::Value::Array(arr);
        let redacted = redact_sensitive(&value, &["token".to_string()]);
        let arr = redacted.as_array().unwrap();
        assert_eq!(arr.len(), 100);
        for item in arr {
            assert_eq!(item["token"], "[REDACTED]");
        }
    }

    #[test]
    fn test_redact_preserves_number_types() {
        let value = json!({
            "integer": 42,
            "negative": -7,
            "float_val": 1.23,
            "zero": 0
        });
        let redacted = redact_sensitive(&value, &["nonexistent".to_string()]);
        assert_eq!(redacted["integer"], 42);
        assert_eq!(redacted["negative"], -7);
        assert_eq!(redacted["zero"], 0);
    }

    #[test]
    fn test_redact_empty_string_field_name() {
        let value = json!({"": "empty_key_value"});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted[""], "empty_key_value");
    }

    #[test]
    fn test_redact_duplicate_fields_list() {
        let value = json!({"password": "secret"});
        let redacted = redact_sensitive(
            &value,
            &[
                "password".to_string(),
                "password".to_string(),
                "password".to_string(),
            ],
        );
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_nested_array_in_object() {
        let value = json!({
            "data": [
                {"safe": "visible"},
                {"api_key": "hidden"}
            ]
        });
        let redacted = redact_sensitive(&value, &["api_key".to_string()]);
        assert_eq!(redacted["data"][0]["safe"], "visible");
        assert_eq!(redacted["data"][1]["api_key"], "[REDACTED]");
    }

    #[test]
    fn test_redact_top_level_string() {
        let value = json!("just a raw string");
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!("just a raw string"));
    }

    #[test]
    fn test_redact_float_top_level() {
        let value = json!(1.5);
        let redacted = redact_sensitive(&value, &["anything".to_string()]);
        assert_eq!(redacted, json!(1.5));
    }

    #[test]
    fn test_redact_nested_objects_depth_three() {
        let value = json!({
            "a": {
                "b": {
                    "c": {
                        "secret": "hidden",
                        "public": "visible"
                    }
                }
            }
        });
        let redacted = redact_sensitive(&value, &["secret".to_string()]);
        assert_eq!(redacted["a"]["b"]["c"]["secret"], "[REDACTED]");
        assert_eq!(redacted["a"]["b"]["c"]["public"], "visible");
    }

    #[test]
    fn test_redact_empty_array_in_object() {
        let value = json!({"items": [], "password": "hidden"});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted["items"], json!([]));
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_mixed_types_in_object() {
        let value = json!({
            "str_val": "hello",
            "num_val": 42,
            "bool_val": true,
            "null_val": null,
            "arr_val": [1, 2, 3],
            "obj_val": {"nested": "yes"},
            "secret": "redact_me"
        });
        let redacted = redact_sensitive(&value, &["secret".to_string()]);
        assert_eq!(redacted["str_val"], "hello");
        assert_eq!(redacted["num_val"], 42);
        assert_eq!(redacted["bool_val"], true);
        assert!(redacted["null_val"].is_null());
        assert_eq!(redacted["arr_val"], json!([1, 2, 3]));
        assert_eq!(redacted["obj_val"]["nested"], "yes");
        assert_eq!(redacted["secret"], "[REDACTED]");
    }

    #[test]
    fn test_redact_single_element_array() {
        let value = json!([{"password": "secret"}]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted[0]["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_with_many_fields() {
        let fields: Vec<String> = (0..50).map(|i| format!("field_{i}")).collect();
        let mut map = serde_json::Map::new();
        for f in &fields {
            map.insert(f.clone(), json!("value"));
        }
        map.insert("safe_field".to_string(), json!("visible"));
        let value = serde_json::Value::Object(map);
        let redacted = redact_sensitive(&value, &fields);
        for f in &fields {
            assert_eq!(redacted[f], "[REDACTED]");
        }
        assert_eq!(redacted["safe_field"], "visible");
    }

    #[test]
    fn test_redact_deeply_nested_array() {
        let value = json!([[[[{"password": "deep"}]]]]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted[0][0][0][0]["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_preserves_empty_nested_object() {
        let value = json!({"outer": {"inner": {}}});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted["outer"]["inner"], json!({}));
    }

    #[test]
    fn sanitize_log_value_escapes_control_characters() {
        let sanitized = sanitize_log_value(&"line one\nline two\t\x1b[31m");

        assert_eq!(sanitized, "line one\\nline two\\t\\u{1b}[31m");
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\t'));
        assert!(!sanitized.contains('\u{1b}'));
    }

    #[test]
    fn sanitize_log_value_preserves_plain_text() {
        let sanitized = sanitize_log_value(&"connector:stripe");
        assert_eq!(sanitized, "connector:stripe");
    }

    /// Regression: the default redact list used by `log_request_response`
    /// previously only covered `password`/`api_key`/`secret`/`token`/`authorization`.
    /// Extending the list adds defense-in-depth against common PII/credential
    /// field names that leaked through under the old set. This test exercises
    /// the expanded list via `log_request_response`'s internal vec by calling
    /// `redact_sensitive` with the same list.
    #[test]
    fn test_redact_covers_expanded_credential_fields() {
        let expanded = vec![
            "password".to_string(),
            "api_key".to_string(),
            "apikey".to_string(),
            "secret".to_string(),
            "token".to_string(),
            "authorization".to_string(),
            "bearer".to_string(),
            "cookie".to_string(),
            "credential".to_string(),
            "private_key".to_string(),
            "session".to_string(),
        ];

        let value = json!({
            "bearer_token": "bearer_xyz",
            "cookie": "sid=123",
            "credentials": {"username": "u", "password": "p"},
            "private_key_pem": "-----BEGIN...",
            "session_id": "sess_abc",
            "api_key_raw": "key_xxx",
            "apiKey": "k2",
            // A field that must NOT be redacted — proves we didn't go too wide.
            "user_name": "alice",
        });

        let redacted = redact_sensitive(&value, &expanded);

        // All sensitive fields are redacted (substring match is permissive).
        assert_eq!(redacted["bearer_token"], "[REDACTED]", "bearer_token");
        assert_eq!(redacted["cookie"], "[REDACTED]", "cookie");
        assert_eq!(
            redacted["credentials"], "[REDACTED]",
            "credentials (whole subtree)"
        );
        assert_eq!(redacted["private_key_pem"], "[REDACTED]", "private_key_pem");
        assert_eq!(redacted["session_id"], "[REDACTED]", "session_id");
        assert_eq!(redacted["api_key_raw"], "[REDACTED]", "api_key_raw");
        assert_eq!(
            redacted["apiKey"], "[REDACTED]",
            "apiKey (case-insensitive)"
        );

        // Non-sensitive field passes through.
        assert_eq!(redacted["user_name"], "alice", "plain user_name untouched");
    }

    /// Regression: JSON surfaced from HTTP headers keeps the hyphenated
    /// form (e.g. `X-API-Key`). An underscore-only substring list
    /// (`api_key`) missed the header form entirely, so `X-API-Key: secret`
    /// was being logged in the clear. Also verify AWS-style
    /// `aws_access_key_id` is now caught. The `user_name` field must
    /// still pass through to prove the additions didn't go over-broad.
    #[test]
    fn test_redact_catches_hyphenated_and_access_key_variants() {
        let expanded = vec![
            "password".to_string(),
            "api_key".to_string(),
            "api-key".to_string(),
            "apikey".to_string(),
            "access_key".to_string(),
            "access-key".to_string(),
            "secret".to_string(),
            "token".to_string(),
            "authorization".to_string(),
            "bearer".to_string(),
            "cookie".to_string(),
            "credential".to_string(),
            "private_key".to_string(),
            "private-key".to_string(),
            "session".to_string(),
        ];

        let value = json!({
            "X-API-Key": "k_hyphenated",
            "X-Api-Key": "k_hyphenated_mixed",
            "aws_access_key_id": "AKIA_example_value",
            "access_key": "raw_key",
            "X-Private-Key": "-----BEGIN_example",
            "user_name": "alice",
        });

        let redacted = redact_sensitive(&value, &expanded);

        assert_eq!(redacted["X-API-Key"], "[REDACTED]", "X-API-Key");
        assert_eq!(redacted["X-Api-Key"], "[REDACTED]", "X-Api-Key");
        assert_eq!(
            redacted["aws_access_key_id"], "[REDACTED]",
            "aws_access_key_id"
        );
        assert_eq!(redacted["access_key"], "[REDACTED]", "access_key");
        assert_eq!(redacted["X-Private-Key"], "[REDACTED]", "X-Private-Key");
        assert_eq!(redacted["user_name"], "alice", "user_name must pass");
    }
}
