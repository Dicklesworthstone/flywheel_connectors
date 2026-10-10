//! Preserve MCP tool-level failure semantics at the FCP invocation boundary.
//!
//! `isError` belongs to CallToolResult, not to its JSON-RPC envelope. Failure
//! content must reach the caller for diagnosis, but must not become an automatic
//! retry, a session-recovery signal, or a successful workflow dependency.

use std::fmt;

use fcp_prelude::FcpError;
use serde_json::Value;

use super::{McpBridgeError, McpBridgeResult};

/// A tool's reported execution failure, including its complete result payload.
///
/// Diagnostic access is explicit: Debug and Display do not print tool output.
/// The FCP error message carries the JSON result so an agent can inspect text,
/// structured content, resource links, and extension fields without data loss.
/// This is not proof that no side effect occurred before the reported failure.
pub struct ToolExecutionFailure {
    result: Value,
}

impl ToolExecutionFailure {
    /// Inspect the original CallToolResult without copying it.
    #[must_use]
    pub const fn result(&self) -> &Value {
        &self.result
    }

    /// Recover the original CallToolResult, including extension fields.
    #[must_use]
    pub fn into_result(self) -> Value {
        self.result
    }

    pub(super) fn to_fcp_error(&self) -> FcpError {
        FcpError::External {
            service: "mcp-bridge".into(),
            // The transport bounds this payload before outcome classification.
            // Preserve diagnostics for the authorized caller, not in logs.
            message: format!("MCP tool execution failed (isError=true): {}", self.result),
            status_code: None,
            retryable: false,
            retry_after: None,
        }
    }
}

impl fmt::Debug for ToolExecutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutionFailure")
            .field("result", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ToolExecutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP tool execution failed (isError=true)")
    }
}

impl std::error::Error for ToolExecutionFailure {}

/// Check only the tool outcome, not the entire provider-defined result schema.
/// Successful payloads are returned verbatim. Other methods may legitimately
/// return a field named `isError`; it has no tool-execution meaning there.
pub(crate) fn check_tool_outcome(method: &str, result: Value) -> McpBridgeResult<Value> {
    if method != "tools/call" {
        return Ok(result);
    }
    let invalid = || {
        McpBridgeError::Json(<serde_json::Error as serde::de::Error>::custom(
            "invalid MCP tool result: expected an object with an optional boolean isError",
        ))
    };
    let object = result.as_object().ok_or_else(invalid)?;
    match object.get("isError") {
        None | Some(Value::Bool(false)) => Ok(result),
        Some(Value::Bool(true)) => Err(ToolExecutionFailure { result }.into()),
        Some(_) => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn failure_result() -> Value {
        json!({
            "isError": true,
            "content": [{"type": "text", "text": "session expired after partial write"}],
            "structuredContent": {"written": 1, "retry_after_ms": 0},
            "_meta": {"provider": "secret-result-marker"},
            "extension": {"opaque": [1, null, true]}
        })
    }

    #[test]
    fn reported_failure_retains_the_entire_result_without_automatic_replay() {
        let result = failure_result();
        let error = check_tool_outcome("tools/call", result.clone()).unwrap_err();
        assert!(!error.is_retryable());
        assert!(!error.replay_is_safe());
        assert!(!error.is_session_expired());
        assert!(error.retry_after().is_none());
        let McpBridgeError::ToolExecution(failure) = error else {
            panic!("expected a tool execution failure, not a fabricated JSON-RPC error");
        };
        assert_eq!(failure.result(), &result);
        assert_eq!(failure.into_result(), result);
    }

    #[test]
    fn fcp_error_retains_diagnostics_and_never_claims_transport_failure_or_retry() {
        let result = failure_result();
        let error = check_tool_outcome("tools/call", result.clone()).unwrap_err();
        let FcpError::External {
            service, message, status_code, retryable, retry_after,
        } = error.to_fcp_error() else {
            panic!("expected a failed external operation");
        };
        assert_eq!(service, "mcp-bridge");
        assert!(status_code.is_none());
        assert!(!retryable);
        assert!(retry_after.is_none());
        let encoded = message.strip_prefix("MCP tool execution failed (isError=true): ").unwrap();
        assert_eq!(serde_json::from_str::<Value>(encoded).unwrap(), result);
    }

    #[test]
    fn debug_and_display_do_not_leak_tool_diagnostics() {
        let error = check_tool_outcome("tools/call", failure_result()).unwrap_err();
        for text in [format!("{error:?}"), error.to_string()] {
            assert!(!text.contains("secret-result-marker"));
            assert!(!text.contains("partial write"));
        }
    }

    #[test]
    fn absent_or_false_outcome_preserves_success_payload_verbatim() {
        for result in [
            json!({"content": [], "structuredContent": {"isError": true}, "extra": null}),
            json!({"isError": false, "content": [{"type": "resource_link", "uri": "urn:result"}]}),
        ] {
            assert_eq!(check_tool_outcome("tools/call", result.clone()).unwrap(), result);
        }
    }

    #[test]
    fn outcome_flags_are_not_coerced_and_invalid_data_is_not_echoed() {
        for flag in [Value::Null, json!("secret-result-marker"), json!(0), json!([]), json!({})] {
            let error = check_tool_outcome("tools/call", json!({"isError": flag})).unwrap_err();
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("secret-result-marker"));
        }
    }

    #[test]
    fn non_object_tool_results_are_not_successful_operations() {
        for result in [Value::Null, json!([]), json!(true), json!(42), json!("secret-result-marker")] {
            let error = check_tool_outcome("tools/call", result).unwrap_err();
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("secret-result-marker"));
        }
    }

    #[test]
    fn other_methods_keep_their_own_result_semantics() {
        for method in ["resources/read", "tools/list", "prompts/get", "custom/method"] {
            let result = failure_result();
            assert_eq!(check_tool_outcome(method, result.clone()).unwrap(), result);
        }
    }
}
