//! MCP argument completion for prompt names and resource URI templates.
//!
//! Protocol: MCP 2025-06-18, server/utilities/completion. Suggestions are opaque
//! data ranked by the server. Never follow a suggested URI, render a prompt,
//! invoke a tool, or select a suggestion as a side effect of completion.

use serde_json::Value;

use super::{McpBridgeError, McpBridgeResult, McpClient, transport};

const MAX_COMPLETION_VALUES: usize = 100;

impl McpClient {
    /// Complete one argument of an MCP prompt or resource URI template.
    ///
    /// `params` is the MCP CompleteRequest parameter object: `ref` selects a
    /// `ref/prompt` by `name` or a `ref/resource` by `uri`; `argument` contains
    /// its `name` and current string `value`. An empty prefix is valid. Optional
    /// `context.arguments` supplies already-resolved string-valued arguments.
    /// Extension metadata and the server's suggestion order are preserved.
    ///
    /// Initialization, capability negotiation, read retries and expired-session
    /// recovery share the existing request deadline and bounded HTTP transport.
    /// A replacement session must independently negotiate completions. Results
    /// contain at most 100 strings; malformed results are terminal errors, never
    /// fabricated empty success or a truncated partial result.
    ///
    /// # Errors
    /// Rejects malformed parameters before I/O, unnegotiated completions,
    /// invalid response envelopes and ordinary managed MCP transport failures.
    pub async fn completion_complete(&self, params: Value) -> McpBridgeResult<Value> {
        self.execute_session_rpc("completion/complete", params)
            .await
    }
}

pub(super) fn validate_request(params: &Value) -> McpBridgeResult<()> {
    let params = params.as_object().ok_or_else(invalid_params)?;
    let reference = params
        .get("ref")
        .and_then(Value::as_object)
        .ok_or_else(invalid_params)?;
    let target = match reference.get("type").and_then(Value::as_str) {
        Some("ref/prompt") => reference.get("name"),
        Some("ref/resource") => reference.get("uri"),
        _ => return Err(invalid_params()),
    };
    if !target
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty())
    {
        return Err(invalid_params());
    }
    let argument = params
        .get("argument")
        .and_then(Value::as_object)
        .ok_or_else(invalid_params)?;
    if !argument
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty())
        || !argument.get("value").is_some_and(Value::is_string)
    {
        return Err(invalid_params());
    }
    if let Some(context) = params.get("context") {
        let context = context.as_object().ok_or_else(invalid_params)?;
        if let Some(arguments) = context.get("arguments") {
            let arguments = arguments.as_object().ok_or_else(invalid_params)?;
            if arguments
                .iter()
                .any(|(name, value)| name.is_empty() || !value.is_string())
            {
                return Err(invalid_params());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_response(result: Value) -> McpBridgeResult<Value> {
    let completion = result
        .get("completion")
        .and_then(Value::as_object)
        .ok_or_else(invalid_result)?;
    let values = completion
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(invalid_result)?;
    if values.len() > MAX_COMPLETION_VALUES || values.iter().any(|value| !value.is_string()) {
        return Err(invalid_result());
    }
    if let Some(total) = completion.get("total") {
        // JSON Schema integers can be encoded as 2 or 2.0. Only compare here;
        // retain the exact JSON number instead of coercing or rounding it.
        let valid = total
            .as_u64()
            .is_some_and(|total| total >= values.len() as u64)
            || total.as_f64().is_some_and(|total| {
                total.is_finite() && total.fract() == 0.0 && total >= values.len() as f64
            });
        if !valid {
            return Err(invalid_result());
        }
    }
    if completion
        .get("hasMore")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_result());
    }
    // Do not sort, deduplicate, trim, expand URI templates or fetch another
    // page. `hasMore` describes suggestions, not an MCP pagination cursor.
    Ok(result)
}

fn invalid_params() -> McpBridgeError {
    McpBridgeError::McpError {
        code: -32602,
        message: "Completion requires a prompt/resource reference, a named string argument, and optional string-valued context arguments".into(),
    }
}

fn invalid_result() -> McpBridgeError {
    transport::invalid_response("invalid MCP completion result")
}

#[cfg(test)]
mod tests;
