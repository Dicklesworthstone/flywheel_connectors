//! Managed MCP initialization, negotiated session authority, and recovery.
//!
//! Session publication follows the initialized notification, not just the
//! initialize response. A cancelled initializer leaves no half-ready state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::{AttemptOutcome, RetryLoop};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};

use super::{McpClient, transport};
use crate::error::{McpBridgeError, McpBridgeResult};
use crate::types::JsonRpcRequest;

pub(super) const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_SESSION_ID_BYTES: usize = 1024;

pub(super) struct McpSession {
    pub(super) id: Option<HeaderValue>,
    pub(super) initialization: Value,
}

impl McpSession {
    fn from_initialize(result: Value, id: Option<HeaderValue>) -> McpBridgeResult<Self> {
        if result.get("protocolVersion").and_then(Value::as_str) != Some(PROTOCOL_VERSION) {
            return Err(transport::invalid_response(
                "unsupported negotiated protocol version",
            ));
        }
        if !result.get("capabilities").is_some_and(Value::is_object)
            || !result.pointer("/serverInfo/name").is_some_and(Value::is_string)
            || !result.pointer("/serverInfo/version").is_some_and(Value::is_string)
        {
            return Err(transport::invalid_response("invalid initialize result"));
        }
        Ok(Self {
            id: validate_session_id(id)?,
            initialization: result,
        })
    }

    fn allows_method(&self, method: &str) -> bool {
        let capability = match method.split('/').next() {
            Some("tools") => "tools",
            Some("resources") => "resources",
            Some("prompts") => "prompts",
            _ => return true,
        };
        self.initialization["capabilities"]
            .get(capability)
            .is_some_and(Value::is_object)
    }
}

pub(super) fn validate_session_id(id: Option<HeaderValue>) -> McpBridgeResult<Option<HeaderValue>> {
    let Some(mut id) = id else {
        return Ok(None);
    };
    if id.as_bytes().is_empty()
        || id.as_bytes().len() > MAX_SESSION_ID_BYTES
        || !id.as_bytes().iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(transport::invalid_response("invalid MCP session header"));
    }
    id.set_sensitive(true);
    Ok(Some(id))
}

#[derive(Debug)]
pub(super) enum RpcFailure {
    // Only an HTTP 404 for an operation actually sent with a negotiated session
    // ID authorizes recovery. Error bodies and JSON-RPC messages never do.
    SessionExpired,
    Failed(McpBridgeError),
}

impl From<McpBridgeError> for RpcFailure {
    fn from(error: McpBridgeError) -> Self {
        Self::Failed(error)
    }
}

impl McpClient {
    /// Establish the MCP session and return the validated InitializeResult.
    /// Ordinary calls do this lazily; concurrent initializers share one exchange.
    pub async fn initialize(&self) -> McpBridgeResult<Value> {
        let context = self.runtime.request_context();
        let url = self.rpc_endpoint();
        context
            .run(async {
                self.ensure_session(&url)
                    .await
                    .map(|session| session.initialization.clone())
            })
            .await
            .map_err(McpBridgeError::from_async_error)?
    }

    async fn ensure_session(&self, url: &str) -> McpBridgeResult<Arc<McpSession>> {
        let mut state = self.session.lock().await;
        if let Some(session) = state.as_ref() {
            return Ok(Arc::clone(session));
        }
        // ID 0 is reserved for initialization; operation IDs begin at 1.
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 0,
            method: "initialize".into(),
            params: json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "fcp-mcp-bridge", "version": env!("CARGO_PKG_VERSION")}
            }),
        };
        let response = self
            .add_auth(self.client.post(url))
            .header("Accept", "application/json, text/event-stream")
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(self.handle_http_error(status, response).await);
        }
        let id = validate_session_id(response.headers().get("Mcp-Session-Id").cloned())?;
        let result = transport::read_rpc_response(response, 0, |reply| {
            self.send_server_reply(url, id.as_ref(), reply)
        })
        .await?;
        let session = Arc::new(McpSession::from_initialize(result, id)?);
        let mut notification = self
            .add_auth(self.client.post(url))
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        if let Some(id) = session.id.as_ref() {
            notification = notification.header("Mcp-Session-Id", id);
        }
        let response = notification.send().await?;
        if response.status() != reqwest::StatusCode::ACCEPTED {
            return Err(transport::invalid_response(
                "initialized notification was not accepted",
            ));
        }
        // No awaited work between publication and returning the session.
        *state = Some(Arc::clone(&session));
        Ok(session)
    }

    async fn invalidate_session(&self, expired: &Arc<McpSession>) {
        let mut state = self.session.lock().await;
        // An old in-flight 404 cannot revoke a replacement published by another
        // request, even if the server reused the same opaque session string.
        if state.as_ref().is_some_and(|current| Arc::ptr_eq(current, expired)) {
            *state = None;
        }
    }

    pub(super) async fn execute_session_rpc(
        &self,
        method: &str,
        params: Value,
    ) -> McpBridgeResult<Value> {
        if method.is_empty()
            || method == "initialize"
            || method.starts_with("notifications/")
            || !params.is_object()
        {
            return Err(transport::invalid_response(
                "use managed initialization and object-valued RPC params",
            ));
        }
        let replay_safe = matches!(
            method,
            "tools/list" | "resources/list" | "resources/read" | "prompts/list" | "ping"
        );
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: self.next_id(),
            method: method.into(),
            params,
        };
        let url = self.rpc_endpoint();
        let context = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let recovered = AtomicBool::new(false);
        RetryLoop::execute(&context, &policy, |attempt| {
            let url = &url;
            let request = &request;
            let recovered = &recovered;
            async move {
                let session = match self.ensure_session(url).await {
                    Ok(session) => session,
                    // No operation was dispatched during a failed initialization.
                    Err(error) if error.is_retryable() => {
                        return AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        };
                    }
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                if !session.allows_method(method) {
                    return AttemptOutcome::Terminal(transport::invalid_response(
                        "server did not negotiate the requested capability",
                    ));
                }
                match self.rpc_call_once(url, request, Some(&session)).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(RpcFailure::SessionExpired) => {
                        self.invalidate_session(&session).await;
                        let error = McpBridgeError::NotFound {
                            resource: "negotiated MCP session no longer exists".into(),
                        };
                        if recovered.swap(true, Ordering::Relaxed) {
                            return AttemptOutcome::Terminal(error);
                        }
                        self.session_expired_retry_count.fetch_add(1, Ordering::Relaxed);
                        AttemptOutcome::Retryable {
                            error,
                            retry_after: Some(Duration::ZERO),
                        }
                    }
                    Err(RpcFailure::Failed(error))
                        if attempt == 0
                            && matches!(error, McpBridgeError::Unauthorized)
                            && self.auth.api_key.is_some() =>
                    {
                        self.auth_retry_count.fetch_add(1, Ordering::Relaxed);
                        AttemptOutcome::Retryable {
                            error,
                            retry_after: Some(Duration::ZERO),
                        }
                    }
                    Err(RpcFailure::Failed(error)) if error.is_retryable() => {
                        if replay_safe || error.replay_is_safe() {
                            AttemptOutcome::Retryable {
                                retry_after: error.retry_after(),
                                error,
                            }
                        } else {
                            // Do not leave a retryable=true hint at the FCP boundary
                            // after refusing an unsafe automatic replay internally.
                            AttemptOutcome::Terminal(transport::invalid_response(
                                "operation may already have executed; automatic replay is unsafe",
                            ))
                        }
                    }
                    Err(RpcFailure::Failed(error)) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests;
