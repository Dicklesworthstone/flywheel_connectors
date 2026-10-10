//! MCP JSON-RPC client over HTTP (Streamable HTTP transport).

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{McpBridgeError, McpBridgeResult},
    types::{ApiErrorResponse, JsonRpcRequest},
};

mod session;
mod transport;
use session::{McpSession, PROTOCOL_VERSION, RpcFailure};

/// MCP server authentication.
#[derive(Clone)]
pub struct McpAuth {
    pub api_key: Option<String>,
}

impl McpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        if self.api_key.is_some() {
            "api_key:redacted".to_string()
        } else {
            "api_key:none".to_string()
        }
    }
}

impl fmt::Debug for McpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpAuth")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// MCP JSON-RPC client that communicates with an MCP server over HTTP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpClientMetrics {
    pub auth_retry_count: u64,
    pub session_expired_retry_count: u64,
}

pub struct McpClient {
    client: Client,
    auth: McpAuth,
    base_url: String,
    request_id: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    auth_retry_count: AtomicU64,
    session_expired_retry_count: AtomicU64,
    session: Mutex<Option<Arc<McpSession>>>,
}

impl fmt::Debug for McpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl McpClient {
    /// Create a new MCP client.
    pub fn new(auth: McpAuth, base_url: &str) -> McpBridgeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            // Redirecting a POST can replay a tool call or leak session headers.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("fcp-mcp-bridge/0.1.0 (FCP connector)")
            .build()?;

        let url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            auth,
            base_url: url,
            request_id: AtomicU64::new(1),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(120)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
            auth_retry_count: AtomicU64::new(0),
            session_expired_retry_count: AtomicU64::new(0),
            session: Mutex::new(None),
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn rpc_endpoint(&self) -> String {
        if self.base_url.ends_with("/mcp") {
            self.base_url.clone()
        } else {
            format!("{}/mcp", self.base_url)
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.auth.api_key {
            req.header("Authorization", format!("Bearer {key}"))
        } else {
            req
        }
    }

    /// Snapshot retry/session metrics.
    #[must_use]
    pub fn metrics(&self) -> McpClientMetrics {
        McpClientMetrics {
            auth_retry_count: self.auth_retry_count.load(Ordering::Relaxed),
            session_expired_retry_count: self.session_expired_retry_count.load(Ordering::Relaxed),
        }
    }

    async fn handle_http_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> McpBridgeError {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = match transport::read_bounded(resp, 64 * 1024).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => "MCP HTTP error body unavailable or exceeds limit".to_owned(),
        };
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or(body);

        match status.as_u16() {
            401 => McpBridgeError::Unauthorized,
            403 => McpBridgeError::Forbidden,
            404 => McpBridgeError::NotFound { resource: detail },
            429 => McpBridgeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60).saturating_mul(1000),
            },
            code => McpBridgeError::Api {
                status_code: code,
                message: detail,
            },
        }
    }

    /// Issue an MCP JSON-RPC call.
    ///
    /// Replay safety is derived from the MCP method: the discovery and read
    /// methods are pure reads, while `tools/call` invokes an arbitrary
    /// downstream tool whose effects this bridge cannot see (br-kxd3e).
    /// Initialization, capability negotiation and expired-session recovery are
    /// managed automatically under the same deadline as the operation.
    #[instrument(skip(self, params), fields(mcp_method))]
    pub async fn rpc_call(
        &self,
        mcp_method: &str,
        params: serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        debug!(url = %redact_url(&self.rpc_endpoint()), method = %mcp_method, "MCP JSON-RPC request");
        self.execute_session_rpc(mcp_method, params).await
    }

    async fn rpc_call_once(
        &self,
        url: &str,
        request: &JsonRpcRequest,
        session: Option<&McpSession>,
    ) -> Result<serde_json::Value, RpcFailure> {
        let mut req = self
            .add_auth(self.client.post(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .json(&request);
        let session_id = session.and_then(|session| session.id.as_ref());
        if let Some(id) = session_id {
            req = req.header("Mcp-Session-Id", id);
        }
        let resp = req.send().await.map_err(McpBridgeError::from)?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND && session_id.is_some() {
            return Err(RpcFailure::SessionExpired);
        }
        if !status.is_success() {
            return Err(self.handle_http_error(status, resp).await.into());
        }
        transport::read_rpc_response(resp, request.id, |reply| {
            self.send_server_reply(url, session_id, reply)
        })
        .await.map_err(RpcFailure::from)
    }

    /// Respond on the same endpoint without forwarding a server request to any
    /// FCP tool, filesystem, model, or other ambient capability.
    async fn send_server_reply(
        &self,
        url: &str,
        session_id: Option<&reqwest::header::HeaderValue>,
        reply: serde_json::Value,
    ) -> McpBridgeResult<()> {
        let mut request = self
            .add_auth(self.client.post(url))
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .json(&reply);
        if let Some(session_id) = session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }
        let response = request.send().await.map_err(|_| {
            transport::invalid_response(
                "server-request reply failed; initiating call outcome is unknown",
            )
        })?;
        let status = response.status();
        // This is an auxiliary POST after the initiating call was accepted.
        // Its failure must never trigger a replay of that original tool call.
        if status != StatusCode::ACCEPTED {
            return Err(transport::invalid_response(
                "server-request reply was not accepted; initiating call outcome is unknown",
            ));
        }
        Ok(())
    }

    // -- MCP Operations --

    /// List every tool under one deadline (128 pages, 10,000 entries, 16 MiB).
    /// Returns an error rather than a partial catalog when a limit is exceeded.
    /// Use `rpc_call("tools/list", params)` for an explicit single-page request.
    pub async fn tools_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.discovery_list("tools/list").await
    }

    /// Call a tool on the MCP server.
    pub async fn tools_call(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
        )
        .await
    }

    /// List every resource with the same aggregate bounds as [`Self::tools_list`].
    pub async fn resources_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.discovery_list("resources/list").await
    }

    /// List every parameterized resource template under the discovery budget.
    /// URI templates are opaque data; this never expands or fetches them.
    pub async fn resource_templates_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.discovery_list("resources/templates/list").await
    }

    /// Read a resource from the MCP server.
    pub async fn resources_read(&self, uri: &str) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("resources/read", json!({"uri": uri})).await
    }

    /// List every prompt with the same aggregate bounds as [`Self::tools_list`].
    pub async fn prompts_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.discovery_list("prompts/list").await
    }

    /// Render a server-provided prompt, preserving all returned content blocks.
    /// Arguments follow MCP's string-valued map contract. No model is invoked
    /// and no embedded resource or resource link is fetched by this operation.
    pub async fn prompts_get(
        &self,
        name: &str,
        arguments: Option<&serde_json::Value>,
    ) -> McpBridgeResult<serde_json::Value> {
        if name.is_empty() {
            return Err(McpBridgeError::McpError {
                code: -32602,
                message: "prompt name must not be empty".into(),
            });
        }
        let mut params = json!({"name": name});
        if let Some(arguments) = arguments {
            if !arguments.as_object().is_some_and(|arguments| {
                arguments.values().all(serde_json::Value::is_string)
            }) {
                return Err(McpBridgeError::McpError {
                    code: -32602,
                    message: "prompt arguments must be an object containing only strings".into(),
                });
            }
            // Do not trim, coerce, interpolate or log caller-supplied values.
            params["arguments"] = arguments.clone();
        }
        let result = self.rpc_call("prompts/get", params).await?;
        validate_prompt_result(&result)?;
        Ok(result)
    }
}

/// Validate the core GetPromptResult envelope without discarding extensions.
/// The transport has already bounded bytes and checked the JSON-RPC envelope.
fn validate_prompt_result(result: &serde_json::Value) -> McpBridgeResult<()> {
    use serde_json::Value;
    let invalid = || transport::invalid_response("invalid prompts/get result");
    let object = result.as_object().ok_or_else(invalid)?;
    if object.get("description").is_some_and(|value| !value.is_string()) {
        return Err(invalid());
    }
    let messages = object.get("messages").and_then(Value::as_array).ok_or_else(invalid)?;
    for message in messages {
        if !matches!(message.get("role").and_then(Value::as_str), Some("user" | "assistant")) {
            return Err(invalid());
        }
        let content = message.get("content").and_then(Value::as_object).ok_or_else(invalid)?;
        let string_field = |name: &str| content.get(name).is_some_and(Value::is_string);
        let valid = match content.get("type").and_then(Value::as_str) {
            Some("text") => string_field("text"),
            Some("image" | "audio") => string_field("data") && string_field("mimeType"),
            Some("resource_link") => string_field("uri") && string_field("name"),
            Some("resource") => content.get("resource").is_some_and(|resource| {
                resource.get("uri").is_some_and(Value::is_string)
                    && (resource.get("text").is_some_and(Value::is_string)
                        || resource.get("blob").is_some_and(Value::is_string))
            }),
            _ => false,
        };
        if !valid {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod prompt_resource_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = McpAuth {
            api_key: Some("secret-key-value".into()),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none_key() {
        let auth = McpAuth { api_key: None };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn auth_redacted_label_with_key() {
        let auth = McpAuth {
            api_key: Some("secret".into()),
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn auth_redacted_label_without_key() {
        let auth = McpAuth { api_key: None };
        let label = auth.redacted_label();
        assert!(label.contains("none"));
    }

    #[test]
    fn client_new_with_url() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://mcp.example.com").unwrap();
        assert_eq!(client.base_url, "https://mcp.example.com");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://mcp.example.com/").unwrap();
        assert_eq!(client.base_url, "https://mcp.example.com");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn client_debug_does_not_leak_key() {
        let auth = McpAuth {
            api_key: Some("super-secret".into()),
        };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_clone() {
        let auth = McpAuth {
            api_key: Some("KEY".into()),
        };
        let cloned = McpAuth::clone(&auth);
        assert_eq!(cloned.api_key, Some("KEY".into()));
    }

    #[test]
    fn auth_clone_none() {
        let auth = McpAuth { api_key: None };
        let cloned = McpAuth::clone(&auth);
        assert!(cloned.api_key.is_none());
    }

    #[test]
    fn next_id_increments() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let id1 = client.next_id();
        let id2 = client.next_id();
        let id3 = client.next_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn next_id_starts_at_one() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        assert_eq!(client.next_id(), 1);
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("McpClient"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = McpAuth { api_key: None };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("McpAuth"));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com///").unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_redacted_label_with_some_key() {
        let auth = McpAuth {
            api_key: Some("key".into()),
        };
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_with_none_key() {
        let auth = McpAuth { api_key: None };
        assert_eq!(auth.redacted_label(), "api_key:none");
    }

    #[test]
    fn client_new_with_localhost_port() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "http://127.0.0.1:3000").unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:3000");
    }

    #[test]
    fn auth_debug_some_key_shows_redacted() {
        let auth = McpAuth {
            api_key: Some("my-super-secret-key".into()),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-super-secret-key"));
    }

    #[test]
    fn client_new_preserves_path() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com/api/v1").unwrap();
        assert_eq!(client.base_url, "https://example.com/api/v1");
    }

    #[test]
    fn explicit_mcp_endpoint_is_not_appended_twice() {
        let client = McpClient::new(McpAuth { api_key: None }, "https://example.com/api/mcp/").unwrap();
        assert_eq!(client.rpc_endpoint(), "https://example.com/api/mcp");
    }
}
