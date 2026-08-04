//! MCP JSON-RPC client over HTTP (Streamable HTTP transport).

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, info, instrument};

use crate::{
    error::{McpBridgeError, McpBridgeResult},
    types::{ApiErrorResponse, JsonRpcRequest, JsonRpcResponse},
};

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
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
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
    ) -> McpBridgeResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(McpBridgeError::Unauthorized),
            403 => Err(McpBridgeError::Forbidden),
            404 => Err(McpBridgeError::NotFound { resource: detail }),
            429 => Err(McpBridgeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(McpBridgeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Send a JSON-RPC request to the MCP server.
    #[instrument(skip(self, params), fields(mcp_method))]
    /// Issue an MCP JSON-RPC call.
    ///
    /// Replay safety is derived from the MCP method: the discovery and read
    /// methods are pure reads, while `tools/call` invokes an arbitrary
    /// downstream tool whose effects this bridge cannot see (br-kxd3e).
    pub async fn rpc_call(
        &self,
        mcp_method: &str,
        params: serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        let replay_safe = matches!(
            mcp_method,
            "tools/list" | "resources/list" | "resources/read" | "prompts/list" | "initialize"
        );
        let id = self.next_id();
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: mcp_method.to_string(),
            params,
        };

        let url = format!("{}/mcp", self.base_url);
        debug!(url = %redact_url(&url), method = %mcp_method, id, "MCP JSON-RPC request");

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = request.clone();
            let url = url.clone();
            async move {
                match self.rpc_call_once(&url, &request).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) if self.should_retry_rpc_error(&error, attempt) => {
                        if matches!(error, McpBridgeError::Unauthorized) {
                            self.auth_retry_count.fetch_add(1, Ordering::Relaxed);
                            info!(
                                event = "mcp_auth_retry",
                                method = %mcp_method,
                                retry_count = attempt + 1,
                                "retrying MCP request after auth error"
                            );
                        } else if error.is_session_expired() {
                            self.session_expired_retry_count
                                .fetch_add(1, Ordering::Relaxed);
                            info!(
                                event = "mcp_session_reopened",
                                method = %mcp_method,
                                reason = "session_expired",
                                retry_count = attempt + 1,
                                "retrying MCP request after session expiry"
                            );
                        }
                        AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        // br-kxd3e: `tools/call` forwards an ARBITRARY tool
                        // invocation on a downstream MCP server. This bridge
                        // cannot know what that tool does, so it cannot know
                        // whether replaying it duplicates a side effect —
                        // which makes fail-closed the only defensible default.
                        // A rate limit is still replayable: it was refused
                        // WITHOUT the downstream tool running. The discovery
                        // and read methods pass `replay_safe`.
                        //
                        // The auth/session-expiry arm above is deliberately
                        // ahead of this one and stays retryable: those failures
                        // are rejected before the tool executes.
                        let replayable = replay_safe || error.replay_is_safe();
                        let retry_after = error.retry_after();
                        AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    async fn rpc_call_once(
        &self,
        url: &str,
        request: &JsonRpcRequest,
    ) -> McpBridgeResult<serde_json::Value> {
        let req = self
            .add_auth(self.client.post(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18")
            .json(&request);

        let resp = req.send().await?;
        let status = resp.status();

        if !status.is_success() {
            return self.handle_http_error(status, resp).await;
        }

        let body = resp.text().await?;
        let rpc_response: JsonRpcResponse = serde_json::from_str(&body)?;

        if let Some(err) = rpc_response.error {
            return Err(McpBridgeError::McpError {
                code: err.code,
                message: err.message,
            });
        }

        Ok(rpc_response.result.unwrap_or(serde_json::Value::Null))
    }

    fn should_retry_rpc_error(&self, error: &McpBridgeError, attempt: u32) -> bool {
        attempt == 0
            && ((matches!(error, McpBridgeError::Unauthorized) && self.auth.api_key.is_some())
                || error.is_session_expired())
    }

    // -- MCP Operations --

    /// List tools from the MCP server.
    pub async fn tools_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("tools/list", json!({})).await
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

    /// List resources from the MCP server.
    pub async fn resources_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("resources/list", json!({})).await
    }

    /// Read a resource from the MCP server.
    pub async fn resources_read(&self, uri: &str) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("resources/read", json!({"uri": uri})).await
    }

    /// List prompts from the MCP server.
    pub async fn prompts_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("prompts/list", json!({})).await
    }
}

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
}
