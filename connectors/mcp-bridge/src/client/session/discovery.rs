//! Complete, bounded MCP discovery under one deadline and one session per pass.
//!
//! A session-expired retry restarts at page one; a cursor is never deliberately
//! carried into a replacement session. No partial catalog is returned on error.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fcp_sdk::migration::{AttemptOutcome, RetryLoop};
use serde_json::{Map, Value, json};

use super::{McpClient, McpSession, RpcFailure, transport};
use crate::error::{McpBridgeError, McpBridgeResult};
use crate::types::JsonRpcRequest;

// Limits apply to the entire public call, including restarted discovery passes.
// Entry and cursor uniqueness are scoped to the currently accumulated catalog.
const MAX_DISCOVERY_PAGES: usize = 128;
const MAX_DISCOVERY_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISCOVERY_ENTRIES: usize = 10_000;
const MAX_CURSOR_BYTES: usize = 8192;

#[derive(Default)]
struct DiscoveryBudget {
    pages: AtomicUsize,
    bytes: AtomicUsize,
}

impl DiscoveryBudget {
    fn charge_page(&self) -> McpBridgeResult<()> {
        Self::charge(&self.pages, 1, MAX_DISCOVERY_PAGES, "discovery page limit exceeded")
    }

    fn charge_response(&self, response: &Value) -> McpBridgeResult<()> {
        // The transport has already bounded each response. This separate limit
        // prevents a sequence of valid small pages from growing without bound.
        let size = serde_json::to_vec(response)?.len();
        Self::charge(&self.bytes, size, MAX_DISCOVERY_BYTES, "discovery byte limit exceeded")
    }

    fn charge(counter: &AtomicUsize, amount: usize, limit: usize, message: &str) -> McpBridgeResult<()> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(amount).filter(|next| *next <= limit)
            })
            .map(|_| ())
            .map_err(|_| transport::invalid_response(message))
    }
}

struct Catalog {
    field: &'static str,
    identity_field: &'static str,
    envelope: Option<Map<String, Value>>,
    entries: Vec<Value>,
    identities: HashSet<String>,
    cursors: HashSet<String>,
}

impl Catalog {
    fn new(method: &str) -> McpBridgeResult<Self> {
        let (field, identity_field) = match method {
            "tools/list" => ("tools", "name"),
            "resources/list" => ("resources", "uri"),
            "prompts/list" => ("prompts", "name"),
            _ => return Err(transport::invalid_response("not a paginated discovery method")),
        };
        Ok(Self {
            field,
            identity_field,
            envelope: None,
            entries: Vec::new(),
            identities: HashSet::new(),
            cursors: HashSet::new(),
        })
    }

    fn append(&mut self, page: Value) -> McpBridgeResult<Option<String>> {
        let Value::Object(mut envelope) = page else {
            return Err(transport::invalid_response("discovery result must be an object"));
        };
        let Some(Value::Array(entries)) = envelope.remove(self.field) else {
            return Err(transport::invalid_response("discovery result is missing its list array"));
        };
        if entries.len() > MAX_DISCOVERY_ENTRIES.saturating_sub(self.entries.len()) {
            return Err(transport::invalid_response("discovery entry limit exceeded"));
        }
        let next = match envelope.remove("nextCursor") {
            None => None,
            Some(Value::String(cursor)) if cursor.len() <= MAX_CURSOR_BYTES => {
                if !self.cursors.insert(cursor.clone()) {
                    return Err(transport::invalid_response("discovery cursor cycle detected"));
                }
                // Opaque includes empty strings, whitespace and non-ASCII text.
                // Do not trim, parse or use the cursor as a URL.
                Some(cursor)
            }
            Some(_) => return Err(transport::invalid_response("invalid or oversized discovery cursor")),
        };
        for entry in &entries {
            let identity = entry.get(self.identity_field).and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| transport::invalid_response("discovery entry has no valid identity"))?;
            if !self.identities.insert(identity.to_owned()) {
                return Err(transport::invalid_response("duplicate discovery entry identity"));
            }
        }
        // Preserve the first page's extension metadata and every entry verbatim.
        // Later page-specific metadata does not overwrite the initial envelope.
        if self.envelope.is_none() {
            self.envelope = Some(envelope);
        }
        self.entries.extend(entries);
        Ok(next)
    }

    fn finish(self) -> Value {
        let mut envelope = self.envelope.unwrap_or_default();
        envelope.insert(self.field.to_owned(), Value::Array(self.entries));
        Value::Object(envelope)
    }
}

impl McpClient {
    /// Collect a complete catalog, never a silently truncated first page.
    ///
    /// Initialization, retries and all pages share a single request context.
    /// Each pass pins the negotiated session; expired-session recovery discards
    /// its partial catalog and starts again without a cursor. The fixed method
    /// allowlist prevents this read-only retry policy from replaying tool calls.
    pub(in crate::client) async fn discovery_list(&self, method: &str) -> McpBridgeResult<Value> {
        Catalog::new(method)?;
        let context = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = self.rpc_endpoint();
        let budget = DiscoveryBudget::default();
        let recovered = AtomicBool::new(false);
        RetryLoop::execute(&context, &policy, |attempt| {
            let url = &url;
            let budget = &budget;
            let recovered = &recovered;
            async move {
                let session = match self.ensure_session(url).await {
                    Ok(session) => session,
                    Err(error) if error.is_retryable() => return AttemptOutcome::Retryable {
                        retry_after: error.retry_after(), error,
                    },
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                if !session.allows_method(method) {
                    return AttemptOutcome::Terminal(transport::invalid_response(
                        "server did not negotiate the requested capability",
                    ));
                }
                match self.collect_catalog(url, method, &session, budget).await {
                    Ok(result) => AttemptOutcome::Success(result),
                    Err(RpcFailure::SessionExpired) => {
                        self.invalidate_session(&session).await;
                        let error = McpBridgeError::NotFound {
                            resource: "MCP session expired during discovery".into(),
                        };
                        if recovered.swap(true, Ordering::Relaxed) {
                            return AttemptOutcome::Terminal(error);
                        }
                        self.session_expired_retry_count.fetch_add(1, Ordering::Relaxed);
                        AttemptOutcome::Retryable { error, retry_after: Some(Duration::ZERO) }
                    }
                    Err(RpcFailure::Failed(error))
                        if attempt == 0
                            && matches!(error, McpBridgeError::Unauthorized)
                            && self.auth.api_key.is_some() =>
                    {
                        self.auth_retry_count.fetch_add(1, Ordering::Relaxed);
                        AttemptOutcome::Retryable { error, retry_after: Some(Duration::ZERO) }
                    }
                    Err(RpcFailure::Failed(error)) if error.is_retryable() => {
                        // No caller has received a partial catalog. Restarting a
                        // list is safe; carrying its cursor into another pass isn't.
                        AttemptOutcome::Retryable { retry_after: error.retry_after(), error }
                    }
                    Err(RpcFailure::Failed(error)) => AttemptOutcome::Terminal(error),
                }
            }
        }).await
    }

    async fn require_catalog_session(&self, expected: &Arc<McpSession>) -> McpBridgeResult<()> {
        let state = self.session.lock().await;
        if state.as_ref().is_some_and(|current| Arc::ptr_eq(current, expected)) {
            Ok(())
        } else {
            // Another operation invalidated/replaced the session. Reject the
            // partial snapshot even if the server reused the opaque session ID.
            Err(transport::invalid_response("MCP session changed during discovery; restart the list"))
        }
    }

    async fn collect_catalog(
        &self,
        url: &str,
        method: &str,
        session: &Arc<McpSession>,
        budget: &DiscoveryBudget,
    ) -> Result<Value, RpcFailure> {
        let mut catalog = Catalog::new(method)?;
        let mut cursor = None;
        loop {
            self.require_catalog_session(session).await?;
            budget.charge_page()?;
            let params = cursor.map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
            let request = JsonRpcRequest {
                jsonrpc: "2.0", id: self.next_id(), method: method.into(), params,
            };
            let page = self.rpc_call_once(url, &request, Some(session.as_ref())).await?;
            self.require_catalog_session(session).await?;
            budget.charge_response(&page)?;
            cursor = catalog.append(page)?;
            if cursor.is_none() {
                return Ok(catalog.finish());
            }
        }
    }
}

#[cfg(test)]
mod tests;
