//! Connector migration framework for the `AsyncSuperSync` transition.
//!
//! This module provides shared helpers that all connectors use when migrating
//! from legacy runtime-specific code to the `fcp-async-core` substrate. It eliminates
//! duplicated runtime bootstrap, retry loop, and error mapping code across
//! connector crates.
//!
//! This module is an implementation helper, not the primary SDK contract.
//! New connector authoring should start from [`crate::ConnectorApp`] and use the
//! migration helpers only where they clarify runtime integration details.
//!
//! # Components
//!
//! - [`RetryLoop`]: Generic retry executor using `ExecutionContext` for
//!   deadline-aware exponential backoff with jitter.
//! - [`crate::ConnectorErrorMapping`]: Trait for consistent `AsyncError` →
//!   connector error conversion.
//! - [`HttpRetryConfig`]: Serializable retry configuration shared by HTTP connectors.
//! - [`classify_http_status`]: Canonical HTTP status → retry decision mapping.
//! - [`map_async_to_fcp_error`]: Canonical `AsyncError` → `FcpError` mapping.
//!
//! # Migration Checklist
//!
//! Every connector migration MUST satisfy all items below. Use this as
//! the acceptance gate before closing a connector migration bead.
//!
//! Runtime bootstrap helpers graduated to [`crate::runtime::ConnectorRuntime`],
//! and the connector error-mapping contract graduated to
//! [`crate::error_mapping`]. Connector authors should import
//! [`crate::ConnectorErrorMapping`] from the SDK root.
//!
//! ## Retry & Error Mapping
//!
//! - [ ] Remove hand-rolled retry loops; replace with [`RetryLoop::execute()`].
//! - [ ] Implement [`crate::ConnectorErrorMapping`] on the connector's error type.
//! - [ ] HTTP status classification delegates to [`classify_http_status()`].
//! - [ ] `AsyncError` mapping delegates to [`map_async_to_fcp_error()`] for
//!   the timeout/cancellation/runtime arms.
//! - [ ] Retry config stored as [`HttpRetryConfig`] (deserializable from TOML / JSON).
//!
//! ## Phase 3: Correctness & Observability
//!
//! - [ ] **No direct runtime imports** — scan connector sources for raw runtime paths
//!   must return zero matches (except `tokio_stream` for SSE if needed).
//! - [ ] All failure paths emit tracing spans with `error_type`, `attempt`,
//!   `delay_ms` fields (handled by `RetryLoop` automatically).
//! - [ ] Structured log schema matches forensics standard (bead 235t.32).
//!
//! ## Phase 4: Testing & Parity
//!
//! - [ ] Unit tests cover: success, transient-then-success, terminal error,
//!   max-attempts exhausted, cancellation, deadline expiry.
//! - [ ] Behavior matches pre-migration golden contracts from bead 235t.30.
//! - [ ] Integration tests exercise the full `configure → invoke → shutdown` lifecycle.
//! - [ ] `cargo check --workspace --all-targets` passes.
//! - [ ] `cargo clippy --workspace --all-targets` passes.
//!
//! # Reference Migration: `OpenAI` Connector
//!
//! Below is a condensed before/after showing how the `OpenAI` connector's
//! `post()` method migrates from hand-rolled retry to this framework.
//!
//! ## Before (hand-rolled retry loop)
//!
//! ```ignore
//! // connectors/openai/src/client.rs — BEFORE migration
//! async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R> {
//!     let url = format!("{}{endpoint}", self.base_url);
//!     let mut delay = Duration::from_millis(self.initial_delay_ms);
//!     let mut attempts = 0;
//!     let context = ExecutionContext::request_scoped(Duration::from_secs(120));
//!
//!     loop {
//!         attempts += 1;
//!         let request = self.client.post(&url).json(body);
//!         let request = self.apply_auth(request);
//!
//!         match request.send().await {
//!             Ok(response) => match self.handle_response(response).await {
//!                 Ok(data) => return Ok(data),
//!                 Err(e) if e.is_retryable() && attempts < self.max_retries => {
//!                     if let Some(retry_after) = e.retry_after() {
//!                         delay = retry_after;
//!                     }
//!                     context.sleep(delay).await.map_err(map_context_error)?;
//!                     delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
//!                 }
//!                 Err(e) => return Err(e),
//!             },
//!             Err(e) if e.is_timeout() || e.is_connect() => {
//!                 if attempts < self.max_retries {
//!                     context.sleep(delay).await.map_err(map_context_error)?;
//!                     delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
//!                 } else {
//!                     return Err(OpenAIError::Http(e));
//!                 }
//!             }
//!             Err(e) => return Err(OpenAIError::Http(e)),
//!         }
//!     }
//! }
//!
//! fn map_context_error(error: AsyncError) -> OpenAIError {
//!     match error {
//!         AsyncError::Timeout { timeout_ms } => OpenAIError::Api { /* ... */ },
//!         AsyncError::Cancelled => OpenAIError::Api { /* ... */ },
//!         other => OpenAIError::Api { message: other.to_string(), /* ... */ },
//!     }
//! }
//! ```
//!
//! ## After (using migration framework)
//!
//! ```ignore
//! // connectors/openai/src/client.rs — AFTER migration
//! use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime};
//! use fcp_sdk::migration::{
//!     AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
//!     map_async_to_fcp_error,
//! };
//!
//! // In OpenAIClient:
//! struct OpenAIClient {
//!     client: Client,
//!     auth: OpenAIAuth,
//!     base_url: String,
//!     runtime: ConnectorRuntime,     // NEW: replaces manual context creation
//!     retry_config: HttpRetryConfig, // NEW: replaces loose fields
//!     // ...
//! }
//!
//! // ConnectorErrorMapping impl replaces map_context_error():
//! impl ConnectorErrorMapping for OpenAIError {
//!     fn from_async_error(error: AsyncError) -> Self {
//!         match error {
//!             AsyncError::Timeout { timeout_ms } => Self::Api {
//!                 error_type: "deadline_timeout".into(),
//!                 message: format!("deadline exceeded after {timeout_ms}ms"),
//!                 status_code: Some(504),
//!             },
//!             AsyncError::Cancelled => Self::Api {
//!                 error_type: "request_cancelled".into(),
//!                 message: "cancelled".into(),
//!                 status_code: None,
//!             },
//!             other => Self::Api {
//!                 error_type: "runtime".into(),
//!                 message: other.to_string(),
//!                 status_code: None,
//!             },
//!         }
//!     }
//!     fn to_fcp_error(&self) -> FcpError { map_async_to_fcp_error(/* ... */) }
//!     fn is_retryable(&self) -> bool { matches!(self, Self::RateLimited { .. } | Self::Overloaded { .. }) }
//!     fn retry_after(&self) -> Option<Duration> { /* from error variant */ }
//! }
//!
//! // Migrated post() — 10 lines replacing 50:
//! async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R> {
//!     let url = format!("{}{endpoint}", self.base_url);
//!     let ctx = self.runtime.request_context();
//!     let policy = self.retry_config.to_retry_policy();
//!
//!     RetryLoop::execute(&ctx, &policy, |_attempt| {
//!         let url = &url;
//!         async move {
//!             let request = self.client.post(url).json(body);
//!             let request = self.apply_auth(request);
//!             match request.send().await {
//!                 Ok(resp) => {
//!                     let status = resp.status().as_u16();
//!                     match self.handle_response(resp).await {
//!                         Ok(data) => AttemptOutcome::Success(data),
//!                         Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
//!                             retry_after: e.retry_after(),
//!                             error: e,
//!                         },
//!                         Err(e) => AttemptOutcome::Terminal(e),
//!                     }
//!                 }
//!                 Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
//!                     error: OpenAIError::Http(e),
//!                     retry_after: None,
//!                 },
//!                 Err(e) => AttemptOutcome::Terminal(OpenAIError::Http(e)),
//!             }
//!         }
//!     }).await
//! }
//! ```
//!
//! Key improvements after migration:
//! - No manual backoff tracking (`delay`, `attempts` variables eliminated)
//! - Cancellation/deadline automatically handled by `RetryLoop` + `ExecutionContext`
//! - Structured tracing emitted for every retry (with `attempt`, `delay_ms`, `error`)
//! - Retry config serializable from connector TOML/JSON configuration
//! - Error mapping centralized in `ConnectorErrorMapping` impl

use std::time::Duration;

use fcp_async_core::http::HttpClientError;
use fcp_async_core::{AsyncError, ExecutionContext};
#[cfg(feature = "connector-http")]
use fcp_manifest::{
    HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpRequest, HostEgressHttpResponse,
    HostEgressTcpRequest, HostEgressTcpResponse,
};
use tracing::{debug, warn};

use crate::FcpError;
use crate::error_mapping::ConnectorErrorMapping;
pub use crate::error_mapping::map_async_to_fcp_error;
use crate::retry::{RetryDecision, RetryPolicy};

#[cfg(test)]
use std::fmt;

/// Connector-side client for the host egress proxy.
///
/// Each call has a total deadline and a bounded JSON response. Redirects,
/// ambient HTTP proxies, and automatic retries are disabled: these requests
/// carry capability material and may cause effects at the upstream service.
#[cfg(feature = "connector-http")]
#[derive(Clone)]
pub struct HostEgressProxyClient {
    base_url: String,
    client: reqwest::Client,
    timeout: Duration,
    max_response_bytes: usize,
}

#[cfg(feature = "connector-http")]
impl std::fmt::Debug for HostEgressProxyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostEgressProxyClient")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "connector-http")]
impl HostEgressProxyClient {
    /// Construct a host egress proxy client from a base URL such as
    /// `http://127.0.0.1:7878`. Defaults to a 30-second total deadline and a
    /// 16 MiB JSON response limit, including base64 encoding and metadata.
    /// Rejection bodies are additionally capped at 64 KiB.
    ///
    /// # Errors
    ///
    /// Rejects invalid URLs, non-HTTP(S) schemes, URL credentials, queries, and
    /// fragments. Also returns transport initialization failures.
    pub fn new(base_url: impl Into<String>) -> Result<Self, HostEgressProxyError> {
        let base_url = base_url.into();
        let url = reqwest::Url::parse(&base_url)
            .map_err(|_| HostEgressProxyError::InvalidConfiguration("invalid host proxy URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(HostEgressProxyError::InvalidConfiguration(
                "host proxy URL must use HTTP(S) without credentials, query, or fragment",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(host_egress_transport_error)?;
        Ok(Self {
            base_url: url.as_str().trim_end_matches('/').to_string(),
            client,
            timeout: Duration::from_secs(30),
            max_response_bytes: 16 * 1024 * 1024,
        })
    }

    /// Set the total deadline for connecting, sending, and reading a response.
    /// A timeout does not establish whether the upstream effect happened.
    ///
    /// # Errors
    ///
    /// Rejects zero or unrepresentable deadlines.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, HostEgressProxyError> {
        if timeout.is_zero() || std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(HostEgressProxyError::InvalidConfiguration(
                "host proxy timeout must be positive and representable",
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Set the maximum encoded JSON response size, including metadata and
    /// base64 overhead. This is a connector-side resource bound; the host still
    /// independently enforces the operation's upstream response policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero byte limit.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, HostEgressProxyError> {
        if max_response_bytes == 0 {
            return Err(HostEgressProxyError::InvalidConfiguration(
                "host proxy response limit must be positive",
            ));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    /// Absolute host RPC endpoint for mediated HTTP egress.
    #[must_use]
    pub fn http_endpoint(&self) -> String {
        format!("{}/rpc/egress/http", self.base_url)
    }

    /// Absolute host RPC endpoint for mediated TCP egress.
    #[must_use]
    pub fn tcp_endpoint(&self) -> String {
        format!("{}/rpc/egress/tcp", self.base_url)
    }

    /// Send an HTTP request through the host egress proxy.
    ///
    /// # Errors
    ///
    /// Returns [`HostEgressProxyError`] when transport fails, the host rejects
    /// the status code, or the response body does not match the contract.
    pub async fn http(
        &self,
        request: &HostEgressHttpRequest,
    ) -> Result<HostEgressHttpResponse, HostEgressProxyError> {
        let (status, body) = self.post(self.http_endpoint(), request).await?;
        if !status.is_success() {
            return Err(HostEgressProxyError::Rejected {
                status: status.as_u16(),
                body: redact_http_host_egress_rejection_body(
                    request,
                    String::from_utf8_lossy(&body).into_owned(),
                ),
            });
        }
        let response: HostEgressHttpResponse = serde_json::from_slice(&body)
            .map_err(|_| HostEgressProxyError::InvalidResponse("invalid HTTP response contract"))?;
        validate_host_egress_response(&request.context, &response.egress)?;
        if !(100..=599).contains(&response.status) {
            return Err(HostEgressProxyError::InvalidResponse(
                "invalid upstream HTTP status",
            ));
        }
        Ok(response)
    }

    /// Send a bounded TCP exchange through the host egress proxy.
    ///
    /// # Errors
    ///
    /// Returns [`HostEgressProxyError`] when transport fails, the host rejects
    /// the status code, or the response body does not match the contract.
    pub async fn tcp(
        &self,
        request: &HostEgressTcpRequest,
    ) -> Result<HostEgressTcpResponse, HostEgressProxyError> {
        let (status, body) = self.post(self.tcp_endpoint(), request).await?;
        if !status.is_success() {
            return Err(HostEgressProxyError::Rejected {
                status: status.as_u16(),
                body: redact_tcp_host_egress_rejection_body(
                    request,
                    String::from_utf8_lossy(&body).into_owned(),
                ),
            });
        }
        let response: HostEgressTcpResponse = serde_json::from_slice(&body)
            .map_err(|_| HostEgressProxyError::InvalidResponse("invalid TCP response contract"))?;
        validate_host_egress_response(&request.context, &response.egress)?;
        if u64::try_from(response.read.as_bytes().len()).ok() != Some(response.bytes_read)
            || request
                .read_limit_bytes
                .is_some_and(|limit| response.bytes_read > limit)
        {
            return Err(HostEgressProxyError::InvalidResponse(
                "TCP response violates read byte accounting",
            ));
        }
        Ok(response)
    }

    async fn post<T: serde::Serialize>(
        &self,
        endpoint: String,
        request: &T,
    ) -> Result<(reqwest::StatusCode, Vec<u8>), HostEgressProxyError> {
        let mut response = self
            .client
            .post(endpoint)
            .timeout(self.timeout)
            .json(request)
            .send()
            .await
            .map_err(host_egress_transport_error)?;
        let status = response.status();
        let limit = if status.is_success() {
            self.max_response_bytes
        } else {
            self.max_response_bytes.min(64 * 1024)
        };
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
        {
            return Err(HostEgressProxyError::ResponseTooLarge { limit });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(host_egress_transport_error)?
        {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(HostEgressProxyError::ResponseTooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }
}

#[cfg(feature = "connector-http")]
fn host_egress_transport_error(error: reqwest::Error) -> HostEgressProxyError {
    HostEgressProxyError::Transport(error.without_url())
}

#[cfg(feature = "connector-http")]
fn validate_host_egress_response(
    request: &HostEgressContext,
    response: &HostEgressDecisionMetadata,
) -> Result<(), HostEgressProxyError> {
    for (field, matches) in [
        (
            "connector_id",
            request.connector_id == response.connector_id,
        ),
        (
            "operation_id",
            request.operation_id == response.operation_id,
        ),
        ("zone_id", request.zone_id == response.zone_id),
        ("request_id", request.request_id == response.request_id),
        (
            "correlation_id",
            request.correlation_id == response.correlation_id,
        ),
        ("decision", response.decision == "allow"),
        (
            "execution_mode",
            response.execution_mode == "host_egress_proxy",
        ),
    ] {
        if !matches {
            // Never echo mismatched values: even an invalid response may carry
            // another request's credentials, payload, or identifying metadata.
            return Err(HostEgressProxyError::InvalidResponse(field));
        }
    }
    Ok(())
}

#[cfg(feature = "connector-http")]
const HOST_EGRESS_REDACTION_MARKER: &str = "[redacted-host-egress-sensitive]";
#[cfg(feature = "connector-http")]
const HOST_EGRESS_REDACTION_MIN_FRAGMENT_LEN: usize = 4;

#[cfg(feature = "connector-http")]
fn redact_sensitive_fragment(redacted: &mut String, fragment: &str) {
    if fragment.len() >= HOST_EGRESS_REDACTION_MIN_FRAGMENT_LEN && redacted.contains(fragment) {
        *redacted = redacted.replace(fragment, HOST_EGRESS_REDACTION_MARKER);
    }
}

#[cfg(feature = "connector-http")]
fn redact_request_body_fragment(redacted: &mut String, bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        redact_sensitive_fragment(redacted, text);
    }
}

#[cfg(feature = "connector-http")]
fn redact_header_value_fragments(redacted: &mut String, header_value: &str) {
    redact_sensitive_fragment(redacted, header_value);
    for fragment in header_value.split_ascii_whitespace() {
        redact_sensitive_fragment(redacted, fragment);
    }
}

#[cfg(feature = "connector-http")]
fn redact_http_host_egress_rejection_body(request: &HostEgressHttpRequest, body: String) -> String {
    let mut redacted = body;
    redact_sensitive_fragment(&mut redacted, &request.context.capability_token_cbor_b64);
    redact_sensitive_fragment(&mut redacted, &request.url);
    if let Some(credential_id) = request.credential_id.as_deref() {
        redact_sensitive_fragment(&mut redacted, credential_id);
    }
    for header in &request.headers {
        redact_header_value_fragments(&mut redacted, &header.value);
    }
    if let Some(request_body) = request.body.as_ref() {
        let encoded: String = request_body.clone().into();
        redact_sensitive_fragment(&mut redacted, &encoded);
        redact_request_body_fragment(&mut redacted, request_body.as_bytes());
    }
    redacted
}

#[cfg(feature = "connector-http")]
fn redact_tcp_host_egress_rejection_body(request: &HostEgressTcpRequest, body: String) -> String {
    let mut redacted = body;
    redact_sensitive_fragment(&mut redacted, &request.context.capability_token_cbor_b64);
    if let Some(credential_id) = request.credential_id.as_deref() {
        redact_sensitive_fragment(&mut redacted, credential_id);
    }
    if let Some(write) = request.write.as_ref() {
        let encoded: String = write.clone().into();
        redact_sensitive_fragment(&mut redacted, &encoded);
        redact_request_body_fragment(&mut redacted, write.as_bytes());
    }
    redacted
}

/// Errors returned by [`HostEgressProxyClient`].
#[cfg(feature = "connector-http")]
#[derive(Debug, thiserror::Error)]
pub enum HostEgressProxyError {
    /// Invalid endpoint or unbounded client configuration.
    #[error("invalid host egress proxy configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The connector could not reach the host proxy or decode its response.
    #[error("host egress proxy transport failed: {0}")]
    Transport(reqwest::Error),
    /// The host sent more encoded response bytes than the configured bound.
    #[error("host egress proxy response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// Maximum encoded response size accepted by this client.
        limit: usize,
    },
    /// Malformed response or response attribution that did not match the call.
    #[error("invalid host egress proxy response: {0}")]
    InvalidResponse(&'static str),
    /// The host proxy rejected the request before returning a contract payload.
    #[error("host egress proxy rejected request with HTTP {status}: {body}")]
    Rejected {
        /// HTTP status returned by the host proxy.
        status: u16,
        /// Redacted rejection body returned by the host proxy.
        body: String,
    },
}

#[cfg(feature = "connector-http")]
impl HostEgressProxyError {
    /// HTTP status for host rejections, when the proxy returned one.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Rejected { status, .. } => Some(*status),
            Self::InvalidConfiguration(_)
            | Self::Transport(_)
            | Self::ResponseTooLarge { .. }
            | Self::InvalidResponse(_) => None,
        }
    }

    /// Redacted rejection body returned by the host proxy.
    #[must_use]
    pub fn rejection_body(&self) -> Option<&str> {
        match self {
            Self::Rejected { body, .. } => Some(body),
            Self::InvalidConfiguration(_)
            | Self::Transport(_)
            | Self::ResponseTooLarge { .. }
            | Self::InvalidResponse(_) => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical HTTP → FCP Error Mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map an HTTP status code to the canonical FCP error.
///
/// Provides a single source of truth for the HTTP-to-FCP error taxonomy so
/// connectors do not each invent ad-hoc mappings. Connectors MAY override
/// specific codes when the service assigns non-standard semantics (e.g., a
/// 403 that means "resource not found" rather than "capability denied").
///
/// The `message` parameter is included in the resulting `FcpError` for
/// diagnostics. Pass the upstream response body or a short summary.
#[must_use]
pub fn map_http_status(status: u16, service: &str, message: String) -> FcpError {
    match status {
        400 => FcpError::InvalidRequest {
            code: 1001,
            message,
        },
        401 => FcpError::Unauthorized {
            code: 2001,
            message,
        },
        403 => FcpError::CapabilityDenied {
            capability: String::new(),
            reason: message,
        },
        404 => FcpError::ResourceNotFound { resource: message },
        408 => FcpError::UpstreamTimeout {
            service: service.to_string(),
        },
        409 => FcpError::Conflict { message },
        429 => FcpError::RateLimited {
            retry_after_ms: default_rate_limit_retry_after_ms(),
            violation: None,
        },
        // Server errors → External (upstream fault, retryable)
        500..=599 => FcpError::External {
            service: service.to_string(),
            message,
            status_code: Some(status),
            retryable: matches!(status, 500 | 502 | 503 | 504),
            retry_after: None,
        },
        // Everything else → External with status context
        _ => FcpError::External {
            service: service.to_string(),
            message: format!("HTTP {status}: {message}"),
            status_code: Some(status),
            retryable: false,
            retry_after: None,
        },
    }
}

fn default_rate_limit_retry_after_ms() -> u64 {
    u64::try_from(crate::retry::default_rate_limit_retry_after().as_millis()).unwrap_or(u64::MAX)
}

/// Whether an HTTP status code is retryable per standard semantics.
///
/// - 408 Request Timeout: transient, retry
/// - 429 Too Many Requests: retry after delay
/// - 500 Internal Server Error: transient, retry
/// - 502 Bad Gateway: transient, retry
/// - 503 Service Unavailable: transient, retry
/// - 504 Gateway Timeout: transient, retry
#[must_use]
pub const fn is_http_status_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

// ─────────────────────────────────────────────────────────────────────────────
// RetryLoop
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a single attempt in a retry loop.
pub enum AttemptOutcome<T, E> {
    /// Operation succeeded.
    Success(T),
    /// Operation failed and is SAFE TO REPLAY.
    ///
    /// "Retryable" is a claim about **side effects**, not just about whether
    /// the error looks transient. Returning this asserts one of:
    /// - the request provably never reached the service (a connect error), or
    /// - the operation is idempotent, or
    /// - the request carries an idempotency key the provider honours.
    ///
    /// It is NOT enough that the status code is in the 5xx family or that the
    /// transport reported a timeout. A 5xx means the service *received* the
    /// request, and `reqwest::Error::is_timeout()` covers the total-request
    /// timeout, which fires after the body was fully sent — so for a
    /// non-idempotent operation either one may mean the work already
    /// happened. Replaying it then performs the side effect again.
    ///
    /// The host's receipt/idempotency-key deduplication does NOT cover this:
    /// it deduplicates repeated *invokes*, while this retry happens inside the
    /// connector process, below that boundary. The host sees one invoke and
    /// writes one receipt while the provider saw N requests.
    ///
    /// Use [`AttemptOutcome::retryable_if_replayable`] when the safety of a
    /// replay depends on whether the request was transmitted.
    Retryable {
        /// The error from this attempt.
        error: E,
        /// Explicit retry-after hint from the service.
        retry_after: Option<Duration>,
    },
    /// Operation failed terminally (no retry).
    Terminal(E),
}

impl<T, E> AttemptOutcome<T, E> {
    /// Classify a transient failure for an operation whose replay safety
    /// depends on whether the request was actually transmitted.
    ///
    /// `replayable` must be `true` only when replaying the request cannot
    /// duplicate a side effect — because the request never left the client,
    /// because the operation is idempotent, or because it carries an
    /// idempotency key. When it is `false` the failure is reported as
    /// [`AttemptOutcome::Terminal`]: giving the caller one honest error beats
    /// silently performing the side effect up to `max_retries` more times.
    ///
    /// See [`transport_error_reached_service`] for classifying a
    /// `reqwest::Error` on that axis, or
    /// [`http_client_error_reached_service`] for the asupersync
    /// `HttpClientError`.
    pub const fn retryable_if_replayable(
        error: E,
        retry_after: Option<Duration>,
        replayable: bool,
    ) -> Self {
        if replayable {
            Self::Retryable { error, retry_after }
        } else {
            Self::Terminal(error)
        }
    }
}

/// Whether a `reqwest` transport error leaves it POSSIBLE that the service
/// received and acted on the request.
///
/// Only a connect-phase failure proves the request never left the client. A
/// timeout, a body/decode error, or a response-phase failure can all occur
/// after the request was fully written, so for a non-idempotent operation they
/// must be treated as "may already have executed".
///
/// Conservative by construction: an unrecognised error class returns `true`
/// (assume it reached the service) so a new upstream variant fails closed.
#[cfg(feature = "connector-http")]
#[must_use]
pub fn transport_error_reached_service(error: &reqwest::Error) -> bool {
    !(error.is_connect() || error.is_builder())
}

/// Whether an asupersync [`HttpClientError`] leaves it POSSIBLE that the
/// service received and acted on the request.
///
/// The asupersync counterpart of [`transport_error_reached_service`], for
/// connectors built on `fcp_async_core::http` rather than `reqwest`. Unlike the
/// `reqwest` helper this needs no feature gate: `fcp-async-core` is an
/// unconditional dependency of this crate.
///
/// Returns `false` only for the variants that are raised while the connection
/// is still being established, which proves no request bytes were written:
/// URL parsing, DNS, TCP connect, the TLS handshake, proxy negotiation
/// (SOCKS5 and HTTP `CONNECT`), and pool exhaustion.
///
/// Everything else returns `true`. In particular:
/// - `Io` may be a mid-body write failure *or* a response-read failure that
///   happens after the body was fully sent. The two are the same variant, so
///   the ambiguous case decides it.
/// - `HttpError` and `TooManyRedirects` are response-phase: the service
///   answered, so it necessarily received the request.
/// - `Cancelled` can be observed at any point, including after transmission.
///
/// Conservative by construction: the classification is an allowlist of
/// pre-transmission variants, so an error class added upstream returns `true`
/// (assume it reached the service) and fails closed without a compile break.
/// Asupersync after 0.3.4 adds `DeadlineExceeded` — the total-request
/// deadline, which fires after the request may have been fully transmitted —
/// and this helper already classifies it correctly.
#[must_use]
pub const fn http_client_error_reached_service(error: &HttpClientError) -> bool {
    !matches!(
        error,
        HttpClientError::InvalidUrl(_)
            | HttpClientError::DnsError(_)
            | HttpClientError::ConnectError(_)
            | HttpClientError::TlsError(_)
            | HttpClientError::ConnectTunnelRefused { .. }
            | HttpClientError::InvalidConnectInput(_)
            | HttpClientError::ProxyError(_)
            | HttpClientError::PoolExhausted { .. }
    )
}

/// Generic retry executor using `ExecutionContext` for deadline-aware backoff.
///
/// Replaces hand-rolled retry loops in connector clients with a consistent
/// pattern that respects cancellation, deadline budgets, and structured logging.
///
/// # Example
///
/// ```ignore
/// let ctx = runtime.request_context();
/// let policy = RetryPolicy::new().with_max_attempts(Some(3));
///
/// // `replayable` is the whole safety question: a POST that creates a
/// // resource must NOT be replayed once the request has left the client,
/// // because a 5xx or a timeout can both be reported after the service
/// // already did the work. Set it to `true` unconditionally only for an
/// // operation that is idempotent or that carries an idempotency key.
/// let create_is_replayable = false;
///
/// let result = RetryLoop::execute(&ctx, &policy, |attempt| async move {
///     match client.post(url).send().await {
///         Ok(resp) if resp.status().is_success() => AttemptOutcome::Success(resp),
///         Ok(resp) if resp.status() == 429 => AttemptOutcome::Retryable {
///             error: MyError::RateLimited,
///             retry_after: Some(Duration::from_secs(30)),
///         },
///         // A 5xx means the service RECEIVED the request.
///         Ok(resp) if resp.status().is_server_error() => {
///             AttemptOutcome::retryable_if_replayable(
///                 MyError::Api(resp.status()),
///                 None,
///                 create_is_replayable,
///             )
///         }
///         Ok(resp) => AttemptOutcome::Terminal(MyError::Api(resp.status())),
///         // Only a connect-phase failure proves the request never left the
///         // client; `is_timeout()` covers the TOTAL request timeout, which
///         // fires after the body was fully sent.
///         Err(e) => {
///             let replayable = create_is_replayable || !transport_error_reached_service(&e);
///             AttemptOutcome::retryable_if_replayable(MyError::Http(e), None, replayable)
///         }
///     }
/// }).await;
/// ```
pub struct RetryLoop;

impl RetryLoop {
    /// Execute an operation with retry logic under an `ExecutionContext`.
    ///
    /// The `operation` closure receives the current attempt number (0-indexed)
    /// and returns an [`AttemptOutcome`]. Retries continue until:
    /// - The operation succeeds
    /// - A terminal error occurs
    /// - The retry policy's max attempts is reached
    /// - The context deadline expires or cancellation is triggered
    ///
    /// Each attempt, including construction of its future, runs under the
    /// context. An interrupted attempt is dropped and is never retried here:
    /// cancellation or timeout does not prove that an upstream side effect
    /// did not happen. Attempts and backoff share the same absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns the last error encountered (either from the operation or from
    /// context timeout/cancellation mapped via `E::from_async_error`).
    pub async fn execute<T, E, F, Fut>(
        ctx: &ExecutionContext,
        policy: &RetryPolicy,
        operation: F,
    ) -> Result<T, E>
    where
        E: ConnectorErrorMapping,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = AttemptOutcome<T, E>>,
    {
        Self::execute_from_attempt(ctx, policy, 0, operation).await
    }

    async fn execute_from_attempt<T, E, F, Fut>(
        ctx: &ExecutionContext,
        policy: &RetryPolicy,
        start_attempt: u32,
        mut operation: F,
    ) -> Result<T, E>
    where
        E: ConnectorErrorMapping,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = AttemptOutcome<T, E>>,
    {
        let mut attempt = start_attempt;
        let mut last_error: Option<E> = None;

        loop {
            // Check if we've exceeded max attempts
            if let Some(max) = policy.max_attempts {
                if attempt >= max {
                    // Safety: at least one attempt ran before `attempt` was incremented
                    return Err(last_error.unwrap_or_else(|| {
                        E::from_async_error(AsyncError::Runtime {
                            message: "retry budget exhausted with no attempts".into(),
                        })
                    }));
                }
            }

            // Check cancellation before each attempt
            if ctx.is_cancelled() {
                return Err(E::from_async_error(AsyncError::Cancelled));
            }

            debug!(attempt, "executing retry attempt");

            // Defer even calling the closure until the context admits work.
            // Awaiting the attempt directly only bounded the backoff, leaving
            // hung I/O uncancellable and allowing expired requests to send.
            let outcome = ctx
                .run(async { operation(attempt).await })
                .await
                .map_err(E::from_async_error)?;

            match outcome {
                AttemptOutcome::Success(value) => return Ok(value),
                AttemptOutcome::Terminal(error) => return Err(error),
                AttemptOutcome::Retryable { error, retry_after } => {
                    // Compute delay: use retry-after hint or policy backoff
                    let decision = retry_after.map_or(RetryDecision::Backoff, RetryDecision::After);

                    let Some(delay) = policy.next_delay(attempt, decision, retry_after) else {
                        // Policy says no more retries
                        return Err(error);
                    };

                    // `redacted_summary()`, never `%error`: a connector error
                    // that forwards a `reqwest::Error` renders the full URL,
                    // and providers that authenticate via `?key=…` would leak
                    // the credential into this line on every retry.
                    warn!(
                        attempt,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        error = %error.redacted_summary(),
                        "retrying after transient error"
                    );

                    // Sleep under context (respects deadline + cancellation)
                    if let Err(async_err) = ctx.sleep(delay).await {
                        return match async_err {
                            AsyncError::Timeout { .. } => Err(error),
                            other => Err(E::from_async_error(other)),
                        };
                    }

                    let Some(next_attempt) = attempt.checked_add(1) else {
                        return Err(error);
                    };
                    last_error = Some(error);
                    attempt = next_attempt;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Client helpers (feature-gated)
// ─────────────────────────────────────────────────────────────────────────────

/// Standard HTTP retry configuration shared across connectors.
///
/// Extracted from the common pattern found in all 6 connectors.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HttpRetryConfig {
    /// Maximum retry attempts after the initial request.
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds.
    pub initial_delay_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub max_delay_ms: u64,
    /// Whether to add jitter to backoff delays.
    pub jitter_enabled: bool,
}

impl Default for HttpRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            jitter_enabled: true,
        }
    }
}

impl HttpRetryConfig {
    /// Convert to a [`RetryPolicy`].
    #[must_use]
    pub fn to_retry_policy(&self) -> RetryPolicy {
        let max_attempts = if self.max_retries == u32::MAX {
            None
        } else {
            Some(self.max_retries + 1)
        };

        RetryPolicy::new()
            .with_base_backoff_ms(self.initial_delay_ms)
            .with_max_backoff_ms(self.max_delay_ms)
            .with_jitter_enabled(self.jitter_enabled)
            .with_max_attempts(max_attempts)
    }
}

/// Classify an HTTP status code into a retry decision with standard FCP semantics.
///
/// This is the canonical classification used across all connectors:
/// - 429 → Retry after hint (or 30s default)
/// - 408, 425, 500-599 → Backoff
/// - Everything else → Terminal
#[must_use]
pub fn classify_http_status(status: u16, retry_after: Option<Duration>) -> RetryDecision {
    crate::retry::decision_from_http_status(status, retry_after)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Replay safety (br-kxd3e) ─────────────────────────────────

    /// `Retryable` is a claim about SIDE EFFECTS, not about how transient the
    /// error looks. When a replay could duplicate one, the honest outcome is a
    /// single terminal error rather than up to `max_retries` more executions.
    #[test]
    fn retryable_if_replayable_downgrades_an_unsafe_replay_to_terminal() {
        let unsafe_replay: AttemptOutcome<(), &str> =
            AttemptOutcome::retryable_if_replayable("boom", Some(Duration::from_secs(1)), false);
        assert!(
            matches!(unsafe_replay, AttemptOutcome::Terminal("boom")),
            "a non-replayable failure must not be retried"
        );

        let safe_replay: AttemptOutcome<(), &str> =
            AttemptOutcome::retryable_if_replayable("boom", Some(Duration::from_secs(1)), true);
        assert!(matches!(
            safe_replay,
            AttemptOutcome::Retryable {
                error: "boom",
                retry_after: Some(_)
            }
        ));
    }

    /// Only the connection-establishment failures prove no request bytes were
    /// written. These are the variants a non-idempotent operation may replay.
    #[test]
    fn http_client_error_pre_transmission_variants_did_not_reach_the_service() {
        let pre_transmission = [
            HttpClientError::InvalidUrl("not a url".to_string()),
            HttpClientError::DnsError(std::io::Error::other("nxdomain")),
            HttpClientError::ConnectError(std::io::Error::other("refused")),
            HttpClientError::TlsError("handshake failed".to_string()),
            HttpClientError::ConnectTunnelRefused {
                status: 403,
                reason: "Forbidden".to_string(),
            },
            HttpClientError::InvalidConnectInput("bad authority".to_string()),
            HttpClientError::ProxyError("SOCKS5 auth rejected".to_string()),
            HttpClientError::PoolExhausted {
                host: "api.example.com".to_string(),
                port: 443,
            },
        ];

        for error in &pre_transmission {
            assert!(
                !http_client_error_reached_service(error),
                "{error:?} is raised while connecting, so no request bytes were written"
            );
        }
    }

    /// Everything else may be observed after the body was fully sent, so a
    /// non-idempotent operation must treat it as "may already have executed".
    #[test]
    fn http_client_error_post_transmission_variants_may_have_reached_the_service() {
        let may_have_reached = [
            // A mid-body write failure and a response-read failure are the
            // same variant; only the latter proves transmission, so both must
            // fail closed.
            HttpClientError::Io(std::io::Error::other("connection reset")),
            // Redirects imply the service answered at least once.
            HttpClientError::TooManyRedirects { count: 11, max: 10 },
            // Cancellation can land at any point, including post-send.
            HttpClientError::Cancelled,
        ];

        for error in &may_have_reached {
            assert!(
                http_client_error_reached_service(error),
                "{error:?} can occur after transmission and must fail closed"
            );
        }
    }

    #[cfg(feature = "connector-http")]
    fn br_b0qqv_host_egress_context(
        operation_id: &str,
        request_id: &str,
    ) -> fcp_manifest::HostEgressContext {
        fcp_manifest::HostEgressContext {
            connector_id: "fcp.test.b0qqv:utility:1.0.0".to_string(),
            operation_id: operation_id.to_string(),
            zone_id: "z:work".to_string(),
            request_id: request_id.to_string(),
            correlation_id: Some(format!("corr-{request_id}")),
            capability_token_cbor_b64: "capability-material-redaction-sentinel".to_string(),
        }
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_http_request_serialization_preserves_strict_contract() {
        let request = HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-b0qqv-http"),
            url: "https://api.example.test/v1/messages".to_string(),
            method: "POST".to_string(),
            headers: vec![fcp_manifest::HostEgressHttpHeader {
                name: "x-fcp-request".to_string(),
                value: "req-b0qqv-http".to_string(),
            }],
            body: Some(fcp_manifest::Base64Bytes::from_vec(
                br#"{"message":"hello"}"#.to_vec(),
            )),
            credential_id: Some("cred-b0qqv-redacted-id".to_string()),
        };

        let value = serde_json::to_value(&request).expect("serialize HTTP host-egress request");
        assert_eq!(
            value["context"]["connector_id"],
            "fcp.test.b0qqv:utility:1.0.0"
        );
        assert_eq!(value["context"]["operation_id"], "messages.create");
        assert_eq!(value["context"]["zone_id"], "z:work");
        assert_eq!(value["context"]["request_id"], "req-b0qqv-http");
        assert_eq!(value["context"]["correlation_id"], "corr-req-b0qqv-http");
        assert_eq!(value["url"], "https://api.example.test/v1/messages");
        assert_eq!(value["method"], "POST");
        assert_eq!(value["headers"][0]["name"], "x-fcp-request");
        assert_eq!(value["headers"][0]["value"], "req-b0qqv-http");
        assert_eq!(value["body"], "base64:eyJtZXNzYWdlIjoiaGVsbG8ifQ==");
        assert_eq!(value["credential_id"], "cred-b0qqv-redacted-id");

        let decoded: HostEgressHttpRequest =
            serde_json::from_value(value).expect("decode HTTP host-egress request");
        assert_eq!(
            decoded.body.expect("request body").as_bytes(),
            br#"{"message":"hello"}"#
        );
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_tcp_request_serialization_preserves_strict_contract() {
        let request = HostEgressTcpRequest {
            context: br_b0qqv_host_egress_context("socket.exchange", "req-b0qqv-tcp"),
            host: "api.example.test".to_string(),
            port: 443,
            tls: true,
            sni_override: Some("api.example.test".to_string()),
            write: Some(fcp_manifest::Base64Bytes::from_vec(b"PING".to_vec())),
            read_limit_bytes: Some(1024),
            credential_id: Some("cred-b0qqv-redacted-id".to_string()),
        };

        let value = serde_json::to_value(&request).expect("serialize TCP host-egress request");
        assert_eq!(value["context"]["operation_id"], "socket.exchange");
        assert_eq!(value["context"]["request_id"], "req-b0qqv-tcp");
        assert_eq!(value["host"], "api.example.test");
        assert_eq!(value["port"], 443);
        assert_eq!(value["tls"], true);
        assert_eq!(value["sni_override"], "api.example.test");
        assert_eq!(value["write"], "base64:UElORw==");
        assert_eq!(value["read_limit_bytes"], 1024);
        assert_eq!(value["credential_id"], "cred-b0qqv-redacted-id");

        let decoded: HostEgressTcpRequest =
            serde_json::from_value(value).expect("decode TCP host-egress request");
        assert_eq!(decoded.write.expect("write payload").as_bytes(), b"PING");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_rejection_redacts_request_material() {
        let request = HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-b0qqv-redact"),
            url: "https://api.example.test/v1/messages?proof_marker=url-redaction-sentinel"
                .to_string(),
            method: "POST".to_string(),
            headers: vec![fcp_manifest::HostEgressHttpHeader {
                name: "authorization".to_string(),
                value: "Bearer header-redaction-sentinel".to_string(),
            }],
            body: Some(fcp_manifest::Base64Bytes::from_vec(
                b"body-redaction-sentinel".to_vec(),
            )),
            credential_id: Some("credential-redaction-sentinel".to_string()),
        };
        let echoed_body = "deny_reason=denied_host; capability-material-redaction-sentinel; \
            https://api.example.test/v1/messages?proof_marker=url-redaction-sentinel; \
            Bearer header-redaction-sentinel; body-redaction-sentinel; \
            base64:Ym9keS1yZWRhY3Rpb24tc2VudGluZWw=; credential-redaction-sentinel";

        let redacted = redact_http_host_egress_rejection_body(&request, echoed_body.to_string());
        assert!(redacted.contains("deny_reason=denied_host"));
        for leaked in [
            "capability-material-redaction-sentinel",
            "url-redaction-sentinel",
            "header-redaction-sentinel",
            "body-redaction-sentinel",
            "base64:Ym9keS1yZWRhY3Rpb24tc2VudGluZWw=",
            "credential-redaction-sentinel",
        ] {
            assert!(
                !redacted.contains(leaked),
                "redacted rejection body leaked {leaked}: {redacted}"
            );
        }

        let error = HostEgressProxyError::Rejected {
            status: 403,
            body: redacted,
        };
        assert_eq!(error.status(), Some(403));
        assert!(
            error
                .rejection_body()
                .expect("rejection body")
                .contains("deny_reason=denied_host")
        );
    }

    #[cfg(feature = "connector-http")]
    fn host_egress_test_http_request() -> HostEgressHttpRequest {
        HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-bounded-http"),
            url: "https://api.example.test/messages".to_string(),
            method: "POST".to_string(),
            headers: vec![fcp_manifest::HostEgressHttpHeader {
                name: "authorization".to_string(),
                value: "Bearer header-secret-sentinel".to_string(),
            }],
            body: Some(fcp_manifest::Base64Bytes::from_vec(
                b"request-body-secret-sentinel".to_vec(),
            )),
            credential_id: Some("credential-secret-sentinel".to_string()),
        }
    }

    #[cfg(feature = "connector-http")]
    fn host_egress_test_metadata(context: &HostEgressContext) -> HostEgressDecisionMetadata {
        HostEgressDecisionMetadata {
            connector_id: context.connector_id.clone(),
            operation_id: context.operation_id.clone(),
            zone_id: context.zone_id.clone(),
            request_id: context.request_id.clone(),
            correlation_id: context.correlation_id.clone(),
            execution_mode: "host_egress_proxy".to_string(),
            constraint_source: "managed_connector_config.operation_network_constraints".to_string(),
            decision: "allow".to_string(),
            resolved_host: "api.example.test".to_string(),
            resolved_port: 443,
            credential_injected: true,
            elapsed_ms: 1,
        }
    }

    #[cfg(feature = "connector-http")]
    fn host_egress_test_http_response(request: &HostEgressHttpRequest) -> HostEgressHttpResponse {
        HostEgressHttpResponse {
            status: 201,
            headers: Vec::new(),
            body: fcp_manifest::Base64Bytes::from_vec(b"created".to_vec()),
            egress: host_egress_test_metadata(&request.context),
        }
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_rejects_unsafe_endpoint_and_unbounded_configuration() {
        for url in [
            "not-a-url-secret-sentinel",
            "file:///tmp/secret-sentinel",
            "https://secret-sentinel:password@host.test/",
            "https://host.test/?token=secret-sentinel",
            "https://host.test/#secret-sentinel",
        ] {
            let error = HostEgressProxyClient::new(url).expect_err("unsafe endpoint");
            assert!(matches!(
                error,
                HostEgressProxyError::InvalidConfiguration(_)
            ));
            assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
        }
        let client =
            HostEgressProxyClient::new("https://host.test/prefix/").expect("valid endpoint");
        assert_eq!(
            client.http_endpoint(),
            "https://host.test/prefix/rpc/egress/http"
        );
        assert_eq!(
            client.tcp_endpoint(),
            "https://host.test/prefix/rpc/egress/tcp"
        );
        assert!(!format!("{client:?}").contains("host.test"));
        assert!(client.clone().with_timeout(Duration::ZERO).is_err());
        assert!(client.clone().with_timeout(Duration::MAX).is_err());
        assert!(client.with_max_response_bytes(0).is_err());
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_binds_http_and_tcp_results_to_the_exact_call() {
        fcp_async_core::runtime::block_on_sync(async {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            let request = host_egress_test_http_request();
            let expected = host_egress_test_http_response(&request);
            let body = serde_json::to_vec(&expected).expect("serialize response");
            Mock::given(method("POST"))
                .and(path("/rpc/egress/http"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let client = HostEgressProxyClient::new(server.uri())
                .expect("proxy client")
                .with_max_response_bytes(body.len())
                .expect("exact response boundary");
            assert_eq!(
                client.http(&request).await.expect("HTTP response"),
                expected
            );

            let tcp_request = HostEgressTcpRequest {
                context: br_b0qqv_host_egress_context("socket.exchange", "req-bounded-tcp"),
                host: "api.example.test".to_string(),
                port: 443,
                tls: true,
                sni_override: None,
                write: Some(fcp_manifest::Base64Bytes::from_vec(b"PING".to_vec())),
                read_limit_bytes: Some(4),
                credential_id: None,
            };
            let tcp_expected = HostEgressTcpResponse {
                bytes_written: 4,
                bytes_read: 4,
                read: fcp_manifest::Base64Bytes::from_vec(b"PONG".to_vec()),
                egress: host_egress_test_metadata(&tcp_request.context),
            };
            Mock::given(method("POST"))
                .and(path("/rpc/egress/tcp"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&tcp_expected))
                .expect(1)
                .mount(&server)
                .await;
            let tcp_client = HostEgressProxyClient::new(server.uri()).expect("TCP proxy client");
            assert_eq!(
                tcp_client.tcp(&tcp_request).await.expect("TCP response"),
                tcp_expected
            );
            let requests = server.received_requests().await.expect("captured requests");
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[0]
                    .body_json::<HostEgressHttpRequest>()
                    .expect("HTTP request"),
                request
            );
            assert_eq!(
                requests[1]
                    .body_json::<HostEgressTcpRequest>()
                    .expect("TCP request"),
                tcp_request
            );
        })
        .expect("host egress response runtime");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_rejects_mismatched_or_malformed_authority_without_echoing_it() {
        fcp_async_core::runtime::block_on_sync(async {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            let client = HostEgressProxyClient::new(server.uri()).expect("proxy client");
            let request = host_egress_test_http_request();
            for field in [
                "connector_id", "operation_id", "zone_id", "request_id", "correlation_id",
                "decision", "execution_mode",
            ] {
                let mut response = serde_json::to_value(host_egress_test_http_response(&request))
                    .expect("response JSON");
                response["egress"][field] = serde_json::json!("another-request-secret-sentinel");
                let _guard = Mock::given(method("POST"))
                    .and(path("/rpc/egress/http"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .expect(1)
                    .mount_as_scoped(&server)
                    .await;
                let error = client.http(&request).await.expect_err("mismatched response");
                assert!(matches!(error, HostEgressProxyError::InvalidResponse(reason) if reason == field));
                assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
            }
            let _guard = Mock::given(method("POST"))
                .and(path("/rpc/egress/http"))
                .respond_with(ResponseTemplate::new(200).set_body_string(
                    r#"{"status":"unexpected-secret-sentinel"}"#,
                ))
                .expect(1)
                .mount_as_scoped(&server)
                .await;
            let error = client.http(&request).await.expect_err("invalid response contract");
            assert!(matches!(error, HostEgressProxyError::InvalidResponse(_)));
            assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
        })
        .expect("host egress identity runtime");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_does_not_redirect_capabilities_or_payloads() {
        fcp_async_core::runtime::block_on_sync(async {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            let redirected = MockServer::start().await;
            let request = host_egress_test_http_request();
            let client = HostEgressProxyClient::new(server.uri()).expect("proxy client");
            for status in [307, 308] {
                let _guard = Mock::given(method("POST"))
                    .and(path("/rpc/egress/http"))
                    .respond_with(
                        ResponseTemplate::new(status)
                            .insert_header("Location", redirected.uri())
                            .set_body_string(format!(
                                "redirect denied: {}; {}; {}; {}",
                                request.context.capability_token_cbor_b64,
                                request.headers[0].value,
                                request.credential_id.as_deref().expect("credential"),
                                "request-body-secret-sentinel",
                            )),
                    )
                    .expect(1)
                    .mount_as_scoped(&server)
                    .await;
                let error = client.http(&request).await.expect_err("redirect rejected");
                assert_eq!(error.status(), Some(status));
                let diagnostic = format!("{error:?} {error}");
                assert!(!diagnostic.contains("secret-sentinel"));
                assert!(!diagnostic.contains("capability-material-redaction-sentinel"));
            }
            assert!(
                redirected
                    .received_requests()
                    .await
                    .expect("redirect capture")
                    .is_empty()
            );
        })
        .expect("host egress redirect runtime");
    }

    #[cfg(feature = "connector-http")]
    fn host_egress_test_raw_server(
        prefix: Vec<u8>,
        pause: Duration,
        suffix: Vec<u8>,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("raw proxy listener");
        let address = listener.local_addr().expect("proxy address");
        listener.set_nonblocking(true).expect("bounded accept");
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "proxy was not contacted"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("raw proxy accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read bound");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("write bound");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("request bytes");
                assert!(read > 0, "request ended before body");
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() < 64 * 1024, "bounded test request");
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("request length"))
                        })
                        .expect("content length");
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(&prefix).expect("response prefix");
            if !pause.is_zero() {
                std::thread::sleep(pause);
            }
            // The client may already have rejected the size or deadline.
            let _ = stream.write_all(&suffix);
        });
        (format!("http://{address}"), thread)
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_bounds_declared_streamed_and_rejection_bodies() {
        fcp_async_core::runtime::block_on_sync(async {
            let request = host_egress_test_http_request();
            for response in [
                b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n".to_vec(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n".to_vec(),
                b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n".to_vec(),
            ] {
                let (url, server) = host_egress_test_raw_server(response, Duration::ZERO, Vec::new());
                let client = HostEgressProxyClient::new(url)
                    .expect("proxy client")
                    .with_max_response_bytes(20)
                    .expect("bounded response");
                let error = client.http(&request).await.expect_err("oversized response");
                assert!(matches!(error, HostEgressProxyError::ResponseTooLarge { limit: 20 }));
                server.join().expect("raw proxy completed");
            }

            let (url, server) = host_egress_test_raw_server(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 65537\r\n\r\n".to_vec(),
                Duration::ZERO,
                Vec::new(),
            );
            let client = HostEgressProxyClient::new(url).expect("default proxy client");
            let error = client.http(&request).await.expect_err("rejection cap");
            assert!(matches!(error, HostEgressProxyError::ResponseTooLarge { limit: 65_536 }));
            server.join().expect("rejection proxy completed");
        })
        .expect("host egress bounds runtime");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_deadline_includes_success_and_error_body_reads() {
        fcp_async_core::runtime::block_on_sync(async {
            let request = host_egress_test_http_request();
            for status in [200, 403] {
                let (url, server) = host_egress_test_raw_server(
                    format!("HTTP/1.1 {status} Test\r\nContent-Length: 100\r\n\r\n{{").into_bytes(),
                    Duration::from_millis(250),
                    vec![b' '; 99],
                );
                let runtime = crate::runtime::ConnectorRuntime::new(
                    crate::runtime::ConnectorRuntimeConfig::default()
                        .with_request_timeout(Duration::from_millis(40))
                        .with_host_egress_proxy_url(url),
                );
                let client = runtime.host_egress_proxy_client()
                    .expect("bounded runtime client")
                    .expect("configured proxy");
                let started = std::time::Instant::now();
                let error = client.http(&request).await.expect_err("stalled body");
                assert!(matches!(error, HostEgressProxyError::Transport(ref source) if source.is_timeout()));
                assert!(started.elapsed() < Duration::from_secs(2));
                assert!(!format!("{error:?} {error}").contains("127.0.0.1"));
                server.join().expect("stalled proxy completed");
            }
        })
        .expect("host egress deadline runtime");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn host_egress_client_rejects_tcp_accounting_and_cross_request_results() {
        fcp_async_core::runtime::block_on_sync(async {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            let client = HostEgressProxyClient::new(server.uri()).expect("proxy client");
            let request = HostEgressTcpRequest {
                context: br_b0qqv_host_egress_context("socket.exchange", "req-bounded-tcp"),
                host: "api.example.test".to_string(),
                port: 443,
                tls: true,
                sni_override: None,
                write: None,
                read_limit_bytes: Some(4),
                credential_id: None,
            };
            for (bytes_read, read, replace_request) in [
                (3, b"PONG".as_slice(), false),
                (5, b"PONG!".as_slice(), false),
                (4, b"PONG".as_slice(), true),
            ] {
                let mut metadata = host_egress_test_metadata(&request.context);
                if replace_request {
                    metadata.request_id = "different-request-secret-sentinel".to_string();
                }
                let response = HostEgressTcpResponse {
                    bytes_written: 0,
                    bytes_read,
                    read: fcp_manifest::Base64Bytes::from_vec(read.to_vec()),
                    egress: metadata,
                };
                let _guard = Mock::given(method("POST"))
                    .and(path("/rpc/egress/tcp"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .expect(1)
                    .mount_as_scoped(&server)
                    .await;
                let error = client
                    .tcp(&request)
                    .await
                    .expect_err("invalid TCP response");
                assert!(matches!(error, HostEgressProxyError::InvalidResponse(_)));
                assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
            }
        })
        .expect("host egress TCP validation runtime");
    }

    // -- HttpRetryConfig tests ------------------------------------------------

    #[test]
    fn http_retry_config_defaults() {
        let config = HttpRetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!(config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_to_policy() {
        let config = HttpRetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(6));
        assert_eq!(policy.base_backoff_ms, 1000);
        assert_eq!(policy.max_backoff_ms, 60_000);
        assert!(!policy.jitter_enabled);
    }

    // -- classify_http_status tests -------------------------------------------

    #[test]
    fn classify_429_retries() {
        let decision = classify_http_status(429, None);
        assert!(decision.is_retryable());
        assert!(decision.retry_after().is_some());
    }

    #[test]
    fn classify_500_backoff() {
        let decision = classify_http_status(500, None);
        assert!(decision.is_retryable());
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn classify_401_terminal() {
        let decision = classify_http_status(401, None);
        assert!(!decision.is_retryable());
        assert_eq!(decision, RetryDecision::Terminal);
    }

    // -- map_async_to_fcp_error tests -----------------------------------------

    #[test]
    fn map_timeout_to_fcp() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(504));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_to_fcp() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("cancelled"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- RetryLoop tests (async) -----------------------------------------------

    #[test]
    fn retry_loop_succeeds_first_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(3));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Success("ok")
                })
                .await;

            assert_eq!(result.unwrap(), "ok");
        })
        .expect("runtime should execute first-attempt retry test");
    }

    #[test]
    fn retry_loop_retries_then_succeeds() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt < 2 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("try again".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("finally")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "finally");
        })
        .expect("runtime should execute retry-then-success test");
    }

    #[test]
    fn retry_loop_terminal_error_stops() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(5));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Terminal(TestError::Fatal("auth failed".into()))
                })
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                TestError::Fatal(msg) => assert_eq!(msg, "auth failed"),
                other => panic!("expected Fatal, got {other:?}"),
            }
        })
        .expect("runtime should execute terminal-error retry test");
    }

    #[test]
    fn retry_loop_max_attempts_exhausted() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(2))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("still failing".into()),
                        retry_after: None,
                    }
                })
                .await;

            assert!(result.is_err());
        })
        .expect("runtime should execute max-attempts retry test");
    }

    #[test]
    fn retry_loop_preserves_retryable_error_when_deadline_expires_during_backoff() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_millis(5));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("service overloaded".into()),
                        retry_after: Some(Duration::from_millis(50)),
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Transient(message) => assert_eq!(message, "service overloaded"),
                other => panic!("expected original retryable error, got {other:?}"),
            }
        })
        .expect("runtime should preserve retryable error on backoff deadline expiry");
    }

    #[test]
    fn retry_loop_respects_cancellation() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(10))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            // Cancel the context immediately
            ctx.cancel();

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("won't get here".into()),
                        retry_after: None,
                    }
                })
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                TestError::Cancelled => {}
                other => panic!("expected Cancelled, got {other:?}"),
            }
        })
        .expect("runtime should execute cancellation-aware retry test");
    }

    // -- HttpRetryConfig serde tests ------------------------------------------

    #[test]
    fn http_retry_config_serde_roundtrip() {
        let config = HttpRetryConfig {
            max_retries: 7,
            initial_delay_ms: 250,
            max_delay_ms: 15_000,
            jitter_enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HttpRetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_retries, 7);
        assert_eq!(deserialized.initial_delay_ms, 250);
        assert_eq!(deserialized.max_delay_ms, 15_000);
        assert!(!deserialized.jitter_enabled);
    }

    #[test]
    fn http_retry_config_serde_default_from_empty() {
        let deserialized: HttpRetryConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(deserialized.max_retries, 3);
        assert_eq!(deserialized.initial_delay_ms, 500);
        assert_eq!(deserialized.max_delay_ms, 30_000);
        assert!(deserialized.jitter_enabled);
    }

    #[test]
    fn http_retry_config_debug_and_clone() {
        let config = HttpRetryConfig::default();
        let cloned = config.clone();
        let debug = format!("{config:?}");
        assert!(debug.contains("HttpRetryConfig"));
        assert_eq!(cloned.max_retries, config.max_retries);
    }

    // -- classify_http_status additional tests --------------------------------

    #[test]
    fn classify_408_backoff() {
        assert_eq!(classify_http_status(408, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_425_backoff() {
        assert_eq!(classify_http_status(425, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_503_backoff() {
        assert_eq!(classify_http_status(503, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_200_terminal() {
        assert_eq!(classify_http_status(200, None), RetryDecision::Terminal);
    }

    #[test]
    fn classify_429_with_custom_retry_after() {
        let hint = Duration::from_secs(60);
        let decision = classify_http_status(429, Some(hint));
        assert_eq!(decision, RetryDecision::After(hint));
    }

    // -- map_async_to_fcp_error additional tests ------------------------------

    #[test]
    fn map_runtime_error_to_fcp_internal() {
        let err = AsyncError::Runtime {
            message: "thread pool exhausted".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("thread pool exhausted"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_protocol_io_error_to_fcp_internal() {
        let err = AsyncError::ProtocolIo {
            message: "broken pipe".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("broken pipe"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_closed_to_fcp_internal() {
        let err = AsyncError::ChannelClosed;
        let fcp_err = map_async_to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn map_timeout_message_contains_ms() {
        let err = AsyncError::Timeout { timeout_ms: 12_345 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("12345"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_not_retryable() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retryable, .. } => {
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- RetryLoop additional tests -------------------------------------------

    #[test]
    fn retry_loop_with_explicit_retry_after() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("rate limited".into()),
                            retry_after: Some(Duration::from_millis(50)),
                        }
                    } else {
                        AttemptOutcome::Success("recovered")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "recovered");
        })
        .expect("runtime should execute retry-after retry test");
    }

    #[test]
    fn retry_loop_max_attempts_zero() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(0));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Success("should not run")
                })
                .await;

            // With 0 max attempts, no attempt runs
            assert!(result.is_err());
        })
        .expect("runtime should execute zero-max-attempts test");
    }

    // -- TestError and ConnectorErrorMapping coverage --------------------------

    #[test]
    fn test_error_display_all_variants() {
        assert_eq!(
            TestError::Transient("oops".into()).to_string(),
            "transient: oops"
        );
        assert_eq!(TestError::Fatal("bad".into()).to_string(), "fatal: bad");
        assert_eq!(
            TestError::DeadlineExceeded("5s".into()).to_string(),
            "deadline: 5s"
        );
        assert_eq!(TestError::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_error_from_async_timeout() {
        let err = TestError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        match err {
            TestError::DeadlineExceeded(msg) => assert!(msg.contains("3000")),
            other => panic!("expected DeadlineExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_cancelled() {
        let err = TestError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TestError::Cancelled));
    }

    #[test]
    fn test_error_from_async_runtime() {
        let err = TestError::from_async_error(AsyncError::Runtime {
            message: "pool died".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("pool died")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_channel_closed() {
        let err = TestError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, TestError::Fatal(_)));
    }

    #[test]
    fn test_error_to_fcp_all_variants() {
        let transient = TestError::Transient("net".into());
        assert!(matches!(
            transient.to_fcp_error(),
            FcpError::Internal { .. }
        ));

        let fatal = TestError::Fatal("auth".into());
        assert!(matches!(fatal.to_fcp_error(), FcpError::Internal { .. }));

        let deadline = TestError::DeadlineExceeded("5s".into());
        assert!(matches!(deadline.to_fcp_error(), FcpError::External { .. }));

        let cancelled = TestError::Cancelled;
        assert!(matches!(
            cancelled.to_fcp_error(),
            FcpError::External { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(TestError::Transient("x".into()).is_retryable());
        assert!(!TestError::Fatal("x".into()).is_retryable());
        assert!(!TestError::DeadlineExceeded("x".into()).is_retryable());
        assert!(!TestError::Cancelled.is_retryable());
    }

    #[test]
    fn test_error_retry_after_default_none() {
        let err = TestError::Transient("x".into());
        assert!(err.retry_after().is_none());
    }

    // -- AttemptOutcome coverage ----------------------------------------------

    #[test]
    fn attempt_outcome_success_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Success(42);
        match outcome {
            AttemptOutcome::Success(v) => assert_eq!(v, 42),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Retryable {
            error: "transient".into(),
            retry_after: Some(Duration::from_secs(5)),
        };
        match outcome {
            AttemptOutcome::Retryable { error, retry_after } => {
                assert_eq!(error, "transient");
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_terminal_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Terminal("fatal".into());
        match outcome {
            AttemptOutcome::Terminal(e) => assert_eq!(e, "fatal"),
            _ => panic!("expected Terminal"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_no_retry_after() {
        let outcome: AttemptOutcome<(), &str> = AttemptOutcome::Retryable {
            error: "err",
            retry_after: None,
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => assert!(retry_after.is_none()),
            _ => panic!("expected Retryable"),
        }
    }

    // -- NEW: HttpRetryConfig edge cases --------------------------------------

    #[test]
    fn http_retry_config_zero_retries_policy() {
        let config = HttpRetryConfig {
            max_retries: 0,
            initial_delay_ms: 100,
            max_delay_ms: 1000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(1));
        // With 0 retries, the initial request still runs but no retry delay is produced.
        assert!(policy.next_delay(0, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn http_retry_config_max_retries_one() {
        let config = HttpRetryConfig {
            max_retries: 1,
            initial_delay_ms: 200,
            max_delay_ms: 5000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(2));
        assert!(policy.next_delay(0, RetryDecision::Backoff, None).is_some());
        assert!(policy.next_delay(1, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn http_retry_config_serde_partial_override() {
        let json = r#"{"max_retries": 10}"#;
        let config: HttpRetryConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_retries, 10);
        // Other fields should use defaults
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!(config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_serde_jitter_false() {
        let json = r#"{"jitter_enabled": false}"#;
        let config: HttpRetryConfig = serde_json::from_str(json).unwrap();
        assert!(!config.jitter_enabled);
        // Other fields should use defaults
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn http_retry_config_serde_roundtrip_all_fields() {
        let config = HttpRetryConfig {
            max_retries: 11,
            initial_delay_ms: 123,
            max_delay_ms: 45_678,
            jitter_enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: HttpRetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_retries, config.max_retries);
        assert_eq!(back.initial_delay_ms, config.initial_delay_ms);
        assert_eq!(back.max_delay_ms, config.max_delay_ms);
        assert_eq!(back.jitter_enabled, config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_large_values() {
        let config = HttpRetryConfig {
            max_retries: u32::MAX,
            initial_delay_ms: u64::MAX,
            max_delay_ms: u64::MAX,
            jitter_enabled: true,
        };
        let policy = config.to_retry_policy();
        assert!(policy.max_attempts.is_none());
        assert_eq!(policy.base_backoff_ms, u64::MAX);
    }

    #[test]
    fn http_retry_config_policy_jitter_flag_propagates() {
        let config_with = HttpRetryConfig {
            jitter_enabled: true,
            ..HttpRetryConfig::default()
        };
        let config_without = HttpRetryConfig {
            jitter_enabled: false,
            ..HttpRetryConfig::default()
        };
        assert!(config_with.to_retry_policy().jitter_enabled);
        assert!(!config_without.to_retry_policy().jitter_enabled);
    }

    // -- NEW: classify_http_status comprehensive edge cases -------------------

    #[test]
    fn classify_all_5xx_range() {
        for status in 500..=599 {
            let decision = classify_http_status(status, None);
            assert!(
                decision.is_retryable(),
                "status {status} should be retryable"
            );
        }
    }

    #[test]
    fn classify_non_retryable_4xx_codes() {
        for status in [400, 401, 402, 403, 404, 405, 406, 409, 410, 422] {
            let decision = classify_http_status(status, None);
            assert_eq!(
                decision,
                RetryDecision::Terminal,
                "status {status} should be terminal"
            );
        }
    }

    #[test]
    fn classify_429_default_retry_after_is_30s() {
        let decision = classify_http_status(429, None);
        assert_eq!(decision, RetryDecision::After(Duration::from_secs(30)));
    }

    #[test]
    fn classify_429_with_zero_retry_after() {
        let decision = classify_http_status(429, Some(Duration::ZERO));
        assert_eq!(decision, RetryDecision::After(Duration::ZERO));
    }

    #[test]
    fn classify_200_range_terminal() {
        for status in [200, 201, 204, 301, 302, 304] {
            assert_eq!(
                classify_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be terminal"
            );
        }
    }

    // -- NEW: map_async_to_fcp_error comprehensive ----------------------------

    #[test]
    fn map_timeout_zero_ms() {
        let err = AsyncError::Timeout { timeout_ms: 0 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External {
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(504));
                assert!(retryable);
                assert!(message.contains('0'));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_large_ms() {
        let err = AsyncError::Timeout {
            timeout_ms: 999_999,
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("999999"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_has_no_status_code() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { status_code, .. } => {
                assert!(status_code.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_service_is_runtime() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { service, .. } => {
                assert_eq!(service, "runtime");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_full_to_fcp_internal() {
        let err = AsyncError::ChannelFull;
        let fcp_err = map_async_to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn map_join_error_to_fcp_internal() {
        let err = AsyncError::Join {
            message: "task panicked".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("task panicked"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_is_retryable_timeout() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_has_no_retry_after() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- NEW: RetryLoop advanced tests ----------------------------------------

    #[test]
    fn retry_loop_single_attempt_policy() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(1))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("first fail".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("should not reach")
                    }
                })
                .await;

            // Only 1 attempt allowed, so retry is not permitted
            assert!(result.is_err());
        })
        .expect("runtime should execute single-attempt test");
    }

    #[test]
    fn retry_loop_terminal_on_second_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("transient".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(TestError::Fatal("permanent".into()))
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Fatal(msg) => assert_eq!(msg, "permanent"),
                other => panic!("expected Fatal, got {other:?}"),
            }
        })
        .expect("runtime should execute terminal-on-second test");
    }

    #[test]
    fn retry_loop_success_on_last_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt < 2 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("not yet".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("made it")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "made it");
        })
        .expect("runtime should execute success-on-last test");
    }

    #[test]
    fn retry_loop_unlimited_attempts_succeeds() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(None)
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt < 5 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("keep going".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("unlimited works")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "unlimited works");
        })
        .expect("runtime should execute unlimited-attempts test");
    }

    #[test]
    fn retry_loop_unlimited_attempts_stop_at_u32_max_without_repeating_attempt() {
        use std::sync::{Arc, Mutex};

        fcp_async_core::runtime::block_on_sync(async {
            // Background context (no deadline) — this test validates that the
            // retry loop stops at the u32::MAX attempt ceiling, not deadline
            // enforcement. A request-scoped deadline races with tokio's 0ms
            // sleep and causes spurious DeadlineExceeded failures.
            let ctx = ExecutionContext::background();
            let policy = RetryPolicy::new()
                .with_max_attempts(None)
                .with_base_backoff_ms(0)
                .with_jitter_enabled(false);
            let seen_attempts = Arc::new(Mutex::new(Vec::new()));

            let result: Result<&str, TestError> =
                RetryLoop::execute_from_attempt(&ctx, &policy, u32::MAX - 1, {
                    let seen_attempts = Arc::clone(&seen_attempts);
                    move |attempt| {
                        let seen_attempts = Arc::clone(&seen_attempts);
                        async move {
                            seen_attempts.lock().unwrap().push(attempt);
                            AttemptOutcome::Retryable {
                                error: TestError::Transient(format!("attempt {attempt}")),
                                retry_after: None,
                            }
                        }
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Transient(message) => {
                    assert!(message.contains(&u32::MAX.to_string()));
                }
                other => panic!("expected Transient, got {other:?}"),
            }
            assert_eq!(
                seen_attempts.lock().unwrap().as_slice(),
                &[u32::MAX - 1, u32::MAX]
            );
        })
        .expect("runtime should stop unlimited retries at the u32 attempt ceiling");
    }

    // -- NEW: ConnectorErrorMapping trait coverage -----------------------------

    #[test]
    fn test_error_from_async_protocol_io() {
        let err = TestError::from_async_error(AsyncError::ProtocolIo {
            message: "socket reset".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("socket reset")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_channel_full() {
        let err = TestError::from_async_error(AsyncError::ChannelFull);
        assert!(matches!(err, TestError::Fatal(_)));
    }

    #[test]
    fn test_error_from_async_join() {
        let err = TestError::from_async_error(AsyncError::Join {
            message: "task panicked".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("task panicked")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_transient_maps_to_internal() {
        let err = TestError::Transient("network flap".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("network flap"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_deadline_maps_to_retryable_timeout() {
        let err = TestError::DeadlineExceeded("10s".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(504));
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_cancelled_maps_to_external() {
        let err = TestError::Cancelled;
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("cancelled"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = TestError::Transient("test msg".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Transient"));
        assert!(debug.contains("test msg"));
    }

    #[test]
    fn test_error_display_cancelled() {
        let err = TestError::Cancelled;
        assert_eq!(err.to_string(), "cancelled");
    }

    #[test]
    fn test_error_display_deadline() {
        let err = TestError::DeadlineExceeded("timeout after 5s".into());
        let display = err.to_string();
        assert!(display.contains("deadline"));
        assert!(display.contains("timeout after 5s"));
    }

    // -- NEW: AttemptOutcome additional coverage --------------------------------

    #[test]
    fn attempt_outcome_success_with_complex_type() {
        let outcome: AttemptOutcome<Vec<u8>, String> = AttemptOutcome::Success(vec![1, 2, 3]);
        match outcome {
            AttemptOutcome::Success(v) => assert_eq!(v.len(), 3),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_with_large_retry_after() {
        let outcome: AttemptOutcome<(), String> = AttemptOutcome::Retryable {
            error: "overloaded".into(),
            retry_after: Some(Duration::from_secs(3600)),
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3600)));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_zero_retry_after() {
        let outcome: AttemptOutcome<(), String> = AttemptOutcome::Retryable {
            error: "retry now".into(),
            retry_after: Some(Duration::ZERO),
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::ZERO));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_terminal_with_structured_error() {
        #[derive(Debug, PartialEq)]
        struct DetailedError {
            code: u16,
            msg: String,
        }
        let outcome: AttemptOutcome<(), DetailedError> = AttemptOutcome::Terminal(DetailedError {
            code: 403,
            msg: "forbidden".into(),
        });
        match outcome {
            AttemptOutcome::Terminal(e) => {
                assert_eq!(e.code, 403);
                assert_eq!(e.msg, "forbidden");
            }
            _ => panic!("expected Terminal"),
        }
    }

    // -- Test error type for testing ------------------------------------------

    #[derive(Debug)]
    enum TestError {
        Transient(String),
        Fatal(String),
        DeadlineExceeded(String),
        Cancelled,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Transient(msg) => write!(f, "transient: {msg}"),
                Self::Fatal(msg) => write!(f, "fatal: {msg}"),
                Self::DeadlineExceeded(msg) => write!(f, "deadline: {msg}"),
                Self::Cancelled => write!(f, "cancelled"),
            }
        }
    }

    impl ConnectorErrorMapping for TestError {
        fn from_async_error(error: AsyncError) -> Self {
            match error {
                AsyncError::Timeout { timeout_ms } => {
                    Self::DeadlineExceeded(format!("exceeded {timeout_ms}ms"))
                }
                AsyncError::Cancelled => Self::Cancelled,
                other => Self::Fatal(other.to_string()),
            }
        }

        fn to_fcp_error(&self) -> FcpError {
            map_async_to_fcp_error(&match self {
                Self::Transient(msg) => AsyncError::ProtocolIo {
                    message: msg.clone(),
                },
                Self::Fatal(msg) => AsyncError::Runtime {
                    message: msg.clone(),
                },
                Self::DeadlineExceeded(_) => AsyncError::Timeout { timeout_ms: 0 },
                Self::Cancelled => AsyncError::Cancelled,
            })
        }

        fn is_retryable(&self) -> bool {
            matches!(self, Self::Transient(_))
        }
    }

    // ── Canonical HTTP → FCP mapping tests ──────────────────────────────────

    #[test]
    fn map_http_400_to_invalid_request() {
        let err = map_http_status(400, "test", "bad input".into());
        assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
    }

    #[test]
    fn map_http_401_to_unauthorized() {
        let err = map_http_status(401, "test", "invalid token".into());
        assert!(matches!(err, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn map_http_403_to_capability_denied() {
        let err = map_http_status(403, "test", "forbidden".into());
        assert!(matches!(err, FcpError::CapabilityDenied { .. }));
    }

    #[test]
    fn map_http_404_to_resource_not_found() {
        let err = map_http_status(404, "test", "not found".into());
        assert!(matches!(err, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn map_http_408_to_upstream_timeout() {
        let err = map_http_status(408, "api.example.com", "timeout".into());
        assert!(matches!(err, FcpError::UpstreamTimeout { .. }));
    }

    #[test]
    fn map_http_429_to_rate_limited() {
        let err = map_http_status(429, "test", "too many".into());
        assert!(matches!(
            err,
            FcpError::RateLimited {
                retry_after_ms,
                ..
            } if retry_after_ms == default_rate_limit_retry_after_ms()
        ));
    }

    #[test]
    fn map_http_500_to_external_retryable() {
        let err = map_http_status(500, "svc", "internal".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn map_http_502_to_external_retryable() {
        let err = map_http_status(502, "svc", "bad gateway".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn map_http_501_to_external_not_retryable() {
        let err = map_http_status(501, "svc", "not implemented".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn map_http_unknown_to_external() {
        let err = map_http_status(418, "svc", "teapot".into());
        assert!(matches!(err, FcpError::External { .. }));
    }

    #[test]
    fn is_http_retryable_standard_codes() {
        assert!(is_http_status_retryable(408));
        assert!(is_http_status_retryable(429));
        assert!(is_http_status_retryable(500));
        assert!(is_http_status_retryable(502));
        assert!(is_http_status_retryable(503));
        assert!(is_http_status_retryable(504));
        assert!(!is_http_status_retryable(400));
        assert!(!is_http_status_retryable(401));
        assert!(!is_http_status_retryable(404));
        assert!(!is_http_status_retryable(501));
    }

    mod retry_loop_context {
        use std::future::{Future, pending};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::*;

        type Outcome = AttemptOutcome<(), TestError>;

        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        async fn bounded(
            future: impl Future<Output = Result<(), TestError>>,
        ) -> Result<(), TestError> {
            fcp_async_core::time::timeout(Duration::from_secs(5), future)
                .await
                .expect("retry loop ignored its context and hit the watchdog")
        }

        #[fcp_async_core::runtime::test]
        async fn expired_context_does_not_call_attempt_factory() {
            let ctx = ExecutionContext::request_scoped(Duration::ZERO);
            let policy = RetryPolicy::new();
            let mut attempts = 0;

            let result = bounded(RetryLoop::execute(&ctx, &policy, |_| {
                // Deliberately outside the future: even constructing an
                // attempt must not initiate work after the deadline.
                attempts += 1;
                std::future::ready(AttemptOutcome::Success(()))
            }))
            .await;

            assert!(matches!(result, Err(TestError::DeadlineExceeded(_))));
            assert_eq!(attempts, 0);
        }

        #[fcp_async_core::runtime::test]
        async fn cancellation_precedes_expiry_without_calling_attempt_factory() {
            let ctx = ExecutionContext::request_scoped(Duration::ZERO);
            ctx.cancel();
            let policy = RetryPolicy::new();
            let mut attempts = 0;

            let result = bounded(RetryLoop::execute(&ctx, &policy, |_| {
                attempts += 1;
                std::future::ready(AttemptOutcome::Success(()))
            }))
            .await;

            assert!(matches!(result, Err(TestError::Cancelled)));
            assert_eq!(attempts, 0);
        }

        #[fcp_async_core::runtime::test]
        async fn cancellation_drops_in_flight_attempt_without_replay() {
            let ctx = ExecutionContext::background();
            let policy = RetryPolicy::new().with_max_attempts(None);
            let dropped = Arc::new(AtomicBool::new(false));
            let mut attempts = 0;

            let result = bounded(RetryLoop::execute(&ctx, &policy, |_| {
                attempts += 1;
                let guard = DropFlag(Arc::clone(&dropped));
                let cancel = ctx.clone();
                async move {
                    let _guard = guard;
                    // Cancel after admission, while the attempt is pending.
                    // No race-prone sleep or independently scheduled task.
                    cancel.cancel();
                    pending::<Outcome>().await
                }
            }))
            .await;

            assert!(matches!(result, Err(TestError::Cancelled)));
            assert_eq!(attempts, 1);
            assert!(dropped.load(Ordering::SeqCst));
        }

        #[fcp_async_core::runtime::test]
        async fn deadline_drops_in_flight_attempt_without_replay() {
            let policy = RetryPolicy::new().with_max_attempts(None);
            let dropped = Arc::new(AtomicBool::new(false));
            let mut attempts = 0;
            let ctx = ExecutionContext::request_scoped(Duration::from_millis(100));

            let result = bounded(RetryLoop::execute(&ctx, &policy, |_| {
                attempts += 1;
                let guard = DropFlag(Arc::clone(&dropped));
                async move {
                    let _guard = guard;
                    pending::<Outcome>().await
                }
            }))
            .await;

            assert!(matches!(result, Err(TestError::DeadlineExceeded(_))));
            assert_eq!(attempts, 1);
            assert!(dropped.load(Ordering::SeqCst));
        }

        #[fcp_async_core::runtime::test]
        async fn cancellation_also_bounds_later_attempts() {
            let ctx = ExecutionContext::background();
            let policy = RetryPolicy::new()
                .with_base_backoff_ms(1)
                .with_jitter_enabled(false)
                .with_max_attempts(None);
            let dropped = Arc::new(AtomicBool::new(false));
            let mut attempts = 0;

            let result = bounded(RetryLoop::execute(&ctx, &policy, |attempt| {
                attempts += 1;
                let dropped = Arc::clone(&dropped);
                let cancel = ctx.clone();
                async move {
                    if attempt == 0 {
                        return AttemptOutcome::Retryable {
                            error: TestError::Transient("connect refused".into()),
                            retry_after: None,
                        };
                    }
                    let _guard = DropFlag(dropped);
                    cancel.cancel();
                    pending::<Outcome>().await
                }
            }))
            .await;

            assert!(matches!(result, Err(TestError::Cancelled)));
            assert_eq!(attempts, 2);
            assert!(dropped.load(Ordering::SeqCst));
        }

        #[fcp_async_core::runtime::test]
        async fn deadline_also_bounds_later_attempts() {
            let policy = RetryPolicy::new()
                .with_base_backoff_ms(1)
                .with_jitter_enabled(false)
                .with_max_attempts(None);
            let dropped = Arc::new(AtomicBool::new(false));
            let mut attempts = 0;
            let ctx = ExecutionContext::request_scoped(Duration::from_millis(100));

            let result = bounded(RetryLoop::execute(&ctx, &policy, |attempt| {
                attempts += 1;
                let dropped = Arc::clone(&dropped);
                async move {
                    if attempt == 0 {
                        return AttemptOutcome::Retryable {
                            error: TestError::Transient("connect refused".into()),
                            retry_after: None,
                        };
                    }
                    let _guard = DropFlag(dropped);
                    pending::<Outcome>().await
                }
            }))
            .await;

            assert!(matches!(result, Err(TestError::DeadlineExceeded(_))));
            assert_eq!(attempts, 2);
            assert!(dropped.load(Ordering::SeqCst));
        }
    }
}
