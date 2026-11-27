//! Anthropic API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::ExecutionContext;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use futures_util::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::{
    error::{AnthropicError, AnthropicResult},
    types::{
        ApiError, Message, MessageRequestOptions, MessagesRequest, MessagesResponse, Model,
        StreamEvent, Tool, ToolChoice, Usage,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Default API version. Anthropic uses a date-based version header.
/// This can be overridden via the `api_version` config field or
/// the `FCP_ANTHROPIC_API_VERSION` environment variable.
pub(crate) const DEFAULT_API_VERSION: &str = "2023-06-01";

/// Hard ceiling for one invocation, including provider retries and stream assembly.
const MAX_INVOCATION_TIMEOUT_MS: u64 = 300_000;

/// Raw JSON bodies stay below the released-response ceiling to leave headroom
/// for parsed tool values and response-settlement copies.
const MAX_PROVIDER_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

/// Resolve the API version to use: config override > env var > compiled default.
fn resolve_api_version(config_override: Option<&str>) -> String {
    if let Some(v) = config_override.map(str::trim).filter(|s| !s.is_empty()) {
        return v.to_string();
    }
    if let Ok(v) = std::env::var("FCP_ANTHROPIC_API_VERSION") {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    DEFAULT_API_VERSION.to_string()
}

/// Authentication mode for the Anthropic API.
#[derive(Clone)]
pub enum AnthropicAuth {
    /// Direct API key (legacy; avoided in secretless deployments).
    ApiKey(String),
    /// Bearer token supplied by an operator or gateway.
    BearerToken(String),
    /// Long-lived Claude Code OAuth token, typically from `claude setup-token`.
    ClaudeCodeOAuth(String),
    /// Explicit FCP alias for the `claude setup-token` OAuth token output.
    SetupToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl AnthropicAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::ClaudeCodeOAuth(_) => "claude_code_oauth:redacted".to_string(),
            Self::SetupToken(_) => "setup_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }

    /// Auth method name for diagnostics and request-policy decisions.
    #[must_use]
    pub const fn method_name(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::BearerToken(_) => "bearer_token",
            Self::ClaudeCodeOAuth(_) => "claude_code_oauth",
            Self::SetupToken(_) => "setup_token",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this token path needs Claude Code OAuth beta headers.
    #[must_use]
    pub const fn uses_claude_code_oauth(&self) -> bool {
        matches!(self, Self::ClaudeCodeOAuth(_) | Self::SetupToken(_))
    }

    /// Whether this credential comes from Claude Code rather than the direct Anthropic API.
    #[must_use]
    pub const fn requires_claude_code_runtime_boundary(&self) -> bool {
        matches!(self, Self::ClaudeCodeOAuth(_) | Self::SetupToken(_))
    }
}

impl fmt::Debug for AnthropicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::ClaudeCodeOAuth(_) => f
                .debug_tuple("ClaudeCodeOAuth")
                .field(&"<redacted>")
                .finish(),
            Self::SetupToken(_) => f.debug_tuple("SetupToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Anthropic API client.
pub struct AnthropicClient {
    client: Client,
    auth: AnthropicAuth,
    base_url: String,
    api_version: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    // Cost tracking
    total_input_tokens: AtomicU64,
    total_output_tokens: AtomicU64,
}

impl fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

fn auth_header_value(value: &str, label: &str) -> AnthropicResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| AnthropicError::Api {
        error_type: "invalid_auth_header".into(),
        message: format!("Anthropic {label} contains characters that are not valid in headers"),
        status_code: None,
    })
}

impl AnthropicClient {
    /// Create a new Anthropic client with a direct API key.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>) -> AnthropicResult<Self> {
        Self::new_with_auth(AnthropicAuth::ApiKey(api_key.into()))
    }

    /// Create a new Anthropic client with explicit auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: AnthropicAuth) -> AnthropicResult<Self> {
        Self::new_with_auth_and_version(auth, None)
    }

    /// # Errors                                               
    pub fn new_with_auth_and_version(
        auth: AnthropicAuth,
        api_version: Option<&str>,
    ) -> AnthropicResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(AnthropicError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            api_version: resolve_api_version(api_version),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig::default(),
            total_input_tokens: AtomicU64::new(0),
            total_output_tokens: AtomicU64::new(0),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Bind an invocation to client shutdown and a caller-narrowed total budget.
    pub(crate) fn invocation_context(&self, deadline_ms: Option<u64>) -> ExecutionContext {
        let timeout_ms = deadline_ms
            .unwrap_or(MAX_INVOCATION_TIMEOUT_MS)
            .min(MAX_INVOCATION_TIMEOUT_MS);
        self.runtime
            .request_context_with_timeout(Duration::from_millis(timeout_ms))
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            ..HttpRetryConfig::default()
        };
        self
    }

    /// Get a reference to the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &AnthropicAuth {
        &self.auth
    }

    /// Get the Anthropic API version header used for requests.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Get total input tokens used.
    #[must_use]
    pub fn total_input_tokens(&self) -> u64 {
        self.total_input_tokens.load(Ordering::Relaxed)
    }

    /// Get total output tokens used.
    #[must_use]
    pub fn total_output_tokens(&self) -> u64 {
        self.total_output_tokens.load(Ordering::Relaxed)
    }

    /// Reset token counters.
    pub fn reset_token_counts(&self) {
        self.total_input_tokens.store(0, Ordering::Relaxed);
        self.total_output_tokens.store(0, Ordering::Relaxed);
    }

    /// Track usage from a response.
    fn track_usage(&self, usage: &Usage) {
        self.total_input_tokens
            .fetch_add(u64::from(usage.input_tokens), Ordering::Relaxed);
        self.total_output_tokens
            .fetch_add(u64::from(usage.output_tokens), Ordering::Relaxed);
    }

    /// Perform a safe, read-only health check by listing models.
    ///
    /// This validates that the API key is valid and the API is reachable
    /// without incurring any cost or side effects.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, authentication errors, or rate limiting.
    pub async fn health_check(&self) -> AnthropicResult<()> {
        // The Models API validates provider access without dispatching generation.
        // https://platform.claude.com/docs/en/api/models/list
        let url = format!("{}/v1/models", self.base_url);
        let request = self
            .client
            .get(&url)
            .query(&[("limit", "1")])
            .header("anthropic-version", &self.api_version)
            .header("accept", "application/json");
        let request = self.apply_auth(request)?;

        let response = request.send().await?;
        let status = response.status();
        let retry_after = extract_retry_after(&response);
        let bytes = read_bounded_body(response).await?;
        if status.is_success() {
            let page: serde_json::Value = serde_json::from_slice(&bytes)?;
            let valid_models = page
                .get("data")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|models| {
                    models.iter().all(|model| {
                        model.get("type").and_then(serde_json::Value::as_str) == Some("model")
                            && model
                                .get("id")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|id| !id.is_empty())
                    })
                });
            if !valid_models
                || !page
                    .get("has_more")
                    .is_some_and(serde_json::Value::is_boolean)
            {
                return Err(AnthropicError::Api {
                    error_type: "invalid_health_response".into(),
                    message: "Anthropic model discovery returned an invalid page".into(),
                    status_code: Some(status.as_u16()),
                });
            }
            Ok(())
        } else {
            Err(parse_error_response(status, &bytes, retry_after))
        }
    }

    /// Apply auth headers to a request builder.
    fn apply_auth(
        &self,
        request: reqwest::RequestBuilder,
    ) -> AnthropicResult<reqwest::RequestBuilder> {
        let mut headers = HeaderMap::new();
        match &self.auth {
            AnthropicAuth::ApiKey(key) => {
                let value = auth_header_value(key, "API key")?;
                headers.insert("x-api-key", value);
            }
            AnthropicAuth::BearerToken(token)
            | AnthropicAuth::ClaudeCodeOAuth(token)
            | AnthropicAuth::SetupToken(token) => {
                let value = auth_header_value(&format!("Bearer {token}"), "bearer token")?;
                headers.insert("authorization", value);
            }
            AnthropicAuth::CredentialId(credential_id) => {
                let credential_id = credential_id.to_string();
                let value = auth_header_value(&credential_id, "credential id")?;
                headers.insert("x-fcp-credential-id", value);
            }
        }
        Ok(request.headers(headers))
    }

    /// Send a message to Claude.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or context length violations.
    #[instrument(skip(self, messages, system, tools))]
    pub async fn message(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<&str>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> AnthropicResult<MessagesResponse> {
        self.message_with_options(
            model,
            messages,
            max_tokens,
            system.map(|value| serde_json::Value::String(value.to_string())),
            MessageRequestOptions {
                temperature,
                tools,
                tool_choice,
                ..MessageRequestOptions::default()
            },
        )
        .await
    }

    /// Send a message with explicit Anthropic advanced options.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or context length violations.
    #[instrument(skip(self, messages, system, options))]
    pub async fn message_with_options(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<serde_json::Value>,
        options: MessageRequestOptions,
    ) -> AnthropicResult<MessagesResponse> {
        let request = MessagesRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            system,
            temperature: options.temperature,
            stream: Some(false),
            tools: options.tools,
            tool_choice: options.tool_choice,
            stop_sequences: None,
            cache_control: options.cache_control,
            service_tier: options.service_tier,
            thinking: options.thinking,
            output_config: options.output_config,
        };

        let response: MessagesResponse = self
            .post_with_betas("/v1/messages", &request, &options.anthropic_betas)
            .await?;
        self.track_usage(&response.usage);
        Ok(response)
    }

    /// Send a simple text message and get the text response.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or context length violations.
    pub async fn chat(
        &self,
        model: Model,
        user_message: &str,
        system: Option<&str>,
        max_tokens: u32,
    ) -> AnthropicResult<String> {
        let messages = vec![Message {
            role: crate::types::Role::User,
            content: user_message.into(),
        }];

        let response = self
            .message(model, messages, max_tokens, system, None, None, None)
            .await?;

        // Extract text from response
        let text = response
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(text)
    }

    /// Stream a message response.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self, messages, system, tools))]
    pub async fn message_stream(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<&str>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> AnthropicResult<impl Stream<Item = AnthropicResult<StreamEvent>>> {
        self.message_stream_with_options(
            model,
            messages,
            max_tokens,
            system.map(|value| serde_json::Value::String(value.to_string())),
            MessageRequestOptions {
                temperature,
                tools,
                tool_choice,
                ..MessageRequestOptions::default()
            },
        )
        .await
    }

    /// Stream a message response with explicit Anthropic advanced options.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self, messages, system, options))]
    pub async fn message_stream_with_options(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: u32,
        system: Option<serde_json::Value>,
        options: MessageRequestOptions,
    ) -> AnthropicResult<impl Stream<Item = AnthropicResult<StreamEvent>>> {
        let request = MessagesRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            system,
            temperature: options.temperature,
            stream: Some(true),
            tools: options.tools,
            tool_choice: options.tool_choice,
            stop_sequences: None,
            cache_control: options.cache_control,
            service_tier: options.service_tier,
            thinking: options.thinking,
            output_config: options.output_config,
        };

        let response = self
            .post_stream_with_betas("/v1/messages", &request, &options.anthropic_betas)
            .await?;
        Ok(parse_sse_stream(response))
    }

    /// Make a POST request with bounded retry after explicit HTTP 429 refusal.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> AnthropicResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        self.post_with_betas(endpoint, body, &[]).await
    }

    /// Make a POST request with optional Anthropic beta headers.
    async fn post_with_betas<T, R>(
        &self,
        endpoint: &str,
        body: &T,
        betas: &[String],
    ) -> AnthropicResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        // Keep retry/backoff cancellation attached to the client runtime. The
        // enclosing invocation can impose an earlier deadline across all attempts.
        let ctx = self.invocation_context(None);
        let policy = self.retry_config.to_retry_policy();
        // Serialize before dispatch: local encoding failures do not imply an
        // uncertain provider outcome and must never enter the retry loop.
        let body = serde_json::to_vec(body)?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            let body = &body;
            async move {
                debug!(attempt, endpoint, "Making Anthropic API request");

                let request = self
                    .client
                    .post(url.as_str())
                    .header("anthropic-version", &self.api_version)
                    .header("content-type", "application/json");
                let request = match apply_beta_headers(request, betas) {
                    Ok(request) => request,
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                let request = match self.apply_auth(request) {
                    Ok(request) => request,
                    Err(error) => return AttemptOutcome::Terminal(error),
                };

                match request.body(body.clone()).send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: e.retry_after(),
                            error: e,
                        },
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) => AttemptOutcome::Terminal(
                        AnthropicError::Http(e).for_dispatched_generation(None),
                    ),
                }
            }
        })
        .await
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> AnthropicResult<Response>
    where
        T: serde::Serialize + Sync,
    {
        self.post_stream_with_betas(endpoint, body, &[]).await
    }

    /// Make a streaming POST request with optional Anthropic beta headers.
    async fn post_stream_with_betas<T>(
        &self,
        endpoint: &str,
        body: &T,
        betas: &[String],
    ) -> AnthropicResult<Response>
    where
        T: serde::Serialize + Sync,
    {
        let url = format!("{}{endpoint}", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("anthropic-version", &self.api_version)
            .header("content-type", "application/json");
        let request = apply_beta_headers(request, betas)?;
        let request = self.apply_auth(request)?;
        let body = serde_json::to_vec(body)?;
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|error| AnthropicError::Http(error).for_dispatched_generation(None))?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = extract_retry_after(&response);
            let bytes = read_bounded_body(response)
                .await
                .map_err(|error| error.for_dispatched_generation(Some(status.as_u16())))?;
            return Err(parse_error_response(status, &bytes, retry_after)
                .for_dispatched_generation(Some(status.as_u16())));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response) -> AnthropicResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();
        let retry_after = extract_retry_after(&response);
        let bytes = read_bounded_body(response)
            .await
            .map_err(|error| error.for_dispatched_generation(Some(status.as_u16())))?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|error| {
                AnthropicError::from(error).for_dispatched_generation(Some(status.as_u16()))
            })
        } else {
            Err(parse_error_response(status, &bytes, retry_after)
                .for_dispatched_generation(Some(status.as_u16())))
        }
    }
}

fn response_body_limit_error() -> AnthropicError {
    AnthropicError::Api {
        error_type: "response_too_large".into(),
        message: format!(
            "Anthropic response exceeded {MAX_PROVIDER_RESPONSE_BYTES} bytes; provider outcome may be unknown"
        ),
        status_code: None,
    }
}

/// Limit both declared and actual provider bytes before retaining or parsing them.
async fn read_bounded_body(response: Response) -> AnthropicResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_PROVIDER_RESPONSE_BYTES)
    {
        return Err(response_body_limit_error());
    }
    let mut body = Vec::new();
    let mut stream = Box::pin(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AnthropicError::Api {
            error_type: "response_body_incomplete".into(),
            message:
                "Anthropic response body could not be read completely; provider outcome may be unknown"
                    .into(),
            // A response-body failure follows dispatch and must not trigger an
            // automatic retry of a possibly completed provider generation.
            status_code: None,
        })?;
        let retained = u64::try_from(body.len()).map_err(|_| response_body_limit_error())?;
        let additional = u64::try_from(chunk.len()).map_err(|_| response_body_limit_error())?;
        if retained
            .checked_add(additional)
            .is_none_or(|total| total > MAX_PROVIDER_RESPONSE_BYTES)
        {
            return Err(response_body_limit_error());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn apply_beta_headers(
    request: reqwest::RequestBuilder,
    betas: &[String],
) -> AnthropicResult<reqwest::RequestBuilder> {
    if betas.is_empty() {
        return Ok(request);
    }
    let joined = betas.join(",");
    let value = auth_header_value(&joined, "beta header")?;
    let mut headers = HeaderMap::new();
    headers.insert("anthropic-beta", value);
    Ok(request.headers(headers))
}

/// Extract the `retry-after` header as milliseconds.
const MAX_RETRY_AFTER_MS: u64 = 60 * 60 * 1000;

fn extract_retry_after(response: &Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_header_value)
}

pub(crate) fn parse_retry_after_header_value(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| secs.saturating_mul(1000).min(MAX_RETRY_AFTER_MS))
}

/// Parse an error response.
pub(crate) fn parse_error_response(
    status: StatusCode,
    bytes: &[u8],
    retry_after_ms: Option<u64>,
) -> AnthropicError {
    // An actual HTTP 429 is an explicit refusal even when a gateway replaces
    // the JSON body. Preserve the provider's retry floor without trusting labels.
    if status == StatusCode::TOO_MANY_REQUESTS {
        return AnthropicError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(30_000),
        };
    }

    // Try to parse as API error
    #[derive(Deserialize)]
    struct ErrorWrapper {
        error: ApiError,
    }

    if let Ok(wrapper) = serde_json::from_slice::<ErrorWrapper>(bytes) {
        let error = wrapper.error;

        // Check for specific error types
        if status.as_u16() == 529 {
            return AnthropicError::Overloaded {
                retry_after_ms: retry_after_ms.unwrap_or(60_000),
            };
        }

        if status == StatusCode::UNAUTHORIZED {
            return AnthropicError::InvalidApiCredential;
        }

        if error.error_type == "invalid_request_error" && error.message.contains("context length") {
            return AnthropicError::ContextLengthExceeded {
                message: error.message,
            };
        }

        return AnthropicError::Api {
            error_type: error.error_type,
            message: error.message,
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable errors
    AnthropicError::Api {
        error_type: "unknown".into(),
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
    }
}

/// Maximum raw SSE event size (1 MiB), before JSON expansion. Complete
/// multi-event chunks may exceed this; each individual event must fit.
pub(crate) const MAX_SSE_BUFFER_BYTES: usize = 1024 * 1024;

fn parse_sse_stream(response: Response) -> impl Stream<Item = AnthropicResult<StreamEvent>> {
    let status_code = response.status().as_u16();
    parse_sse_chunks(response.bytes_stream()).map(move |event| {
        event.map_err(|error| match error {
            AnthropicError::OutcomeUnknown { status_code: None } => {
                AnthropicError::OutcomeUnknown {
                    status_code: Some(status_code),
                }
            }
            other => other.for_dispatched_generation(Some(status_code)),
        })
    })
}

fn parse_sse_chunks<S>(stream: S) -> impl Stream<Item = AnthropicResult<StreamEvent>>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    async_stream::stream! {
        let mut stream = Box::pin(stream);
        let mut buffer = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    yield Err(AnthropicError::Http(e).for_dispatched_generation(None));
                    return;
                }
            };

            let mut remaining = chunk.as_ref();
            while !remaining.is_empty() {
                // At most one bounded event and a split CRLF delimiter are
                // retained, even if a network chunk batches many events.
                let available = (MAX_SSE_BUFFER_BYTES + 4).saturating_sub(buffer.len());
                if available == 0 {
                    yield Err(sse_buffer_limit_error());
                    return;
                }
                let take = available.min(remaining.len());
                buffer.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];

                while let Some(event_bytes) = take_next_sse_event(&mut buffer) {
                    let event_bytes = match event_bytes {
                        Ok(event_bytes) => event_bytes,
                        Err(error) => {
                            yield Err(error);
                            return;
                        }
                    };
                    if let Some(event) = parse_sse_event_bytes(&event_bytes) {
                        let terminal = matches!(
                            &event,
                            Ok(StreamEvent::MessageStop | StreamEvent::Error { .. }) | Err(_)
                        );
                        yield event;
                        if terminal {
                            return;
                        }
                    }
                }

                if buffer.len() == MAX_SSE_BUFFER_BYTES + 4 {
                    yield Err(sse_buffer_limit_error());
                    return;
                }
            }
        }

        // EOF alone never establishes generation completion. A final complete
        // message_stop or provider error may be emitted without another chunk.
        if !buffer.is_empty() {
            if let Some(event) = parse_sse_event_bytes(&buffer) {
                let terminal = matches!(
                    &event,
                    Ok(StreamEvent::MessageStop | StreamEvent::Error { .. }) | Err(_)
                );
                yield event;
                if terminal {
                    return;
                }
            }
        }
        yield Err(AnthropicError::OutcomeUnknown { status_code: None });
    }
}

fn sse_buffer_limit_error() -> AnthropicError {
    AnthropicError::Api {
        error_type: "sse_buffer_overflow".into(),
        message: format!(
            "SSE buffer exceeded {MAX_SSE_BUFFER_BYTES} bytes without a complete bounded event"
        ),
        status_code: None,
    }
}

fn take_next_sse_event(buffer: &mut Vec<u8>) -> Option<AnthropicResult<Vec<u8>>> {
    let (event_end, delimiter_len) = next_sse_event_boundary(buffer)?;
    if event_end > MAX_SSE_BUFFER_BYTES {
        return Some(Err(AnthropicError::Api {
            error_type: "sse_event_too_large".into(),
            message: format!("Anthropic SSE event exceeded {MAX_SSE_BUFFER_BYTES} bytes"),
            status_code: None,
        }));
    }
    let event = buffer[..event_end].to_vec();
    buffer.drain(..event_end + delimiter_len);
    Some(Ok(event))
}

fn next_sse_event_boundary(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|pos| (pos, 2));
    let crlf = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| (pos, 4));

    match (lf, crlf) {
        (Some(lf), Some(crlf)) => Some(if lf.0 <= crlf.0 { lf } else { crlf }),
        (Some(lf), None) => Some(lf),
        (None, Some(crlf)) => Some(crlf),
        (None, None) => None,
    }
}

pub(crate) fn parse_sse_event_bytes(event_bytes: &[u8]) -> Option<AnthropicResult<StreamEvent>> {
    if event_bytes.len() > MAX_SSE_BUFFER_BYTES {
        return Some(Err(AnthropicError::Api {
            error_type: "sse_event_too_large".into(),
            message: format!("Anthropic SSE event exceeded {MAX_SSE_BUFFER_BYTES} bytes"),
            status_code: None,
        }));
    }

    let event_str = match std::str::from_utf8(event_bytes) {
        Ok(event_str) => event_str,
        Err(error) => {
            return Some(Err(AnthropicError::Api {
                error_type: "invalid_sse_utf8".to_string(),
                message: format!("Anthropic SSE event was not valid UTF-8: {error}"),
                status_code: None,
            }));
        }
    };

    parse_sse_event(event_str)
}

fn parse_sse_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let value = line.strip_prefix(field)?;
    Some(value.strip_prefix(' ').unwrap_or(value))
}

/// Parse a single SSE event.
fn parse_sse_event(event_str: &str) -> Option<AnthropicResult<StreamEvent>> {
    let mut event_type = None;
    let mut data_lines = Vec::new();

    for raw_line in event_str.lines() {
        let line = raw_line.trim_end_matches('\r');

        if let Some(value) = parse_sse_field(line, "event:") {
            event_type = Some(value.trim());
        } else if let Some(value) = parse_sse_field(line, "data:") {
            data_lines.push(value);
        }
    }

    if data_lines.is_empty() {
        return None;
    }

    let data = data_lines.join("\n");

    let expected_event_type = event_type?;

    // Parse based on event type
    match expected_event_type {
        "message_start"
        | "content_block_start"
        | "content_block_delta"
        | "content_block_stop"
        | "message_delta"
        | "message_stop"
        | "ping"
        | "error" => match serde_json::from_str::<StreamEvent>(&data) {
            Ok(event) => {
                let payload_event_type = stream_event_type(&event);
                if payload_event_type != expected_event_type {
                    return Some(Err(AnthropicError::Api {
                        error_type: "sse_event_type_mismatch".into(),
                        message: format!(
                            "Anthropic SSE event type mismatch: envelope {expected_event_type}, payload {payload_event_type}"
                        ),
                        status_code: None,
                    }));
                }
                Some(Ok(event))
            }
            Err(e) => Some(Err(AnthropicError::Json(e))),
        },
        _ => None,
    }
}

const fn stream_event_type(event: &StreamEvent) -> &'static str {
    match event {
        StreamEvent::MessageStart { .. } => "message_start",
        StreamEvent::ContentBlockStart { .. } => "content_block_start",
        StreamEvent::ContentBlockDelta { .. } => "content_block_delta",
        StreamEvent::ContentBlockStop { .. } => "content_block_stop",
        StreamEvent::MessageDelta { .. } => "message_delta",
        StreamEvent::MessageStop => "message_stop",
        StreamEvent::Ping => "ping",
        StreamEvent::Error { .. } => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_testkit::LogCapture;
    use futures_util::stream;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: serde_json::Value,
        required_headers: Vec<(&'static str, &'static str)>,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body,
                required_headers: Vec::new(),
            }
        }

        fn with_required_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.required_headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, &response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        StdInstant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        let mut required_headers_seen = vec![false; response.required_headers.len()];
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                for (index, (required_name, required_value)) in
                    response.required_headers.iter().enumerate()
                {
                    if name.eq_ignore_ascii_case(required_name) && value.trim() == *required_value {
                        required_headers_seen[index] = true;
                    }
                }
            }
        }
        assert!(
            required_headers_seen.into_iter().all(|seen| seen),
            "required header was not sent"
        );
        if content_length > 0 {
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let body = response.body.to_string();
        let reason = match response.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            529 => "Overloaded",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn invocation_context_clamps_caller_deadline_and_inherits_shutdown() {
        let client = AnthropicClient::new("test-key").unwrap();
        for deadline in [None, Some(u64::MAX)] {
            let budget = client
                .invocation_context(deadline)
                .remaining_budget()
                .unwrap();
            assert!(budget <= Duration::from_millis(MAX_INVOCATION_TIMEOUT_MS));
            assert!(!budget.is_zero());
        }
        let narrowed = client.invocation_context(Some(5_000));
        assert!(narrowed.remaining_budget().unwrap() <= Duration::from_secs(5));
        assert_eq!(
            client.invocation_context(Some(0)).remaining_budget(),
            Some(Duration::ZERO)
        );
        assert!(!narrowed.is_cancelled());
        client.shutdown();
        assert!(narrowed.is_cancelled());
        assert!(client.invocation_context(None).is_cancelled());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_stops_provider_retry_loop_before_http_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = AnthropicClient::new("test-key")
            .unwrap()
            .with_base_url(format!("http://{}", listener.local_addr().unwrap()));
        client.shutdown();

        let result = fcp_async_core::time::timeout(
            Duration::from_secs(1),
            client.chat(Model::default(), "hello", None, 16),
        )
        .await
        .expect("a stopped runtime must not start or wait for provider traffic");
        assert!(
            matches!(
                &result,
                Err(AnthropicError::Api { error_type, .. })
                    if error_type == "request_cancelled"
            ),
            "{result:?}"
        );
        assert!(
            matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ),
            "shutdown must prevent opening a provider connection"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn local_serialization_failure_never_opens_a_provider_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = AnthropicClient::new("test-key")
            .unwrap()
            .with_base_url(format!("http://{}", listener.local_addr().unwrap()));
        let body = std::collections::BTreeMap::from([(vec![1_u8, 2], "invalid JSON key")]);
        let result: AnthropicResult<serde_json::Value> = client.post("/v1/messages", &body).await;
        assert!(matches!(result, Err(AnthropicError::Json(_))));
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn sse_eof_is_terminal_once_and_message_stop_discards_trailing_frames() {
        for payload in [
            "",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: content_block_delta\ndata: {",
        ] {
            let mut events = Box::pin(parse_sse_chunks(stream::iter(vec![Ok(Bytes::from(
                payload.to_owned(),
            ))])));
            let mut terminal_errors = 0;
            while let Some(event) = events.next().await {
                if let Err(error) = event {
                    terminal_errors += 1;
                    assert!(!error.is_retryable());
                    assert!(!error.to_fcp_error().is_retryable());
                }
            }
            assert_eq!(terminal_errors, 1);
            assert!(events.next().await.is_none());
        }

        let payload = concat!(
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: error\ndata: {\"type\":\"error\",\"error\":{",
            "\"type\":\"api_error\",\"message\":\"after completion\"}}\n\n"
        );
        let events: Vec<_> = parse_sse_chunks(stream::iter(vec![Ok(Bytes::from_static(
            payload.as_bytes(),
        ))]))
        .collect()
        .await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events.first(), Some(Ok(StreamEvent::MessageStop))));
    }

    #[fcp_async_core::runtime::test]
    async fn test_chat_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/messages",
                200,
                serde_json::json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello!"}],
                "model": "claude-sonnet-4-20250514",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
                }),
            )
            .with_required_header("x-api-key", "test_key")
            .with_required_header("anthropic-version", DEFAULT_API_VERSION),
        ]);

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(server.uri());

        let response = client
            .chat(Model::ClaudeSonnet4, "Hi", None, 1024)
            .await
            .unwrap();

        assert_eq!(response, "Hello!");
        assert_eq!(client.total_input_tokens(), 10);
        assert_eq!(client.total_output_tokens(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            401,
            serde_json::json!({
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid API key"
                }
            }),
        )]);

        let client = AnthropicClient::new("bad_key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::InvalidApiCredential
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            429,
            serde_json::json!({
                "error": {
                    "type": "rate_limit_error",
                    "message": "Rate limit exceeded"
                }
            }),
        )]);

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(0, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::RateLimited { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_overloaded() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            529,
            serde_json::json!({
                "error": {
                    "type": "overloaded_error",
                    "message": "Overloaded"
                }
            }),
        )]);

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(0, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::OutcomeUnknown {
                status_code: Some(529)
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_context_length_exceeded() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            400,
            serde_json::json!({
                "error": {
                    "type": "invalid_request_error",
                    "message": "context length exceeded"
                }
            }),
        )]);

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::ContextLengthExceeded { .. }
        ));
    }

    #[fcp_async_core::runtime::test(flavor = "current_thread")]
    async fn test_logs_redact_api_key_and_prompt() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/messages",
                200,
                serde_json::json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello!"}],
                "model": "claude-sonnet-4-20250514",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
                }),
            )
            .with_required_header("x-api-key", "test_key")
            .with_required_header("anthropic-version", DEFAULT_API_VERSION),
        ]);

        let client = AnthropicClient::new("test_key")
            .unwrap()
            .with_base_url(server.uri());
        let secret_prompt = "TopSecretPrompt";
        let _ = client
            .chat(Model::ClaudeSonnet4, secret_prompt, None, 1024)
            .await
            .unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains("test_key"),
            "API key should not appear in logs"
        );
        assert!(
            !logs.contains(secret_prompt),
            "prompt text should not appear in logs"
        );
    }

    #[test]
    fn test_parse_sse_event_ping() {
        let event = parse_sse_event("event: ping\ndata: {\"type\":\"ping\"}\n");
        let event = event
            .expect("expected ping event")
            .expect("expected ok event");

        assert!(matches!(event, StreamEvent::Ping));
    }

    #[test]
    fn test_parse_sse_event_invalid_json() {
        let event = parse_sse_event("event: ping\ndata: {not json}\n");
        let event = event.expect("expected ping event");

        assert!(matches!(event, Err(AnthropicError::Json(_))));
    }

    #[test]
    fn test_parse_sse_event_unknown_ignored() {
        let event = parse_sse_event("event: unknown\ndata: {}\n");
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_sse_event_accepts_fields_without_optional_space() {
        let event = parse_sse_event("event:ping\ndata:{\"type\":\"ping\"}\n");
        let event = event
            .expect("expected ping event")
            .expect("expected ok event");

        assert!(matches!(event, StreamEvent::Ping));
    }

    #[test]
    fn test_parse_sse_event_multiline_data_joins_lines() {
        let event = parse_sse_event("event: ping\ndata: {\"type\":\ndata: \"ping\"}\n");
        let event = event
            .expect("expected ping event")
            .expect("expected ok event");

        assert!(matches!(event, StreamEvent::Ping));
    }

    #[test]
    fn test_parse_sse_event_rejects_event_payload_type_mismatch() {
        let event = parse_sse_event("event: error\ndata: {\"type\":\"message_stop\"}\n");
        let event = event.expect("expected mismatch error");

        match event {
            Err(AnthropicError::Api {
                error_type,
                message,
                status_code,
            }) => {
                assert_eq!(error_type, "sse_event_type_mismatch");
                assert!(message.contains("envelope error"));
                assert!(message.contains("payload message_stop"));
                assert_eq!(status_code, None);
            }
            other => assert!(
                matches!(other, Err(AnthropicError::Api { .. })),
                "expected SSE type mismatch error"
            ),
        }
    }

    #[test]
    fn test_take_next_sse_event_handles_crlf_delimiters() {
        let mut buffer = concat!(
            "event: ping\r\n",
            "data: {\"type\":\"ping\"}\r\n",
            "\r\n",
            "event: message_stop\r\n",
            "data: {\"type\":\"message_stop\"}\r\n",
            "\r\n",
        )
        .as_bytes()
        .to_vec();

        let first = take_next_sse_event(&mut buffer)
            .expect("expected first event")
            .expect("first event should be bounded");
        let first = parse_sse_event_bytes(&first)
            .expect("expected first parsed event")
            .expect("expected first ok event");
        assert!(matches!(first, StreamEvent::Ping));

        let second = take_next_sse_event(&mut buffer)
            .expect("expected second event")
            .expect("second event should be bounded");
        let second = parse_sse_event_bytes(&second)
            .expect("expected second parsed event")
            .expect("expected second ok event");
        assert!(matches!(second, StreamEvent::MessageStop));

        assert!(buffer.is_empty(), "expected buffer to be fully consumed");
    }

    #[test]
    fn test_take_next_sse_event_preserves_utf8_across_chunk_boundaries() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(
            b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"caf",
        );
        buffer.push(0xC3);

        assert!(
            take_next_sse_event(&mut buffer).is_none(),
            "partial multibyte code point should not produce an event yet"
        );

        buffer.push(0xA9);
        buffer.extend_from_slice(b"\"}}\n\n");

        let event = take_next_sse_event(&mut buffer)
            .expect("expected complete event")
            .expect("event should be bounded");
        let event = parse_sse_event_bytes(&event)
            .expect("expected parsed event")
            .expect("expected ok event");

        match event {
            StreamEvent::Error { error } => {
                assert_eq!(error.error_type, "api_error");
                assert_eq!(error.message, "café");
            }
            other => assert!(matches!(other, StreamEvent::Error { .. }), "expected Error"),
        }
    }

    #[test]
    fn parse_sse_event_bytes_rejects_oversized_complete_event() {
        let event_bytes = vec![b'x'; MAX_SSE_BUFFER_BYTES + 1];
        let event = parse_sse_event_bytes(&event_bytes).expect("expected oversized event error");

        match event {
            Err(AnthropicError::Api {
                error_type,
                message,
                status_code,
            }) => {
                assert_eq!(error_type, "sse_event_too_large");
                assert!(message.contains("SSE event exceeded"));
                assert_eq!(status_code, None);
            }
            other => assert!(
                matches!(other, Err(AnthropicError::Api { .. })),
                "expected oversized event API error"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn parse_sse_chunks_allows_large_chunk_when_delimited_remainder_stays_within_limit() {
        let mut chunk = b"event: ping\ndata: {\"type\":\"ping\"}\n\n".to_vec();
        chunk.extend(std::iter::repeat_n(b'x', MAX_SSE_BUFFER_BYTES));

        let events: Vec<_> = parse_sse_chunks(stream::iter(vec![Ok(Bytes::from(chunk))]))
            .collect()
            .await;

        assert_eq!(
            events.len(),
            2,
            "ping must be followed by a terminal EOF error"
        );
        assert!(matches!(&events[0], Ok(StreamEvent::Ping)));
        assert!(matches!(
            &events[1],
            Err(AnthropicError::OutcomeUnknown { status_code: None })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_sse_parser_preserves_large_batches_of_small_events() {
        let event = format!(
            ":{}\nevent: ping\ndata: {{\"type\":\"ping\"}}\n\n",
            "x".repeat(4096)
        );
        let count = MAX_SSE_BUFFER_BYTES / event.len() + 2;
        let mut chunk = event.repeat(count).into_bytes();
        assert!(chunk.len() > MAX_SSE_BUFFER_BYTES);
        chunk.extend_from_slice(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
        let received: Vec<_> = parse_sse_chunks(stream::iter(vec![Ok(Bytes::from(chunk))]))
            .collect()
            .await;
        assert_eq!(received.len(), count + 1);
        assert!(
            received[..count]
                .iter()
                .all(|event| matches!(event, Ok(StreamEvent::Ping)))
        );
        assert!(matches!(
            received.last(),
            Some(Ok(StreamEvent::MessageStop))
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_sse_parser_allows_exact_limit_with_split_crlf_delimiter() {
        let suffix = "\r\nevent: ping\r\ndata: {\"type\":\"ping\"}";
        let mut payload = format!(
            ":{}{suffix}",
            "x".repeat(MAX_SSE_BUFFER_BYTES - suffix.len() - 1)
        )
        .into_bytes();
        assert_eq!(payload.len(), MAX_SSE_BUFFER_BYTES);
        payload.extend_from_slice(b"\r\n\r\n");
        for delimiter_bytes in 1..=3 {
            let split = MAX_SSE_BUFFER_BYTES + delimiter_bytes;
            let events: Vec<_> = parse_sse_chunks(stream::iter(vec![
                Ok(Bytes::copy_from_slice(&payload[..split])),
                Ok(Bytes::copy_from_slice(&payload[split..])),
            ]))
            .collect()
            .await;
            assert_eq!(events.len(), 2);
            assert!(matches!(&events[0], Ok(StreamEvent::Ping)));
            assert!(matches!(
                &events[1],
                Err(AnthropicError::OutcomeUnknown { .. })
            ));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_sse_parser_rejects_oversized_event_with_or_without_delimiter() {
        let suffix = "\nevent: ping\ndata: {\"type\":\"ping\"}";
        for delimiter in ["", "\n\n"] {
            let payload = format!(
                ":{}{suffix}{delimiter}",
                "x".repeat(MAX_SSE_BUFFER_BYTES - suffix.len())
            );
            let events: Vec<_> = parse_sse_chunks(stream::iter(vec![Ok(Bytes::from(payload))]))
                .collect()
                .await;
            assert_eq!(events.len(), 1);
            let error = events.into_iter().next().unwrap().unwrap_err();
            assert!(
                matches!(
                    &error,
                    AnthropicError::Api { error_type, status_code: None, .. }
                        if error_type == "sse_event_too_large"
                ),
                "{error:?}"
            );
            assert!(!error.is_retryable());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_sse_parser_preserves_utf8_split_between_network_chunks() {
        let mut first =
            b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"caf"
                .to_vec();
        first.push(0xC3);
        let second = vec![0xA9, b'"', b'}', b'}', b'\n', b'\n'];
        let events: Vec<_> = parse_sse_chunks(stream::iter(vec![
            Ok(Bytes::from(first)),
            Ok(Bytes::from(second)),
        ]))
        .collect()
        .await;
        assert_eq!(events.len(), 1);
        match events.into_iter().next().unwrap().unwrap() {
            StreamEvent::Error { error } => assert_eq!(error.message, "café"),
            event => panic!("unexpected SSE event: {event:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_model_pricing() {
        assert_eq!(Model::ClaudeOpus4_5.input_price_per_million(), 5.0);
        assert_eq!(Model::ClaudeOpus4_5.output_price_per_million(), 25.0);
        assert_eq!(Model::ClaudeSonnet4.input_price_per_million(), 3.0);
        assert_eq!(Model::ClaudeSonnet4.output_price_per_million(), 15.0);
        assert_eq!(Model::Claude3_5Haiku.input_price_per_million(), 0.25);
        assert_eq!(Model::Claude3_5Haiku.output_price_per_million(), 1.25);
    }

    #[fcp_async_core::runtime::test]
    async fn test_usage_cost_calculation() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            cache_creation: crate::types::CacheCreation::default(),
            service_tier: None,
        };

        // Sonnet: 1000 input * $3/1M + 500 output * $15/1M
        let cost = usage.calculate_cost(Model::ClaudeSonnet4);
        assert!((cost - 0.0105).abs() < 0.0001);
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            AnthropicError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(
            AnthropicError::Overloaded {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!AnthropicError::InvalidApiCredential.is_retryable());
    }

    // ---- Auth tests ----

    #[test]
    fn auth_api_key_redacted_label() {
        let auth = AnthropicAuth::ApiKey("secret-key".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_api_key_not_secretless() {
        let auth = AnthropicAuth::ApiKey("key".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_api_key_redacted() {
        let auth = AnthropicAuth::ApiKey("super-secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred_id = fcp_core::CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = AnthropicAuth::CredentialId(cred_id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone_api_key() {
        let original = AnthropicAuth::ApiKey("clone-me".into());
        let cloned = original.clone();
        drop(original);
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    // ---- Client construction tests ----

    #[test]
    fn client_new_default_base_url() {
        let client = AnthropicClient::new("test-key").unwrap();
        assert_eq!(client.api_version(), DEFAULT_API_VERSION);
        assert_eq!(client.total_input_tokens(), 0);
        assert_eq!(client.total_output_tokens(), 0);
    }

    #[test]
    fn client_api_version_override_is_trimmed() {
        let client = AnthropicClient::new_with_auth_and_version(
            AnthropicAuth::ApiKey("test-key".into()),
            Some(" 2024-10-22 "),
        )
        .unwrap();
        assert_eq!(client.api_version(), "2024-10-22");
    }

    #[test]
    fn client_with_base_url_changes_url() {
        let client = AnthropicClient::new("key")
            .unwrap()
            .with_base_url("https://custom.api.com");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.api.com"));
    }

    #[test]
    fn client_with_retry_config() {
        let client = AnthropicClient::new("key")
            .unwrap()
            .with_retry_config(5, 100, 60_000);
        let dbg = format!("{client:?}");
        assert!(dbg.contains("max_retries: 5"));
    }

    #[test]
    fn client_debug_format() {
        let client = AnthropicClient::new("secret-key").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AnthropicClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("secret-key"));
    }

    #[test]
    fn client_reset_token_counts() {
        let client = AnthropicClient::new("key").unwrap();
        client
            .total_input_tokens
            .store(100, std::sync::atomic::Ordering::Relaxed);
        client
            .total_output_tokens
            .store(50, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(client.total_input_tokens(), 100);
        assert_eq!(client.total_output_tokens(), 50);
        client.reset_token_counts();
        assert_eq!(client.total_input_tokens(), 0);
        assert_eq!(client.total_output_tokens(), 0);
    }

    #[test]
    fn client_track_usage() {
        let client = AnthropicClient::new("key").unwrap();
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            cache_creation: crate::types::CacheCreation::default(),
            service_tier: None,
        };
        client.track_usage(&usage);
        assert_eq!(client.total_input_tokens(), 100);
        assert_eq!(client.total_output_tokens(), 50);
        client.track_usage(&usage);
        assert_eq!(client.total_input_tokens(), 200);
        assert_eq!(client.total_output_tokens(), 100);
    }

    #[test]
    fn client_auth_accessor() {
        let client = AnthropicClient::new("test-key").unwrap();
        assert!(!client.auth().is_secretless());
    }

    // ---- SSE parsing additional tests ----

    #[test]
    fn parse_sse_event_message_stop() {
        let event = parse_sse_event("event: message_stop\ndata: {\"type\":\"message_stop\"}\n");
        let event = event.unwrap().unwrap();
        assert!(matches!(event, StreamEvent::MessageStop));
    }

    #[test]
    fn parse_sse_event_content_block_stop() {
        let event = parse_sse_event(
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::ContentBlockStop { index } => assert_eq!(index, 0),
            other => assert!(
                matches!(other, StreamEvent::ContentBlockStop { .. }),
                "expected ContentBlockStop"
            ),
        }
    }

    #[test]
    fn parse_sse_event_error() {
        let event = parse_sse_event(
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"fail\"}}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::Error { error } => {
                assert_eq!(error.error_type, "api_error");
                assert_eq!(error.message, "fail");
            }
            other => assert!(matches!(other, StreamEvent::Error { .. }), "expected Error"),
        }
    }

    #[test]
    fn parse_sse_event_no_data() {
        let event = parse_sse_event("event: ping\n");
        assert!(event.is_none());
    }

    #[test]
    fn parse_sse_event_empty_string() {
        let event = parse_sse_event("");
        assert!(event.is_none());
    }

    #[test]
    fn parse_sse_event_message_start() {
        let event = parse_sse_event(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n",
        );
        let event = event.unwrap().unwrap();
        match event {
            StreamEvent::MessageStart { message } => {
                assert_eq!(message.id, "msg_1");
                assert_eq!(message.role, crate::types::Role::Assistant);
            }
            other => assert!(
                matches!(other, StreamEvent::MessageStart { .. }),
                "expected MessageStart"
            ),
        }
    }

    // ---- parse_error_response tests ----

    #[test]
    fn parse_error_response_429() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}"#,
        );
        let err = parse_error_response(StatusCode::TOO_MANY_REQUESTS, &bytes, None);
        assert!(matches!(
            err,
            AnthropicError::RateLimited {
                retry_after_ms: 30_000
            }
        ));
    }

    #[test]
    fn parse_error_response_429_with_header() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}"#,
        );
        let err = parse_error_response(StatusCode::TOO_MANY_REQUESTS, &bytes, Some(5_000));
        assert!(matches!(
            err,
            AnthropicError::RateLimited {
                retry_after_ms: 5_000
            }
        ));
    }

    #[test]
    fn parse_retry_after_header_clamps_large_value() {
        assert_eq!(
            parse_retry_after_header_value(&u64::MAX.to_string()),
            Some(MAX_RETRY_AFTER_MS)
        );
    }

    #[test]
    fn parse_retry_after_header_rejects_invalid_values() {
        assert_eq!(parse_retry_after_header_value("-1"), None);
        assert_eq!(parse_retry_after_header_value("not-a-number"), None);
        assert_eq!(parse_retry_after_header_value("1.5"), None);
    }

    #[test]
    fn parse_error_response_529_clamps_retry_after() {
        let bytes =
            bytes::Bytes::from(r#"{"error":{"type":"overloaded_error","message":"Overloaded"}}"#);
        let err = parse_error_response(
            StatusCode::from_u16(529).unwrap(),
            &bytes,
            parse_retry_after_header_value(&u64::MAX.to_string()),
        );
        assert!(matches!(
            err,
            AnthropicError::Overloaded {
                retry_after_ms: MAX_RETRY_AFTER_MS
            }
        ));
    }

    #[test]
    fn parse_error_response_529() {
        let bytes =
            bytes::Bytes::from(r#"{"error":{"type":"overloaded_error","message":"Overloaded"}}"#);
        let err = parse_error_response(StatusCode::from_u16(529).unwrap(), &bytes, None);
        assert!(matches!(err, AnthropicError::Overloaded { .. }));
    }

    #[test]
    fn parse_error_response_401() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"authentication_error","message":"Invalid key"}}"#,
        );
        let err = parse_error_response(StatusCode::UNAUTHORIZED, &bytes, None);
        assert!(matches!(err, AnthropicError::InvalidApiCredential));
    }

    #[test]
    fn parse_error_response_context_length() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"invalid_request_error","message":"context length exceeded"}}"#,
        );
        let err = parse_error_response(StatusCode::BAD_REQUEST, &bytes, None);
        assert!(matches!(err, AnthropicError::ContextLengthExceeded { .. }));
    }

    #[test]
    fn parse_error_response_generic_api_error() {
        let bytes = bytes::Bytes::from(
            r#"{"error":{"type":"not_found_error","message":"Model not found"}}"#,
        );
        let err = parse_error_response(StatusCode::NOT_FOUND, &bytes, None);
        match err {
            AnthropicError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "not_found_error");
                assert_eq!(message, "Model not found");
                assert_eq!(status_code, Some(404));
            }
            other => assert!(
                matches!(other, AnthropicError::Api { .. }),
                "expected Api error"
            ),
        }
    }

    #[test]
    fn parse_error_response_unparseable() {
        let bytes = bytes::Bytes::from("not json");
        let err = parse_error_response(StatusCode::INTERNAL_SERVER_ERROR, &bytes, None);
        match err {
            AnthropicError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "unknown");
                assert_eq!(message, "not json");
                assert_eq!(status_code, Some(500));
            }
            other => assert!(
                matches!(other, AnthropicError::Api { .. }),
                "expected Api error"
            ),
        }
    }

    // ---- DEFAULT_BASE_URL ----

    #[test]
    fn default_base_url_is_anthropic() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.anthropic.com");
    }
}
