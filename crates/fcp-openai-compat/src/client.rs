//! HTTP client implementation.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::Bytes;
use fcp_async_core::bytes::Buf as _;
use fcp_async_core::http::body::Body as _;
use fcp_async_core::http::client_io::ClientIo;
use fcp_async_core::http::{ClientIncomingBody, HttpClient, Method};
use fcp_async_core::{Cx, Deadline, time, wait_for_cx_cancellation};
use futures_util::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{NetworkError, OpenAiError, StreamingError, truncate_response_body};
use crate::rate_limit::{
    HeaderList, RateLimitConfig, RateLimitPolicy, RateLimitSnapshot, parse_rate_limit_headers,
    upsert_header,
};
use crate::sse::{OpenAiSseDecoder, OpenAiStreamEvent};
use crate::types::{
    ChatChunk, ChatCompletionsRequest, ChatCompletionsResponse, CompletionsRequest,
    CompletionsResponse, EmbeddingsRequest, EmbeddingsResponse, ModelInfo, ModelsResponse,
};

const ACCEPT_HEADER: &str = "Accept";
const AUTHORIZATION_HEADER: &str = "Authorization";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

static DEFAULT_ERROR_MAPPER: DefaultOpenAiErrorMapper = DefaultOpenAiErrorMapper;

/// Mutable request metadata passed to provider auth hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequest {
    /// Request headers.
    pub headers: HeaderList,
}

impl HttpRequest {
    /// Add or replace a header.
    pub fn upsert_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        upsert_header(&mut self.headers, name, value);
    }

    /// Add an Authorization bearer token without storing it in this crate.
    pub fn bearer_auth(&mut self, bearer: &str) {
        self.upsert_header(AUTHORIZATION_HEADER, format!("Bearer {bearer}"));
    }
}

/// Provider policy for an OpenAI-compatible endpoint.
pub trait OpenAiCompatProvider: Send + Sync + 'static {
    /// Base URL, for example `https://api.groq.com/openai/v1`.
    fn base_url(&self) -> &str;

    /// Apply provider authentication headers.
    fn auth_header(&self, req: &mut HttpRequest);

    /// Connector-specific user agent.
    fn user_agent(&self) -> &'static str;

    /// Provider name for diagnostics.
    fn provider_name(&self) -> &'static str;

    /// Provider-specific rate-limit header overrides.
    fn rate_limit_overrides(&self) -> Option<RateLimitConfig> {
        None
    }

    /// Provider-specific error mapper.
    fn error_mapper(&self) -> &dyn ErrorMapper {
        &DEFAULT_ERROR_MAPPER
    }

    /// Extra request headers for a model.
    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

/// Maps provider error responses into the shared taxonomy.
pub trait ErrorMapper: Send + Sync {
    /// Map a non-success HTTP response.
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError;
}

/// Default OpenAI-compatible error mapper.
#[derive(Debug, Clone, Copy)]
pub struct DefaultOpenAiErrorMapper;

#[derive(Debug, serde::Deserialize)]
struct ProviderErrorEnvelope {
    error: Option<ProviderErrorBody>,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderErrorBody {
    #[serde(rename = "type")]
    error_type: Option<String>,
    message: Option<String>,
    param: Option<String>,
    code: Option<String>,
}

impl ErrorMapper for DefaultOpenAiErrorMapper {
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        _headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError {
        let body_text = truncate_response_body(body);
        let parsed = serde_json::from_slice::<ProviderErrorEnvelope>(body)
            .ok()
            .and_then(|envelope| envelope.error);
        let message = parsed
            .as_ref()
            .and_then(|error| error.message.clone())
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| {
                if body_text.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body_text.clone()
                }
            });
        let error_type = parsed
            .as_ref()
            .and_then(|error| error.error_type.as_deref());
        let param = parsed.as_ref().and_then(|error| error.param.clone());
        let code = parsed.as_ref().and_then(|error| error.code.clone());

        match status {
            400 => OpenAiError::InvalidRequest {
                message,
                param,
                code,
            },
            401 => OpenAiError::Authentication { message },
            403 => OpenAiError::PermissionDenied { message },
            404 => OpenAiError::NotFound {
                message,
                resource: param,
            },
            429 => OpenAiError::RateLimited {
                message,
                retry_after: rate_limits.retry_after,
            },
            500 => OpenAiError::InternalError { message },
            503 => OpenAiError::ServiceUnavailable {
                message,
                retry_after: rate_limits.retry_after,
            },
            _ if matches!(error_type, Some("rate_limit" | "rate_limit_error")) => {
                OpenAiError::RateLimited {
                    message,
                    retry_after: rate_limits.retry_after,
                }
            }
            _ => OpenAiError::Provider {
                provider: provider.to_string(),
                status,
                body: body_text,
            },
        }
    }
}

/// Client behavior knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAiCompatClientConfig {
    /// Total operation timeout, including retries and the complete response stream.
    pub request_timeout: Duration,
    /// Model-list cache time-to-live.
    pub model_cache_ttl: Duration,
    /// Rate-limit retry behavior.
    pub rate_limit_policy: RateLimitPolicy,
}

impl Default for OpenAiCompatClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            model_cache_ttl: Duration::from_secs(60 * 60),
            rate_limit_policy: RateLimitPolicy::FailFast,
        }
    }
}

/// One execution budget shared by a provider request, backoff, and response body.
///
/// Provider-specific endpoints should create this once, outside their retry
/// loop. The caller's native deadline can only shorten the configured timeout.
/// Cancellation actively wakes pending I/O and sleeps; no background task or
/// periodic cancellation polling is required.
pub struct RequestBudget {
    cx: Cx,
    deadline: Deadline,
    timeout_ms: u64,
    timer: Option<Pin<Box<time::Sleep>>>,
    cancellation: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl RequestBudget {
    /// Start a total operation budget, narrowed by the explicit caller context.
    pub fn new(cx: &Cx, timeout: Duration) -> Self {
        let timeout = cx.budget().deadline.map_or(timeout, |deadline| {
            timeout.min(Duration::from_nanos(
                deadline.as_nanos().saturating_sub(cx.now().as_nanos()),
            ))
        });
        let cancellation_cx = cx.clone();
        Self {
            cx: cx.clone(),
            deadline: Deadline::after(timeout),
            timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            timer: None,
            cancellation: Box::pin(async move {
                wait_for_cx_cancellation(&cancellation_cx).await;
            }),
        }
    }

    /// Check the budget before constructing requests or returning cached results.
    pub fn checkpoint(&self) -> Result<(), OpenAiError> {
        if self.deadline.is_expired()
            || self
                .cx
                .budget()
                .deadline
                .is_some_and(|deadline| self.cx.now() >= deadline)
        {
            return Err(self.timeout_error());
        }
        checkpoint(&self.cx)
    }

    fn timeout_error(&self) -> OpenAiError {
        OpenAiError::Network(NetworkError::DeadlineExceeded {
            timeout_ms: self.timeout_ms,
        })
    }

    fn poll_interruption(&mut self, task: &mut Context<'_>) -> Poll<OpenAiError> {
        if let Err(error) = self.checkpoint() {
            return Poll::Ready(error);
        }
        if self.cancellation.as_mut().poll(task).is_ready() {
            return Poll::Ready(self.checkpoint().err().unwrap_or_else(|| {
                OpenAiError::Network(NetworkError::Cancelled {
                    message: "caller context cancelled".into(),
                })
            }));
        }
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(time::sleep(self.deadline.remaining())));
        if timer.as_mut().poll(task).is_ready() {
            return Poll::Ready(self.timeout_error());
        }
        Poll::Pending
    }

    /// Run an I/O phase under the original deadline and caller cancellation.
    ///
    /// An interrupted future is dropped and is never retried here: cancellation
    /// and timeout cannot establish whether a provider already applied an effect.
    pub async fn run<T>(&mut self, future: impl Future<Output = T>) -> Result<T, OpenAiError> {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|task| {
            if let Poll::Ready(error) = self.poll_interruption(task) {
                return Poll::Ready(Err(error));
            }
            future.as_mut().poll(task).map(Ok)
        })
        .await
    }

    /// Wait for an entire provider minimum delay, or refuse the retry.
    ///
    /// `false` means the minimum wait leaves no request budget. Callers must
    /// return the original provider error rather than shorten the delay.
    pub async fn wait_for_retry(&mut self, delay: Duration) -> Result<bool, OpenAiError> {
        self.checkpoint()?;
        if delay >= self.deadline.remaining() {
            return Ok(false);
        }
        self.run(time::sleep(delay)).await?;
        Ok(true)
    }
}

#[derive(Debug, Clone)]
struct ModelCache {
    fetched_at: Instant,
    models: Vec<ModelInfo>,
}

/// OpenAI-compatible HTTP client.
pub struct OpenAiCompatClient<P: OpenAiCompatProvider> {
    provider: P,
    http_client: Arc<HttpClient>,
    config: OpenAiCompatClientConfig,
    model_cache: fcp_async_core::sync::Mutex<Option<ModelCache>>,
}

impl<P: OpenAiCompatProvider> OpenAiCompatClient<P> {
    /// Create a client from provider policy and injected HTTP client.
    pub fn new(provider: P, http_client: HttpClient) -> Self {
        Self::new_with_config(provider, http_client, OpenAiCompatClientConfig::default())
    }

    /// Create a client with explicit behavior knobs.
    pub fn new_with_config(
        provider: P,
        http_client: HttpClient,
        config: OpenAiCompatClientConfig,
    ) -> Self {
        Self {
            provider,
            http_client: Arc::new(http_client),
            config,
            model_cache: fcp_async_core::sync::Mutex::new(None),
        }
    }

    /// Provider policy.
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// Invalidate the model-list cache.
    pub async fn invalidate_model_cache(&self) {
        *self.model_cache.lock().await = None;
    }

    /// Send a non-streaming chat-completions request.
    pub async fn chat_completions(
        &self,
        cx: &Cx,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse, OpenAiError> {
        req.stream = false;
        self.request_json(cx, Method::Post, "/chat/completions", &req.model, &req)
            .await
    }

    /// Send a streaming chat-completions request.
    pub async fn chat_completions_stream(
        &self,
        cx: &Cx,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionStream, OpenAiError> {
        req.stream = true;
        let mut budget = RequestBudget::new(cx, self.config.request_timeout);
        let response = self
            .request_streaming(cx, &mut budget, "/chat/completions", &req.model, &req)
            .await?;
        Ok(ChatCompletionStream::new(budget, response))
    }

    /// Send an embeddings request.
    pub async fn embeddings(
        &self,
        cx: &Cx,
        req: EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, OpenAiError> {
        self.request_json(cx, Method::Post, "/embeddings", &req.model, &req)
            .await
    }

    /// List models, using the configured in-memory cache.
    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        let mut budget = RequestBudget::new(cx, self.config.request_timeout);
        {
            let guard = budget.run(self.model_cache.lock()).await?;
            if let Some(cache) = guard.as_ref() {
                if cache.fetched_at.elapsed() <= self.config.model_cache_ttl {
                    budget.checkpoint()?;
                    return Ok(cache.models.clone());
                }
            }
        }

        let response: ModelsResponse = self
            .request_json_with_budget(cx, &mut budget, Method::Get, "/models", "", &())
            .await?;
        *budget.run(self.model_cache.lock()).await? = Some(ModelCache {
            fetched_at: Instant::now(),
            models: response.data.clone(),
        });
        Ok(response.data)
    }

    /// Send a legacy completions request.
    pub async fn legacy_completions(
        &self,
        cx: &Cx,
        req: CompletionsRequest,
    ) -> Result<CompletionsResponse, OpenAiError> {
        self.request_json(cx, Method::Post, "/completions", &req.model, &req)
            .await
    }

    async fn request_json<T, R>(
        &self,
        cx: &Cx,
        method: Method,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<R, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
        R: DeserializeOwned,
    {
        let mut budget = RequestBudget::new(cx, self.config.request_timeout);
        self.request_json_with_budget(cx, &mut budget, method, path, model, body)
            .await
    }

    async fn request_json_with_budget<T, R>(
        &self,
        cx: &Cx,
        budget: &mut RequestBudget,
        method: Method,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<R, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
        R: DeserializeOwned,
    {
        budget.checkpoint()?;
        let body_bytes = if matches!(method, Method::Get) {
            Vec::new()
        } else {
            serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
                message: format!("failed to serialize request: {err}"),
                param: None,
                code: Some("serialize_request".to_string()),
            })?
        };
        let mut attempted_rate_limit_retry = false;
        loop {
            budget.checkpoint()?;
            let headers = self.headers_for(model);
            let url = self.url(path);
            let request =
                self.http_client
                    .request(cx, method.clone(), &url, headers, body_bytes.clone());
            let response = budget
                .run(request)
                .await?
                .map_err(|err| OpenAiError::Network(err.into()))?;

            let status = response.status_code();
            let rate_limits = parse_rate_limit_headers(
                &response.headers,
                self.provider.rate_limit_overrides().as_ref(),
            );
            if !status.is_success() {
                let mapped = self.provider.error_mapper().map_response(
                    self.provider.provider_name(),
                    status.as_u16(),
                    &response.headers,
                    &response.body,
                    rate_limits,
                );
                if !attempted_rate_limit_retry {
                    if let Some(delay) =
                        retry_delay_for_policy(&mapped, self.config.rate_limit_policy)
                    {
                        attempted_rate_limit_retry = true;
                        if budget.wait_for_retry(delay).await? {
                            continue;
                        }
                    }
                }
                return Err(mapped);
            }

            budget.checkpoint()?;
            return serde_json::from_slice(&response.body).map_err(|err| {
                OpenAiError::InvalidRequest {
                    message: format!("failed to decode provider response: {err}"),
                    param: None,
                    code: Some("decode_response".to_string()),
                }
            });
        }
    }

    async fn request_streaming<T>(
        &self,
        cx: &Cx,
        budget: &mut RequestBudget,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<ClientIncomingBody<ClientIo>, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
    {
        budget.checkpoint()?;
        let body_bytes = serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
            message: format!("failed to serialize request: {err}"),
            param: None,
            code: Some("serialize_request".to_string()),
        })?;
        let mut attempted_rate_limit_retry = false;
        loop {
            budget.checkpoint()?;
            let url = self.url(path);
            let response = budget
                .run(self.http_client.request_streaming(
                    cx,
                    Method::Post,
                    &url,
                    self.headers_for(model),
                    body_bytes.clone(),
                ))
                .await?
                .map_err(|err| OpenAiError::Network(err.into()))?;
            if !(200..300).contains(&response.head.status) {
                let rate_limits = parse_rate_limit_headers(
                    &response.head.headers,
                    self.provider.rate_limit_overrides().as_ref(),
                );
                let error = self.provider.error_mapper().map_response(
                    self.provider.provider_name(),
                    response.head.status,
                    &response.head.headers,
                    response.head.reason.as_bytes(),
                    rate_limits,
                );
                // No response stream has been exposed. Drop the rejected body
                // before any backoff so it cannot retain a live connection.
                drop(response);
                if !attempted_rate_limit_retry {
                    if let Some(delay) =
                        retry_delay_for_policy(&error, self.config.rate_limit_policy)
                    {
                        attempted_rate_limit_retry = true;
                        if budget.wait_for_retry(delay).await? {
                            continue;
                        }
                    }
                }
                return Err(error);
            }
            budget.checkpoint()?;
            return Ok(response.body);
        }
    }

    fn headers_for(&self, model: &str) -> HeaderList {
        let mut request = HttpRequest {
            headers: vec![
                (ACCEPT_HEADER.to_string(), JSON_CONTENT_TYPE.to_string()),
                (
                    CONTENT_TYPE_HEADER.to_string(),
                    JSON_CONTENT_TYPE.to_string(),
                ),
                (
                    USER_AGENT_HEADER.to_string(),
                    self.provider.user_agent().to_string(),
                ),
            ],
        };
        request
            .headers
            .extend(self.provider.extra_request_headers(model));
        self.provider.auth_header(&mut request);
        request.headers
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.provider.base_url().trim_end_matches('/'), path)
    }
}

fn retry_delay_for_policy(error: &OpenAiError, policy: RateLimitPolicy) -> Option<Duration> {
    let retry_after = error.retry_after()?;
    match policy {
        RateLimitPolicy::WaitUpTo(max_wait) if retry_after <= max_wait => Some(retry_after),
        RateLimitPolicy::FailFast | RateLimitPolicy::WaitUpTo(_) => None,
        RateLimitPolicy::WaitForever => Some(retry_after),
    }
}

fn checkpoint(cx: &Cx) -> Result<(), OpenAiError> {
    cx.checkpoint().map_err(|err| {
        OpenAiError::Network(NetworkError::Cancelled {
            message: err.to_string(),
        })
    })
}

/// Streaming chat-completion chunks.
pub struct ChatCompletionStream {
    budget: Option<RequestBudget>,
    body: Option<Pin<Box<ClientIncomingBody<ClientIo>>>>,
    decoder: OpenAiSseDecoder,
    pending: VecDeque<Result<ChatChunk, OpenAiError>>,
    finished: bool,
}

impl ChatCompletionStream {
    fn new(budget: RequestBudget, body: ClientIncomingBody<ClientIo>) -> Self {
        Self {
            budget: Some(budget),
            body: Some(Box::pin(body)),
            decoder: OpenAiSseDecoder::new(),
            pending: VecDeque::new(),
            finished: false,
        }
    }

    fn enqueue_events(&mut self, events: Vec<Result<OpenAiStreamEvent, OpenAiError>>) {
        for event in events {
            match event {
                Ok(OpenAiStreamEvent::Chunk(chunk)) => self.pending.push_back(Ok(chunk)),
                Ok(OpenAiStreamEvent::Done) => {
                    self.finished = true;
                    self.body = None;
                    self.budget = None;
                    break;
                }
                Err(err) => {
                    self.finished = true;
                    self.body = None;
                    self.budget = None;
                    self.pending.push_back(Err(err));
                    break;
                }
            }
        }
    }
}

impl Stream for ChatCompletionStream {
    type Item = Result<ChatChunk, OpenAiError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.finished {
            return Poll::Ready(this.pending.pop_front());
        }

        loop {
            if let Some(budget) = this.budget.as_mut() {
                if let Poll::Ready(error) = budget.poll_interruption(cx) {
                    this.finished = true;
                    this.body = None;
                    this.budget = None;
                    this.pending.clear();
                    return Poll::Ready(Some(Err(error)));
                }
            }
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }
            let Some(body) = this.body.as_mut() else {
                this.finished = true;
                this.budget = None;
                return Poll::Ready(None);
            };

            match ready!(body.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.into_data() {
                        let bytes = Bytes::copy_from_slice(data.chunk());
                        let events = this.decoder.feed(&bytes);
                        this.enqueue_events(events);
                        if let Some(event) = this.pending.pop_front() {
                            return Poll::Ready(Some(event));
                        }
                        if this.finished {
                            return Poll::Ready(None);
                        }
                    }
                }
                Some(Err(error)) => {
                    this.finished = true;
                    this.body = None;
                    this.budget = None;
                    return Poll::Ready(Some(Err(OpenAiError::Streaming(
                        StreamingError::MalformedPayload {
                            message: error.to_string(),
                        },
                    ))));
                }
                None => {
                    this.body = None;
                    this.finished = true;
                    this.budget = None;
                    return match this.decoder.finish() {
                        Some(Ok(OpenAiStreamEvent::Chunk(chunk))) => Poll::Ready(Some(Ok(chunk))),
                        Some(Ok(OpenAiStreamEvent::Done)) | None => Poll::Ready(None),
                        Some(Err(err)) => Poll::Ready(Some(Err(err))),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct TestProvider {
        base_url: String,
    }

    impl OpenAiCompatProvider for TestProvider {
        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn auth_header(&self, req: &mut HttpRequest) {
            req.bearer_auth("test-token");
        }

        fn user_agent(&self) -> &'static str {
            "fcp-openai-compat-test/0.1.0"
        }

        fn provider_name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn provider_headers_include_auth_user_agent_and_content_type() {
        let client = OpenAiCompatClient::new(
            TestProvider {
                base_url: "https://example.test/v1".to_string(),
            },
            fcp_async_core::http::HttpClientBuilder::new().build(),
        );

        let headers = client.headers_for("model");
        assert!(
            headers.iter().any(|(name, value)| {
                name == AUTHORIZATION_HEADER && value == "Bearer test-token"
            })
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == USER_AGENT_HEADER && value.contains("test"))
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == CONTENT_TYPE_HEADER && value == JSON_CONTENT_TYPE)
        );
    }

    #[test]
    fn default_error_mapper_maps_provider_taxonomy() {
        let body = json!({
            "error": {
                "type": "invalid_request_error",
                "message": "bad input",
                "param": "messages",
                "code": "bad_messages"
            }
        })
        .to_string();
        let err = DefaultOpenAiErrorMapper.map_response(
            "test",
            400,
            &Vec::new(),
            body.as_bytes(),
            RateLimitSnapshot::default(),
        );
        assert!(matches!(
            err,
            OpenAiError::InvalidRequest {
                param: Some(_),
                code: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn retry_policy_wait_up_to_honors_budget() {
        let err = OpenAiError::RateLimited {
            message: "slow down".to_string(),
            retry_after: Some(Duration::from_secs(2)),
        };
        assert_eq!(
            retry_delay_for_policy(&err, RateLimitPolicy::WaitUpTo(Duration::from_secs(5))),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_delay_for_policy(&err, RateLimitPolicy::WaitUpTo(Duration::from_secs(1))),
            None
        );
    }

    #[fcp_async_core::runtime::test]
    async fn expired_caller_budget_prevents_polling_provider_work() {
        let cx = Cx::for_testing();
        let expired = Cx::for_testing_with_budget(cx.budget_for_timeout(Duration::ZERO));
        let mut budget = RequestBudget::new(&expired, Duration::from_secs(60));
        let mut dispatched = false;
        let error = budget
            .run(async { dispatched = true })
            .await
            .expect_err("the caller's deadline must take precedence");
        assert!(!dispatched);
        assert!(matches!(
            error,
            OpenAiError::Network(NetworkError::DeadlineExceeded { timeout_ms: 0 })
        ));
        assert!(!error.is_retryable());
    }

    #[test]
    fn explicit_cancellation_wakes_pending_request_and_releases_waiter() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct WakeCounter(AtomicUsize);
        impl Wake for WakeCounter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = Cx::for_testing();
        let mut budget = RequestBudget::new(&cx, Duration::from_secs(60));
        let wakes = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let mut request = Box::pin(budget.run(std::future::pending::<()>()));
        assert!(request.as_mut().poll(&mut task).is_pending());
        cx.set_cancel_requested(true);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            request.as_mut().poll(&mut task),
            Poll::Ready(Err(OpenAiError::Network(NetworkError::Cancelled { .. })))
        ));
        drop(request);
        drop(budget);

        cx.set_cancel_requested(false);
        let before = wakes.0.load(Ordering::SeqCst);
        cx.set_cancel_requested(true);
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
    }

    #[fcp_async_core::runtime::test]
    async fn provider_minimum_delay_is_refused_when_total_budget_cannot_fit_it() {
        let cx = Cx::for_testing();
        let mut budget = RequestBudget::new(&cx, Duration::from_secs(1));
        assert!(
            !budget
                .wait_for_retry(Duration::from_secs(60))
                .await
                .expect("too-long retry delay should be refused")
        );
    }
}
