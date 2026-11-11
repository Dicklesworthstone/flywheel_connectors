use std::sync::Arc;
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, HeaderList, HttpRequest,
    ModelInfo, OpenAiCompatClient, OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError,
    RateLimitConfig, RateLimitPolicy, RequestBudget, parse_rate_limit_headers,
};
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::types::ResponsesCreateRequest;

pub const DEFAULT_BASE_URL: &str = "https://api.x.ai/v1";
pub const DEFAULT_MODEL: &str = "grok-4.3";
pub const USER_AGENT: &str = "fcp-xai/0.1.0";

const ACCEPT_HEADER: &str = "Accept";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XaiAuth {
    ApiKey(String),
    CredentialId(String),
}

impl XaiAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug)]
pub struct XaiProvider {
    base_url: String,
    auth: XaiAuth,
}

impl XaiProvider {
    pub fn new(base_url: impl Into<String>, auth: XaiAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &XaiAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for XaiProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            XaiAuth::ApiKey(key) => req.bearer_auth(key),
            XaiAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "xai"
    }

    fn rate_limit_overrides(&self) -> Option<RateLimitConfig> {
        Some(RateLimitConfig {
            request_limit_header: Some("x-ratelimit-limit-requests".to_string()),
            request_remaining_header: Some("x-ratelimit-remaining-requests".to_string()),
            request_reset_header: Some("x-ratelimit-reset-requests".to_string()),
            token_limit_header: Some("x-ratelimit-limit-tokens".to_string()),
            token_remaining_header: Some("x-ratelimit-remaining-tokens".to_string()),
            token_reset_header: Some("x-ratelimit-reset-tokens".to_string()),
            retry_after_header: Some("retry-after".to_string()),
        })
    }
}

pub struct XaiClient {
    inner: OpenAiCompatClient<XaiProvider>,
    provider: XaiProvider,
    http_client: Arc<HttpClient>,
    request_timeout: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl XaiClient {
    pub fn new(
        provider: XaiProvider,
        request_timeout: Duration,
        model_cache_ttl: Duration,
        rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        let inner_http_client = HttpClientBuilder::new().build();
        let direct_http_client = HttpClientBuilder::new().build();
        Self {
            inner: OpenAiCompatClient::new_with_config(
                provider.clone(),
                inner_http_client,
                OpenAiCompatClientConfig {
                    request_timeout,
                    model_cache_ttl,
                    rate_limit_policy,
                },
            ),
            provider,
            http_client: Arc::new(direct_http_client),
            request_timeout,
            rate_limit_policy,
        }
    }

    pub const fn provider(&self) -> &XaiProvider {
        &self.provider
    }

    pub async fn chat_completions(
        &self,
        cx: &Cx,
        request: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse, OpenAiError> {
        self.inner.chat_completions(cx, request).await
    }

    pub async fn chat_completions_stream(
        &self,
        cx: &Cx,
        request: ChatCompletionsRequest,
    ) -> Result<ChatCompletionStream, OpenAiError> {
        self.inner.chat_completions_stream(cx, request).await
    }

    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        self.inner.list_models(cx).await
    }

    pub async fn invalidate_model_cache(&self) {
        self.inner.invalidate_model_cache().await;
    }

    pub async fn responses_create(
        &self,
        cx: &Cx,
        request: ResponsesCreateRequest,
    ) -> Result<Value, OpenAiError> {
        self.request_json(cx, "/responses", &request.model, &request)
            .await
    }

    async fn request_json<T>(
        &self,
        cx: &Cx,
        path: &str,
        model: &str,
        body: &T,
    ) -> Result<Value, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let mut budget = RequestBudget::new(cx, self.request_timeout);
        let mut attempted_rate_limit_retry = false;
        loop {
            budget.checkpoint()?;
            let body_bytes =
                serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
                    message: format!("failed to serialize request: {err}"),
                    param: None,
                    code: Some("serialize_request".to_string()),
                })?;
            let url = self.url(path);
            let request = self.http_client.request(
                cx,
                Method::Post,
                &url,
                self.headers_for(model),
                body_bytes,
            );
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
                    if let Some(delay) = retry_delay_for_policy(&mapped, self.rate_limit_policy) {
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

    fn headers_for(&self, model: &str) -> HeaderList {
        let mut request = HttpRequest {
            headers: vec![
                (ACCEPT_HEADER.to_string(), JSON_CONTENT_TYPE.to_string()),
                (
                    CONTENT_TYPE_HEADER.to_string(),
                    JSON_CONTENT_TYPE.to_string(),
                ),
                (USER_AGENT_HEADER.to_string(), USER_AGENT.to_string()),
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

pub fn normalize_xai_base_url(raw: Option<&str>) -> Result<String, String> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BASE_URL);
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let path = parsed.path().trim_end_matches('/');
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let allowed_host = normalized_host == "api.x.ai" || local;

    if !allowed_host || !valid_scheme || path != "/v1" {
        return Err(format!(
            "base_url must be https://api.x.ai/v1 (localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn validate_auth_material(field: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(format!(
            "{field} contains characters that are invalid in headers"
        ));
    }
    Ok(trimmed.to_string())
}

fn retry_delay_for_policy(error: &OpenAiError, policy: RateLimitPolicy) -> Option<Duration> {
    let retry_after = error.retry_after()?;
    match policy {
        RateLimitPolicy::WaitUpTo(max_wait) if retry_after <= max_wait => Some(retry_after),
        RateLimitPolicy::FailFast | RateLimitPolicy::WaitUpTo(_) => None,
        RateLimitPolicy::WaitForever => Some(retry_after),
    }
}
