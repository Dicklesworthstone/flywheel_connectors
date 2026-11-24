use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, HeaderList, HttpRequest,
    ModelInfo, OpenAiCompatClient, OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError,
    RateLimitPolicy,
};
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://api.deepseek.com";
pub const DEFAULT_MODEL: &str = "deepseek-v4-pro";
pub const USER_AGENT: &str = "fcp-deepseek/0.1.0";

// Enforce the manifest's response bound while reading JSON or SSE bodies,
// before the completed FCP response is checked against its admission budget.
const MAX_PROVIDER_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeepSeekAuth {
    ApiKey(String),
    CredentialId(String),
}

impl DeepSeekAuth {
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
pub struct DeepSeekProvider {
    base_url: String,
    auth: DeepSeekAuth,
}

impl DeepSeekProvider {
    pub fn new(base_url: impl Into<String>, auth: DeepSeekAuth) -> Self {
        Self {
            auth,
            base_url: base_url.into(),
        }
    }

    pub const fn auth(&self) -> &DeepSeekAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for DeepSeekProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            DeepSeekAuth::ApiKey(key) => req.bearer_auth(key),
            DeepSeekAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "deepseek"
    }

    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

pub struct DeepSeekClient {
    inner: OpenAiCompatClient<DeepSeekProvider>,
}

impl DeepSeekClient {
    pub fn new(
        provider: DeepSeekProvider,
        request_timeout: Duration,
        model_cache_ttl: Duration,
        rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        Self {
            inner: OpenAiCompatClient::new_with_config(
                provider,
                HttpClientBuilder::new()
                    .max_body_size(MAX_PROVIDER_RESPONSE_BYTES)
                    .build(),
                OpenAiCompatClientConfig {
                    request_timeout,
                    model_cache_ttl,
                    rate_limit_policy,
                },
            ),
        }
    }

    pub const fn provider(&self) -> &DeepSeekProvider {
        self.inner.provider()
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
}

pub fn normalize_deepseek_base_url(raw: Option<&str>) -> Result<String, String> {
    let value = raw.unwrap_or(DEFAULT_BASE_URL).trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = normalize_host(host);
    let local = is_loopback_host(&normalized_host);
    let path = parsed.path().trim_end_matches('/');
    let valid_path = path.is_empty() || path == "/v1";
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let allowed_host = normalized_host == "api.deepseek.com" || local;

    if !allowed_host || !valid_scheme || !valid_path {
        return Err(format!(
            "base_url must be https://api.deepseek.com (optional /v1; localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn normalize_host(host: &str) -> String {
    host.trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase()
}

fn is_loopback_host(normalized_host: &str) -> bool {
    matches!(normalized_host, "localhost" | "127.0.0.1" | "::1")
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
