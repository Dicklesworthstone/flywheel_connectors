use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::Cx;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, CompletionsRequest,
    CompletionsResponse, EmbeddingsRequest, EmbeddingsResponse, HeaderList, HttpRequest, ModelInfo,
    OpenAiCompatClient, OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError,
    RateLimitPolicy, RequestBudget, parse_rate_limit_headers,
};
use serde::Deserialize;
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://api.fireworks.ai/inference/v1";
pub const DEFAULT_MODEL: &str = "accounts/fireworks/models/llama-v3p1-8b-instruct";
pub const DEFAULT_EMBEDDING_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
pub const USER_AGENT: &str = "fcp-fireworks/0.1.0";

const ACCEPT_HEADER: &str = "Accept";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FireworksAuth {
    ApiKey(String),
    CredentialId(String),
}

impl FireworksAuth {
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
pub struct FireworksProvider {
    base_url: String,
    auth: FireworksAuth,
}

impl FireworksProvider {
    pub fn new(base_url: impl Into<String>, auth: FireworksAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &FireworksAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for FireworksProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            FireworksAuth::ApiKey(key) => req.bearer_auth(key),
            FireworksAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "fireworks"
    }

    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
struct ModelCache {
    fetched_at: Instant,
    models: Vec<ModelInfo>,
}

pub struct FireworksClient {
    inner: OpenAiCompatClient<FireworksProvider>,
    provider: FireworksProvider,
    http_client: Arc<HttpClient>,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
    model_cache: fcp_async_core::sync::Mutex<Option<ModelCache>>,
}

impl FireworksClient {
    pub fn new(
        provider: FireworksProvider,
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
            model_cache_ttl,
            rate_limit_policy,
            model_cache: fcp_async_core::sync::Mutex::new(None),
        }
    }

    pub const fn provider(&self) -> &FireworksProvider {
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

    pub async fn embeddings(
        &self,
        cx: &Cx,
        request: EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, OpenAiError> {
        self.inner.embeddings(cx, request).await
    }

    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        let mut budget = RequestBudget::new(cx, self.request_timeout);
        {
            let guard = budget.run(self.model_cache.lock()).await?;
            if let Some(cache) = guard.as_ref() {
                if cache.fetched_at.elapsed() <= self.model_cache_ttl {
                    return Ok(cache.models.clone());
                }
            }
        }

        let models = self.fetch_models(cx, &mut budget).await?;
        *budget.run(self.model_cache.lock()).await? = Some(ModelCache {
            fetched_at: Instant::now(),
            models: models.clone(),
        });
        Ok(models)
    }

    pub async fn invalidate_model_cache(&self) {
        *self.model_cache.lock().await = None;
        self.inner.invalidate_model_cache().await;
    }

    pub async fn legacy_completions(
        &self,
        cx: &Cx,
        request: CompletionsRequest,
    ) -> Result<CompletionsResponse, OpenAiError> {
        self.inner.legacy_completions(cx, request).await
    }

    async fn fetch_models(
        &self,
        cx: &Cx,
        budget: &mut RequestBudget,
    ) -> Result<Vec<ModelInfo>, OpenAiError> {
        let mut attempted_rate_limit_retry = false;
        loop {
            budget.checkpoint()?;
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
            self.provider.auth_header(&mut request);
            let url = format!("{}/models", self.provider.base_url().trim_end_matches('/'));
            let response = budget
                .run(
                    self.http_client
                        .request(cx, Method::Get, &url, request.headers, Vec::new()),
                )
                .await?
                .map_err(|err| OpenAiError::Network(err.into()))?;
            let status = response.status_code();
            let rate_limits = parse_rate_limit_headers(&response.headers, None);
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
            return parse_models_body(&response.body);
        }
    }
}

pub fn normalize_fireworks_base_url(raw: Option<&str>) -> Result<String, String> {
    let value = raw.unwrap_or(DEFAULT_BASE_URL).trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "base_url must not include username or password components: {value}"
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let path = parsed.path().trim_end_matches('/');
    let allowed_host = normalized_host == "api.fireworks.ai" || local;

    if !allowed_host || !valid_scheme || path != "/inference/v1" {
        return Err(format!(
            "base_url must be https://api.fireworks.ai/inference/v1 (localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
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

fn parse_models_body(body: &[u8]) -> Result<Vec<ModelInfo>, OpenAiError> {
    let envelope = serde_json::from_slice::<FireworksModelsEnvelope>(body).map_err(|err| {
        OpenAiError::InvalidRequest {
            message: format!("failed to decode Fireworks models response: {err}"),
            param: None,
            code: Some("decode_response".to_string()),
        }
    })?;
    let models = match envelope {
        FireworksModelsEnvelope::OpenAi { data, .. } | FireworksModelsEnvelope::Array(data) => data,
    };
    Ok(models
        .into_iter()
        .map(FireworksModelInfo::into_model_info)
        .collect())
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FireworksModelsEnvelope {
    OpenAi {
        #[allow(dead_code)]
        object: Option<String>,
        data: Vec<FireworksModelInfo>,
    },
    Array(Vec<FireworksModelInfo>),
}

#[derive(Debug, Deserialize)]
struct FireworksModelInfo {
    id: String,
    object: Option<String>,
    owned_by: Option<String>,
    organization: Option<String>,
    created: Option<i64>,
}

impl FireworksModelInfo {
    fn into_model_info(self) -> ModelInfo {
        ModelInfo {
            id: self.id,
            object: self.object.or_else(|| Some("model".into())),
            owned_by: self.owned_by.or(self.organization),
            created: self.created,
        }
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
