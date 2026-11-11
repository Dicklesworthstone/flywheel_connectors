use std::sync::Arc;
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_openai_compat::{
    EmbeddingsRequest, EmbeddingsResponse, ErrorMapper, HeaderList, HttpRequest, ModelInfo,
    OpenAiCompatClient, OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError,
    RateLimitPolicy, RateLimitSnapshot, RequestBudget, parse_rate_limit_headers,
    redact_sensitive_text, truncate_response_body,
};
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::types::{MultimodalEmbeddingsRequest, RerankRequest, documented_model_catalog_value};

pub const DEFAULT_BASE_URL: &str = "https://api.voyageai.com/v1";
pub const DEFAULT_EMBEDDING_MODEL: &str = "voyage-3.5";
pub const DEFAULT_MULTIMODAL_MODEL: &str = "voyage-multimodal-3.5";
pub const DEFAULT_RERANK_MODEL: &str = "rerank-2.5";
pub const USER_AGENT: &str = "fcp-voyage/0.1.0";

const ACCEPT_HEADER: &str = "Accept";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoyageAuth {
    ApiKey(String),
    CredentialId(String),
}

impl VoyageAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "bearer:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn uses_host_credential_reference(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug)]
pub struct VoyageProvider {
    base_url: String,
    auth: VoyageAuth,
}

impl VoyageProvider {
    pub fn new(base_url: impl Into<String>, auth: VoyageAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &VoyageAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for VoyageProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            VoyageAuth::ApiKey(key) => req.bearer_auth(key),
            VoyageAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "voyage"
    }

    fn error_mapper(&self) -> &dyn ErrorMapper {
        &VOYAGE_ERROR_MAPPER
    }
}

static VOYAGE_ERROR_MAPPER: VoyageErrorMapper = VoyageErrorMapper;

#[derive(Debug, Clone, Copy)]
struct VoyageErrorMapper;

#[derive(Debug, serde::Deserialize)]
struct VoyageErrorEnvelope {
    error: Option<VoyageErrorBody>,
    detail: Option<Value>,
    message: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct VoyageErrorBody {
    message: Option<String>,
    code: Option<Value>,
    #[serde(rename = "type")]
    error_type: Option<String>,
    param: Option<String>,
}

impl ErrorMapper for VoyageErrorMapper {
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        _headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError {
        let body_text = truncate_response_body(body);
        let parsed = serde_json::from_slice::<VoyageErrorEnvelope>(body).ok();
        let error = parsed.as_ref().and_then(|envelope| envelope.error.as_ref());
        let message = error
            .and_then(|body| body.message.clone())
            .or_else(|| {
                parsed
                    .as_ref()
                    .and_then(|envelope| envelope.message.clone())
            })
            .or_else(|| {
                parsed
                    .as_ref()
                    .and_then(|envelope| envelope.detail.as_ref())
                    .map(Value::to_string)
            })
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| {
                if body_text.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body_text.clone()
                }
            });
        let code = error
            .and_then(|body| body.code.as_ref())
            .and_then(code_to_string);
        let error_type = error.and_then(|body| body.error_type.as_deref());
        let param = error.and_then(|body| body.param.clone());
        let safe_message = redact_sensitive_text(&message);

        match status {
            400 => OpenAiError::InvalidRequest {
                message: safe_message,
                param,
                code,
            },
            401 => OpenAiError::Authentication {
                message: safe_message,
            },
            403 => OpenAiError::PermissionDenied {
                message: safe_message,
            },
            404 => OpenAiError::NotFound {
                message: safe_message,
                resource: param,
            },
            429 => OpenAiError::RateLimited {
                message: safe_message,
                retry_after: rate_limits.retry_after,
            },
            500 => OpenAiError::InternalError {
                message: safe_message,
            },
            503 => OpenAiError::ServiceUnavailable {
                message: safe_message,
                retry_after: rate_limits.retry_after,
            },
            _ if matches!(error_type, Some("rate_limit" | "rate_limit_error")) => {
                OpenAiError::RateLimited {
                    message: safe_message,
                    retry_after: rate_limits.retry_after,
                }
            }
            _ => OpenAiError::Provider {
                provider: provider.to_string(),
                status,
                body: redact_sensitive_text(&body_text),
            },
        }
    }
}

pub struct VoyageClient {
    inner: OpenAiCompatClient<VoyageProvider>,
    provider: VoyageProvider,
    http_client: Arc<HttpClient>,
    request_timeout: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl VoyageClient {
    pub fn new(
        provider: VoyageProvider,
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

    pub const fn provider(&self) -> &VoyageProvider {
        &self.provider
    }

    pub async fn embeddings(
        &self,
        cx: &Cx,
        request: EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, OpenAiError> {
        self.inner.embeddings(cx, request).await
    }

    pub async fn multimodal_embeddings(
        &self,
        cx: &Cx,
        request: MultimodalEmbeddingsRequest,
    ) -> Result<Value, OpenAiError> {
        self.request_json(cx, "/multimodalembeddings", &request.model, &request)
            .await
    }

    pub async fn rerank(&self, cx: &Cx, request: RerankRequest) -> Result<Value, OpenAiError> {
        self.request_json(cx, "/rerank", &request.model, &request)
            .await
    }

    pub async fn list_models(&self) -> Vec<ModelInfo> {
        documented_model_catalog_value()
            .iter()
            .map(|id| ModelInfo {
                id: id.to_string(),
                object: Some("model".into()),
                owned_by: Some("voyage".into()),
                created: None,
            })
            .collect()
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

pub fn normalize_voyage_base_url(value: Option<&str>) -> Result<String, String> {
    let raw = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BASE_URL);
    let parsed = Url::parse(raw).map_err(|err| format!("invalid base_url: {err}"))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    if is_loopback {
        if !matches!(scheme, "http" | "https") {
            return Err("loopback base_url must use http or https".into());
        }
        return Ok(raw.trim_end_matches('/').to_string());
    }
    if scheme != "https" || host != "api.voyageai.com" || path != "/v1" {
        return Err("base_url must be https://api.voyageai.com/v1".into());
    }
    Ok(DEFAULT_BASE_URL.to_string())
}

pub fn validate_auth_material(field: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(format!("{field} must not contain newline characters"));
    }
    Ok(trimmed.to_string())
}

fn code_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
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
