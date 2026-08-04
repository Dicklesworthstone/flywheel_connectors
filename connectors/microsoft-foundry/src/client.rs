use std::sync::Arc;
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_async_core::time;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, EmbeddingsRequest,
    EmbeddingsResponse, HeaderList, HttpRequest, ModelInfo, NetworkError, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitConfig, RateLimitPolicy,
    parse_rate_limit_headers,
};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::types::ResponsesCreateRequest;

pub const DEFAULT_MODEL: &str = "gpt-4o";
pub const USER_AGENT: &str = "fcp-microsoft-foundry/0.1.0";
pub const ENTRA_TOKEN_SCOPE: &str = "https://ai.azure.com/.default";

const ACCEPT_HEADER: &str = "Accept";
const API_KEY_HEADER: &str = "api-key";
const AUTH_POLICY_HEADER: &str = "x-fcp-credential-auth-policy";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";
const ENTRA_SCOPE_HEADER: &str = "x-fcp-entra-token-scope";
const JSON_CONTENT_TYPE: &str = "application/json";
const USER_AGENT_HEADER: &str = "User-Agent";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicrosoftFoundryEndpointClass {
    AzureOpenAi,
    FoundryServices,
    Loopback,
}

impl MicrosoftFoundryEndpointClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AzureOpenAi => "azure_openai",
            Self::FoundryServices => "foundry_services",
            Self::Loopback => "loopback_fixture",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MicrosoftFoundryAuth {
    ApiKey(String),
    EntraBearer(String),
    CredentialId { id: String, policy: AuthPolicy },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    EntraBearer,
    ApiKey,
}

impl AuthPolicy {
    pub const fn as_str(self) -> &'static str {
        if matches!(self, Self::EntraBearer) {
            "entra_bearer"
        } else {
            "api_key"
        }
    }
}

impl MicrosoftFoundryAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::EntraBearer(_) => "entra_bearer:redacted".into(),
            Self::CredentialId { id, policy } => {
                format!("credential_id:{id}:{}", policy.as_str())
            }
        }
    }

    pub const fn uses_host_credential_reference(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }
}

#[derive(Clone, Debug)]
pub struct MicrosoftFoundryProvider {
    base_url: String,
    endpoint_class: MicrosoftFoundryEndpointClass,
    auth: MicrosoftFoundryAuth,
}

impl MicrosoftFoundryProvider {
    pub fn new(
        base_url: impl Into<String>,
        endpoint_class: MicrosoftFoundryEndpointClass,
        auth: MicrosoftFoundryAuth,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            endpoint_class,
            auth,
        }
    }

    pub const fn auth(&self) -> &MicrosoftFoundryAuth {
        &self.auth
    }

    pub const fn endpoint_class(&self) -> MicrosoftFoundryEndpointClass {
        self.endpoint_class
    }
}

impl OpenAiCompatProvider for MicrosoftFoundryProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            MicrosoftFoundryAuth::ApiKey(key) => req.upsert_header(API_KEY_HEADER, key),
            MicrosoftFoundryAuth::EntraBearer(token) => req.bearer_auth(token),
            MicrosoftFoundryAuth::CredentialId { id, policy } => {
                req.upsert_header(CREDENTIAL_ID_HEADER, id);
                req.upsert_header(AUTH_POLICY_HEADER, policy.as_str());
                if *policy == AuthPolicy::EntraBearer {
                    req.upsert_header(ENTRA_SCOPE_HEADER, ENTRA_TOKEN_SCOPE);
                }
            }
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "microsoft_foundry"
    }

    fn rate_limit_overrides(&self) -> Option<RateLimitConfig> {
        Some(RateLimitConfig {
            request_limit_header: Some("x-ratelimit-limit-requests".into()),
            request_remaining_header: Some("x-ratelimit-remaining-requests".into()),
            request_reset_header: Some("x-ratelimit-reset-requests".into()),
            token_limit_header: Some("x-ratelimit-limit-tokens".into()),
            token_remaining_header: Some("x-ratelimit-remaining-tokens".into()),
            token_reset_header: Some("x-ratelimit-reset-tokens".into()),
            retry_after_header: Some("retry-after".into()),
        })
    }
}

pub struct MicrosoftFoundryClient {
    inner: OpenAiCompatClient<MicrosoftFoundryProvider>,
    provider: MicrosoftFoundryProvider,
    http_client: Arc<HttpClient>,
    request_timeout: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl MicrosoftFoundryClient {
    pub fn new(
        provider: MicrosoftFoundryProvider,
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

    pub const fn provider(&self) -> &MicrosoftFoundryProvider {
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
        self.request_json(
            cx,
            Method::Post,
            "/responses",
            &request.model,
            Some(&request),
        )
        .await
    }

    pub async fn responses_cancel(&self, cx: &Cx, response_id: &str) -> Result<Value, OpenAiError> {
        let safe_id = validate_response_id(response_id)?;
        let path = format!("/responses/{safe_id}/cancel");
        self.request_json(cx, Method::Post, &path, DEFAULT_MODEL, Some(&json!({})))
            .await
    }

    pub async fn responses_input_items(
        &self,
        cx: &Cx,
        response_id: &str,
    ) -> Result<Value, OpenAiError> {
        let safe_id = validate_response_id(response_id)?;
        let path = format!("/responses/{safe_id}/input_items");
        self.request_json::<Value>(cx, Method::Get, &path, DEFAULT_MODEL, None)
            .await
    }

    async fn request_json<T>(
        &self,
        cx: &Cx,
        method: Method,
        path: &str,
        model: &str,
        body: Option<&T>,
    ) -> Result<Value, OpenAiError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let mut attempted_rate_limit_retry = false;
        loop {
            checkpoint(cx)?;
            let url = self.url(path);
            let body_bytes = match body {
                Some(body) => {
                    serde_json::to_vec(body).map_err(|err| OpenAiError::InvalidRequest {
                        message: format!("failed to serialize request: {err}"),
                        param: None,
                        code: Some("serialize_request".to_string()),
                    })?
                }
                None => Vec::new(),
            };
            let request = self.http_client.request(
                cx,
                method.clone(),
                &url,
                self.headers_for(model),
                body_bytes,
            );
            let response = match time::timeout(self.request_timeout, request).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => return Err(OpenAiError::Network(err.into())),
                Err(err) => {
                    return Err(OpenAiError::Network(NetworkError::Http {
                        message: err.to_string(),
                    }));
                }
            };

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
                        time::sleep(delay).await;
                        continue;
                    }
                }
                return Err(mapped);
            }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFoundryBaseUrl {
    pub base_url: String,
    pub endpoint_class: MicrosoftFoundryEndpointClass,
    pub host_hash: String,
}

pub fn normalize_microsoft_foundry_base_url(
    raw: Option<&str>,
) -> Result<NormalizedFoundryBaseUrl, String> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "base_url is required and must end in /openai/v1".to_string())?;
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
    let endpoint_class = if local {
        MicrosoftFoundryEndpointClass::Loopback
    } else if normalized_host.ends_with(".openai.azure.com") {
        MicrosoftFoundryEndpointClass::AzureOpenAi
    } else if normalized_host.ends_with(".services.ai.azure.com") {
        MicrosoftFoundryEndpointClass::FoundryServices
    } else {
        return Err(format!(
            "base_url host must be an Azure OpenAI or Foundry service host ending in openai.azure.com or services.ai.azure.com: {value}"
        ));
    };

    if !valid_scheme || path != "/openai/v1" {
        return Err(format!(
            "base_url must be https://<resource>.openai.azure.com/openai/v1 or https://<resource>.services.ai.azure.com/openai/v1; loopback http(s) /openai/v1 is allowed for tests: {value}"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    Ok(NormalizedFoundryBaseUrl {
        base_url: parsed.as_str().trim_end_matches('/').to_string(),
        endpoint_class,
        host_hash: host_hash(&normalized_host),
    })
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

pub fn auth_policy_from_str(value: Option<&str>) -> Result<AuthPolicy, String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("entra_bearer" | "entra" | "managed_identity" | "oauth") | None => {
            Ok(AuthPolicy::EntraBearer)
        }
        Some("api_key") => Ok(AuthPolicy::ApiKey),
        Some(other) => Err(format!(
            "credential_auth_policy must be entra_bearer or api_key, got {other}"
        )),
    }
}

pub fn host_hash(host: &str) -> String {
    let digest = blake3::hash(host.as_bytes()).to_hex().to_string();
    digest.chars().take(16).collect()
}

fn validate_response_id(response_id: &str) -> Result<String, OpenAiError> {
    let trimmed = response_id.trim();
    // The id is interpolated into `/responses/{id}/cancel` (and `/input_items`)
    // on the trusted, host-validated base URL. `/`, `\`, and `..` let the server
    // normalize to a sibling endpoint; `?`/`#` open a query/fragment that
    // truncates the intended suffix; `%` enables encoded traversal (`%2f`,
    // `%2e`). Response ids are opaque `resp_…` tokens, so none of these are
    // legitimate. (Mirrors anthropic-vertex's `validate_path_component`.)
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('%')
        || trimmed
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(OpenAiError::InvalidRequest {
            message: "response_id must be a single non-empty, non-traversing path segment".into(),
            param: Some("response_id".into()),
            code: Some("invalid_response_id".into()),
        });
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

fn checkpoint(cx: &Cx) -> Result<(), OpenAiError> {
    if cx.is_cancel_requested() {
        return Err(OpenAiError::Network(NetworkError::Cancelled {
            message: "request cancelled before dispatch".into(),
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_response_id_rejects_path_traversal() {
        // A crafted response_id must not escape `/responses/{id}/…` to a
        // sibling endpoint or inject a query/fragment on the trusted host.
        for evil in [
            "..",
            "../cancel",
            "x/../y",
            "a\\b",
            "x?api-version=attacker",
            "x#frag",
            "x%2f..",
            "x%2e%2e",
            "",
            "  ",
        ] {
            assert!(
                validate_response_id(evil).is_err(),
                "response_id {evil:?} must be rejected"
            );
        }
        // Opaque, well-formed response ids are accepted (and trimmed).
        assert_eq!(
            validate_response_id("  resp_abc123DEF  ").unwrap(),
            "resp_abc123DEF"
        );
    }

    #[test]
    fn normalizes_official_foundry_endpoint_classes() {
        let azure =
            normalize_microsoft_foundry_base_url(Some("https://acct.openai.azure.com/openai/v1/"))
                .expect("azure openai endpoint should normalize");
        assert_eq!(azure.base_url, "https://acct.openai.azure.com/openai/v1");
        assert_eq!(
            azure.endpoint_class,
            MicrosoftFoundryEndpointClass::AzureOpenAi
        );

        let services = normalize_microsoft_foundry_base_url(Some(
            "https://acct.services.ai.azure.com/openai/v1",
        ))
        .expect("services endpoint should normalize");
        assert_eq!(
            services.endpoint_class,
            MicrosoftFoundryEndpointClass::FoundryServices
        );
    }

    #[test]
    fn rejects_ambiguous_or_insecure_non_fixture_endpoints() {
        assert!(normalize_microsoft_foundry_base_url(None).is_err());
        assert!(
            normalize_microsoft_foundry_base_url(Some("http://acct.openai.azure.com/openai/v1"))
                .is_err()
        );
        assert!(
            normalize_microsoft_foundry_base_url(Some("https://acct.openai.azure.com/v1")).is_err()
        );
        assert!(
            normalize_microsoft_foundry_base_url(Some("https://example.com/openai/v1")).is_err()
        );
    }

    #[test]
    fn credential_policy_defaults_to_entra_bearer() {
        assert_eq!(auth_policy_from_str(None), Ok(AuthPolicy::EntraBearer));
        assert_eq!(
            auth_policy_from_str(Some("api_key")),
            Ok(AuthPolicy::ApiKey)
        );
        assert!(auth_policy_from_str(Some("password")).is_err());
    }
}
