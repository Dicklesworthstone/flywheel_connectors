use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, EmbeddingsRequest,
    EmbeddingsResponse, HeaderList, HttpRequest, ModelInfo, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitPolicy, RequestBudget,
    parse_rate_limit_headers, redact_sensitive_text, truncate_response_body,
};
use serde_json::Value;
use url::Url;

use crate::types::{RerankRequest, RerankResponse};

pub const DEFAULT_BASE_URL: &str = "https://integrate.api.nvidia.com/v1";
pub const DEFAULT_RERANK_BASE_URL: &str = "https://ai.api.nvidia.com/v1";
pub const DEFAULT_MODEL: &str = "meta/llama-3.1-8b-instruct";
pub const DEFAULT_EMBEDDING_MODEL: &str = "nvidia/nv-embedqa-e5-v5";
pub const DEFAULT_RERANK_MODEL: &str = "nv-rerank-qa-mistral-4b:1";
pub const USER_AGENT: &str = "fcp-nvidia-nim/0.1.0";

const HOSTED_INFERENCE_HOST: &str = "integrate.api.nvidia.com";
const HOSTED_RERANK_HOST: &str = "ai.api.nvidia.com";
const HOSTED_RERANK_PATH: &str = "/retrieval/nvidia/reranking";
const SELF_HOSTED_RERANK_PATH: &str = "/ranking";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvidiaNimDeploymentMode {
    Hosted,
    SelfHosted,
}

impl NvidiaNimDeploymentMode {
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some("hosted") => Ok(Self::Hosted),
            Some("self_hosted" | "self-hosted" | "selfhosted") => Ok(Self::SelfHosted),
            Some(value) => Err(format!(
                "deployment_mode must be hosted or self_hosted, got `{value}`"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::SelfHosted => "self_hosted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NvidiaNimAuth {
    None,
    ApiKey(String),
    CredentialId(String),
}

impl NvidiaNimAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvidiaNimUrlPolicy {
    pub deployment_mode: NvidiaNimDeploymentMode,
    pub tailnet_only: bool,
    pub allow_private_hosts: bool,
    pub allowed_hosts: Vec<String>,
}

impl NvidiaNimUrlPolicy {
    pub fn new(
        deployment_mode: NvidiaNimDeploymentMode,
        tailnet_only: bool,
        allow_private_hosts: bool,
        allowed_hosts: Vec<String>,
    ) -> Self {
        Self {
            deployment_mode,
            tailnet_only,
            allow_private_hosts,
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| canonical_host(&host))
                .filter(|host| !host.is_empty())
                .collect(),
        }
    }

    fn host_is_allowed(&self, host: &str) -> bool {
        let host = canonical_host(host);
        self.allowed_hosts.iter().any(|allowed| allowed == &host)
    }
}

#[derive(Clone, Debug)]
pub struct NvidiaNimProvider {
    base_url: String,
    auth: NvidiaNimAuth,
}

impl NvidiaNimProvider {
    pub fn new(base_url: impl Into<String>, auth: NvidiaNimAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &NvidiaNimAuth {
        &self.auth
    }

    fn auth_headers(&self, req: &mut HttpRequest) {
        match &self.auth {
            NvidiaNimAuth::None => {}
            NvidiaNimAuth::ApiKey(key) => req.bearer_auth(key),
            NvidiaNimAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }
}

impl OpenAiCompatProvider for NvidiaNimProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        self.auth_headers(req);
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "nvidia_nim"
    }

    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

pub struct NvidiaNimClient {
    inner: OpenAiCompatClient<NvidiaNimProvider>,
    provider: NvidiaNimProvider,
    http_client: HttpClient,
    request_timeout: Duration,
    rate_limit_policy: RateLimitPolicy,
    rerank_base_url: String,
    rerank_path: &'static str,
}

impl NvidiaNimClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: NvidiaNimProvider,
        rerank_base_url: String,
        rerank_path: &'static str,
        request_timeout: Duration,
        model_cache_ttl: Duration,
        rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        let inner_http_client = HttpClientBuilder::new().build();
        let rerank_http_client = HttpClientBuilder::new().build();
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
            http_client: rerank_http_client,
            request_timeout,
            rate_limit_policy,
            rerank_base_url,
            rerank_path,
        }
    }

    pub const fn provider(&self) -> &NvidiaNimProvider {
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

    pub async fn rerank(
        &self,
        cx: &Cx,
        request: RerankRequest,
    ) -> Result<RerankResponse, OpenAiError> {
        let mut budget = RequestBudget::new(cx, self.request_timeout);
        let mut attempted_rate_limit_retry = false;
        loop {
            budget.checkpoint()?;
            let body = serde_json::to_vec(&request).map_err(|err| OpenAiError::InvalidRequest {
                message: format!("failed to serialize rerank request: {err}"),
                param: None,
                code: Some("serialize_request".into()),
            })?;
            let response = budget
                .run(self.http_client.request(
                    cx,
                    Method::Post,
                    &self.rerank_url(),
                    self.headers_for(&request.model),
                    body,
                ))
                .await?
                .map_err(|err| OpenAiError::Network(err.into()))?;

            let status = response.status_code();
            let rate_limits = parse_rate_limit_headers(&response.headers, None);
            if !status.is_success() {
                let mapped = map_rerank_response(status.as_u16(), &response.body, rate_limits);
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
                    message: format!("failed to decode rerank response: {err}"),
                    param: None,
                    code: Some("decode_response".into()),
                }
            });
        }
    }

    fn headers_for(&self, model: &str) -> HeaderList {
        let mut request = HttpRequest {
            headers: vec![
                ("Accept".into(), "application/json".into()),
                ("Content-Type".into(), "application/json".into()),
                ("User-Agent".into(), USER_AGENT.into()),
            ],
        };
        request
            .headers
            .extend(self.provider.extra_request_headers(model));
        self.provider.auth_header(&mut request);
        request.headers
    }

    fn rerank_url(&self) -> String {
        format!(
            "{}{}",
            self.rerank_base_url.trim_end_matches('/'),
            self.rerank_path
        )
    }
}

pub fn normalize_nim_base_url(
    raw: Option<&str>,
    policy: &NvidiaNimUrlPolicy,
) -> Result<String, String> {
    normalize_url(
        raw.unwrap_or(DEFAULT_BASE_URL),
        policy,
        UrlPurpose::Inference,
    )
}

pub fn normalize_nim_rerank_base_url(
    raw: Option<&str>,
    inference_base_url: &str,
    policy: &NvidiaNimUrlPolicy,
) -> Result<(String, &'static str), String> {
    match policy.deployment_mode {
        NvidiaNimDeploymentMode::Hosted => Ok((
            normalize_url(
                raw.unwrap_or(DEFAULT_RERANK_BASE_URL),
                policy,
                UrlPurpose::HostedRerank,
            )?,
            HOSTED_RERANK_PATH,
        )),
        NvidiaNimDeploymentMode::SelfHosted => Ok((
            normalize_url(
                raw.unwrap_or(inference_base_url),
                policy,
                UrlPurpose::SelfHostedRerank,
            )?,
            SELF_HOSTED_RERANK_PATH,
        )),
    }
}

pub fn classify_nim_base_url(base_url: &str) -> &'static str {
    let Ok(parsed) = Url::parse(base_url) else {
        return "invalid";
    };
    let Some(host) = parsed.host_str() else {
        return "invalid";
    };
    let host = canonical_host(host);
    if host == HOSTED_INFERENCE_HOST {
        "hosted_api"
    } else if host == HOSTED_RERANK_HOST {
        "hosted_retrieval"
    } else if is_loopback_host(&host) {
        "loopback"
    } else if host.ends_with(".ts.net") {
        "tailnet_dns"
    } else if host.parse::<IpAddr>().is_ok_and(is_tailscale_ip) {
        "tailnet_ip"
    } else if host.parse::<IpAddr>().is_ok_and(is_private_ip) {
        "private_ip"
    } else {
        "operator_allowed_host"
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UrlPurpose {
    Inference,
    HostedRerank,
    SelfHostedRerank,
}

fn normalize_url(
    value: &str,
    policy: &NvidiaNimUrlPolicy,
    purpose: UrlPurpose,
) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = canonical_host(host);
    let path = parsed.path().trim_end_matches('/');

    if path != "/v1" {
        return Err(format!("base_url path must be exactly /v1: {value}"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("base_url must use http or https: {value}"));
    }

    match policy.deployment_mode {
        NvidiaNimDeploymentMode::Hosted => validate_hosted_url(&parsed, &normalized_host, purpose)?,
        NvidiaNimDeploymentMode::SelfHosted => {
            validate_self_hosted_url(policy, &normalized_host)?;
        }
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn validate_hosted_url(parsed: &Url, host: &str, purpose: UrlPurpose) -> Result<(), String> {
    if parsed.scheme() != "https" {
        return Err("hosted NVIDIA NIM endpoints must use https".into());
    }
    let expected_host = match purpose {
        UrlPurpose::Inference => HOSTED_INFERENCE_HOST,
        UrlPurpose::HostedRerank => HOSTED_RERANK_HOST,
        UrlPurpose::SelfHostedRerank => {
            return Err("self-hosted rerank URL cannot be used in hosted mode".into());
        }
    };
    if host != expected_host {
        return Err(format!(
            "hosted NVIDIA NIM {purpose:?} endpoint must use host `{expected_host}`"
        ));
    }
    Ok(())
}

fn validate_self_hosted_url(policy: &NvidiaNimUrlPolicy, host: &str) -> Result<(), String> {
    let loopback = is_loopback_host(host);
    if policy.tailnet_only && loopback {
        return Err("tailnet_only mode rejects localhost and loopback base_url values".into());
    }
    if loopback {
        return Ok(());
    }
    if !policy.host_is_allowed(host) {
        return Err(format!(
            "base_url host `{host}` is not loopback and is not listed in allowed_hosts"
        ));
    }
    let ip = host.parse::<IpAddr>().ok();
    if ip.is_some_and(|addr| is_private_ip(addr) || is_tailscale_ip(addr))
        && !policy.allow_private_hosts
    {
        return Err(format!(
            "base_url host `{host}` is private or tailnet IP literal; set allow_private_hosts=true for self-hosted NIM"
        ));
    }
    Ok(())
}

fn map_rerank_response(
    status: u16,
    body: &[u8],
    rate_limits: fcp_openai_compat::RateLimitSnapshot,
) -> OpenAiError {
    let message = provider_message(body, status);
    match status {
        400 | 422 => OpenAiError::InvalidRequest {
            message,
            param: None,
            code: Some(status.to_string()),
        },
        401 => OpenAiError::Authentication { message },
        403 => OpenAiError::PermissionDenied { message },
        404 => OpenAiError::NotFound {
            message,
            resource: None,
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
        _ => OpenAiError::Provider {
            provider: "nvidia_nim".into(),
            status,
            body: truncate_response_body(body),
        },
    }
}

fn provider_message(body: &[u8], status: u16) -> String {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    let message = parsed
        .as_ref()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .or_else(|| value.get("detail"))
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
        })
        .filter(|message| !message.trim().is_empty())
        .map_or_else(
            || {
                let body_text = truncate_response_body(body);
                if body_text.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body_text
                }
            },
            ToString::to_string,
        );
    redact_sensitive_text(&message)
}

fn retry_delay_for_policy(error: &OpenAiError, policy: RateLimitPolicy) -> Option<Duration> {
    let retry_after = error.retry_after()?;
    match policy {
        RateLimitPolicy::WaitUpTo(max_wait) if retry_after <= max_wait => Some(retry_after),
        RateLimitPolicy::FailFast | RateLimitPolicy::WaitUpTo(_) => None,
        RateLimitPolicy::WaitForever => Some(retry_after),
    }
}

fn canonical_host(host: &str) -> String {
    host.trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
        || host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
}

fn is_tailscale_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let [first, second, _, _] = ip.octets();
            first == 100 && (64..=127).contains(&second)
        }
        IpAddr::V6(_) => false,
    }
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

pub fn allowed_host_is_valid(host: &str) -> bool {
    let host = canonical_host(host);
    !host.is_empty()
        && !host.contains('/')
        && (!host.contains(':') || host.parse::<IpAddr>().is_ok())
        && !host.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        && host
            .parse::<Ipv4Addr>()
            .map_or(true, |ip| !ip.is_broadcast())
}

#[cfg(test)]
mod tests {
    use fcp_openai_compat::{RateLimitSnapshot, header_value};
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn deployment_mode_parser_accepts_operator_spellings_only() {
        assert_eq!(
            NvidiaNimDeploymentMode::parse(None).expect("default should be hosted"),
            NvidiaNimDeploymentMode::Hosted
        );
        assert_eq!(
            NvidiaNimDeploymentMode::parse(Some(" self-hosted "))
                .expect("hyphen spelling should parse"),
            NvidiaNimDeploymentMode::SelfHosted
        );
        assert_eq!(
            NvidiaNimDeploymentMode::parse(Some("selfhosted"))
                .expect("compact spelling should parse"),
            NvidiaNimDeploymentMode::SelfHosted
        );
        assert!(NvidiaNimDeploymentMode::parse(Some("local")).is_err());
    }

    #[test]
    fn auth_headers_are_injected_without_leaking_secret_labels() {
        let api_provider =
            NvidiaNimProvider::new(DEFAULT_BASE_URL, NvidiaNimAuth::ApiKey("secret-key".into()));
        let mut api_request = HttpRequest::default();
        api_provider.auth_header(&mut api_request);
        assert_eq!(
            header_value(&api_request.headers, "authorization"),
            Some("Bearer secret-key")
        );
        assert_eq!(api_provider.auth().redacted_label(), "api_key:redacted");

        let credential_provider = NvidiaNimProvider::new(
            DEFAULT_BASE_URL,
            NvidiaNimAuth::CredentialId("cred-nim".into()),
        );
        let mut credential_request = HttpRequest::default();
        credential_provider.auth_header(&mut credential_request);
        assert_eq!(
            header_value(&credential_request.headers, "x-fcp-credential-id"),
            Some("cred-nim")
        );
        assert!(credential_provider.auth().is_secretless());

        assert_eq!(
            validate_auth_material("api_key", "  trimmed-key  ")
                .expect("auth material should trim"),
            "trimmed-key"
        );
        assert!(validate_auth_material("api_key", "bad\r\nheader").is_err());
        assert!(validate_auth_material("credential_id", "").is_err());
    }

    #[test]
    fn hosted_policy_accepts_only_documented_nvidia_https_hosts() {
        let policy =
            NvidiaNimUrlPolicy::new(NvidiaNimDeploymentMode::Hosted, false, false, Vec::new());

        assert_eq!(
            normalize_nim_base_url(None, &policy).expect("default hosted base URL should pass"),
            DEFAULT_BASE_URL
        );
        assert_eq!(
            normalize_nim_base_url(Some("https://integrate.api.nvidia.com/v1/"), &policy)
                .expect("canonical inference URL should pass"),
            "https://integrate.api.nvidia.com/v1"
        );
        assert_eq!(
            normalize_nim_rerank_base_url(None, DEFAULT_BASE_URL, &policy)
                .expect("default hosted rerank URL should pass"),
            (
                DEFAULT_RERANK_BASE_URL.to_string(),
                "/retrieval/nvidia/reranking"
            )
        );

        assert!(
            normalize_nim_base_url(Some("http://integrate.api.nvidia.com/v1"), &policy).is_err()
        );
        assert!(normalize_nim_base_url(Some("https://api.nvidia.com/v1"), &policy).is_err());
        assert!(
            normalize_nim_base_url(Some("https://integrate.api.nvidia.com/v1?x=1"), &policy)
                .is_err()
        );
        assert!(
            normalize_nim_base_url(Some("https://integrate.api.nvidia.com/v2"), &policy).is_err()
        );
    }

    #[test]
    fn self_hosted_policy_requires_loopback_or_exact_operator_allowlist() {
        let local_policy = NvidiaNimUrlPolicy::new(
            NvidiaNimDeploymentMode::SelfHosted,
            false,
            false,
            Vec::new(),
        );
        assert_eq!(
            normalize_nim_base_url(Some("http://localhost:8000/v1"), &local_policy)
                .expect("loopback should be allowed by default"),
            "http://localhost:8000/v1"
        );

        let tailnet_only =
            NvidiaNimUrlPolicy::new(NvidiaNimDeploymentMode::SelfHosted, true, false, Vec::new());
        assert!(normalize_nim_base_url(Some("http://127.0.0.1:8000/v1"), &tailnet_only).is_err());

        let hostname_policy = NvidiaNimUrlPolicy::new(
            NvidiaNimDeploymentMode::SelfHosted,
            false,
            false,
            vec!["NIM.Example.COM.".into()],
        );
        assert_eq!(
            normalize_nim_base_url(Some("https://nim.example.com/v1"), &hostname_policy)
                .expect("canonical allowed host should pass"),
            "https://nim.example.com/v1"
        );
        assert!(
            normalize_nim_base_url(Some("https://other.example.com/v1"), &hostname_policy).is_err()
        );

        let private_denied = NvidiaNimUrlPolicy::new(
            NvidiaNimDeploymentMode::SelfHosted,
            false,
            false,
            vec!["100.64.12.8".into()],
        );
        assert!(
            normalize_nim_base_url(Some("http://100.64.12.8:8000/v1"), &private_denied).is_err()
        );
        let private_allowed = NvidiaNimUrlPolicy::new(
            NvidiaNimDeploymentMode::SelfHosted,
            false,
            true,
            vec!["100.64.12.8".into()],
        );
        assert_eq!(
            normalize_nim_base_url(Some("http://100.64.12.8:8000/v1"), &private_allowed)
                .expect("explicit private/tailnet IP opt-in should pass"),
            "http://100.64.12.8:8000/v1"
        );
    }

    #[test]
    fn url_classification_and_allowed_host_validation_are_specific() {
        assert_eq!(classify_nim_base_url(DEFAULT_BASE_URL), "hosted_api");
        assert_eq!(
            classify_nim_base_url(DEFAULT_RERANK_BASE_URL),
            "hosted_retrieval"
        );
        assert_eq!(classify_nim_base_url("http://[::1]:8000/v1"), "loopback");
        assert_eq!(
            classify_nim_base_url("https://nim.tailnet.ts.net/v1"),
            "tailnet_dns"
        );
        assert_eq!(
            classify_nim_base_url("http://100.64.0.7:8000/v1"),
            "tailnet_ip"
        );
        assert_eq!(
            classify_nim_base_url("http://10.0.0.12:8000/v1"),
            "private_ip"
        );
        assert_eq!(
            classify_nim_base_url("https://nim.example.com/v1"),
            "operator_allowed_host"
        );
        assert_eq!(classify_nim_base_url("not a url"), "invalid");

        assert!(allowed_host_is_valid("nim.example.com"));
        assert!(allowed_host_is_valid("[::1]"));
        assert!(!allowed_host_is_valid("bad/host"));
        assert!(!allowed_host_is_valid("host:443"));
        assert!(!allowed_host_is_valid("255.255.255.255"));
    }

    #[test]
    fn rerank_response_mapping_redacts_provider_messages_and_honors_retry_policy() {
        let rate_limits = RateLimitSnapshot {
            retry_after: Some(Duration::from_millis(50)),
            ..RateLimitSnapshot::default()
        };
        let invalid = map_rerank_response(
            400,
            br#"{"error":{"message":"bad Bearer secret-token for private prompt"}}"#,
            RateLimitSnapshot::default(),
        );
        assert!(matches!(invalid, OpenAiError::InvalidRequest { .. }));
        assert!(!invalid.to_string().contains("secret-token"));

        let limited = map_rerank_response(429, br#"{"message":"rate limited"}"#, rate_limits);
        assert_eq!(
            retry_delay_for_policy(&limited, RateLimitPolicy::WaitUpTo(Duration::from_secs(1))),
            Some(Duration::from_millis(50))
        );
        assert_eq!(
            retry_delay_for_policy(
                &limited,
                RateLimitPolicy::WaitUpTo(Duration::from_millis(1))
            ),
            None
        );
        assert_eq!(
            retry_delay_for_policy(&limited, RateLimitPolicy::FailFast),
            None
        );

        let provider =
            map_rerank_response(599, b"upstream unavailable", RateLimitSnapshot::default());
        assert!(matches!(
            provider,
            OpenAiError::Provider { status: 599, .. }
        ));
    }
}
