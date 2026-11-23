//! HTTP client for Hugging Face Inference and Hub APIs.

use std::time::Duration;

use base64::Engine;
use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressHttpHeader, HostEgressHttpRequest,
    HostEgressHttpResponse,
};
use fcp_prelude::{CredentialId, InvokeRequest};
use reqwest::{Client, RequestBuilder};
use tracing::debug;
use url::Url;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HostEgressProxyClient, HttpRetryConfig, RetryLoop,
    transport_error_reached_service,
};

use crate::error::{HuggingfaceError, HuggingfaceResult};
use crate::types::{
    HfApiError, ModelInfo, ModelListRequest, SummarizationRequest, SummarizationResponse,
    TextGenerationRequest, TextGenerationResponse,
};

/// Default task API on Hugging Face's first-party inference router.
pub(crate) const DEFAULT_INFERENCE_URL: &str = "https://router.huggingface.co/hf-inference";
/// Default Hub API base URL.
const DEFAULT_HUB_URL: &str = "https://huggingface.co/api";
/// The manifest permits at most one MiB of provider response bytes.
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
/// Includes base64 overhead and bounded host attribution metadata.
const MAX_PROXY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Validate a user-supplied model ID to prevent URL path injection.
pub(crate) fn sanitize_model_id(value: &str) -> HuggingfaceResult<&str> {
    if value.trim().is_empty() {
        return Err(HuggingfaceError::InvalidInput(
            "model_id must not be empty".into(),
        ));
    }
    if value.contains("..")
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '\\' | '%' | '?' | '#')
        })
    {
        return Err(HuggingfaceError::InvalidInput(
            "model_id contains URL syntax, whitespace, or path traversal characters".into(),
        ));
    }
    // Model IDs may contain one slash separating the organization and model.
    let slash_count = value.chars().filter(|&c| c == '/').count();
    if slash_count > 1 {
        return Err(HuggingfaceError::InvalidInput(
            "model_id may contain at most one slash (org/model format)".into(),
        ));
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == ".")
    {
        return Err(HuggingfaceError::InvalidInput(
            "model_id must contain non-empty model or org/model path segments".into(),
        ));
    }
    Ok(value)
}

fn normalize_api_base_url(value: &str, field: &str) -> HuggingfaceResult<String> {
    if value.chars().any(char::is_control) {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not contain control characters"
        )));
    }
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|_| HuggingfaceError::InvalidInput(format!("{field} must be an absolute URL")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must use http or https with a host"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not contain embedded credentials; use api_token instead"
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not contain query or fragment components"
        )));
    }

    let loopback = match parsed.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    let provider_endpoint = parsed.scheme() == "https"
        && parsed.port_or_known_default() == Some(443)
        && match field {
            "inference_url" => {
                parsed.host_str() == Some("router.huggingface.co")
                    && parsed.path().trim_end_matches('/') == "/hf-inference"
            }
            "hub_url" => {
                parsed.host_str() == Some("huggingface.co")
                    && parsed.path().trim_end_matches('/') == "/api"
            }
            _ => false,
        };
    if !loopback && !provider_endpoint {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must use its supported Hugging Face HTTPS endpoint or loopback"
        )));
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// Hugging Face API client with retry support.
#[derive(Clone)]
pub struct HuggingfaceClient {
    client: Client,
    inference_url: String,
    hub_url: String,
    api_token: String,
    proxy: Option<ProxyTransport>,
    retry_config: HttpRetryConfig,
    pub(crate) timeout: Duration,
}

/// Invocation authority belongs to a clone, never shared mutable client state.
#[derive(Clone)]
struct ProxyTransport {
    client: HostEgressProxyClient,
    credential_id: CredentialId,
    context: Option<HostEgressContext>,
}

/// Task API responses can be a documented singleton or a batch from the
/// Transformers serving backend. Native connector output always uses a list.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum InferenceResults<T> {
    Batch(Vec<T>),
    Single(T),
}

impl<T> InferenceResults<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::Batch(results) => results,
            Self::Single(result) => vec![result],
        }
    }
}

impl std::fmt::Debug for HuggingfaceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuggingfaceClient")
            .field("inference_url", &self.inference_url)
            .field("hub_url", &self.hub_url)
            .field(
                "api_token",
                &if self.api_token.is_empty() {
                    "(empty)"
                } else {
                    "[REDACTED]"
                },
            )
            .field("host_egress_proxy", &self.proxy.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HuggingfaceClient {
    /// Create a new Hugging Face API client.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid endpoint configuration or HTTP client setup.
    pub fn new(
        inference_url: Option<&str>,
        hub_url: Option<&str>,
        api_token: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> HuggingfaceResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            // Redirects and transport retries are hidden sends below RetryLoop.
            // They must not replay billable inference or move private prompts.
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(HuggingfaceError::Http)?;

        Ok(Self {
            client,
            inference_url: normalize_api_base_url(
                inference_url.unwrap_or(DEFAULT_INFERENCE_URL),
                "inference_url",
            )?,
            hub_url: normalize_api_base_url(hub_url.unwrap_or(DEFAULT_HUB_URL), "hub_url")?,
            api_token: api_token.to_string(),
            proxy: None,
            retry_config,
            timeout,
        })
    }

    /// Configure host-mediated credential injection without exposing the secret
    /// to this process. Admission failures never fall back to direct transport.
    ///
    /// # Errors
    ///
    /// Rejects simultaneous direct credentials or invalid proxy bounds.
    pub fn with_credential_id(
        mut self,
        credential_id: CredentialId,
        proxy: HostEgressProxyClient,
    ) -> HuggingfaceResult<Self> {
        if !self.api_token.is_empty() {
            return Err(HuggingfaceError::InvalidInput(
                "api_token and credential_id are mutually exclusive".into(),
            ));
        }
        let proxy = proxy
            .with_timeout(self.timeout)
            .and_then(|client| client.with_max_response_bytes(MAX_PROXY_RESPONSE_BYTES))
            .map_err(|_| {
                HuggingfaceError::InvalidInput("invalid host egress proxy configuration".into())
            })?;
        self.proxy = Some(ProxyTransport {
            client: proxy,
            credential_id,
            context: None,
        });
        Ok(self)
    }

    /// Bind the original signed request to one invocation. The host verifies
    /// this same token, operation, zone, target URL, and credential allow-list.
    ///
    /// # Errors
    ///
    /// Returns an error if the original capability cannot be encoded.
    pub fn for_invocation(&self, request: &InvokeRequest) -> HuggingfaceResult<Self> {
        let mut client = self.clone();
        if let Some(proxy) = client.proxy.as_mut() {
            let capability = request.capability_token.raw().to_cbor().map_err(|_| {
                HuggingfaceError::InvalidInput(
                    "capability token cannot be encoded for host egress".into(),
                )
            })?;
            proxy.context = Some(HostEgressContext {
                connector_id: request.connector_id.to_string(),
                operation_id: request.operation.to_string(),
                zone_id: request.zone_id.to_string(),
                request_id: request.id.to_string(),
                correlation_id: request.correlation_id.as_ref().map(ToString::to_string),
                capability_token_cbor_b64: base64::engine::general_purpose::STANDARD
                    .encode(capability),
            });
        }
        Ok(client)
    }

    fn transport(&self, operation: &str) -> HuggingfaceResult<Option<ProxyTransport>> {
        if let Some(proxy) = &self.proxy {
            let context = proxy.context.as_ref().ok_or_else(|| {
                HuggingfaceError::InvalidInput(
                    "host credential injection requires an admitted invocation".into(),
                )
            })?;
            if context.operation_id != operation {
                return Err(HuggingfaceError::InvalidInput(
                    "host egress operation does not match invocation authority".into(),
                ));
            }
        }
        Ok(self.proxy.clone())
    }

    #[must_use]
    pub fn inference_url(&self) -> &str {
        &self.inference_url
    }

    #[must_use]
    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.proxy.is_some()
    }

    // ── Text Generation ──

    /// Run text generation inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP, auth, rate-limit, or parse failures.
    pub async fn text_generation(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
        request: &TextGenerationRequest,
    ) -> HuggingfaceResult<Vec<TextGenerationResponse>> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.inference_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(HuggingfaceError::Json)?;
        let proxy = self.transport("huggingface.inference.text_generation")?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            let proxy = proxy.clone();
            async move {
                debug!(attempt, model_id, "Text generation request");
                if let Some(proxy) = proxy {
                    return handle_proxy_inference_response::<
                        InferenceResults<TextGenerationResponse>,
                    >(&proxy, url, &body, attempt)
                    .await;
                }
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<InferenceResults<TextGenerationResponse>>(req, attempt)
                    .await
            }
        })
        .await
        .map(InferenceResults::into_vec)
    }

    // ── Summarization ──

    /// Run summarization inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP, auth, rate-limit, or parse failures.
    pub async fn summarization(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
        request: &SummarizationRequest,
    ) -> HuggingfaceResult<Vec<SummarizationResponse>> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.inference_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(HuggingfaceError::Json)?;
        let proxy = self.transport("huggingface.inference.summarization")?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            let proxy = proxy.clone();
            async move {
                debug!(attempt, model_id, "Summarization request");
                if let Some(proxy) = proxy {
                    return handle_proxy_inference_response::<
                        InferenceResults<SummarizationResponse>,
                    >(&proxy, url, &body, attempt)
                    .await;
                }
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<InferenceResults<SummarizationResponse>>(req, attempt)
                    .await
            }
        })
        .await
        .map(InferenceResults::into_vec)
    }

    // ── Model Info (Hub API) ──

    /// Fetch model metadata from the Hugging Face Hub API.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP, auth, rate-limit, or parse failures.
    pub async fn model_info(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
    ) -> HuggingfaceResult<ModelInfo> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.hub_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let proxy = self.transport("huggingface.models.info")?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            let proxy = proxy.clone();
            async move {
                debug!(attempt, model_id, "Model info request");
                if let Some(proxy) = proxy {
                    return handle_proxy_json_response::<ModelInfo>(&proxy, url, attempt).await;
                }
                let req = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };
                handle_json_response::<ModelInfo>(req, attempt).await
            }
        })
        .await
    }

    /// List Hub models with bounded catalog filters.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid parameters, HTTP, auth, rate-limit, or parse failures.
    pub async fn list_models(
        &self,
        runtime: &ConnectorRuntime,
        request: &ModelListRequest,
    ) -> HuggingfaceResult<Vec<ModelInfo>> {
        let mut url = Url::parse(&format!("{}/models", self.hub_url))
            .map_err(|_| HuggingfaceError::InvalidInput("hub_url cannot form models URL".into()))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(search) = request
                .search
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                query.append_pair("search", search);
            }
            if let Some(pipeline_tag) = request
                .pipeline_tag
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                query.append_pair("pipeline_tag", pipeline_tag);
            }
            if let Some(limit) = request.limit {
                query.append_pair("limit", &limit.to_string());
            }
        }

        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let proxy = self.transport("huggingface.models.list")?;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            let proxy = proxy.clone();
            async move {
                debug!(attempt, "Model catalog list request");
                if let Some(proxy) = proxy {
                    return handle_proxy_json_response::<Vec<ModelInfo>>(
                        &proxy,
                        url.to_string(),
                        attempt,
                    )
                    .await;
                }
                let req = if token.is_empty() {
                    client.get(url.clone())
                } else {
                    client.get(url.clone()).bearer_auth(&token)
                };
                handle_json_response::<Vec<ModelInfo>>(req, attempt).await
            }
        })
        .await
    }

    // ── Health check ──

    /// Validate the API token via the whoami endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP, auth, or parse failures.
    pub async fn whoami(&self, runtime: &ConnectorRuntime) -> HuggingfaceResult<serde_json::Value> {
        if self.proxy.is_some() {
            return Err(HuggingfaceError::InvalidInput(
                "secretless identity checks require signed host invocation authority".into(),
            ));
        }
        // Identity is under the same /api prefix as model discovery.
        let url = format!("{}/whoami-v2", self.hub_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            async move {
                debug!(attempt, "Whoami health check");
                let req = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };
                handle_json_response::<serde_json::Value>(req, attempt).await
            }
        })
        .await
    }
}

// ── Response handlers ──

/// Both transports use the same provider status and replay policy.
enum ProviderResponse {
    Direct(reqwest::Response),
    Proxy(HostEgressHttpResponse),
}

impl ProviderResponse {
    fn status(&self) -> u16 {
        match self {
            Self::Direct(response) => response.status().as_u16(),
            Self::Proxy(response) => response.status,
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        let value = match self {
            Self::Direct(response) => response.headers().get("retry-after")?.to_str().ok()?,
            Self::Proxy(response) => response
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("retry-after"))?
                .value
                .as_str(),
        };
        value.parse::<u64>().ok().map(Duration::from_secs)
    }

    async fn read(self) -> HuggingfaceResult<Vec<u8>> {
        match self {
            Self::Direct(response) => read_bounded_response(response).await,
            Self::Proxy(response) => {
                let body = response.body.as_bytes();
                if body.len() > MAX_PROVIDER_RESPONSE_BYTES {
                    return Err(HuggingfaceError::ResponseTooLarge {
                        limit: MAX_PROVIDER_RESPONSE_BYTES,
                    });
                }
                Ok(body.to_vec())
            }
        }
    }
}

impl ProxyTransport {
    async fn request(
        &self,
        method: &str,
        url: String,
        body: Option<Vec<u8>>,
    ) -> HuggingfaceResult<ProviderResponse> {
        let context = self.context.clone().ok_or_else(|| {
            HuggingfaceError::InvalidInput(
                "host credential injection requires an admitted invocation".into(),
            )
        })?;
        let mut headers = vec![HostEgressHttpHeader {
            name: "accept".into(),
            value: "application/json".into(),
        }];
        if body.is_some() {
            headers.push(HostEgressHttpHeader {
                name: "content-type".into(),
                value: "application/json".into(),
            });
        }
        let request = HostEgressHttpRequest {
            context,
            url,
            method: method.into(),
            headers,
            body: body.map(Base64Bytes::from_vec),
            credential_id: Some(self.credential_id.to_string()),
        };
        let response = self.client.http(&request).await.map_err(|error| {
            // The SDK validates response attribution. Never retain its error
            // body here: even a rejected host can echo request authority.
            HuggingfaceError::HostProxy {
                status: error.status(),
            }
        })?;
        if response.body.as_bytes().len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(HuggingfaceError::ResponseTooLarge {
                limit: MAX_PROVIDER_RESPONSE_BYTES,
            });
        }
        if !response.egress.credential_injected {
            return Err(HuggingfaceError::HostProxy { status: None });
        }
        Ok(ProviderResponse::Proxy(response))
    }
}

async fn handle_proxy_inference_response<T: serde::de::DeserializeOwned>(
    proxy: &ProxyTransport,
    url: String,
    body: &serde_json::Value,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let body = match serde_json::to_vec(body) {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(HuggingfaceError::Json(error)),
    };
    let response = match proxy.request("POST", url, Some(body)).await {
        Ok(response) => response,
        Err(error) => {
            // A failed connector-to-host hop does not prove whether the host
            // already dispatched billable inference. Never retry or fall back.
            let status = match error {
                HuggingfaceError::HostProxy { status } => status,
                _ => None,
            };
            return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown { status });
        }
    };
    handle_inference_provider_response(response, attempt).await
}

async fn handle_proxy_json_response<T: serde::de::DeserializeOwned>(
    proxy: &ProxyTransport,
    url: String,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    match proxy.request("GET", url, None).await {
        Ok(response) => handle_json_provider_response(response, attempt).await,
        Err(error) => AttemptOutcome::Terminal(error),
    }
}

/// Read both declared and chunked bodies with the manifest's provider byte limit.
async fn read_bounded_response(mut response: reqwest::Response) -> HuggingfaceResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(HuggingfaceError::ResponseTooLarge {
            limit: MAX_PROVIDER_RESPONSE_BYTES,
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| HuggingfaceError::Http(error.without_url()))?
    {
        if chunk.len() > MAX_PROVIDER_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(HuggingfaceError::ResponseTooLarge {
                limit: MAX_PROVIDER_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Extract retry-after duration from response headers, clamped to u64.
fn extract_retry_after_ms(retry_after: Option<Duration>) -> u64 {
    let millis = retry_after.unwrap_or(Duration::from_secs(30)).as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Handle the Inference API response, which returns JSON directly (no envelope).
/// Inference POSTs are not replay-safe once provider execution may have begun.
async fn handle_inference_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            if transport_error_reached_service(&e) {
                return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                    status: e.status().map(|status| status.as_u16()),
                });
            }
            let replayable = e.is_connect();
            return AttemptOutcome::retryable_if_replayable(
                HuggingfaceError::Http(e.without_url()),
                None,
                replayable,
            );
        }
    };

    handle_inference_provider_response(ProviderResponse::Direct(resp), attempt).await
}

async fn handle_inference_provider_response<T: serde::de::DeserializeOwned>(
    resp: ProviderResponse,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let status = resp.status();

    if (300..400).contains(&status) {
        return AttemptOutcome::Terminal(HuggingfaceError::Api {
            status,
            message: "redirect refused; configure the intended inference_url explicitly".into(),
        });
    }

    if status == 429 {
        let retry_after = resp.retry_after();
        return AttemptOutcome::Retryable {
            error: HuggingfaceError::RateLimited {
                retry_after_ms: extract_retry_after_ms(retry_after),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(HuggingfaceError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(HuggingfaceError::NotFound(format!(
            "Model not found (HTTP {status})"
        )));
    }

    // A valid loading response explicitly says inference has not started.
    // A generic 503, oversized/truncated body, or invalid estimate gives no proof.
    if status == 503 {
        let body = match resp.read().await {
            Ok(body) => body,
            Err(_) => {
                return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                    status: Some(status),
                });
            }
        };
        if let Ok(hf_err) = serde_json::from_slice::<HfApiError>(&body)
            && let Some(estimate) = hf_err
                .estimated_time
                .filter(|estimate| estimate.is_finite() && *estimate >= 0.0)
            && let Ok(wait) = Duration::try_from_secs_f64(estimate.max(1.0))
        {
            return AttemptOutcome::Retryable {
                error: HuggingfaceError::ModelLoading { retry_after: wait },
                retry_after: Some(wait),
            };
        }
        return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
            status: Some(status),
        });
    }

    if status == 408 || status >= 500 {
        return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
            status: Some(status),
        });
    }

    if !(200..300).contains(&status) {
        // Error bodies can echo a private prompt or bearer material.
        return AttemptOutcome::Terminal(HuggingfaceError::Api {
            status,
            message: "inference request rejected by provider".into(),
        });
    }

    let body = match resp.read().await {
        Ok(body) => body,
        Err(_) => {
            return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                status: Some(status),
            });
        }
    };

    match serde_json::from_slice::<T>(&body) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(_) => {
            debug!(
                attempt,
                "Inference response could not be decoded; replay suppressed"
            );
            AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                status: Some(status),
            })
        }
    }
}

/// Handle a standard JSON response (e.g., Hub API model info).
async fn handle_json_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let replayable = e.is_connect() || e.is_timeout();
            return AttemptOutcome::retryable_if_replayable(
                HuggingfaceError::Http(e.without_url()),
                None,
                replayable,
            );
        }
    };

    handle_json_provider_response(ProviderResponse::Direct(resp), attempt).await
}

async fn handle_json_provider_response<T: serde::de::DeserializeOwned>(
    resp: ProviderResponse,
    attempt: u32,
) -> AttemptOutcome<T, HuggingfaceError> {
    let status = resp.status();

    if (300..400).contains(&status) {
        return AttemptOutcome::Terminal(HuggingfaceError::Api {
            status,
            message: "redirect refused; configure the intended hub_url explicitly".into(),
        });
    }

    if status == 429 {
        let retry_after = resp.retry_after();
        return AttemptOutcome::Retryable {
            error: HuggingfaceError::RateLimited {
                retry_after_ms: extract_retry_after_ms(retry_after),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(HuggingfaceError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(HuggingfaceError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !(200..300).contains(&status) {
        let err = HuggingfaceError::Api {
            status,
            message: "Hub request rejected by provider".into(),
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let body = match resp.read().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(error),
    };

    match serde_json::from_slice::<T>(&body) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(_) => {
            debug!(attempt, "Hub response did not match its JSON contract");
            AttemptOutcome::Terminal(HuggingfaceError::Api {
                status,
                message: "Hub response did not match its JSON contract".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_invocation(operation: &str, id: &str, credential_id: CredentialId) -> InvokeRequest {
        use chrono::{Duration as ChronoDuration, Utc};
        use fcp_core::{CapabilityConstraints, CapabilityToken};
        use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

        let constraints = CapabilityConstraints {
            resource_allow: vec!["huggingface:*".into(), "http://127.0.0.1:*".into()],
            credential_allow: vec![credential_id],
            ..CapabilityConstraints::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let signing_key = Ed25519SigningKey::from_bytes(&[71; 32]).unwrap();
        let now = Utc::now();
        let capability = if operation.starts_with("huggingface.inference.") {
            "huggingface.inference"
        } else {
            "huggingface.models"
        };
        let token = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:hf-proxy-test")
            .operations(&[operation])
            .issuer("node:hf-proxy-test")
            .target_instance("hf-proxy-test")
            .token_id(id.as_bytes())
            .validity(
                now - ChronoDuration::minutes(1),
                now + ChronoDuration::hours(1),
            )
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap();
        serde_json::from_value(serde_json::json!({
            "type": "invoke",
            "id": id,
            "connector_id": "fcp.huggingface",
            "operation": operation,
            "zone_id": "z:work",
            "input": {},
            "correlation_id": "99c09d94-3189-4608-b390-8fa5e9508a00",
            "capability_token": CapabilityToken::from_raw(token),
        }))
        .unwrap()
    }

    fn proxy_reply(
        request: &HostEgressHttpRequest,
        body: serde_json::Value,
    ) -> HostEgressHttpResponse {
        HostEgressHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Base64Bytes::from_vec(serde_json::to_vec(&body).unwrap()),
            egress: fcp_manifest::HostEgressDecisionMetadata {
                connector_id: request.context.connector_id.clone(),
                operation_id: request.context.operation_id.clone(),
                zone_id: request.context.zone_id.clone(),
                request_id: request.context.request_id.clone(),
                correlation_id: request.context.correlation_id.clone(),
                execution_mode: "host_egress_proxy".into(),
                constraint_source: "manifest".into(),
                decision: "allow".into(),
                resolved_host: "127.0.0.1".into(),
                resolved_port: 443,
                credential_injected: true,
                elapsed_ms: 1,
            },
        }
    }

    fn proxied_client(
        proxy: &str,
        provider: &str,
        credential_id: CredentialId,
    ) -> HuggingfaceClient {
        HuggingfaceClient::new(
            Some(provider),
            Some(provider),
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(2),
        )
        .unwrap()
        .with_credential_id(credential_id, HostEgressProxyClient::new(proxy).unwrap())
        .unwrap()
    }

    #[fcp_async_core::runtime::test]
    async fn host_proxy_carries_original_authority_for_every_provider_operation() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(|request: &wiremock::Request| {
                let request: HostEgressHttpRequest = serde_json::from_slice(&request.body).unwrap();
                let body = match request.context.operation_id.as_str() {
                    "huggingface.inference.text_generation" => {
                        serde_json::json!([{"generated_text":"hello"}])
                    }
                    "huggingface.inference.summarization" => {
                        serde_json::json!([{"summary_text":"summary"}])
                    }
                    "huggingface.models.info" => serde_json::json!({"modelId":"org/model"}),
                    "huggingface.models.list" => serde_json::json!([{"modelId":"org/model"}]),
                    _ => panic!("unexpected host operation"),
                };
                ResponseTemplate::new(200).set_body_json(proxy_reply(&request, body))
            })
            .expect(4)
            .mount(&proxy)
            .await;
        let credential_id = CredentialId::new();
        let client = proxied_client(&proxy.uri(), &provider.uri(), credential_id);
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let mut invocations = Vec::new();
        for (index, operation) in [
            "huggingface.inference.text_generation",
            "huggingface.inference.summarization",
            "huggingface.models.info",
            "huggingface.models.list",
        ]
        .iter()
        .enumerate()
        {
            let invocation = proxy_invocation(operation, &format!("proxy-{index}"), credential_id);
            let bound = client.for_invocation(&invocation).unwrap();
            match index {
                0 => assert_eq!(
                    bound
                        .text_generation(
                            &runtime,
                            "org/model",
                            &TextGenerationRequest {
                                inputs: "private prompt".into(),
                                parameters: None,
                            }
                        )
                        .await
                        .unwrap()[0]
                        .generated_text,
                    "hello"
                ),
                1 => assert_eq!(
                    bound
                        .summarization(
                            &runtime,
                            "org/model",
                            &SummarizationRequest {
                                inputs: "private document".into(),
                                parameters: None,
                            }
                        )
                        .await
                        .unwrap()[0]
                        .summary_text,
                    "summary"
                ),
                2 => assert_eq!(
                    bound
                        .model_info(&runtime, "org/model")
                        .await
                        .unwrap()
                        .model_id,
                    "org/model"
                ),
                _ => assert_eq!(
                    bound
                        .list_models(
                            &runtime,
                            &ModelListRequest {
                                search: Some("org/model".into()),
                                limit: Some(1),
                                ..ModelListRequest::default()
                            }
                        )
                        .await
                        .unwrap()[0]
                        .model_id,
                    "org/model"
                ),
            }
            invocations.push(invocation);
        }
        let requests = proxy.received_requests().await.unwrap();
        assert_eq!(requests.len(), 4);
        for (index, request) in requests.iter().enumerate() {
            let body: HostEgressHttpRequest = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                body.credential_id.as_deref(),
                Some(credential_id.to_string().as_str())
            );
            assert_eq!(body.context.request_id, invocations[index].id.to_string());
            assert_eq!(
                body.context.operation_id,
                invocations[index].operation.to_string()
            );
            assert_eq!(
                body.context.correlation_id,
                invocations[index]
                    .correlation_id
                    .as_ref()
                    .map(ToString::to_string)
            );
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&body.context.capability_token_cbor_b64)
                    .unwrap(),
                invocations[index].capability_token.raw().to_cbor().unwrap()
            );
            assert_eq!(body.method, if index < 2 { "POST" } else { "GET" });
            assert!(
                !body
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case("authorization"))
            );
            if index < 3 {
                assert_eq!(body.url, format!("{}/models/org/model", provider.uri()));
            } else {
                let url = Url::parse(&body.url).unwrap();
                assert_eq!(url.path(), "/models");
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "search" && value == "org/model")
                );
            }
        }
        assert!(provider.received_requests().await.unwrap().is_empty());
        assert!(client.transport("huggingface.models.info").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn host_proxy_rejection_never_replays_inference_or_falls_back() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(503).set_body_string("private capability and prompt"),
            )
            .expect(1)
            .mount(&proxy)
            .await;
        let credential_id = CredentialId::new();
        let client = proxied_client(&proxy.uri(), &provider.uri(), credential_id);
        let invocation = proxy_invocation(
            "huggingface.inference.text_generation",
            "rejected",
            credential_id,
        );
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let error = client
            .for_invocation(&invocation)
            .unwrap()
            .text_generation(
                &runtime,
                "org/model",
                &TextGenerationRequest {
                    inputs: "private prompt".into(),
                    parameters: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            HuggingfaceError::InferenceOutcomeUnknown { status: Some(503) }
        ));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("private"));
        assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn host_proxy_requires_bound_matching_operation_before_any_send() {
        let proxy = wiremock::MockServer::start().await;
        let provider = wiremock::MockServer::start().await;
        let credential_id = CredentialId::new();
        let client = proxied_client(&proxy.uri(), &provider.uri(), credential_id);
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        assert!(client.model_info(&runtime, "org/model").await.is_err());
        assert!(client.whoami(&runtime).await.is_err());
        let invocation = proxy_invocation("huggingface.models.list", "mismatch", credential_id);
        let bound = client.for_invocation(&invocation).unwrap();
        assert!(bound.model_info(&runtime, "org/model").await.is_err());
        assert!(proxy.received_requests().await.unwrap().is_empty());
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn host_proxy_response_requires_matching_attribution_and_injection() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let provider = MockServer::start().await;
        let credential_id = CredentialId::new();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        for invalid_attribution in [true, false] {
            let proxy = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(move |request: &wiremock::Request| {
                    let request = serde_json::from_slice(&request.body).unwrap();
                    let mut response =
                        proxy_reply(&request, serde_json::json!({"modelId":"org/model"}));
                    if invalid_attribution {
                        response.egress.request_id = "another-request".into();
                    } else {
                        response.egress.credential_injected = false;
                    }
                    ResponseTemplate::new(200).set_body_json(response)
                })
                .expect(1)
                .mount(&proxy)
                .await;
            let invocation =
                proxy_invocation("huggingface.models.info", "bad-reply", credential_id);
            let error = proxied_client(&proxy.uri(), &provider.uri(), credential_id)
                .for_invocation(&invocation)
                .unwrap()
                .model_info(&runtime, "org/model")
                .await
                .unwrap_err();
            assert!(matches!(error, HuggingfaceError::HostProxy { .. }));
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("another-request"));
        }
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "hf_secret_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();

        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("hf_secret_token"));
    }

    #[test]
    fn secretless_detection() {
        let anonymous = HuggingfaceClient::new(
            None,
            None,
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!anonymous.is_secretless());
        let secretless = anonymous
            .with_credential_id(
                CredentialId::new(),
                HostEgressProxyClient::new("http://127.0.0.1:1").unwrap(),
            )
            .unwrap();
        assert!(secretless.is_secretless());

        let configured = HuggingfaceClient::new(
            None,
            None,
            "hf_test",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!configured.is_secretless());
    }

    #[test]
    fn default_urls() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            client.inference_url(),
            "https://router.huggingface.co/hf-inference"
        );
        assert_eq!(client.hub_url(), "https://huggingface.co/api");
    }

    #[test]
    fn custom_urls_strip_trailing_slash() {
        let client = HuggingfaceClient::new(
            Some("http://localhost:8080/"),
            Some("http://localhost:8081/"),
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.inference_url().ends_with('/'));
        assert!(!client.hub_url().ends_with('/'));
    }

    #[test]
    fn custom_urls_reject_query_or_fragment() {
        let err = HuggingfaceClient::new(
            Some("https://example.test/hf?x=bad"),
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .expect_err("query strings should be rejected");
        assert!(err.to_string().contains("query or fragment"));
    }

    #[test]
    fn configured_endpoints_cannot_redirect_credentials_off_provider() {
        for url in [
            "https://router.huggingface.co.attacker.test/hf-inference",
            "http://router.huggingface.co/hf-inference",
            "https://router.huggingface.co:8443/hf-inference",
            "https://router.huggingface.co/other",
            "https://api-inference.huggingface.co",
            "https://router.huggingface.co/hf-inference\n",
        ] {
            assert!(normalize_api_base_url(url, "inference_url").is_err());
        }
        assert!(normalize_api_base_url(DEFAULT_INFERENCE_URL, "inference_url").is_ok());
        assert!(normalize_api_base_url(DEFAULT_HUB_URL, "hub_url").is_ok());
        assert!(normalize_api_base_url("http://[::1]:1234/api", "hub_url").is_ok());
    }

    #[test]
    fn sanitize_model_id_rejects_traversal() {
        assert!(sanitize_model_id("../etc/passwd").is_err());
        assert!(sanitize_model_id("foo\\bar").is_err());
        assert!(sanitize_model_id("foo%2fbar").is_err());
        assert!(sanitize_model_id("foo%5Cbar").is_err());
        assert!(sanitize_model_id("").is_err());
        assert!(sanitize_model_id("  ").is_err());
    }

    #[test]
    fn sanitize_model_id_rejects_multiple_slashes() {
        assert!(sanitize_model_id("org/sub/model").is_err());
    }

    #[test]
    fn sanitize_model_id_accepts_valid() {
        assert_eq!(sanitize_model_id("gpt2").unwrap(), "gpt2");
        assert_eq!(
            sanitize_model_id("facebook/bart-large-cnn").unwrap(),
            "facebook/bart-large-cnn"
        );
        assert_eq!(
            sanitize_model_id("mistralai/Mistral-7B-v0.1").unwrap(),
            "mistralai/Mistral-7B-v0.1"
        );
    }

    #[test]
    fn sanitize_model_id_rejects_url_component_injection() {
        for model_id in [
            ".",
            "/gpt2",
            "org/",
            "org/.",
            "gpt2?redirect=elsewhere",
            "org/model#ignored",
            "%2e%2e",
            "org/%2E%2e",
            "org/%252e%252e",
            "org%255cmodel",
            " gpt2",
            "org /model",
            "org/\tmodel",
            "gpt2\n",
            "gpt2\0",
        ] {
            assert!(
                sanitize_model_id(model_id).is_err(),
                "accepted URL-changing model ID: {model_id:?}"
            );
        }
    }

    #[test]
    fn custom_urls_reject_embedded_credentials_without_echoing_them() {
        for url in [
            "https://user:private-password@example.test/api",
            "https://private-user@example.test/api",
            "https://:private-password@example.test/api",
        ] {
            for field in ["inference_url", "hub_url"] {
                let err = normalize_api_base_url(url, field)
                    .expect_err("URL credentials must not bypass the explicit auth channel");
                let message = err.to_string();
                assert!(message.contains("embedded credentials"));
                assert!(!message.contains("private-password"));
                assert!(!message.contains("private-user"));
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn inference_builder_failure_is_terminal() {
        let request = Client::new()
            .post("http://127.0.0.1:0/models/gpt2")
            .header("authorization", "invalid\nheader");
        assert!(matches!(
            handle_inference_response::<serde_json::Value>(request, 0).await,
            AttemptOutcome::Terminal(HuggingfaceError::Http(error)) if error.is_builder()
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn inference_connect_failure_remains_replayable() {
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let request = client.post("http://127.0.0.1:0/models/gpt2");
        assert!(matches!(
            handle_inference_response::<serde_json::Value>(request, 0).await,
            AttemptOutcome::Retryable {
                error: HuggingfaceError::Http(error),
                retry_after: None,
            } if error.is_connect()
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn inference_http_timeout_reports_unknown_outcome() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(250))
                    .set_body_json(serde_json::json!([{"generated_text": "already computed"}])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let request = client.post(format!("{}/models/gpt2", server.uri()));
        assert!(matches!(
            handle_inference_response::<serde_json::Value>(request, 0).await,
            AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown { status: None })
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[test]
    fn client_uses_configured_timeout() {
        let client = HuggingfaceClient::new(
            None,
            None,
            "t",
            HttpRetryConfig::default(),
            Duration::from_millis(1_234),
        )
        .unwrap();
        assert_eq!(client.timeout, Duration::from_millis(1_234));
    }

    #[fcp_async_core::runtime::test]
    async fn whoami_keeps_the_hub_api_prefix() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/whoami-v2"))
            .and(header("authorization", "Bearer hf_identity_fixture"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"name": "fixture-account"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = HuggingfaceClient::new(
            None,
            Some(&format!("{}/api", server.uri())),
            "hf_identity_fixture",
            HttpRetryConfig::default(),
            Duration::from_secs(2),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        assert_eq!(
            client.whoami(&runtime).await.unwrap()["name"],
            "fixture-account"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_inference_success_is_unknown_and_never_retried() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!([{"generated_text": "x".repeat(MAX_PROVIDER_RESPONSE_BYTES)}]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let client = HuggingfaceClient::new(
            Some(&server.uri()),
            None,
            "hf_fixture",
            HttpRetryConfig::default(),
            Duration::from_secs(2),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let error = client
            .text_generation(
                &runtime,
                "gpt2",
                &TextGenerationRequest {
                    inputs: "private prompt".into(),
                    parameters: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            HuggingfaceError::InferenceOutcomeUnknown { status: Some(200) }
        ));
        assert!(!error.is_retryable());
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_hub_success_is_rejected_before_parsing() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let request = Client::new().get(server.uri());
        assert!(matches!(
            handle_json_response::<serde_json::Value>(request, 0).await,
            AttemptOutcome::Terminal(HuggingfaceError::ResponseTooLarge {
                limit: MAX_PROVIDER_RESPONSE_BYTES,
            })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn body_limit_covers_chunked_responses_without_content_length() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            let _ = socket.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..=MAX_PROVIDER_RESPONSE_BYTES / chunk.len() {
                if socket.write_all(b"10000\r\n").is_err()
                    || socket.write_all(&chunk).is_err()
                    || socket.write_all(b"\r\n").is_err()
                {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n");
        });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let response = client
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        assert!(response.content_length().is_none());
        assert!(matches!(
            read_bounded_response(response).await,
            Err(HuggingfaceError::ResponseTooLarge {
                limit: MAX_PROVIDER_RESPONSE_BYTES,
            })
        ));
        server.join().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn loading_estimate_is_not_shortened_or_echoed() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "error": "private prompt and token must not escape",
                "estimated_time": 180.5
            })))
            .expect(1)
            .mount(&server)
            .await;
        let request = Client::new().post(server.uri());
        match handle_inference_response::<serde_json::Value>(request, 0).await {
            AttemptOutcome::Retryable {
                error: HuggingfaceError::ModelLoading { retry_after },
                retry_after: Some(hint),
            } => {
                assert_eq!(retry_after, Duration::from_millis(180_500));
                assert_eq!(hint, retry_after);
                let error = HuggingfaceError::ModelLoading { retry_after };
                assert!(!error.to_string().contains("private prompt"));
                assert_eq!(error.retry_after(), Some(hint));
            }
            _ => panic!("expected an unchanged model loading minimum"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn provider_rejection_does_not_expose_its_body() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("private prompt and hf_secret_canary"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let request = Client::new().post(server.uri());
        match handle_inference_response::<serde_json::Value>(request, 0).await {
            AttemptOutcome::Terminal(error) => {
                assert!(!error.to_string().contains("private prompt"));
                assert!(!error.to_string().contains("hf_secret_canary"));
                assert!(!error.is_retryable());
            }
            _ => panic!("provider rejection must be terminal"),
        }
    }
}
