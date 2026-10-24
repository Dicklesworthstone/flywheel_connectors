//! HTTP client for Hugging Face Inference and Hub APIs.

use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;
use url::Url;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{HuggingfaceError, HuggingfaceResult};
use crate::types::{
    HfApiError, ModelInfo, ModelListRequest, SummarizationRequest, SummarizationResponse,
    TextGenerationRequest, TextGenerationResponse,
};

/// Default Inference API base URL.
const DEFAULT_INFERENCE_URL: &str = "https://api-inference.huggingface.co";
/// Default Hub API base URL.
const DEFAULT_HUB_URL: &str = "https://huggingface.co/api";

/// Validate a user-supplied model ID to prevent URL path injection.
fn sanitize_model_id(value: &str) -> HuggingfaceResult<&str> {
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
    // model_id can contain exactly one `/` for org/model format (e.g. "facebook/bart-large-cnn")
    let slash_count = value.chars().filter(|&c| c == '/').count();
    if slash_count > 1 {
        return Err(HuggingfaceError::InvalidInput(
            "model_id may contain at most one `/` (org/model format)".into(),
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
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }

    let parsed = Url::parse(trimmed).map_err(|e| {
        HuggingfaceError::InvalidInput(format!("{field} must be an absolute URL: {e}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(HuggingfaceError::InvalidInput(format!(
            "{field} must use http or https"
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

    Ok(trimmed.to_string())
}

/// Hugging Face API client with retry support.
pub struct HuggingfaceClient {
    client: Client,
    inference_url: String,
    hub_url: String,
    api_token: String,
    retry_config: HttpRetryConfig,
    pub(crate) timeout: Duration,
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
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HuggingfaceClient {
    /// Create a new Hugging Face API client.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError::Http` if the underlying HTTP client cannot be built.
    pub fn new(
        inference_url: Option<&str>,
        hub_url: Option<&str>,
        api_token: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> HuggingfaceResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            // Redirects are hidden sends below RetryLoop. A 307/308 can
            // replay billable inference and forward a private prompt to a
            // different endpoint even if Authorization is stripped.
            .redirect(reqwest::redirect::Policy::none())
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
            retry_config,
            timeout,
        })
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
    pub fn is_secretless(&self) -> bool {
        self.api_token.trim().is_empty()
    }

    // ── Text Generation ──

    /// Run text generation inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
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

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            async move {
                debug!(attempt, model_id, "Text generation request");
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<Vec<TextGenerationResponse>>(req, attempt).await
            }
        })
        .await
    }

    // ── Summarization ──

    /// Run summarization inference on the given model.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
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

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let body = body.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            async move {
                debug!(attempt, model_id, "Summarization request");
                let req = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let req = req.json(&body);
                handle_inference_response::<Vec<SummarizationResponse>>(req, attempt).await
            }
        })
        .await
    }

    // ── Model Info (Hub API) ──

    /// Fetch model metadata from the Hugging Face Hub API.
    ///
    /// # Errors
    ///
    /// Returns `HuggingfaceError` on HTTP, auth, rate-limit, or parse failures.
    pub async fn model_info(
        &self,
        runtime: &ConnectorRuntime,
        model_id: &str,
    ) -> HuggingfaceResult<ModelInfo> {
        let model_id = sanitize_model_id(model_id)?;
        let url = format!("{}/models/{model_id}", self.hub_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            async move {
                debug!(attempt, model_id, "Model info request");
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
    /// Returns `HuggingfaceError` on invalid query parameters, HTTP, auth, rate-limit,
    /// or parse failures.
    pub async fn list_models(
        &self,
        runtime: &ConnectorRuntime,
        request: &ModelListRequest,
    ) -> HuggingfaceResult<Vec<ModelInfo>> {
        let mut url = Url::parse(&format!("{}/models", self.hub_url)).map_err(|e| {
            HuggingfaceError::InvalidInput(format!("hub_url cannot form models URL: {e}"))
        })?;
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

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone(); // ubs:ignore - runtime auth value, not a literal.
            async move {
                debug!(attempt, "Model catalog list request");
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
    /// Returns `HuggingfaceError` on HTTP, auth, or parse failures.
    pub async fn whoami(&self, runtime: &ConnectorRuntime) -> HuggingfaceResult<serde_json::Value> {
        // Strip trailing /api or /api/ path segment to get the base HuggingFace URL
        // (hub_url is "https://huggingface.co/api" but whoami lives at "https://huggingface.co/whoami-v2")
        let base = self.hub_url.trim_end_matches('/');
        let base = base.strip_suffix("/api").unwrap_or(base);
        let url = format!("{base}/whoami-v2");
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

/// Extract retry-after duration from response headers, clamped to u64.
fn extract_retry_after_ms(retry_after: Option<Duration>) -> u64 {
    let millis = retry_after.unwrap_or(Duration::from_secs(30)).as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Handle the Inference API response, which returns JSON directly (no envelope).
/// The HF Inference API returns 503 with `estimated_time` when the model is loading.
/// Inference POSTs are not replay-safe: a timeout or generic server error can
/// arrive after billable work has completed. Preserve that uncertainty in the
/// returned error as well as the local retry decision, so the host cannot
/// accidentally retry it at the invoke layer (br-kxd3e).
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
            // A builder error is terminal; only a connect-phase failure is
            // both transient and provably pre-transmission.
            let replayable = e.is_connect();
            return AttemptOutcome::retryable_if_replayable(
                HuggingfaceError::Http(e),
                None,
                replayable,
            );
        }
    };

    let status = resp.status().as_u16();

    if resp.status().is_redirection() {
        return AttemptOutcome::Terminal(HuggingfaceError::Api {
            status,
            message: "redirect refused; configure the intended inference_url explicitly".into(),
        });
    }

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
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
    // A generic 503, truncated body, or invalid estimate gives no such proof.
    if status == 503 {
        let text = match resp.text().await {
            Ok(text) => text,
            Err(_) => {
                return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                    status: Some(status),
                });
            }
        };
        if let Ok(hf_err) = serde_json::from_str::<HfApiError>(&text) {
            if let Some(estimate) = hf_err
                .estimated_time
                .filter(|estimate| estimate.is_finite() && *estimate >= 0.0)
            {
                let wait = Duration::from_secs_f64(estimate.clamp(1.0, 120.0));
                return AttemptOutcome::Retryable {
                    error: HuggingfaceError::ModelLoading(hf_err.error),
                    retry_after: Some(wait),
                };
            }
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

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = HuggingfaceError::Api {
            status,
            message: text,
        };
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => {
            return AttemptOutcome::Terminal(HuggingfaceError::InferenceOutcomeUnknown {
                status: Some(status),
            });
        }
    };

    match serde_json::from_str::<T>(&text) {
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
            return AttemptOutcome::Retryable {
                error: HuggingfaceError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if resp.status().is_redirection() {
        return AttemptOutcome::Terminal(HuggingfaceError::Api {
            status,
            message: "redirect refused; configure the intended hub_url explicitly".into(),
        });
    }

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
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

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = HuggingfaceError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(HuggingfaceError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse JSON response: {e}");
            AttemptOutcome::Terminal(HuggingfaceError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let secretless = HuggingfaceClient::new(
            None,
            None,
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
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
            "https://api-inference.huggingface.co"
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
        // Port zero cannot be assigned to a listening TCP service; binding
        // it instead allocates a nonzero ephemeral port. This avoids racing
        // another test for an ephemeral port that we just closed.
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
        // No enclosing execution deadline: exercise the HTTP timeout arm
        // itself rather than allowing the runtime timeout to win the race.
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
}
