use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};

use crate::error::{PerplexityError, PerplexityResult};
use crate::types::{
    ApiErrorResponse, ChatCompletionRequest, ChatCompletionResponse, PerplexityAuth,
    SearchApiRequest, SearchApiResponse,
};

pub const DEFAULT_BASE_URL: &str = "https://api.perplexity.ai";

/// Header Perplexity uses to attribute API traffic to a client integration.
const INTEGRATION_HEADER: &str = "X-Pplx-Integration";
/// Value identifying this connector in Perplexity's attribution telemetry.
const INTEGRATION_NAME: &str = "flywheel-connectors";

/// Returns whether `base_url` points at Perplexity's own API host (the only
/// place the attribution header is meaningful; proxies such as `OpenRouter`,
/// self-hosted mocks, and look-alike hosts must not receive it).
fn targets_perplexity_api(base_url: &str) -> bool {
    url::Url::parse(base_url).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("api.perplexity.ai"))
    })
}

/// Perplexity API client with retry support.
pub struct PerplexityClient {
    http: Client,
    base_url: String,
    /// True when `base_url` is Perplexity's own API host, so requests carry
    /// the integration attribution header.
    attribute_requests: bool,
    auth: PerplexityAuth,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for PerplexityClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerplexityClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

fn redact_sensitive_material(message: String, sensitive_material: &str) -> String {
    let auth_material = sensitive_material.trim();
    if auth_material.len() < 8 {
        return message;
    }
    message.replace(auth_material, "[REDACTED]")
}

#[allow(clippy::missing_errors_doc)]
impl PerplexityClient {
    pub fn new(
        auth: PerplexityAuth,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> PerplexityResult<Self> {
        let http = Client::builder()
            .timeout(request_timeout)
            .user_agent("fcp-perplexity-search/0.1.0")
            .build()
            .map_err(PerplexityError::Http)?;

        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());

        Ok(Self {
            http,
            base_url: DEFAULT_BASE_URL.into(),
            attribute_requests: targets_perplexity_api(DEFAULT_BASE_URL),
            auth,
            runtime,
            retry_config,
        })
    }

    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim_end_matches('/').to_string();
        self.attribute_requests = targets_perplexity_api(&self.base_url);
        self
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    pub const fn shutdown(&self) {
        // No persistent resources to clean up.
    }

    /// Health check: performs a minimal chat completion request to verify the API key.
    pub async fn health_check(&self) -> PerplexityResult<()> {
        use crate::types::ChatMessage;

        let req = ChatCompletionRequest {
            model: "sonar".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "ping".into(),
            }],
            max_tokens: Some(1),
            temperature: Some(0.0),
            top_p: None,
            search_domain_filter: None,
            return_images: None,
            return_related_questions: None,
            search_recency_filter: None,
            top_k: None,
            stream: Some(false),
            presence_penalty: None,
            frequency_penalty: None,
        };

        let _ = self.chat_completions(&req).await?;
        Ok(())
    }

    /// Execute a chat completions request against the Perplexity API.
    ///
    /// POST /chat/completions (OpenAI-compatible with citations extension).
    pub async fn chat_completions(
        &self,
        request: &ChatCompletionRequest,
    ) -> PerplexityResult<ChatCompletionResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = serde_json::to_value(request).map_err(PerplexityError::Json)?;
        self.post_json(url, body, "chat/completions").await
    }

    /// Execute a native Perplexity Search API request.
    ///
    /// POST /search with structured web-search filters and result metadata.
    pub async fn native_search(
        &self,
        request: &SearchApiRequest,
    ) -> PerplexityResult<SearchApiResponse> {
        let url = format!("{}/search", self.base_url);
        let body = serde_json::to_value(request).map_err(PerplexityError::Json)?;
        self.post_json(url, body, "search").await
    }

    async fn post_json<R>(
        &self,
        url: String,
        body: serde_json::Value,
        endpoint_label: &'static str,
    ) -> PerplexityResult<R>
    where
        R: DeserializeOwned,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth_material = self.auth.api_key.clone();
        let attribute_requests = self.attribute_requests;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.http.clone();
            let auth_material = auth_material.clone();
            let body = body.clone();
            async move {
                debug!(attempt, endpoint = endpoint_label, "Perplexity request");

                let mut req = if auth_material.is_empty() {
                    client.post(&url).json(&body)
                } else {
                    client
                        .post(&url)
                        .bearer_auth(&auth_material)
                        .header(reqwest::header::ACCEPT, "application/json")
                        .json(&body)
                };
                if attribute_requests {
                    req = req.header(INTEGRATION_HEADER, INTEGRATION_NAME);
                }

                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: PerplexityError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();

                // Rate limiting
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: PerplexityError::RateLimited {
                            retry_after_ms: u64::try_from(
                                retry_after.unwrap_or(Duration::from_secs(30)).as_millis(),
                            )
                            .unwrap_or(u64::MAX),
                        },
                        retry_after,
                    };
                }

                // Authentication errors
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(PerplexityError::Unauthorized(format!(
                        "Authentication failed (HTTP {status})"
                    )));
                }

                // Non-success: parse error body
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();

                    // Try to parse structured error
                    let (message, error_type) =
                        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
                            if let Some(detail) = api_err.error {
                                (detail.message, detail.error_type)
                            } else {
                                (text.clone(), None)
                            }
                        } else {
                            (text, None)
                        };
                    let message = redact_sensitive_material(message, &auth_material);

                    let err = PerplexityError::Api {
                        status,
                        message,
                        error_type,
                    };

                    if err.is_retryable() {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                // Success: parse response
                let text = match resp.text().await {
                    Ok(t) => t,
                    Err(e) => return AttemptOutcome::Terminal(PerplexityError::Http(e)),
                };

                match serde_json::from_str::<R>(&text) {
                    Ok(response) => AttemptOutcome::Success(response),
                    Err(e) => {
                        debug!(attempt, "Failed to parse Perplexity response: {e}");
                        AttemptOutcome::Terminal(PerplexityError::Json(e))
                    }
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PerplexityAuth;

    #[test]
    fn client_debug_redacts_auth() {
        let client = PerplexityClient::new(
            PerplexityAuth {
                api_key: "pplx-secret-key".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();

        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("pplx-secret"));
    }

    #[test]
    fn secretless_detection() {
        let secretless = PerplexityClient::new(
            PerplexityAuth {
                api_key: String::new(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(secretless.is_secretless());

        let with_key = PerplexityClient::new(
            PerplexityAuth {
                api_key: "pplx-abc".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!with_key.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let client = PerplexityClient::new(
            PerplexityAuth {
                api_key: "pplx-t".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap()
        .with_base_url("https://api.perplexity.ai/");

        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn attribution_only_targets_perplexity_api_host() {
        assert!(targets_perplexity_api("https://api.perplexity.ai"));
        assert!(targets_perplexity_api("https://API.Perplexity.AI/"));
        assert!(!targets_perplexity_api("http://api.perplexity.ai"));
        assert!(!targets_perplexity_api(
            "https://api.perplexity.ai.example.com"
        ));
        assert!(!targets_perplexity_api("https://openrouter.ai/api/v1"));
        assert!(!targets_perplexity_api("http://localhost:8080"));
        assert!(!targets_perplexity_api("not a url"));
    }

    #[test]
    fn attribution_flag_follows_base_url() {
        let client = PerplexityClient::new(
            PerplexityAuth {
                api_key: "pplx-t".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.attribute_requests);
        let client = client.with_base_url("https://openrouter.ai/api/v1/");
        assert!(!client.attribute_requests);
        let client = client.with_base_url("https://api.perplexity.ai/");
        assert!(client.attribute_requests);
    }

    #[test]
    fn custom_base_url_works() {
        let client = PerplexityClient::new(
            PerplexityAuth {
                api_key: "pplx-t".into(),
            },
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap()
        .with_base_url("http://localhost:8080");

        assert_eq!(client.base_url(), "http://localhost:8080");
    }

    #[test]
    fn redacts_secret_from_error_text() {
        let redacted =
            redact_sensitive_material("bad key pplx-redacted-value".into(), "pplx-redacted-value");
        assert_eq!(redacted, "bad key [REDACTED]");
    }
}
