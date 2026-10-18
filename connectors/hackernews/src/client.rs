//! Hacker News API client.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::debug;

use crate::error::{HackerNewsError, HackerNewsResult};
use crate::types::{Item, User};

/// Hacker News Firebase API client with retry and runtime integration.
///
/// The HN API is entirely public and requires no authentication.
pub struct HackerNewsClient {
    client: Client,
    base_url: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for HackerNewsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HackerNewsClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl HackerNewsClient {
    /// Create a new Hacker News client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(base_url: Option<&str>, retry_config: HttpRetryConfig) -> HackerNewsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(HackerNewsError::Http)?;

        let base_url = base_url
            .unwrap_or("https://hacker-news.firebaseio.com/v0")
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            client,
            base_url,
            retry_config,
        })
    }

    /// Get the base URL (for diagnostics).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> HackerNewsResult<&str> {
        if segment.trim().is_empty()
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains("..")
            || segment.contains('\0')
        {
            return Err(HackerNewsError::Config(
                "Invalid path segment: contains forbidden characters".into(),
            ));
        }
        Ok(segment)
    }

    /// Execute a GET request with retry.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> HackerNewsResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "HN GET request");
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: HackerNewsError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    let retry_after_ms = u64::try_from(
                        retry_after.unwrap_or(Duration::from_secs(60)).as_millis(),
                    )
                    .unwrap_or(u64::MAX);
                    return AttemptOutcome::Retryable {
                        error: HackerNewsError::RateLimited { retry_after_ms },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = HackerNewsError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(HackerNewsError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get a nullable item (returns Option).
    async fn get_nullable_item(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> HackerNewsResult<Option<Item>> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "HN GET item request");
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: HackerNewsError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    let retry_after_ms = u64::try_from(
                        retry_after.unwrap_or(Duration::from_secs(60)).as_millis(),
                    )
                    .unwrap_or(u64::MAX);
                    return AttemptOutcome::Retryable {
                        error: HackerNewsError::RateLimited { retry_after_ms },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = HackerNewsError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                // HN API returns "null" for items that don't exist
                let text = match resp.text().await {
                    Ok(t) => t,
                    Err(e) => return AttemptOutcome::Terminal(HackerNewsError::Http(e)),
                };

                if text.trim() == "null" {
                    return AttemptOutcome::Success(None);
                }

                match serde_json::from_str::<Item>(&text) {
                    Ok(item) => AttemptOutcome::Success(Some(item)),
                    Err(e) => AttemptOutcome::Terminal(HackerNewsError::Json(e)),
                }
            }
        })
        .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get an item by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the item does not exist or the HTTP request fails.
    pub async fn get_item(&self, runtime: &ConnectorRuntime, id: u64) -> HackerNewsResult<Item> {
        let url = format!("{}/item/{}.json", self.base_url, id);
        let item = self.get_nullable_item(runtime, &url).await?;
        item.ok_or_else(|| HackerNewsError::NotFound(format!("item {id}")))
    }

    /// Get a user by username.
    ///
    /// # Errors
    ///
    /// Returns an error if the username contains invalid path characters or the HTTP request fails.
    pub async fn get_user(
        &self,
        runtime: &ConnectorRuntime,
        username: &str,
    ) -> HackerNewsResult<User> {
        let username = Self::sanitize_path_segment(username)?;
        let url = format!("{}/user/{}.json", self.base_url, username);
        self.get_with_retry(runtime, &url).await
    }

    /// Get top story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn top_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/topstories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Get new story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn new_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/newstories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Get best story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn best_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/beststories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Get Ask HN story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn ask_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/askstories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Get Show HN story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn show_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/showstories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Get job story IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn job_stories(&self, runtime: &ConnectorRuntime) -> HackerNewsResult<Vec<u64>> {
        let url = format!("{}/jobstories.json", self.base_url);
        self.get_with_retry(runtime, &url).await
    }

    /// Health check: fetch top stories endpoint to verify API reachability.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream endpoint is unreachable or returns a non-success status.
    pub async fn health_check(&self) -> HackerNewsResult<()> {
        let url = format!("{}/topstories.json", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(HackerNewsError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            Err(HackerNewsError::RateLimited { retry_after_ms })
        } else {
            Err(HackerNewsError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }
}

/// Fuzz-only entry points for Hacker News path parser guards.
///
/// Bead `flywheel_connectors-73u29`.
#[doc(hidden)]
pub mod __fuzz {
    use super::HackerNewsClient;

    /// Return whether a candidate item/user id is safe for URL path interpolation.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        HackerNewsClient::sanitize_path_segment(value).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = HackerNewsClient::new(None, HttpRetryConfig::default());
        assert!(client.is_ok());
    }

    #[test]
    fn default_base_url() {
        let client = HackerNewsClient::new(None, HttpRetryConfig::default()).unwrap();
        assert_eq!(client.base_url(), "https://hacker-news.firebaseio.com/v0");
    }

    #[test]
    fn custom_base_url() {
        let client = HackerNewsClient::new(
            Some("http://localhost:8080/v0/"),
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert_eq!(client.base_url(), "http://localhost:8080/v0");
    }

    #[test]
    fn sanitize_path_valid() {
        assert!(HackerNewsClient::sanitize_path_segment("dang").is_ok());
        assert!(HackerNewsClient::sanitize_path_segment("user_123").is_ok());
    }

    #[test]
    fn sanitize_path_invalid() {
        assert!(HackerNewsClient::sanitize_path_segment("../etc/passwd").is_err());
        assert!(HackerNewsClient::sanitize_path_segment("foo/bar").is_err());
        assert!(HackerNewsClient::sanitize_path_segment("").is_err());
    }
}
