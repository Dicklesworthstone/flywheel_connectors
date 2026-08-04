use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder, header::HeaderMap};
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{DockerHubError, DockerHubResult};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DockerHubResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DockerHubError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(DockerHubError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Docker Hub API client with retry support.
pub struct DockerHubClient {
    client: Client,
    base_url: String,
    auth: DockerHubAuth,
    /// Session auth value obtained after login for credentials-based auth.
    session_auth_value: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for DockerHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerHubClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("has_session_auth", &self.session_auth_value.is_some())
            .finish()
    }
}

impl DockerHubClient {
    pub async fn new(
        base_url: &str,
        auth: DockerHubAuth,
        retry_config: HttpRetryConfig,
    ) -> DockerHubResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(DockerHubError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            session_auth_value: None,
            retry_config,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    fn bearer_token(&self) -> Option<&str> {
        match &self.auth {
            DockerHubAuth::Token { access_token } if !access_token.is_empty() => {
                Some(access_token.as_str())
            }
            DockerHubAuth::Credentials { .. } => self.session_auth_value.as_deref(),
            _ => None,
        }
    }

    // ── Login (for credentials-based auth) ──

    pub async fn login(&mut self, runtime: &ConnectorRuntime) -> DockerHubResult<()> {
        if let DockerHubAuth::Credentials { username, password } = &self.auth {
            let url = format!("{}/v2/users/login", self.base_url);
            let login_req = LoginRequest {
                username: username.clone(),
                password: password.clone(),
            };
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();
            let body = serde_json::to_value(&login_req).unwrap_or_default();
            let base_url = self.base_url.clone();
            let client = self.client.clone();

            let resp: LoginResponse = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = client.clone();
                let body = body.clone();
                async move {
                    debug!(attempt, "Docker Hub login");
                    let req = client.post(&url).json(&body);
                    // Replay-safe: a token mint reads credentials and
                    // creates nothing durable — the sweep's standing rule for
                    // OAuth-style token POSTs.
                    handle_response::<LoginResponse>(req, attempt, true).await
                }
            })
            .await?;

            self.session_auth_value.replace(resp.token);
            let _ = base_url;
        }
        Ok(())
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> DockerHubResult<User> {
        let url = format!("{}/v2/user", self.base_url);
        self.get_single(runtime, &url).await
    }

    // ── Repositories ──

    pub async fn list_repos(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
    ) -> DockerHubResult<Vec<Repository>> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let url = format!("{}/v2/repositories/{namespace}/", self.base_url);
        self.get_paginated(runtime, &url).await
    }

    pub async fn get_repo(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<Repository> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!("{}/v2/repositories/{namespace}/{name}/", self.base_url);
        self.get_single(runtime, &url).await
    }

    pub async fn create_repo(
        &self,
        runtime: &ConnectorRuntime,
        req: &CreateRepositoryRequest,
    ) -> DockerHubResult<Repository> {
        let namespace = sanitize_path_segment(&req.namespace, "namespace")?;
        let url = format!("{}/v2/repositories/{namespace}/", self.base_url);
        let body = serde_json::to_value(req).unwrap_or_default();
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_repo(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!("{}/v2/repositories/{namespace}/{name}/", self.base_url);
        self.delete(runtime, &url).await
    }

    // ── Tags ──

    pub async fn list_tags(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
    ) -> DockerHubResult<Vec<Tag>> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let url = format!("{}/v2/repositories/{namespace}/{name}/tags/", self.base_url);
        self.get_paginated(runtime, &url).await
    }

    pub async fn get_tag(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
        tag: &str,
    ) -> DockerHubResult<Tag> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let tag = sanitize_path_segment(tag, "tag")?;
        let url = format!(
            "{}/v2/repositories/{namespace}/{name}/tags/{tag}/",
            self.base_url
        );
        self.get_single(runtime, &url).await
    }

    pub async fn delete_tag(
        &self,
        runtime: &ConnectorRuntime,
        namespace: &str,
        name: &str,
        tag: &str,
    ) -> DockerHubResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "repository")?;
        let tag = sanitize_path_segment(tag, "tag")?;
        let url = format!(
            "{}/v2/repositories/{namespace}/{name}/tags/{tag}/",
            self.base_url
        );
        self.delete(runtime, &url).await
    }

    // ── Organizations ──

    pub async fn list_orgs(
        &self,
        runtime: &ConnectorRuntime,
    ) -> DockerHubResult<Vec<Organization>> {
        let url = format!("{}/v2/user/orgs/", self.base_url);
        self.get_paginated(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_paginated<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<Vec<T>> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth_header_value = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_header_value = auth_header_value.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET paginated");
                let req = authenticate_request(client.get(&url), auth_header_value.as_deref());
                handle_paginated_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth_header_value = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_header_value = auth_header_value.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET single");
                let req = authenticate_request(client.get(&url), auth_header_value.as_deref());
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: NOT replay-safe. Every caller of this helper CREATES a
    /// resource and the provider offers no idempotency key, so a duplicate is a second repository.
    /// Only a connect-phase failure is retried. A converging POST added
    /// later needs its own helper rather than reusing this one.
    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();
        let auth_header_value = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_header_value = auth_header_value.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "POST");
                let req = authenticate_request(client.post(&url), auth_header_value.as_deref())
                    .json(&body);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> DockerHubResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let auth_header_value = self.bearer_token().map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_header_value = auth_header_value.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "DELETE");
                let req = authenticate_request(client.delete(&url), auth_header_value.as_deref());
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }
}

// ── Free functions ──

fn authenticate_request(req: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token {
        Some(t) if !t.is_empty() => req.bearer_auth(t),
        _ => req,
    }
}

fn duration_millis_saturated(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        Some(wait.to_std().unwrap_or(Duration::from_secs(u64::MAX)))
    }
}

fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after)
}

fn rate_limited_outcome<T>(headers: &HeaderMap) -> AttemptOutcome<T, DockerHubError> {
    let retry_after = retry_after_from_headers(headers).unwrap_or(Duration::from_secs(30));
    AttemptOutcome::Retryable {
        error: DockerHubError::RateLimited {
            retry_after_ms: duration_millis_saturated(retry_after),
        },
        retry_after: Some(retry_after),
    }
}

/// Classify a response.
///
/// `replay_safe` gates only the post-transmission classes; the 429 arm stays
/// retryable because the provider refused the request WITHOUT performing it
/// (br-kxd3e).
async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<T, DockerHubError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(
                DockerHubError::Http(e),
                None,
                replayable,
            );
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        return rate_limited_outcome(resp.headers());
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(DockerHubError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(DockerHubError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = DockerHubError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            // A 5xx means the provider received the request and may already
            // have created the resource.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(DockerHubError::Http(e)),
    };

    // Handle actual 204 responses without allowing other 2xx calls to fake success.
    if text.trim().is_empty() {
        if status != 204 {
            return AttemptOutcome::Terminal(DockerHubError::Api {
                status,
                message: "empty response body".into(),
            });
        }
        if let Ok(v) = serde_json::from_str::<T>("null") {
            return AttemptOutcome::Success(v);
        }
        if let Ok(v) = serde_json::from_str::<T>("{}") {
            return AttemptOutcome::Success(v);
        }
    }

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(DockerHubError::Json(e))
        }
    }
}

async fn handle_paginated_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<Vec<T>, DockerHubError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            // Read path: always retryable.
            return AttemptOutcome::Retryable {
                error: DockerHubError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        return rate_limited_outcome(resp.headers());
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(DockerHubError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = DockerHubError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            // A 5xx means the provider received the request and may already
            // have created the resource.
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(DockerHubError::Http(e)),
    };

    // Docker Hub uses paginated responses with { count, results: [...] }
    if let Ok(paginated) = serde_json::from_str::<PaginatedResponse<T>>(&text) {
        return AttemptOutcome::Success(paginated.results);
    }

    // Fallback: try direct array
    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse paginated response: {e}");
            AttemptOutcome::Terminal(DockerHubError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

    #[test]
    fn parse_retry_after_trims_delta_seconds() {
        assert_eq!(parse_retry_after(" 7 "), Some(Duration::from_secs(7)));
    }

    #[test]
    fn parse_retry_after_saturates_large_delta_seconds() {
        assert_eq!(
            parse_retry_after("340282366920938463463374607431768211455"),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn parse_retry_after_http_date() {
        let retry_at = (Utc::now() + chrono::Duration::seconds(120))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        assert!(
            matches!(
                parse_retry_after(&retry_at),
                Some(retry_after)
                    if retry_after >= Duration::from_secs(118)
                        && retry_after <= Duration::from_secs(121)
            ),
            "future HTTP-date should parse to a delay near 120 seconds"
        );
    }

    #[test]
    fn parse_retry_after_past_http_date_is_zero() {
        let retry_at = (Utc::now() - chrono::Duration::seconds(30))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        assert_eq!(parse_retry_after(&retry_at), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_from_headers_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("4"),
        );

        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(4))
        );
    }

    #[test]
    fn rate_limited_outcome_uses_retry_after_header() {
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", HeaderValue::from_static("5"));

        assert!(matches!(
            rate_limited_outcome::<()>(&headers),
            AttemptOutcome::Retryable {
                error: DockerHubError::RateLimited {
                    retry_after_ms: 5_000,
                },
                retry_after: Some(delay),
            } if delay == Duration::from_secs(5)
        ));
    }

    #[test]
    fn rate_limited_outcome_uses_default_retry_after_when_header_missing() {
        let headers = HeaderMap::new();

        assert!(matches!(
            rate_limited_outcome::<()>(&headers),
            AttemptOutcome::Retryable {
                error: DockerHubError::RateLimited {
                    retry_after_ms: 30_000,
                },
                retry_after: Some(delay),
            } if delay == Duration::from_secs(30)
        ));
    }

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "redaction-fixture-value".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("redaction-fixture-value"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "token".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com/",
                DockerHubAuth::Token {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn bearer_token_from_access_token() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: "my-pat".into(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.bearer_token(), Some("my-pat"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "namespace").is_err());
        assert!(sanitize_path_segment("foo/bar", "namespace").is_err());
        assert!(sanitize_path_segment("foo\\bar", "namespace").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "namespace").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "namespace").is_err());
        assert!(sanitize_path_segment("", "namespace").is_err());
        assert!(sanitize_path_segment("  ", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("myuser", "namespace").unwrap(),
            "myuser"
        );
        assert_eq!(
            sanitize_path_segment("my-org", "namespace").unwrap(),
            "my-org"
        );
    }

    #[test]
    fn bearer_token_none_when_empty() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            DockerHubClient::new(
                "https://hub.docker.com",
                DockerHubAuth::Token {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.bearer_token().is_none());
    }
}
