//! Vercel API client primitives and shared request logic.

mod deployments;
mod domains;
mod env_vars;
mod projects;

use std::time::Duration;

use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use tracing::debug;

use crate::{
    error::{VercelError, VercelResult},
    types::{ApiErrorResponse, TeamScope, VercelAuth},
};

pub(crate) fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> VercelResult<&'a str> {
    if value.trim().is_empty() {
        return Err(VercelError::Validation(format!(
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
        return Err(VercelError::Validation(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(value)
}

pub const DEFAULT_BASE_URL: &str = "https://api.vercel.com";

pub struct VercelClient {
    http: Client,
    auth: VercelAuth,
    base_url: String,
    scope: TeamScope,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for VercelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("scope", &self.scope)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl VercelClient {
    /// Create a Vercel API client for the given auth and team scope.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError::Http`] if the
    /// HTTP client cannot be built.
    pub fn new(
        auth: VercelAuth,
        scope: TeamScope,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> VercelResult<Self> {
        let http = Client::builder()
            .timeout(request_timeout)
            .user_agent("fcp-vercel/0.1.0")
            .build()
            .map_err(VercelError::Http)?;

        Ok(Self {
            http,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            scope,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config,
        })
    }

    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim().trim_end_matches('/').to_string();
        self
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    #[must_use]
    pub const fn auth(&self) -> &VercelAuth {
        &self.auth
    }

    #[must_use]
    pub const fn scope(&self) -> &TeamScope {
        &self.scope
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    /// Run a lightweight health check against the Vercel API.
    ///
    /// # Errors
    ///
    /// Returns [`VercelError`] on transport failure
    /// or a non-2xx response.
    pub async fn health_check(&self) -> VercelResult<()> {
        let _ = self.list_projects(Some(1)).await?;
        Ok(())
    }

    async fn get<R>(
        &self,
        endpoint: &str,
        extra_query: Vec<(&'static str, String)>,
    ) -> VercelResult<R>
    where
        R: DeserializeOwned + Send,
    {
        self.request_json(
            Method::GET,
            endpoint,
            extra_query,
            Option::<serde_json::Value>::None,
        )
        .await
    }

    async fn post<T, R>(
        &self,
        endpoint: &str,
        extra_query: Vec<(&'static str, String)>,
        body: &T,
    ) -> VercelResult<R>
    where
        T: Serialize + Sync + ?Sized,
        R: DeserializeOwned + Send,
    {
        let json_body = serde_json::to_value(body).map_err(VercelError::Json)?;
        self.request_json(Method::POST, endpoint, extra_query, Some(json_body))
            .await
    }

    async fn delete<R>(
        &self,
        endpoint: &str,
        extra_query: Vec<(&'static str, String)>,
    ) -> VercelResult<R>
    where
        R: DeserializeOwned + Send,
    {
        self.request_json(
            Method::DELETE,
            endpoint,
            extra_query,
            Option::<serde_json::Value>::None,
        )
        .await
    }

    async fn delete_no_content(
        &self,
        endpoint: &str,
        extra_query: Vec<(&'static str, String)>,
    ) -> VercelResult<()> {
        let url = self.endpoint_url(endpoint);
        let query = self.scope_query(extra_query);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let method = Method::DELETE;
            let url = url.clone();
            let query = query.clone();
            async move {
                debug!(attempt, endpoint, "Vercel API DELETE");

                let builder = self
                    .apply_common(self.request_builder(method, &url))
                    .query(&query);

                match builder.send().await {
                    Ok(response) => match self.handle_no_content(response).await {
                        Ok(()) => AttemptOutcome::Success(()),
                        Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        },
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            error: VercelError::Http(error),
                            retry_after: None,
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(VercelError::Http(error)),
                }
            }
        })
        .await
    }

    /// Issue a request with retry.
    ///
    /// br-kxd3e: replay safety is derived from the verb — GET reads, PUT/PATCH
    /// set named fields, DELETE converges, and only POST creates. Vercel has
    /// no idempotency key, so a replayed POST can trigger a SECOND deployment.
    /// (The POST helper currently has no callers; the gate is here so the
    /// first one added inherits the safe behaviour.)
    async fn request_json<R>(
        &self,
        method: Method,
        endpoint: &str,
        extra_query: Vec<(&'static str, String)>,
        body: Option<serde_json::Value>,
    ) -> VercelResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let url = self.endpoint_url(endpoint);
        let query = self.scope_query(extra_query);
        let replay_safe = method != Method::POST;
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let method = method.clone();
            let url = url.clone();
            let query = query.clone();
            let body = body.clone();
            async move {
                debug!(attempt, endpoint, "Vercel API request");

                let mut builder = self
                    .apply_common(self.request_builder(method, &url))
                    .query(&query);
                if let Some(body) = &body {
                    builder = builder.json(body);
                }

                match builder.send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(error) if error.is_retryable() => {
                            // 429 stays retryable — refused WITHOUT deploying.
                            let replayable =
                                replay_safe || matches!(error, VercelError::RateLimited { .. });
                            let retry_after = error.retry_after();
                            AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                        }
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    // `is_timeout()` is the TOTAL request timeout and fires
                    // after the body was written; only a connect-phase failure
                    // proves the request never arrived.
                    Err(error) => {
                        let replayable = replay_safe || !transport_error_reached_service(&error);
                        AttemptOutcome::retryable_if_replayable(
                            VercelError::Http(error),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    async fn handle_response<R>(&self, response: Response) -> VercelResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds * 1_000);
        let body = response.text().await.map_err(VercelError::Http)?;

        if status.is_success() {
            if body.trim().is_empty() {
                serde_json::from_value(serde_json::json!({"deleted": true}))
                    .map_err(VercelError::Json)
            } else {
                serde_json::from_str(&body).map_err(VercelError::Json)
            }
        } else {
            Err(parse_error_response(status, &body, retry_after_ms))
        }
    }

    async fn handle_no_content(&self, response: Response) -> VercelResult<()> {
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds * 1_000);
        let body = response.text().await.map_err(VercelError::Http)?;

        if status.is_success() {
            Ok(())
        } else {
            Err(parse_error_response(status, &body, retry_after_ms))
        }
    }

    fn request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        match method {
            Method::GET => self.http.get(url),
            Method::POST => self.http.post(url),
            Method::DELETE => self.http.delete(url),
            other => self.http.request(other, url),
        }
    }

    fn endpoint_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.base_url, endpoint)
    }

    fn scope_query(&self, extra_query: Vec<(&'static str, String)>) -> Vec<(String, String)> {
        let mut query: Vec<(String, String)> = extra_query
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();

        if let Some(team_id) = &self.scope.team_id {
            query.push(("teamId".into(), team_id.clone()));
        }
        if let Some(team_slug) = &self.scope.team_slug {
            query.push(("slug".into(), team_slug.clone()));
        }

        query
    }

    fn apply_common(&self, builder: RequestBuilder) -> RequestBuilder {
        self.apply_auth(builder)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            VercelAuth::AccessToken { access_token } => {
                builder.header("Authorization", format!("Bearer {access_token}"))
            }
            VercelAuth::CredentialId { credential_id } => {
                builder.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }
}

fn parse_error_response(
    status: StatusCode,
    body: &str,
    retry_after_ms: Option<u64>,
) -> VercelError {
    let parsed = serde_json::from_str::<ApiErrorResponse>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|payload| payload.error.as_ref())
        .and_then(|error| error.code.clone());
    let message = parsed
        .as_ref()
        .and_then(|payload| payload.error.as_ref())
        .map(|error| error.message.clone())
        .or_else(|| parsed.and_then(|payload| payload.message))
        .unwrap_or_else(|| {
            if body.trim().is_empty() {
                format!("Vercel API request failed with status {}", status.as_u16())
            } else {
                body.to_string()
            }
        });

    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => VercelError::Unauthorized(message),
        StatusCode::NOT_FOUND => VercelError::NotFound(message),
        StatusCode::TOO_MANY_REQUESTS => VercelError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(60_000),
        },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            VercelError::Validation(message)
        }
        _ => VercelError::Api {
            message,
            status_code: Some(status.as_u16()),
            code,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "id").is_err());
        assert!(sanitize_path_segment("foo/bar", "id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "id").is_err());
        assert!(sanitize_path_segment("", "id").is_err());
        assert!(sanitize_path_segment("  ", "id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("prj_abc123", "id").unwrap(),
            "prj_abc123"
        );
        assert_eq!(
            sanitize_path_segment("my-project", "id").unwrap(),
            "my-project"
        );
    }

    #[test]
    fn get_project_rejects_invalid_path_input_before_http() {
        fcp_async_core::runtime::block_on_sync(async {
            let client = VercelClient::new(
                VercelAuth::AccessToken {
                    access_token: "token".into(),
                },
                TeamScope::default(),
                HttpRetryConfig::default(),
                Duration::from_secs(5),
            )
            .unwrap()
            .with_base_url("http://127.0.0.1:9");

            match client.get_project("../admin").await {
                Err(VercelError::Validation(message)) => {
                    assert!(message.contains("project_id_or_name"));
                }
                other => panic!("expected validation error, got {other:?}"),
            }
        })
        .unwrap();
    }
}
