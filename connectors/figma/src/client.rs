//! Figma REST API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::instrument;

use crate::{
    error::{FigmaError, FigmaResult},
    types::{
        Comment, CommentsResponse, ComponentsResponse, CreateWebhookRequest, ExportImagesResponse,
        FileNodesResponse, FileResponse, PostCommentRequest, ProjectFilesResponse, StylesResponse,
        TeamProjectsResponse, VersionsResponse, Webhook, WebhooksListResponse,
    },
};

/// Default Figma API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.figma.com/v1";

/// Validate a caller-supplied id before it is interpolated into a request path.
///
/// Figma resource ids (team/project/file/comment/webhook) are opaque tokens but
/// arrive as connector input. The request helpers build the URL with a plain
/// `format!("{base}/{path}")`, and `reqwest` normalizes `..` segments while
/// building the request, so an unsanitized id could traverse to a sibling
/// endpoint under `api.figma.com` or inject extra path segments. Rejecting
/// slashes, `..`, and their percent-encoded forms closes that vector.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> FigmaResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FigmaError::InvalidInput {
            message: format!("{field} must not be empty"),
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(FigmaError::InvalidInput {
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(trimmed)
}

/// Authentication mode for the Figma client.
#[derive(Clone)]
pub enum FigmaAuth {
    /// Direct personal access token.
    Token(String),
    /// Secretless credential injection via egress proxy.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for FigmaAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl FigmaAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Figma REST API client with retry logic and rate limit awareness.
pub struct FigmaClient {
    client: Client,
    auth: FigmaAuth,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for FigmaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FigmaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl FigmaClient {
    /// Create a new Figma client with a personal access token.
    pub fn new(token: impl Into<String>) -> FigmaResult<Self> {
        Self::new_with_auth(FigmaAuth::Token(token.into()))
    }

    /// Create a new Figma client with the specified auth mode.
    pub fn new_with_auth(auth: FigmaAuth) -> FigmaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-figma/0.1.0")
            .build()
            .map_err(FigmaError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Apply authentication to a request builder.
    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            FigmaAuth::Token(token) => builder.header("X-FIGMA-TOKEN", token),
            FigmaAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Lightweight connectivity probe for self-check.
    pub async fn health_check(&self) -> FigmaResult<()> {
        let url = format!("{}/me", self.base_url);
        let response = self
            .apply_auth(self.client.get(&url))
            .send()
            .await
            .map_err(FigmaError::Http)?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(FigmaError::Unauthorized);
        }
        if !status.is_success() {
            let mut body = response.text().await.unwrap_or_default();
            body.truncate(2048);
            return Err(FigmaError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            jitter_enabled: self.retry_config.jitter_enabled,
        };
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Team & project operations ─────────────────────────────────

    /// List projects within a team.
    #[instrument(skip(self))]
    pub async fn list_team_projects(&self, team_id: &str) -> FigmaResult<TeamProjectsResponse> {
        let team_id = sanitize_path_segment(team_id, "team_id")?;
        self.get_with_params::<TeamProjectsResponse>(&format!("teams/{team_id}/projects"), &[])
            .await
    }

    /// List files within a project.
    #[instrument(skip(self))]
    pub async fn list_project_files(&self, project_id: &str) -> FigmaResult<ProjectFilesResponse> {
        let project_id = sanitize_path_segment(project_id, "project_id")?;
        self.get_with_params::<ProjectFilesResponse>(&format!("projects/{project_id}/files"), &[])
            .await
    }

    // ── File operations ─────────────────────────────────────────

    /// Get a Figma file's document tree.
    #[instrument(skip(self))]
    pub async fn get_file(
        &self,
        file_key: &str,
        ids: Option<&str>,
        depth: Option<u32>,
        geometry: Option<&str>,
        plugin_data: Option<&str>,
    ) -> FigmaResult<FileResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(ids) = ids {
            params.push(("ids", ids.to_string()));
        }
        if let Some(depth) = depth {
            params.push(("depth", depth.to_string()));
        }
        if let Some(geometry) = geometry {
            params.push(("geometry", geometry.to_string()));
        }
        if let Some(plugin_data) = plugin_data {
            params.push(("plugin_data", plugin_data.to_string()));
        }

        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params(&format!("files/{file_key}"), &params)
            .await
    }

    /// Get specific nodes from a Figma file.
    #[instrument(skip(self))]
    pub async fn get_file_nodes(
        &self,
        file_key: &str,
        ids: &str,
        depth: Option<u32>,
    ) -> FigmaResult<FileNodesResponse> {
        let mut params = vec![("ids", ids.to_string())];
        if let Some(depth) = depth {
            params.push(("depth", depth.to_string()));
        }

        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params(&format!("files/{file_key}/nodes"), &params)
            .await
    }

    /// Get all components in a file.
    #[instrument(skip(self))]
    pub async fn get_file_components(&self, file_key: &str) -> FigmaResult<ComponentsResponse> {
        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params::<ComponentsResponse>(&format!("files/{file_key}/components"), &[])
            .await
    }

    /// Get all styles in a file.
    #[instrument(skip(self))]
    pub async fn get_file_styles(&self, file_key: &str) -> FigmaResult<StylesResponse> {
        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params::<StylesResponse>(&format!("files/{file_key}/styles"), &[])
            .await
    }

    // ── Image Export ────────────────────────────────────────────

    /// Export node(s) as images.
    #[instrument(skip(self))]
    pub async fn export_images(
        &self,
        file_key: &str,
        ids: &str,
        format: &str,
        scale: Option<f64>,
        svg_include_id: Option<bool>,
        svg_simplify_stroke: Option<bool>,
        use_absolute_bounds: Option<bool>,
    ) -> FigmaResult<ExportImagesResponse> {
        let mut params = vec![("ids", ids.to_string()), ("format", format.to_string())];
        if let Some(scale) = scale {
            params.push(("scale", scale.to_string()));
        }
        if let Some(v) = svg_include_id {
            params.push(("svg_include_id", v.to_string()));
        }
        if let Some(v) = svg_simplify_stroke {
            params.push(("svg_simplify_stroke", v.to_string()));
        }
        if let Some(v) = use_absolute_bounds {
            params.push(("use_absolute_bounds", v.to_string()));
        }

        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params(&format!("images/{file_key}"), &params)
            .await
    }

    // ── Version History ────────────────────────────────────────

    /// List version history for a file.
    #[instrument(skip(self))]
    pub async fn list_file_versions(&self, file_key: &str) -> FigmaResult<VersionsResponse> {
        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params::<VersionsResponse>(&format!("files/{file_key}/versions"), &[])
            .await
    }

    // ── Comment operations ─────────────────────────────────────

    /// List comments on a file.
    #[instrument(skip(self))]
    pub async fn list_comments(
        &self,
        file_key: &str,
        as_md: Option<bool>,
    ) -> FigmaResult<CommentsResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if as_md == Some(true) {
            params.push(("as_md", "true".to_string()));
        }

        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.get_with_params(&format!("files/{file_key}/comments"), &params)
            .await
    }

    /// Post a comment on a file.
    #[instrument(skip(self))]
    pub async fn post_comment(
        &self,
        file_key: &str,
        message: &str,
        comment_id: Option<&str>,
        client_meta: Option<serde_json::Value>,
    ) -> FigmaResult<Comment> {
        let body = PostCommentRequest {
            message: message.to_string(),
            comment_id: comment_id.map(String::from),
            client_meta,
        };

        let file_key = sanitize_path_segment(file_key, "file_key")?;
        self.post_json(&format!("files/{file_key}/comments"), &body)
            .await
    }

    /// Delete a comment from a file.
    #[instrument(skip(self))]
    pub async fn delete_comment(&self, file_key: &str, comment_id: &str) -> FigmaResult<()> {
        let file_key = sanitize_path_segment(file_key, "file_key")?;
        let comment_id = sanitize_path_segment(comment_id, "comment_id")?;
        self.delete(&format!("files/{file_key}/comments/{comment_id}"))
            .await
    }

    // ── Webhook operations ─────────────────────────────────────

    /// List webhooks for a team.
    #[instrument(skip(self))]
    pub async fn list_webhooks(&self, team_id: &str) -> FigmaResult<WebhooksListResponse> {
        // Webhooks use v2 API. The `../v2/` prefix is a deliberate version switch
        // relative to the v1 base; only the id is caller-controlled, so sanitize
        // it (not the literal prefix) to keep the version hop intact.
        let team_id = sanitize_path_segment(team_id, "team_id")?;
        let path = format!("../v2/webhooks/{team_id}");
        self.get_with_params(&path, &[]).await
    }

    /// Create a webhook.
    #[instrument(skip(self))]
    pub async fn create_webhook(
        &self,
        team_id: &str,
        event_type: &str,
        endpoint: &str,
        passcode: &str,
        description: Option<&str>,
    ) -> FigmaResult<Webhook> {
        let body = CreateWebhookRequest {
            team_id: team_id.to_string(),
            event_type: event_type.to_string(),
            endpoint: endpoint.to_string(),
            passcode: passcode.to_string(),
            description: description.map(String::from),
        };

        // Webhooks use v2 API
        self.post_json("../v2/webhooks", &body).await
    }

    /// Delete a webhook.
    #[instrument(skip(self))]
    pub async fn delete_webhook(&self, webhook_id: &str) -> FigmaResult<()> {
        // `../v2/` is a deliberate version switch; only the id is caller-controlled.
        let webhook_id = sanitize_path_segment(webhook_id, "webhook_id")?;
        self.delete(&format!("../v2/webhooks/{webhook_id}")).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> FigmaResult<T> {
        let mut url = format!("{}/{path}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.get(&url));
            async move { Self::execute_get_once::<T>(req, path).await }
        })
        .await
    }

    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> FigmaResult<T> {
        let url = format!("{}/{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.post(&url)).json(body);
            async move { Self::execute_post_once::<T>(req, path).await }
        })
        .await
    }

    async fn delete(&self, path: &str) -> FigmaResult<()> {
        let url = format!("{}/{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.delete(&url));
            async move { Self::execute_delete_once(req, path).await }
        })
        .await
    }

    async fn execute_get_once<T: serde::de::DeserializeOwned>(
        req: RequestBuilder,
        path: &str,
    ) -> AttemptOutcome<T, FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if status == StatusCode::NOT_FOUND {
                    return AttemptOutcome::Terminal(FigmaError::Api {
                        status: 404,
                        message: format!("Not found: {path}"),
                    });
                }
                if !status.is_success() {
                    let mut body = resp.text().await.unwrap_or_default();
                    body.truncate(2048);
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body,
                    };
                    return if status.is_server_error() {
                        AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    };
                }

                match resp.json::<T>().await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) => AttemptOutcome::Terminal(e.into()),
                }
            }
            Err(e) => {
                let err: FigmaError = e.into();
                if err.is_retryable() {
                    AttemptOutcome::Retryable {
                        retry_after: None,
                        error: err,
                    }
                } else {
                    AttemptOutcome::Terminal(err)
                }
            }
        }
    }

    /// Execute one POST attempt.
    ///
    /// br-kxd3e: NOT replay-safe. Both callers CREATE — a file comment and a
    /// webhook — and Figma offers no idempotency key, so a replay posts a
    /// second comment or registers a second webhook. Only the rate-limit arm
    /// (refused WITHOUT creating) and a connect-phase transport failure retry.
    /// A converging POST added later needs its own path.
    async fn execute_post_once<T: serde::de::DeserializeOwned>(
        req: RequestBuilder,
        _path: &str,
    ) -> AttemptOutcome<T, FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if !status.is_success() {
                    let mut body_text = resp.text().await.unwrap_or_default();
                    body_text.truncate(2048);
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body_text,
                    };
                    // A 5xx means Figma received the request and may already
                    // have created the comment or webhook.
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) => AttemptOutcome::Terminal(e.into()),
                }
            }
            Err(e) => {
                // Only a connect-phase failure proves the request never
                // reached Figma.
                let replayable = !transport_error_reached_service(&e);
                AttemptOutcome::retryable_if_replayable(e.into(), None, replayable)
            }
        }
    }

    async fn execute_delete_once(
        req: RequestBuilder,
        path: &str,
    ) -> AttemptOutcome<(), FigmaError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = FigmaError::RateLimited {
                        retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }

                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(FigmaError::Unauthorized);
                }
                if status == StatusCode::NOT_FOUND {
                    return AttemptOutcome::Terminal(FigmaError::Api {
                        status: 404,
                        message: format!("Not found: {path}"),
                    });
                }
                if !status.is_success() {
                    let mut body_text = resp.text().await.unwrap_or_default();
                    body_text.truncate(2048);
                    let err = FigmaError::Api {
                        status: status.as_u16(),
                        message: body_text,
                    };
                    return if status.is_server_error() {
                        AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    };
                }

                AttemptOutcome::Success(())
            }
            Err(e) => {
                let err: FigmaError = e.into();
                if err.is_retryable() {
                    AttemptOutcome::Retryable {
                        retry_after: None,
                        error: err,
                    }
                } else {
                    AttemptOutcome::Terminal(err)
                }
            }
        }
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_segment_accepts_opaque_ids() {
        assert_eq!(
            sanitize_path_segment("abc123DEF456", "file_key").unwrap(),
            "abc123DEF456"
        );
        assert_eq!(sanitize_path_segment("12345", "team_id").unwrap(), "12345");
        assert_eq!(
            sanitize_path_segment("  67890 ", "project_id").unwrap(),
            "67890"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("   ", "file_key").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("abc/../admin", "file_key").is_err());
        assert!(sanitize_path_segment("..", "team_id").is_err());
        assert!(sanitize_path_segment("a/b", "file_key").is_err());
        assert!(sanitize_path_segment("a\\b", "webhook_id").is_err());
        assert!(sanitize_path_segment("a%2Fb", "comment_id").is_err());
        assert!(sanitize_path_segment("a%5Cb", "comment_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_blocks_v2_version_escape() {
        // A file_key like "../v2/webhooks" must not let a v1 file operation hop
        // to the v2 webhook surface.
        assert!(sanitize_path_segment("../v2/webhooks", "file_key").is_err());
    }
}
