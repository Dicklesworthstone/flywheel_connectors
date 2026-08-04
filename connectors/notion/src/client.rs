//! Notion REST API client.

use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{NotionError, NotionResult},
    types::{ApiErrorResponse, Page, PaginatedResponse},
};

/// Default Notion API base URL.
pub const DEFAULT_API_URL: &str = "https://api.notion.com/v1";

/// Default Notion API version. Notion uses a date-based version header.
/// This can be overridden via the `config_override` parameter or
/// the `FCP_NOTION_API_VERSION` environment variable.
///
/// Verified against Notion's changes-by-version reference (latest version
/// `2026-03-11` as of March 25, 2026).
pub const DEFAULT_NOTION_VERSION: &str = "2026-03-11";
const MAX_PAGINATION_CURSOR_BYTES: usize = 512;

/// Truncate a response body string to `max` characters at a safe UTF-8 boundary.
fn truncate_body(body: String, max: usize) -> String {
    if body.len() <= max {
        return body;
    }
    // Find the last char boundary at or before `max` bytes
    let end = body
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    format!("{}...[truncated]", &body[..end])
}

fn is_valid_notion_version(version: &str) -> bool {
    if version.len() != 10 {
        return false;
    }

    let bytes = version.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }

    let year = version[0..4].parse::<u16>().ok();
    let month = version[5..7].parse::<u8>().ok();
    let day = version[8..10].parse::<u8>().ok();

    matches!((year, month, day), (Some(_), Some(1..=12), Some(1..=31)))
}

pub(crate) fn normalize_notion_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !is_valid_notion_version(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Resolve the Notion API version to use: config override > env var > compiled default.
fn resolve_notion_version(config_override: Option<&str>) -> String {
    if let Some(version) = config_override.and_then(normalize_notion_version) {
        return version;
    }
    if let Ok(version) = std::env::var("FCP_NOTION_API_VERSION")
        && let Some(version) = normalize_notion_version(&version)
    {
        return version;
    }
    DEFAULT_NOTION_VERSION.to_string()
}

/// Characters that are NOT percent-encoded in a path segment.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Characters that are dangerous in URLs: path separators, query string
/// markers, fragment markers, percent signs (double-encoding), ampersands,
/// equals signs, and whitespace.
const FORBIDDEN_ID_CHARS: &[char] = &[
    '/', '\\', '?', '#', '&', '=', '%', ' ', '\t', '\n', '\r', '\0',
];

/// Validate a Notion object ID. Rejects empty strings and strings containing
/// URL-active characters (slashes, query markers, fragments, ampersands,
/// percent signs) that could allow URL injection or path traversal.
fn validate_notion_id(id: &str, label: &str) -> NotionResult<()> {
    if id.is_empty() {
        return Err(NotionError::Validation {
            message: format!("{label} must not be empty"),
        });
    }
    if id.chars().any(|c| FORBIDDEN_ID_CHARS.contains(&c)) {
        return Err(NotionError::Validation {
            message: format!("{label} contains URL-unsafe characters: {id:?}"),
        });
    }
    Ok(())
}

fn validate_pagination_cursor(cursor: &str, label: &str) -> NotionResult<()> {
    if cursor.is_empty() {
        return Err(NotionError::Validation {
            message: format!("{label} must not be empty"),
        });
    }
    if cursor.len() > MAX_PAGINATION_CURSOR_BYTES {
        return Err(NotionError::Validation {
            message: format!(
                "{label} exceeds maximum length of {MAX_PAGINATION_CURSOR_BYTES} bytes"
            ),
        });
    }
    if cursor.chars().any(char::is_control) {
        return Err(NotionError::Validation {
            message: format!("{label} contains control characters"),
        });
    }
    Ok(())
}

/// Percent-encode a value for safe inclusion in a URL path segment.
fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

/// Authentication mode for the Notion connector.
#[derive(Clone)]
pub enum NotionAuth {
    /// Direct integration/OAuth token (Bearer auth).
    Token(String),
    /// Secretless mode – egress proxy injects credentials at runtime.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for NotionAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotionAuth").finish_non_exhaustive()
    }
}

impl NotionAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token:****",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (egress proxy).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Notion REST API client.
pub struct NotionClient {
    http: Client,
    api_url: String,
    notion_version: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    auth: NotionAuth,
}

impl std::fmt::Debug for NotionClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotionClient").finish_non_exhaustive()
    }
}

impl NotionClient {
    /// Create a new Notion client with a direct integration token.
    pub fn new(token: &str) -> NotionResult<Self> {
        Self::new_with_auth(NotionAuth::Token(token.to_string()))
    }

    /// Create a new Notion client with specified auth and optional API version override.
    pub fn new_with_version(
        auth: NotionAuth,
        version_override: Option<&str>,
    ) -> NotionResult<Self> {
        Self::build(auth, version_override)
    }

    /// Create a new Notion client with the specified auth mode.
    pub fn new_with_auth(auth: NotionAuth) -> NotionResult<Self> {
        Self::build(auth, None)
    }

    fn build(auth: NotionAuth, version_override: Option<&str>) -> NotionResult<Self> {
        let notion_version = resolve_notion_version(version_override);
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("Notion-Version", notion_version.parse().unwrap());

        match &auth {
            NotionAuth::Token(token) => {
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Bearer {token}")
                        .parse()
                        .map_err(|_| NotionError::Api {
                            message: "Invalid token value for header".into(),
                            status_code: None,
                        })?,
                );
            }
            NotionAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| NotionError::Api {
                        message: "Invalid credential_id value for header".into(),
                        status_code: None,
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-notion/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(NotionError::Http)?;

        Ok(Self {
            http,
            api_url: DEFAULT_API_URL.to_string(),
            notion_version,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
            auth,
        })
    }

    /// Lightweight connectivity probe – search with no query.
    pub async fn health_check(&self) -> NotionResult<()> {
        let url = format!("{}/search", self.api_url);
        let body = serde_json::json!({ "page_size": 1 });
        // `/search` with no query — read-only POST.
        self.post(&url, Some(body), true).await?;
        Ok(())
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the Notion API version header used for requests.
    #[must_use]
    pub fn notion_version(&self) -> &str {
        &self.notion_version
    }

    // ── Page operations ───────────────────────────────────────────

    /// Create a page.
    pub async fn create_page(&self, body: serde_json::Value) -> NotionResult<Page> {
        let url = format!("{}/pages", self.api_url);
        // NOT replay-safe: POST /pages creates a page.
        let data = self.post(&url, Some(body), false).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a page by ID.
    pub async fn get_page(&self, page_id: &str) -> NotionResult<Page> {
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Update a page (PATCH properties).
    pub async fn update_page(&self, page_id: &str, body: serde_json::Value) -> NotionResult<Page> {
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
        let data = self.patch(&url, body, true).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Archive (soft-delete) a page.
    pub async fn delete_page(&self, page_id: &str) -> NotionResult<Page> {
        validate_notion_id(page_id, "page_id")?;
        let seg = encode_path_segment(page_id);
        let url = format!("{}/pages/{seg}", self.api_url);
        let body = serde_json::json!({ "archived": true });
        let data = self.patch(&url, body, true).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Database operations ───────────────────────────────────────

    /// Query a database with optional filter and sorts.
    pub async fn query_database(
        &self,
        database_id: &str,
        filter: Option<serde_json::Value>,
        start_cursor: Option<&str>,
    ) -> NotionResult<PaginatedResponse> {
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}/query", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(f) = filter {
            body["filter"] = f;
        }
        if let Some(cursor) = start_cursor {
            validate_pagination_cursor(cursor, "start_cursor")?;
            body["start_cursor"] = serde_json::Value::String(cursor.into());
        }
        // Read-only POST: Notion models database query this way.
        let data = self.post(&url, Some(body), true).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a database by ID.
    pub async fn get_database(&self, database_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}", self.api_url);
        self.get(&url).await
    }

    /// Create a database.
    pub async fn create_database(
        &self,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        let url = format!("{}/databases", self.api_url);
        // NOT replay-safe: POST /databases creates a database.
        self.post(&url, Some(body), false).await
    }

    /// Update a database (PATCH title/properties/description).
    pub async fn update_database(
        &self,
        database_id: &str,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        validate_notion_id(database_id, "database_id")?;
        let seg = encode_path_segment(database_id);
        let url = format!("{}/databases/{seg}", self.api_url);
        self.patch(&url, body, true).await
    }

    // ── Search ────────────────────────────────────────────────────

    /// Search pages and databases.
    pub async fn search(
        &self,
        query: Option<&str>,
        filter: Option<serde_json::Value>,
    ) -> NotionResult<PaginatedResponse> {
        let url = format!("{}/search", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(q) = query {
            body["query"] = serde_json::Value::String(q.into());
        }
        if let Some(f) = filter {
            body["filter"] = f;
        }
        // `/search` is a read-only POST.
        let data = self.post(&url, Some(body), true).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Block operations ──────────────────────────────────────────

    /// Get child blocks of a block or page.
    pub async fn get_block_children(&self, block_id: &str) -> NotionResult<PaginatedResponse> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}/children", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a single block by ID.
    pub async fn get_block(&self, block_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        self.get(&url).await
    }

    /// Update a block's content.
    pub async fn update_block(
        &self,
        block_id: &str,
        body: serde_json::Value,
    ) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        self.patch(&url, body, true).await
    }

    /// Archive (soft-delete) a block.
    pub async fn delete_block(&self, block_id: &str) -> NotionResult<serde_json::Value> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}", self.api_url);
        let body = serde_json::json!({ "archived": true });
        self.patch(&url, body, true).await
    }

    /// Append child blocks to a page or block.
    pub async fn append_blocks(
        &self,
        block_id: &str,
        children: serde_json::Value,
    ) -> NotionResult<PaginatedResponse> {
        validate_notion_id(block_id, "block_id")?;
        let seg = encode_path_segment(block_id);
        let url = format!("{}/blocks/{seg}/children", self.api_url);
        let body = serde_json::json!({ "children": children });
        // NOT replay-safe: PATCH /blocks/{id}/children APPENDS —
        // a PATCH that is not idempotent. Replaying adds the blocks twice.
        let data = self.patch(&url, body, false).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Comment operations ────────────────────────────────────────

    /// Add a comment to a page.
    pub async fn add_comment(&self, body: serde_json::Value) -> NotionResult<serde_json::Value> {
        let url = format!("{}/comments", self.api_url);
        // NOT replay-safe: POST /comments creates a comment.
        self.post(&url, Some(body), false).await
    }

    /// List comments on a block or page.
    pub async fn list_comments(&self, block_id: &str) -> NotionResult<PaginatedResponse> {
        validate_notion_id(block_id, "block_id")?;
        let encoded_id = utf8_percent_encode(block_id, PATH_SEGMENT_ENCODE_SET).to_string();
        let url = format!("{}/comments?block_id={encoded_id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> NotionResult<serde_json::Value> {
        self.execute(|| self.http.get(url), true).await
    }

    /// POST with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). Notion has no idempotency key, and it models
    /// several READ-ONLY operations as POSTs (`/search`, `/databases/{id}/
    /// query`), so the verb decides nothing here in either direction.
    async fn post(
        &self,
        url: &str,
        body: Option<serde_json::Value>,
        replay_safe: bool,
    ) -> NotionResult<serde_json::Value> {
        self.execute(
            || {
                let mut req = self.http.post(url);
                if let Some(b) = &body {
                    req = req.json(b);
                }
                req
            },
            replay_safe,
        )
        .await
    }

    /// PATCH with retry.
    ///
    /// `replay_safe` is required rather than assumed: most Notion PATCHes set
    /// named properties and converge, but `PATCH /blocks/{id}/children`
    /// APPENDS, so replaying it adds the blocks a second time.
    async fn patch(
        &self,
        url: &str,
        body: serde_json::Value,
        replay_safe: bool,
    ) -> NotionResult<serde_json::Value> {
        self.execute(|| self.http.patch(url).json(&body), replay_safe)
            .await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> NotionResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = build_request();
            async move {
                debug!(attempt, "Notion API request");

                match request.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(NotionError::Unauthorized);
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            let body = truncate_body(body, 500);
                            return AttemptOutcome::Terminal(NotionError::NotFound {
                                resource: body,
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after_secs = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            let retry_after = retry_after_secs
                                .map_or(Duration::from_secs(60), Duration::from_secs);

                            return AttemptOutcome::Retryable {
                                error: NotionError::RateLimited {
                                    retry_after_ms: retry_after.as_millis() as u64,
                                },
                                retry_after: Some(retry_after),
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            let body = truncate_body(body, 500);
                            // br-kxd3e: a 5xx means Notion RECEIVED the
                            // request and may already have created the page,
                            // database, comment, or appended the blocks. The
                            // 429 arm above stays ahead of this one because a
                            // rate limit was refused WITHOUT executing.
                            return AttemptOutcome::retryable_if_replayable(
                                NotionError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                },
                                None,
                                replay_safe,
                            );
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let body = truncate_body(body, 500);
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.message.clone())
                                .unwrap_or(format!("HTTP {status}: {body}"));
                            return AttemptOutcome::Terminal(NotionError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(error) => AttemptOutcome::Terminal(NotionError::Json(error)),
                            },
                            // A body-read failure lands after the request was
                            // fully sent, so it is never proof of non-delivery.
                            Err(error) => AttemptOutcome::retryable_if_replayable(
                                NotionError::Http(error),
                                None,
                                replay_safe,
                            ),
                        }
                    }
                    // br-kxd3e: `is_timeout()` is the TOTAL request timeout and
                    // fires after the body was written; only a connect-phase
                    // failure proves Notion never saw the request.
                    Err(error) => {
                        let replayable = replay_safe || !transport_error_reached_service(&error);
                        AttemptOutcome::retryable_if_replayable(
                            NotionError::Http(error),
                            None,
                            replayable,
                        )
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

    #[test]
    fn test_default_notion_version_value() {
        assert_eq!(DEFAULT_NOTION_VERSION, "2026-03-11");
    }

    #[test]
    fn test_normalize_notion_version_rejects_malformed_values() {
        assert_eq!(normalize_notion_version("2026-3-11"), None);
        assert_eq!(normalize_notion_version("2026/03/11"), None);
        assert_eq!(normalize_notion_version("2026-13-11"), None);
    }

    #[test]
    fn test_new_with_version_override() {
        let client = NotionClient::new_with_version(
            NotionAuth::Token("test-token".into()),
            Some("2025-09-03"),
        )
        .unwrap();
        assert_eq!(client.notion_version(), "2025-09-03");
    }

    // ─── URL injection prevention tests ──────────────────────────────

    #[test]
    fn test_validate_notion_id_valid_uuid() {
        assert!(validate_notion_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "page_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_no_hyphens() {
        assert!(validate_notion_id("a1b2c3d4e5f67890abcdef1234567890", "page_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_short_name() {
        // Notion test IDs like "page-1", "block-1", "db-1" are valid
        assert!(validate_notion_id("page-1", "page_id").is_ok());
        assert!(validate_notion_id("block-1", "block_id").is_ok());
        assert!(validate_notion_id("db-1", "database_id").is_ok());
    }

    #[test]
    fn test_validate_notion_id_rejects_empty() {
        let result = validate_notion_id("", "page_id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[test]
    fn test_validate_notion_id_rejects_slashes() {
        let result = validate_notion_id("../../etc/passwd", "block_id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[test]
    fn test_validate_notion_id_rejects_query_injection() {
        let result = validate_notion_id("abc?admin=true", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_spaces() {
        let result = validate_notion_id("abc def", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_hash_fragment() {
        let result = validate_notion_id("abc#fragment", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_ampersand() {
        let result = validate_notion_id("abc&other=1", "block_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_percent_encoding() {
        let result = validate_notion_id("abc%2F..%2Fetc", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_backslash() {
        let result = validate_notion_id("abc\\def", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notion_id_rejects_null_byte() {
        let result = validate_notion_id("abc\0def", "page_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_path_segment_safe_chars() {
        let encoded = encode_path_segment("a1b2c3d4-e5f6-7890");
        assert_eq!(encoded, "a1b2c3d4-e5f6-7890");
    }

    #[test]
    fn test_encode_path_segment_special_chars() {
        let encoded = encode_path_segment("abc?foo=bar&x=1");
        assert!(encoded.contains("%3F"));
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn test_encode_path_segment_slash() {
        let encoded = encode_path_segment("../../etc");
        assert!(encoded.contains("%2F"));
        assert!(!encoded.contains('/'));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_page_rejects_path_traversal() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.get_page("../../admin").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_block_rejects_query_injection() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.get_block("abc?admin=true").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments_rejects_injection() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.list_comments("abc&admin=true").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_database_rejects_empty_id() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client.query_database("", None, None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_database_rejects_control_chars_in_cursor() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");

        let result = client
            .query_database("db-1", None, Some("cursor\nnext"))
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_query_database_rejects_oversized_cursor() {
        let client = NotionClient::new("test-token")
            .unwrap()
            .with_api_url("http://localhost:1234/v1");
        let cursor = "a".repeat(MAX_PAGINATION_CURSOR_BYTES + 1);

        let result = client
            .query_database("db-1", None, Some(cursor.as_str()))
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NotionError::Validation { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = NotionError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = NotionError::Unauthorized;
        assert!(!err.is_retryable());

        let err = NotionError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
