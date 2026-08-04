//! Elasticsearch API client.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{ElasticsearchError, ElasticsearchResult},
    types::ApiErrorResponse,
};

/// Default Elasticsearch Cloud base URL (placeholder — must be configured).
pub const DEFAULT_BASE_URL: &str = "https://localhost:9200";

/// Validate that a value is safe to embed as a URL path segment.
///
/// Rejects empty/whitespace-only strings and strings containing path traversal
/// characters (`/`, `\`, `..`, `%2f`, `%5c`).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> ElasticsearchResult<&'a str> {
    if value.trim().is_empty() {
        return Err(ElasticsearchError::InvalidInput(format!(
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
        return Err(ElasticsearchError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Authentication mode for the Elasticsearch API.
#[derive(Clone)]
pub enum ElasticsearchAuth {
    /// API key (base64-encoded `id:api_key`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl ElasticsearchAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for ElasticsearchAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Elasticsearch API client.
pub struct ElasticsearchClient {
    client: Client,
    auth: ElasticsearchAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for ElasticsearchClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticsearchClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ElasticsearchClient {
    /// Create a new Elasticsearch client.
    pub fn new(auth: ElasticsearchAuth, base_url: Option<&str>) -> ElasticsearchResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-elasticsearch/0.1.0")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: ElasticsearchAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Gracefully shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            ElasticsearchAuth::ApiKey(key) => req.header("Authorization", format!("ApiKey {key}")),
            ElasticsearchAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> ElasticsearchResult<serde_json::Value> {
        let status = resp.status();

        if status.is_success() {
            let body = resp.text().await?;
            if status == StatusCode::NO_CONTENT {
                return Ok(serde_json::json!({}));
            }
            if body.trim().is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> ElasticsearchResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.reason)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(ElasticsearchError::Unauthorized),
            403 => Err(ElasticsearchError::Forbidden),
            404 => Err(ElasticsearchError::NotFound { resource: detail }),
            429 => Err(ElasticsearchError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(ElasticsearchError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Issue a request with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It cannot be derived from `http_method` here,
    /// because Elasticsearch uses POST for BOTH `_search` (a pure read) and
    /// `_doc` without an id (which mints a new document id server-side).
    async fn request_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        replay_safe: bool,
    ) -> ElasticsearchResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "elasticsearch request");

            let req = match http_method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "DELETE" => self.client.delete(url),
                _ => unreachable!(),
            };
            let req = if let Some(b) = body { req.json(b) } else { req };
            let req = self.add_auth(req);

            match req.send().await {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(val) => AttemptOutcome::Success(val),
                    Err(err) if err.is_retryable() => {
                        // 429 stays retryable — Elasticsearch rejected the
                        // request WITHOUT indexing. A 5xx did reach it.
                        let replayable = replay_safe || err.replay_is_safe();
                        let retry_after = err.retry_after();
                        AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                    }
                    Err(err) => AttemptOutcome::Terminal(err),
                },
                Err(err) => {
                    let replayable = replay_safe || !transport_error_reached_service(&err);
                    AttemptOutcome::retryable_if_replayable(
                        ElasticsearchError::Http(err),
                        None,
                        replayable,
                    )
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None, true).await
    }

    #[instrument(skip(self, body), fields(url))]
    /// POST with retry.
    ///
    /// br-kxd3e: fail-closed, because `_doc` without an id mints a new
    /// document id server-side and a replay indexes the document TWICE.
    /// `_search` uses [`Self::post_replay_safe`].
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body), false)
            .await
    }

    /// POST whose replay cannot duplicate a side effect.
    ///
    /// Elasticsearch models search as a POST because the query travels in the
    /// body; it indexes nothing.
    async fn post_replay_safe(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body), true)
            .await
    }

    #[instrument(skip(self, body), fields(url))]
    /// POST an ndjson body (the `_bulk` API).
    ///
    /// br-kxd3e: NOT replay-safe. A bulk body whose actions omit document ids
    /// indexes new documents, so a replay indexes them a second time. Bulk
    /// actions that DO carry ids would be idempotent, but the body is opaque
    /// here, so this fails closed.
    async fn post_ndjson(&self, path: &str, body: &str) -> ElasticsearchResult<serde_json::Value> {
        let replay_safe = false;
        let url_owned = format!("{}{path}", self.base_url);
        let url: &str = &url_owned;
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(
                attempt,
                method = "POST",
                url,
                "elasticsearch ndjson request"
            );

            let req = self
                .client
                .post(url)
                .header("Content-Type", "application/x-ndjson")
                .body(body.to_string());
            let req = self.add_auth(req);

            match req.send().await {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(val) => AttemptOutcome::Success(val),
                    Err(err) if err.is_retryable() => {
                        // 429 stays retryable — Elasticsearch rejected the
                        // request WITHOUT indexing. A 5xx did reach it.
                        let replayable = replay_safe || err.replay_is_safe();
                        let retry_after = err.retry_after();
                        AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                    }
                    Err(err) => AttemptOutcome::Terminal(err),
                },
                Err(err) => {
                    let replayable = replay_safe || !transport_error_reached_service(&err);
                    AttemptOutcome::retryable_if_replayable(
                        ElasticsearchError::Http(err),
                        None,
                        replayable,
                    )
                }
            }
        })
        .await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        // PUT indexes at a caller-chosen id, so a replay overwrites rather
        // than duplicating.
        self.request_with_retry("PUT", &url, Some(body), true).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> ElasticsearchResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("DELETE", &url, None, true).await
    }

    // -- Search --

    /// Search documents.
    pub async fn search(
        &self,
        index: &str,
        query: Option<&serde_json::Value>,
        size: Option<i64>,
        from: Option<i64>,
        sort: Option<&serde_json::Value>,
    ) -> ElasticsearchResult<serde_json::Value> {
        let index = sanitize_path_segment(index, "index")?;
        let mut body = serde_json::json!({});
        if let Some(q) = query {
            body["query"] = q.clone();
        }
        if let Some(s) = size {
            body["size"] = serde_json::json!(s);
        }
        if let Some(f) = from {
            body["from"] = serde_json::json!(f);
        }
        if let Some(s) = sort {
            body["sort"] = s.clone();
        }
        self.post_replay_safe(&format!("/{index}/_search"), &body)
            .await
    }

    /// Get a document by ID.
    pub async fn get_document(
        &self,
        index: &str,
        document_id: &str,
    ) -> ElasticsearchResult<serde_json::Value> {
        let index = sanitize_path_segment(index, "index")?;
        let document_id = sanitize_path_segment(document_id, "document_id")?;
        self.get(&format!("/{index}/_doc/{document_id}")).await
    }

    // -- Indexing --

    /// Index (create or update) a document.
    pub async fn index_document(
        &self,
        index: &str,
        document_id: Option<&str>,
        document: &serde_json::Value,
    ) -> ElasticsearchResult<serde_json::Value> {
        let index = sanitize_path_segment(index, "index")?;
        match document_id {
            Some(id) => {
                let id = sanitize_path_segment(id, "document_id")?;
                self.put(&format!("/{index}/_doc/{id}"), document).await
            }
            None => self.post(&format!("/{index}/_doc"), document).await,
        }
    }

    /// Bulk operations.
    pub async fn bulk(
        &self,
        operations: &[serde_json::Value],
    ) -> ElasticsearchResult<serde_json::Value> {
        let mut ndjson = String::new();
        for op in operations {
            ndjson.push_str(&serde_json::to_string(op)?);
            ndjson.push('\n');
        }
        self.post_ndjson("/_bulk", &ndjson).await
    }

    // -- Indices --

    /// List indices.
    pub async fn list_indices(
        &self,
        pattern: Option<&str>,
    ) -> ElasticsearchResult<serde_json::Value> {
        let idx = pattern.unwrap_or("*");
        let idx = sanitize_path_segment(idx, "pattern")?;
        self.get(&format!("/_cat/indices/{idx}?format=json")).await
    }

    /// Delete an index.
    pub async fn delete_index(&self, index: &str) -> ElasticsearchResult<serde_json::Value> {
        let index = sanitize_path_segment(index, "index")?;
        self.delete(&format!("/{index}")).await
    }

    // -- Cluster --

    /// Get cluster health.
    pub async fn cluster_health(&self) -> ElasticsearchResult<serde_json::Value> {
        self.get("/_cluster/health").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = ElasticsearchAuth::ApiKey("base64secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("base64secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let api_key = ElasticsearchAuth::ApiKey("key".into());
        assert!(!api_key.is_secretless());

        let cred = ElasticsearchAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let api_key = ElasticsearchAuth::ApiKey("key".into());
        assert_eq!(api_key.redacted_label(), "api_key:redacted");

        let cred = ElasticsearchAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_redacted_label_credential_id_no_redacted() {
        let cred = ElasticsearchAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(!label.contains("redacted"));
    }

    #[test]
    fn auth_debug_credential_id_shows_id() {
        let id = CredentialId::new();
        let auth = ElasticsearchAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id.to_string()));
    }

    #[test]
    fn auth_debug_apikey_does_not_leak() {
        let auth = ElasticsearchAuth::ApiKey("super-secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret-api-key-12345"));
        assert!(dbg.contains("ApiKey"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn auth_clone() {
        let auth = ElasticsearchAuth::ApiKey("key".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "api_key:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn client_new_default_url() {
        let client = ElasticsearchClient::new(ElasticsearchAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = ElasticsearchClient::new(
            ElasticsearchAuth::ApiKey("k".into()),
            Some("https://my-es.example.com:9243"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://my-es.example.com:9243"));
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = ElasticsearchClient::new(
            ElasticsearchAuth::ApiKey("k".into()),
            Some("https://example.com/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://example.com"));
        assert!(!dbg.contains("https://example.com/\""));
    }

    #[test]
    fn client_new_trims_multiple_trailing_slashes() {
        let client = ElasticsearchClient::new(
            ElasticsearchAuth::ApiKey("k".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("///"));
    }

    #[test]
    fn client_debug_shows_struct() {
        let client = ElasticsearchClient::new(ElasticsearchAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("ElasticsearchClient"));
        assert!(dbg.contains("auth"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_debug_redacts_auth() {
        let client =
            ElasticsearchClient::new(ElasticsearchAuth::ApiKey("my-secret-key".into()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://localhost:9200");
    }

    #[test]
    fn client_with_credential_id_auth() {
        let client =
            ElasticsearchClient::new(ElasticsearchAuth::CredentialId(CredentialId::new()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_with_client_trims_trailing_slash() {
        let http_client = Client::new();
        let client = ElasticsearchClient::with_client(
            http_client,
            ElasticsearchAuth::ApiKey("k".into()),
            "https://es.example.com/",
        );
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://es.example.com"));
        assert!(!dbg.contains("https://es.example.com/\""));
    }

    #[test]
    fn client_with_client_preserves_base_url() {
        let http_client = Client::new();
        let client = ElasticsearchClient::with_client(
            http_client,
            ElasticsearchAuth::ApiKey("k".into()),
            "https://custom-es:9200",
        );
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://custom-es:9200"));
    }

    // ── sanitize_path_segment ──────────────────────────────────────

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        assert!(sanitize_path_segment("foo/bar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        assert!(sanitize_path_segment("foo\\bar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        assert!(sanitize_path_segment("../admin", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        assert!(sanitize_path_segment("foo%2fbar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash_upper() {
        assert!(sanitize_path_segment("foo%5Cbar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash_lower() {
        assert!(sanitize_path_segment("foo%5cbar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        assert!(sanitize_path_segment("  ", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid_index() {
        assert_eq!(
            sanitize_path_segment("my-index-2024", "index").unwrap(),
            "my-index-2024"
        );
    }

    #[test]
    fn sanitize_path_segment_accepts_valid_document_id() {
        assert_eq!(
            sanitize_path_segment("doc_abc-123", "document_id").unwrap(),
            "doc_abc-123"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash_upper() {
        assert!(sanitize_path_segment("foo%2Fbar", "index").is_err());
    }

    #[test]
    fn sanitize_path_segment_error_message_contains_field() {
        let err = sanitize_path_segment("a/b", "index").unwrap_err();
        assert!(err.to_string().contains("index"));
    }

    #[test]
    fn sanitize_path_segment_empty_error_contains_field() {
        let err = sanitize_path_segment("", "document_id").unwrap_err();
        assert!(err.to_string().contains("document_id"));
    }
}
