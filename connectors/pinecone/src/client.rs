//! Pinecone REST API client.
//!
//! Pinecone uses two API planes:
//! - Control plane (`https://api.pinecone.io`) for index management
//! - Data plane (`https://{index-host}`) for vector operations

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{PineconeError, PineconeResult},
    types::{
        ApiErrorResponse, FetchResponse, Index, IndexStats, ListIndexesResponse, QueryResponse,
        UpsertResponse, Vector,
    },
};

/// Default Pinecone control plane URL.
pub const DEFAULT_CONTROL_PLANE_URL: &str = "https://api.pinecone.io";

/// Validate a path segment to prevent path traversal and query/fragment
/// injection. Pinecone index names are `[a-z0-9-]`-shaped, so rejecting slashes,
/// any `..` substring, encoded slashes, and URL delimiters (`?`/`#`/`&`/`=`/`%`)
/// never trips a legitimate name while stopping `x?y` (wrong-endpoint via query
/// injection) and `..%2f..`.
fn sanitize_path_segment(segment: &str) -> PineconeResult<&str> {
    if segment.trim().is_empty()
        || segment == "."
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment.contains("..")
        || segment.contains('?')
        || segment.contains('#')
        || segment.contains('&')
        || segment.contains('=')
        || segment.contains('%')
    {
        return Err(PineconeError::InvalidInput(format!(
            "Invalid path segment: {segment}"
        )));
    }
    Ok(segment)
}

/// Authentication mode for Pinecone.
#[derive(Clone)]
pub enum PineconeAuth {
    /// Direct API key.
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl PineconeAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(key) => {
                let prefix = if key.len() > 8 {
                    &key[..8]
                } else {
                    key.as_str()
                };
                format!("api_key:{prefix}***")
            }
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for PineconeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f
                .debug_struct("ApiKey")
                .field("key", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Pinecone REST API client.
pub struct PineconeClient {
    http: Client,
    auth: PineconeAuth,
    control_plane_url: String,
    data_plane_url: Option<String>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for PineconeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PineconeClient")
            .field("auth", &self.auth)
            .field("control_plane_url", &self.control_plane_url)
            .field("data_plane_url", &self.data_plane_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl PineconeClient {
    /// Create a new Pinecone client with an API key.
    pub fn new(api_key: &str) -> PineconeResult<Self> {
        Self::new_with_auth(PineconeAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new Pinecone client with explicit auth mode.
    pub fn new_with_auth(auth: PineconeAuth) -> PineconeResult<Self> {
        let mut headers = header::HeaderMap::new();
        match &auth {
            PineconeAuth::ApiKey(key) => {
                headers.insert(
                    "Api-Key",
                    key.parse().map_err(|_| {
                        PineconeError::InvalidConfig("Invalid API key format".into())
                    })?,
                );
            }
            PineconeAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| {
                        PineconeError::InvalidConfig("Invalid credential ID format".into())
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-pinecone/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(PineconeError::Http)?;

        Ok(Self {
            http,
            auth,
            control_plane_url: DEFAULT_CONTROL_PLANE_URL.to_string(),
            data_plane_url: None,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Perform a lightweight health check (list indexes).
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn health_check(&self) -> PineconeResult<()> {
        let _ = self.list_indexes().await?;
        Ok(())
    }

    /// Set a custom control plane URL (for testing).
    #[must_use]
    pub fn with_control_plane_url(mut self, url: &str) -> Self {
        self.control_plane_url = url.to_string();
        self
    }

    /// Set a custom data plane URL (for testing or when index host is known).
    #[must_use]
    pub fn with_data_plane_url(mut self, url: &str) -> Self {
        self.data_plane_url = Some(url.to_string());
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..HttpRetryConfig::default()
        };
        self
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn data_plane_base(&self) -> PineconeResult<&str> {
        self.data_plane_url.as_deref().ok_or_else(|| {
            PineconeError::InvalidConfig(
                "Data plane URL not configured. Call describe_index first or set data_plane_url."
                    .into(),
            )
        })
    }

    // ── Control plane operations ──────────────────────────────────

    /// List all indexes.
    pub async fn list_indexes(&self) -> PineconeResult<ListIndexesResponse> {
        let url = format!("{}/indexes", self.control_plane_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Describe a specific index.
    pub async fn describe_index(&self, index_name: &str) -> PineconeResult<Index> {
        let index_name = sanitize_path_segment(index_name)?;
        let url = format!("{}/indexes/{index_name}", self.control_plane_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a new index.
    pub async fn create_index(
        &self,
        name: &str,
        dimension: u32,
        metric: &str,
        spec: Option<&serde_json::Value>,
    ) -> PineconeResult<Index> {
        sanitize_path_segment(name)?;
        let url = format!("{}/indexes", self.control_plane_url);
        let mut body = serde_json::json!({
            "name": name,
            "dimension": dimension,
            "metric": metric,
        });
        if let Some(s) = spec {
            body["spec"] = s.clone();
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Delete an index by name.
    pub async fn delete_index(&self, index_name: &str) -> PineconeResult<()> {
        let index_name = sanitize_path_segment(index_name)?;
        let url = format!("{}/indexes/{index_name}", self.control_plane_url);
        self.execute_delete(&url).await?;
        Ok(())
    }

    // ── Data plane operations ─────────────────────────────────────

    /// Get index statistics.
    pub async fn describe_index_stats(
        &self,
        filter: Option<&serde_json::Value>,
    ) -> PineconeResult<IndexStats> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/describe_index_stats");
        let body = match filter {
            Some(f) => serde_json::json!({ "filter": f }),
            None => serde_json::json!({}),
        };
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Query vectors by similarity.
    pub async fn query(
        &self,
        vector: Option<&[f32]>,
        id: Option<&str>,
        top_k: u32,
        namespace: Option<&str>,
        filter: Option<&serde_json::Value>,
        include_metadata: bool,
        include_values: bool,
    ) -> PineconeResult<QueryResponse> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/query");
        let mut body = serde_json::json!({
            "topK": top_k,
            "includeMetadata": include_metadata,
            "includeValues": include_values,
        });
        if let Some(v) = vector {
            body["vector"] = serde_json::to_value(v).unwrap_or_default();
        }
        if let Some(i) = id {
            body["id"] = serde_json::Value::String(i.to_string());
        }
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        if let Some(f) = filter {
            body["filter"] = f.clone();
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fetch vectors by ID.
    ///
    /// Uses reqwest `.query()` for proper URL encoding of IDs and namespace.
    pub async fn fetch(
        &self,
        ids: &[String],
        namespace: Option<&str>,
    ) -> PineconeResult<FetchResponse> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/vectors/fetch");
        let mut query_params: Vec<(&str, &str)> = Vec::new();
        for id in ids {
            query_params.push(("ids", id.as_str()));
        }
        if let Some(ns) = namespace {
            query_params.push(("namespace", ns));
        }
        let data = self.get_with_query(&url, &query_params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Upsert vectors.
    pub async fn upsert(
        &self,
        vectors: &[Vector],
        namespace: Option<&str>,
    ) -> PineconeResult<UpsertResponse> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/vectors/upsert");
        let mut body = serde_json::json!({ "vectors": vectors });
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Delete vectors.
    pub async fn delete(
        &self,
        ids: Option<&[String]>,
        delete_all: bool,
        namespace: Option<&str>,
        filter: Option<&serde_json::Value>,
    ) -> PineconeResult<serde_json::Value> {
        let base = self.data_plane_base()?;
        let url = format!("{base}/vectors/delete");
        let mut body = serde_json::json!({});
        if let Some(i) = ids {
            body["ids"] = serde_json::to_value(i).unwrap_or_default();
        }
        if delete_all {
            body["deleteAll"] = serde_json::Value::Bool(true);
        }
        if let Some(ns) = namespace {
            body["namespace"] = serde_json::Value::String(ns.to_string());
        }
        if let Some(f) = filter {
            body["filter"] = f.clone();
        }
        self.post_json(&url, &body).await
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn get_with_query(
        &self,
        url: &str,
        query: &[(&str, &str)],
    ) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.get(url).query(query)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn execute_delete(&self, url: &str) -> PineconeResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> PineconeResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let req = build_request();
            async move {
                debug!(attempt, "Pinecone request");
                let result = req.send().await;

                match result {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(PineconeError::Api {
                                message: format!("Authentication failed: {body}"),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(PineconeError::Api {
                                message: format!("Not found: {body}"),
                                status_code: Some(404),
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .map_or(60_000, |s| s * 1000);
                            return AttemptOutcome::Retryable {
                                error: PineconeError::RateLimit {
                                    retry_after_ms: retry_after,
                                },
                                retry_after: Some(Duration::from_millis(retry_after)),
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Retryable {
                                error: PineconeError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                },
                                retry_after: None,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| {
                                    e.message.clone().or_else(|| {
                                        e.error.as_ref().and_then(|d| d.message.clone())
                                    })
                                })
                                .unwrap_or_else(|| format!("HTTP {status}: {body}"));
                            return AttemptOutcome::Terminal(PineconeError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        let body = match response.text().await {
                            Ok(b) => b,
                            Err(e) => return AttemptOutcome::Terminal(PineconeError::Http(e)),
                        };
                        if body.is_empty() {
                            return AttemptOutcome::Success(serde_json::json!({}));
                        }
                        match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(PineconeError::from(e)),
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: PineconeError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(PineconeError::Http(e)),
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
    fn test_error_is_retryable() {
        let err = PineconeError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = PineconeError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = PineconeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = PineconeError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_data_plane_url_required() {
        let client = PineconeClient::new("test-api-key").unwrap();
        assert!(client.data_plane_base().is_err());
    }

    // ── PineconeAuth tests ──────────────────────────────────────────────

    #[test]
    fn auth_api_key_redacted_label_short_key() {
        let auth = PineconeAuth::ApiKey("abc".into());
        let label = auth.redacted_label();
        assert!(label.starts_with("api_key:"), "got: {label}");
        assert!(label.contains("abc"), "got: {label}");
    }

    #[test]
    fn auth_api_key_redacted_label_long_key() {
        let auth = PineconeAuth::ApiKey("pcsk_1234567890abcdef".into());
        let label = auth.redacted_label();
        assert!(label.starts_with("api_key:pcsk_123"), "got: {label}");
        assert!(label.ends_with("***"), "got: {label}");
        assert!(!label.contains("abcdef"), "should be truncated: {label}");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = PineconeAuth::CredentialId(cid);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"), "got: {label}");
    }

    #[test]
    fn auth_api_key_is_not_secretless() {
        let auth = PineconeAuth::ApiKey("key".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = PineconeAuth::CredentialId(cid);
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_api_key_debug_redacts() {
        let auth = PineconeAuth::ApiKey("super_secret_key_dont_show".into());
        let debug = format!("{auth:?}");
        assert!(debug.contains("<redacted>"), "debug: {debug}");
        assert!(
            !debug.contains("super_secret_key_dont_show"),
            "key should be redacted: {debug}"
        );
    }

    #[test]
    fn auth_credential_id_debug() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let auth = PineconeAuth::CredentialId(cid);
        let debug = format!("{auth:?}");
        assert!(debug.contains("CredentialId"), "debug: {debug}");
    }

    #[test]
    fn auth_clone_api_key() {
        let original = PineconeAuth::ApiKey("key_clone".into());
        let cloned = original.clone();
        drop(original);
        assert!(!cloned.is_secretless());
        assert!(cloned.redacted_label().contains("key_clon"));
    }

    #[test]
    fn auth_clone_credential_id() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let original = PineconeAuth::CredentialId(cid);
        let cloned = original.clone();
        drop(original);
        assert!(cloned.is_secretless());
    }

    // ── PineconeClient construction tests ───────────────────────────────

    #[test]
    fn client_new_creates_with_defaults() {
        let client = PineconeClient::new("test-key-123").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("PineconeClient"), "debug: {debug}");
    }

    #[test]
    fn client_with_control_plane_url() {
        let client = PineconeClient::new("key")
            .unwrap()
            .with_control_plane_url("http://custom-control.io");
        let debug = format!("{client:?}");
        assert!(debug.contains("http://custom-control.io"), "debug: {debug}");
    }

    #[test]
    fn client_with_data_plane_url() {
        let client = PineconeClient::new("key")
            .unwrap()
            .with_data_plane_url("http://custom-data.io");
        let debug = format!("{client:?}");
        assert!(debug.contains("http://custom-data.io"), "debug: {debug}");
    }

    #[test]
    fn client_with_retry_config() {
        let client = PineconeClient::new("key").unwrap().with_retry_config(5);
        let debug = format!("{client:?}");
        assert!(debug.contains("PineconeClient"), "debug: {debug}");
    }

    #[test]
    fn client_debug_format_shows_fields() {
        let client = PineconeClient::new("key")
            .unwrap()
            .with_control_plane_url("http://cp.io")
            .with_data_plane_url("http://dp.io");
        let debug = format!("{client:?}");
        assert!(debug.contains("http://cp.io"), "debug: {debug}");
        assert!(debug.contains("http://dp.io"), "debug: {debug}");
    }

    #[test]
    fn client_data_plane_base_after_set() {
        let client = PineconeClient::new("key")
            .unwrap()
            .with_data_plane_url("http://dp-test.io");
        let base = client.data_plane_base().unwrap();
        assert_eq!(base, "http://dp-test.io");
    }

    #[test]
    fn client_new_with_auth_api_key() {
        let client = PineconeClient::new_with_auth(PineconeAuth::ApiKey("mykey".into())).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("PineconeClient"), "debug: {debug}");
    }

    #[test]
    fn client_new_with_auth_credential_id() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let client = PineconeClient::new_with_auth(PineconeAuth::CredentialId(cid)).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("CredentialId"), "debug: {debug}");
    }

    // ── Default constant tests ──────────────────────────────────────────

    #[test]
    fn default_control_plane_url_is_pinecone() {
        assert!(DEFAULT_CONTROL_PLANE_URL.contains("api.pinecone.io"));
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        assert!(sanitize_path_segment("..").is_err());
        assert!(sanitize_path_segment(".").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
        assert!(sanitize_path_segment("foo\\bar").is_err());
    }

    #[test]
    fn sanitize_accepts_valid_index_names() {
        assert!(sanitize_path_segment("my-index").is_ok());
        assert!(sanitize_path_segment("docs-1536").is_ok());
        assert!(sanitize_path_segment("prod_embeddings").is_ok());
    }
}
