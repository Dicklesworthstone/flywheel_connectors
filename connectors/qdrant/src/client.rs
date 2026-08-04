//! Qdrant REST API client.
//!
//! Qdrant uses JSON POST bodies for most data operations and GET for collection reads.
//! Auth via `api-key` header.

use std::time::Duration;

use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{QdrantError, QdrantResult},
    types::{CollectionInfo, CountResult, ListCollectionsResult, ScrollResult},
};

/// Validate a path segment to prevent path traversal and query/fragment
/// injection. Qdrant collection names are `[A-Za-z0-9_-]`-shaped, so rejecting
/// slashes, any `..` substring, encoded slashes, and URL delimiters
/// (`?`/`#`/`&`/`=`/`%`) never trips a legitimate name while stopping
/// `a?b` (wrong-endpoint via query injection) and `..%2f..`.
fn sanitize_path_segment(segment: &str) -> QdrantResult<&str> {
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
        return Err(QdrantError::InvalidInput(format!(
            "Invalid path segment: {segment}"
        )));
    }
    Ok(segment)
}

/// Qdrant REST API client.
pub struct QdrantClient {
    http: Client,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl QdrantClient {
    /// Create a new Qdrant client with an API key and cluster URL.
    pub fn new(api_key: &str, cluster_url: &str) -> QdrantResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("api-key"),
            api_key.parse().map_err(|_| QdrantError::InvalidConfig {
                message: "Invalid API key format".into(),
            })?,
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-qdrant/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(QdrantError::Http)?;

        Ok(Self {
            http,
            base_url: cluster_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
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

    // -- Collection operations --

    /// List all collections.
    pub async fn list_collections(&self) -> QdrantResult<ListCollectionsResult> {
        let url = format!("{}/collections", self.base_url);
        let data = self.get(&url).await?;
        let result = data
            .get("result")
            .cloned()
            .unwrap_or(serde_json::json!({ "collections": [] }));
        Ok(serde_json::from_value(result)?)
    }

    /// Get collection info.
    pub async fn collection_info(&self, collection_name: &str) -> QdrantResult<CollectionInfo> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!("{}/collections/{collection_name}", self.base_url);
        let data = self.get(&url).await?;
        let result = data.get("result").cloned().unwrap_or(serde_json::json!({}));
        Ok(serde_json::from_value(result)?)
    }

    /// Create a collection.
    pub async fn create_collection(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!("{}/collections/{collection_name}", self.base_url);
        self.put_json(&url, body).await
    }

    /// Delete a collection.
    pub async fn delete_collection(
        &self,
        collection_name: &str,
    ) -> QdrantResult<serde_json::Value> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!("{}/collections/{collection_name}", self.base_url);
        self.delete(&url).await
    }

    // -- Point read operations --

    /// Search for similar points by vector.
    pub async fn search(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/search",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Query points using Qdrant query API.
    pub async fn query_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/query",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        if let Some(result) = data.get("result") {
            if let Some(array) = result.as_array() {
                return Ok(array.clone());
            }
            if let Some(points) = result.get("points").and_then(|value| value.as_array()) {
                return Ok(points.clone());
            }
        }
        Ok(Vec::new())
    }

    /// Batch query points using Qdrant query API.
    pub async fn batch_query_points(
        &self,
        collection_name: &str,
        queries: &[serde_json::Value],
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/query/batch",
            self.base_url
        );
        let body = serde_json::json!({ "searches": queries });
        let data = self.post_json(&url, &body).await?;
        let result = data
            .get("result")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Get points by IDs.
    pub async fn get_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<Vec<serde_json::Value>> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!("{}/collections/{collection_name}/points", self.base_url);
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(result)
    }

    /// Scroll through points.
    pub async fn scroll(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<ScrollResult> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/scroll",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data.get("result").cloned().unwrap_or(serde_json::json!({
            "points": [],
            "next_page_offset": null
        }));
        Ok(serde_json::from_value(result)?)
    }

    /// Count points in a collection.
    pub async fn count(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<CountResult> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/count",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        let result = data
            .get("result")
            .cloned()
            .unwrap_or(serde_json::json!({ "count": 0 }));
        Ok(serde_json::from_value(result)?)
    }

    // -- Point write operations --

    /// Upsert points.
    pub async fn upsert_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!("{}/collections/{collection_name}/points", self.base_url);
        let data = self.put_json(&url, body).await?;
        Ok(data)
    }

    /// Delete points.
    pub async fn delete_points(
        &self,
        collection_name: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        let collection_name = sanitize_path_segment(collection_name)?;
        let url = format!(
            "{}/collections/{collection_name}/points/delete",
            self.base_url
        );
        let data = self.post_json(&url, body).await?;
        Ok(data)
    }

    // -- HTTP helpers --

    async fn get(&self, url: &str) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn put_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.put(url).json(body)).await
    }

    async fn delete(&self, url: &str) -> QdrantResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> QdrantResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let req = build_request();
            async move {
                debug!(attempt, "Qdrant request");
                let result = req.send().await;

                match result {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(QdrantError::Api {
                                message: "Qdrant API authentication failed".into(),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(QdrantError::Api {
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
                            return AttemptOutcome::Terminal(QdrantError::RateLimit {
                                retry_after_ms: retry_after,
                            });
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Retryable {
                                error: QdrantError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                },
                                retry_after: None,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(QdrantError::Api {
                                message: format!("HTTP {status}: {body}"),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        let body = match response.text().await {
                            Ok(b) => b,
                            Err(e) => return AttemptOutcome::Terminal(QdrantError::Http(e)),
                        };
                        match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(QdrantError::from(e)),
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: QdrantError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(QdrantError::Http(e)),
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
        let err = QdrantError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = QdrantError::InvalidConfig {
            message: "bad config".into(),
        };
        assert!(!err.is_retryable());

        let err = QdrantError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = QdrantError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
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
    fn sanitize_accepts_valid_collection_names() {
        assert!(sanitize_path_segment("docs").is_ok());
        assert!(sanitize_path_segment("my-collection").is_ok());
        assert!(sanitize_path_segment("embeddings_v2").is_ok());
    }
}
