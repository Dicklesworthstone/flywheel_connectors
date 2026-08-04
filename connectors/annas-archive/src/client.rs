use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{AnnasArchiveError, AnnasArchiveResult},
    types::ApiErrorResponse,
};

/// Default Anna's Archive API base URL.
pub const DEFAULT_BASE_URL: &str = "https://annas-archive.org";

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> AnnasArchiveResult<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
        || segment.contains('?')
        || segment.contains('#')
    {
        return Err(AnnasArchiveError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

/// Anna's Archive API client.
pub struct AnnasArchiveClient {
    client: Client,
    base_url: String,
    runtime: ConnectorRuntime,
}

impl fmt::Debug for AnnasArchiveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnnasArchiveClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AnnasArchiveClient {
    /// Create a new Anna's Archive client.
    pub fn new(base_url: Option<&str>) -> AnnasArchiveResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-annas-archive/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    async fn handle_response(&self, resp: Response) -> AnnasArchiveResult<serde_json::Value> {
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
    ) -> AnnasArchiveResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error).or(e.detail))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            404 => Err(AnnasArchiveError::NotFound { resource: detail }),
            429 => Err(AnnasArchiveError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            503 => Err(AnnasArchiveError::ServiceUnavailable),
            code => Err(AnnasArchiveError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> AnnasArchiveResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self.client.get(&url).header("Accept", "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Search for books and documents.
    pub async fn search(
        &self,
        query: &str,
        lang: Option<&str>,
        ext: Option<&str>,
        sort: Option<&str>,
    ) -> AnnasArchiveResult<serde_json::Value> {
        let mut q = vec![("q", query.to_string())];
        if let Some(l) = lang {
            q.push(("lang", l.to_string()));
        }
        if let Some(e) = ext {
            q.push(("ext", e.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        self.get("/search", Some(&q)).await
    }

    /// Get book metadata by MD5 hash.
    pub async fn get_metadata(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        let md5 = sanitize_path_segment(md5)?;
        self.get(&format!("/md5/{md5}"), None).await
    }

    /// Look up a book by ISBN.
    pub async fn lookup_isbn(&self, isbn: &str) -> AnnasArchiveResult<serde_json::Value> {
        let isbn = sanitize_path_segment(isbn)?;
        self.get(&format!("/isbn/{isbn}"), None).await
    }

    /// Look up a book by MD5 hash.
    pub async fn lookup_md5(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        let md5 = sanitize_path_segment(md5)?;
        self.get(&format!("/md5/{md5}"), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url_correct() {
        assert_eq!(DEFAULT_BASE_URL, "https://annas-archive.org");
    }

    #[test]
    fn sanitize_path_segment_valid() {
        assert!(sanitize_path_segment("d41d8cd98f00b204e9800998ecf8427e").is_ok());
        assert!(sanitize_path_segment("978-3-16-148410-0").is_ok());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../etc/passwd").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("foo\\bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("   ").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
        assert!(sanitize_path_segment("foo?bar=1").is_err());
        assert!(sanitize_path_segment("foo#frag").is_err());
    }

    #[test]
    fn client_new_default_url() {
        let client = AnnasArchiveClient::new(None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = AnnasArchiveClient::new(Some("https://mirror.example.com")).unwrap();
        assert_eq!(client.base_url, "https://mirror.example.com");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = AnnasArchiveClient::new(Some("https://example.com/")).unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_new_no_trailing_slash_unchanged() {
        let client = AnnasArchiveClient::new(Some("https://example.com")).unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = AnnasArchiveClient::new(Some("https://test.example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AnnasArchiveClient"));
        assert!(dbg.contains("test.example.com"));
    }

    #[test]
    fn client_new_empty_url() {
        let client = AnnasArchiveClient::new(Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_debug_default_url() {
        let client = AnnasArchiveClient::new(None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("annas-archive.org"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_no_trailing_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = AnnasArchiveClient::new(Some("https://x.com///")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_new_unicode_url() {
        let client = AnnasArchiveClient::new(Some("https://example.com/日本語")).unwrap();
        assert!(client.base_url.contains("日本語"));
    }

    #[test]
    fn client_debug_format_includes_struct_name() {
        let client = AnnasArchiveClient::new(None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.starts_with("AnnasArchiveClient"));
    }

    #[test]
    fn client_new_with_path_url() {
        let client = AnnasArchiveClient::new(Some("https://mirror.example.com/api/v2")).unwrap();
        assert_eq!(client.base_url, "https://mirror.example.com/api/v2");
    }

    #[test]
    fn client_new_trailing_slash_stripped_once() {
        let client = AnnasArchiveClient::new(Some("https://example.com/path/")).unwrap();
        assert_eq!(client.base_url, "https://example.com/path");
    }
}
