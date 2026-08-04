//! Semantic Scholar API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SemanticScholarError, SemanticScholarResult},
    types::ApiErrorResponse,
};

/// Validate a URL path segment to prevent path-traversal attacks.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SemanticScholarResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SemanticScholarError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('&')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(SemanticScholarError::InvalidInput(format!(
            "{field} contains path traversal or query-injection characters"
        )));
    }
    Ok(trimmed)
}

/// Default Semantic Scholar API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.semanticscholar.org/graph/v1";

/// Default fields for paper search results.
pub const DEFAULT_PAPER_SEARCH_FIELDS: &str = "paperId,title,abstract,year,citationCount,authors";

/// Default fields for paper detail.
pub const DEFAULT_PAPER_DETAIL_FIELDS: &str = "paperId,title,abstract,year,venue,citationCount,referenceCount,authors,isOpenAccess,externalIds,fieldsOfStudy";

/// Default fields for citations/references.
pub const DEFAULT_CITATION_FIELDS: &str = "paperId,title,year,citationCount,authors";

/// Default fields for author detail.
pub const DEFAULT_AUTHOR_FIELDS: &str =
    "authorId,name,hIndex,citationCount,paperCount,affiliations";

/// Default fields for author papers.
pub const DEFAULT_AUTHOR_PAPERS_FIELDS: &str = "paperId,title,year,citationCount";

/// Authentication mode for the Semantic Scholar API.
#[derive(Clone)]
pub enum SemanticScholarAuth {
    /// API key header authentication.
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
    /// No authentication (free tier).
    None,
}

impl SemanticScholarAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{}", redact_credential_id(id)),
            Self::None => "none".to_string(),
        }
    }

    #[must_use]
    pub const fn has_key(&self) -> bool {
        matches!(self, Self::ApiKey(_))
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SemanticScholarAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => {
                let redacted = redact_credential_id(id);
                f.debug_tuple("CredentialId").field(&redacted).finish()
            }
            Self::None => f.write_str("None"),
        }
    }
}

/// Semantic Scholar API client.
pub struct SemanticScholarClient {
    client: Client,
    auth: SemanticScholarAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SemanticScholarClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticScholarClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SemanticScholarClient {
    /// Create a new Semantic Scholar client.
    pub fn new(auth: SemanticScholarAuth, base_url: Option<&str>) -> SemanticScholarResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-semanticscholar/0.1.0 (FCP connector)")
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

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SemanticScholarAuth::ApiKey(key) => req.header("x-api-key", key),
            SemanticScholarAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
            SemanticScholarAuth::None => req,
        }
    }

    async fn handle_response(&self, resp: Response) -> SemanticScholarResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> SemanticScholarResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SemanticScholarError::Unauthorized),
            403 => Err(SemanticScholarError::Forbidden),
            404 => Err(SemanticScholarError::NotFound { resource: detail }),
            429 => Err(SemanticScholarError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SemanticScholarError::Api {
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
    ) -> SemanticScholarResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Run a lightweight connectivity probe against the paper search endpoint.
    pub async fn health_check(&self) -> SemanticScholarResult<()> {
        self.get(
            "/paper/search",
            Some(&[
                ("query", "transformers".to_string()),
                ("fields", "paperId".to_string()),
                ("limit", "1".to_string()),
                ("offset", "0".to_string()),
            ]),
        )
        .await
        .map(|_| ())
    }

    // -- Papers --

    /// Search for papers by keyword.
    pub async fn search_papers(
        &self,
        query: &str,
        limit: Option<i64>,
        offset: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_PAPER_SEARCH_FIELDS);
        let mut q = vec![("query", query.to_string()), ("fields", f.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(o) = offset {
            q.push(("offset", o.to_string()));
        }
        self.get("/paper/search", Some(&q)).await
    }

    /// Get paper details by ID.
    pub async fn get_paper(
        &self,
        paper_id: &str,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let pid = sanitize_path_segment(paper_id, "paper_id")?;
        let f = fields.unwrap_or(DEFAULT_PAPER_DETAIL_FIELDS);
        self.get(&format!("/paper/{pid}"), Some(&[("fields", f.to_string())]))
            .await
    }

    /// Get citations of a paper.
    pub async fn get_paper_citations(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let pid = sanitize_path_segment(paper_id, "paper_id")?;
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let mut q = vec![("fields", f.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        self.get(&format!("/paper/{pid}/citations"), Some(&q)).await
    }

    /// Get references of a paper.
    pub async fn get_paper_references(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let pid = sanitize_path_segment(paper_id, "paper_id")?;
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let mut q = vec![("fields", f.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        self.get(&format!("/paper/{pid}/references"), Some(&q))
            .await
    }

    /// Get recommended papers based on a seed paper.
    pub async fn get_paper_recommendations(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let pid = sanitize_path_segment(paper_id, "paper_id")?;
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let mut q = vec![("fields", f.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        self.get(&format!("/paper/{pid}/recommendations"), Some(&q))
            .await
    }

    // -- Authors --

    /// Get author details by ID.
    pub async fn get_author(
        &self,
        author_id: &str,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let aid = sanitize_path_segment(author_id, "author_id")?;
        let f = fields.unwrap_or(DEFAULT_AUTHOR_FIELDS);
        self.get(
            &format!("/author/{aid}"),
            Some(&[("fields", f.to_string())]),
        )
        .await
    }

    /// Get papers by an author.
    pub async fn get_author_papers(
        &self,
        author_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let aid = sanitize_path_segment(author_id, "author_id")?;
        let f = fields.unwrap_or(DEFAULT_AUTHOR_PAPERS_FIELDS);
        let mut q = vec![("fields", f.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        self.get(&format!("/author/{aid}/papers"), Some(&q)).await
    }
}

fn redact_credential_id(id: &CredentialId) -> String {
    let raw = id.to_string();
    let prefix: String = raw.chars().take(8).collect();
    format!("{prefix}...redacted")
}

fn decode_success_body(status: StatusCode, body: &str) -> SemanticScholarResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SemanticScholarError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::FcpError;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = SemanticScholarAuth::ApiKey("secret-key-123".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none() {
        let auth = SemanticScholarAuth::None;
        let dbg = format!("{auth:?}");
        assert_eq!(dbg, "None");
    }

    #[test]
    fn auth_debug_credential_id_redacts_value() {
        let raw = "550e8400-e29b-41d4-a716-446655440000";
        let auth = SemanticScholarAuth::CredentialId(CredentialId::parse(raw).unwrap());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains("550e8400"));
        assert!(!dbg.contains(raw));
    }

    #[test]
    fn auth_has_key_detection() {
        let key = SemanticScholarAuth::ApiKey("key".into());
        assert!(key.has_key());
        let credential = SemanticScholarAuth::CredentialId(
            CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        );
        assert!(!credential.has_key());
        let none = SemanticScholarAuth::None;
        assert!(!none.has_key());
    }

    #[test]
    fn auth_is_secretless_detection() {
        let key = SemanticScholarAuth::ApiKey("key".into());
        assert!(!key.is_secretless());
        let credential = SemanticScholarAuth::CredentialId(
            CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        );
        assert!(credential.is_secretless());
        let none = SemanticScholarAuth::None;
        assert!(!none.is_secretless());
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let auth = SemanticScholarAuth::ApiKey("key".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let raw = "550e8400-e29b-41d4-a716-446655440000";
        let auth = SemanticScholarAuth::CredentialId(CredentialId::parse(raw).unwrap());
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:550e8400"));
        assert!(!label.contains(raw));
    }

    #[test]
    fn auth_redacted_label_none() {
        let auth = SemanticScholarAuth::None;
        assert_eq!(auth.redacted_label(), "none");
    }

    #[test]
    fn default_base_url_has_graph_v1() {
        assert!(DEFAULT_BASE_URL.contains("graph/v1"));
    }

    #[test]
    fn default_paper_search_fields_non_empty() {
        assert!(!DEFAULT_PAPER_SEARCH_FIELDS.is_empty());
        assert!(DEFAULT_PAPER_SEARCH_FIELDS.contains("title"));
    }

    #[test]
    fn default_paper_detail_fields_non_empty() {
        assert!(!DEFAULT_PAPER_DETAIL_FIELDS.is_empty());
        assert!(DEFAULT_PAPER_DETAIL_FIELDS.contains("paperId"));
    }

    #[test]
    fn default_citation_fields_non_empty() {
        assert!(!DEFAULT_CITATION_FIELDS.is_empty());
        assert!(DEFAULT_CITATION_FIELDS.contains("paperId"));
    }

    #[test]
    fn default_author_fields_non_empty() {
        assert!(!DEFAULT_AUTHOR_FIELDS.is_empty());
        assert!(DEFAULT_AUTHOR_FIELDS.contains("authorId"));
    }

    #[test]
    fn default_author_papers_fields_non_empty() {
        assert!(!DEFAULT_AUTHOR_PAPERS_FIELDS.is_empty());
        assert!(DEFAULT_AUTHOR_PAPERS_FIELDS.contains("paperId"));
    }

    #[test]
    fn client_new_default_url() {
        let client = SemanticScholarClient::new(SemanticScholarAuth::None, None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SemanticScholarClient::new(
            SemanticScholarAuth::None,
            Some("https://custom.api.com/v1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.api.com/v1");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::None, Some("https://example.com/"))
                .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_format() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::ApiKey("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SemanticScholarClient"));
        assert!(!dbg.contains("secret"));
    }

    // --- Auth clone ---

    #[test]
    fn auth_clone_api_key() {
        let original = SemanticScholarAuth::ApiKey("key123".into());
        let cloned = original.clone();
        drop(original);
        assert!(cloned.has_key());
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_clone_none() {
        let original = SemanticScholarAuth::None;
        let cloned = original.clone();
        drop(original);
        assert!(!cloned.has_key());
    }

    #[test]
    fn auth_clone_credential_id() {
        let original = SemanticScholarAuth::CredentialId(
            CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        );
        let cloned = original.clone();
        drop(original);
        assert!(cloned.is_secretless());
    }

    // --- Constants content checks ---

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_paper_search_fields_contains_abstract() {
        assert!(DEFAULT_PAPER_SEARCH_FIELDS.contains("abstract"));
    }

    #[test]
    fn default_paper_detail_fields_contains_venue() {
        assert!(DEFAULT_PAPER_DETAIL_FIELDS.contains("venue"));
    }

    #[test]
    fn default_citation_fields_contains_year() {
        assert!(DEFAULT_CITATION_FIELDS.contains("year"));
    }

    #[test]
    fn default_author_fields_contains_hindex() {
        assert!(DEFAULT_AUTHOR_FIELDS.contains("hIndex"));
    }

    #[test]
    fn default_author_papers_fields_contains_year() {
        assert!(DEFAULT_AUTHOR_PAPERS_FIELDS.contains("year"));
    }

    // --- Client with multiple trailing slashes ---

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::None, Some("https://example.com///"))
                .unwrap();
        // trim_end_matches('/') removes all trailing slashes
        assert!(!client.base_url.ends_with('/'));
    }

    // --- Auth Debug format details ---

    #[test]
    fn auth_debug_api_key_shows_redacted() {
        let auth = SemanticScholarAuth::ApiKey("super_secret_key_123".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super_secret_key_123"));
    }

    // --- Client debug shows base_url ---

    #[test]
    fn client_debug_shows_base_url() {
        let client = SemanticScholarClient::new(
            SemanticScholarAuth::None,
            Some("https://custom.example.com/api"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.example.com"));
    }

    // --- Client stores auth correctly ---

    #[test]
    fn client_stores_api_key_auth() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::ApiKey("my_key".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("ApiKey"));
        assert!(!dbg.contains("my_key"));
    }

    #[test]
    fn client_stores_none_auth() {
        let client = SemanticScholarClient::new(SemanticScholarAuth::None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn client_stores_credential_id_auth() {
        let client = SemanticScholarClient::new(
            SemanticScholarAuth::CredentialId(
                CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            ),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(!dbg.contains("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            SemanticScholarError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t").unwrap_err();
        assert!(matches!(
            err,
            SemanticScholarError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }

    // ── sanitize_path_segment tests ─────────────────────────────────

    #[test]
    fn sanitize_path_segment_valid() {
        assert_eq!(
            sanitize_path_segment("abc123def", "paper_id").unwrap(),
            "abc123def"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        let err = sanitize_path_segment("", "paper_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        let err = sanitize_path_segment("   ", "paper_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        let err = sanitize_path_segment("abc/def", "paper_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        let err = sanitize_path_segment("abc\\def", "paper_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        let err = sanitize_path_segment("abc..def", "paper_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        let err = sanitize_path_segment("abc%2fdef", "paper_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        let err = sanitize_path_segment("abc%5Cdef", "paper_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_allows_hyphens_and_underscores() {
        assert_eq!(
            sanitize_path_segment("paper-id_123", "paper_id").unwrap(),
            "paper-id_123"
        );
    }

    #[test]
    fn sanitize_invalid_input_not_retryable() {
        let err = SemanticScholarError::InvalidInput("test".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn sanitize_invalid_input_to_fcp_error() {
        let err = SemanticScholarError::InvalidInput("bad id".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::InvalidRequest { .. }));
    }
}
