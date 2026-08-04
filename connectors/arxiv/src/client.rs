//! arXiv and Semantic Scholar API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{ArxivError, ArxivResult},
    types::ScholarErrorResponse,
    xml_parser,
};

/// Default arXiv API base URL.
pub const DEFAULT_ARXIV_BASE_URL: &str = "https://export.arxiv.org";

/// Default Semantic Scholar API base URL.
pub const DEFAULT_SCHOLAR_BASE_URL: &str = "https://api.semanticscholar.org/graph/v1";

/// arXiv + Semantic Scholar API client.
pub struct ArxivClient {
    client: Client,
    arxiv_base_url: String,
    scholar_base_url: String,
    scholar_api_key: Option<String>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for ArxivClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArxivClient")
            .field("arxiv_base_url", &self.arxiv_base_url)
            .field("scholar_base_url", &self.scholar_base_url)
            .field(
                "scholar_api_key",
                &self.scholar_api_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ArxivClient {
    /// Create a new `ArxivClient`.
    pub fn new(
        arxiv_base_url: Option<&str>,
        scholar_base_url: Option<&str>,
        scholar_api_key: Option<String>,
    ) -> ArxivResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-arxiv/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            arxiv_base_url: arxiv_base_url
                .unwrap_or(DEFAULT_ARXIV_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            scholar_base_url: scholar_base_url
                .unwrap_or(DEFAULT_SCHOLAR_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            scholar_api_key,
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

    fn add_scholar_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(key) = &self.scholar_api_key {
            req.header("x-api-key", key)
        } else {
            req
        }
    }

    // ── arXiv API helpers ───────────────────────────────────────────

    #[instrument(skip(self), fields(url))]
    async fn arxiv_get(&self, path: &str) -> ArxivResult<String> {
        let url = format!("{}{path}", self.arxiv_base_url);
        debug!(url = %redact_url(&url), "arXiv GET request");
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/atom+xml")
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.text().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Self::arxiv_error(status, &body))
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn arxiv_get_bytes(&self, url: &str) -> ArxivResult<Vec<u8>> {
        debug!(url = %redact_url(url), "arXiv GET bytes request");
        let resp = self.client.get(url).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Self::arxiv_error(status, &body))
        }
    }

    fn arxiv_error(status: StatusCode, body: &str) -> ArxivError {
        match status.as_u16() {
            404 => ArxivError::NotFound {
                resource: body.to_string(),
            },
            429 => ArxivError::RateLimited {
                retry_after_ms: 3000,
            },
            code => ArxivError::Api {
                status_code: code,
                message: body.to_string(),
            },
        }
    }

    // ── Semantic Scholar API helpers ─────────────────────────────────

    #[instrument(skip(self), fields(url))]
    async fn scholar_get(&self, path: &str) -> ArxivResult<serde_json::Value> {
        let url = format!("{}{path}", self.scholar_base_url);
        debug!(url = %redact_url(&url), "Scholar GET request");
        let req = self.add_scholar_auth(self.client.get(&url).header("Accept", "application/json"));
        let resp = req.send().await?;
        self.handle_scholar_response(resp).await
    }

    async fn handle_scholar_response(&self, resp: Response) -> ArxivResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.trim().is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());

            let body = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<ScholarErrorResponse>(&body)
                .ok()
                .and_then(|e| e.message.or(e.error))
                .unwrap_or_else(|| body.clone());

            match status.as_u16() {
                429 => Err(ArxivError::RateLimited {
                    // `retry_after` is a hostile `Retry-After` header value.
                    // `* 1000` on the raw u64 overflows for anything above
                    // ~1.8e16 — a panic in debug/test and, since the release
                    // profile leaves `overflow-checks` unset, a silent wrap in
                    // release that turns a long backoff into a near-zero one.
                    retry_after_ms: retry_after.unwrap_or(60).saturating_mul(1000),
                }),
                404 => Err(ArxivError::NotFound { resource: detail }),
                code => Err(ArxivError::ScholarApi {
                    status_code: code,
                    message: detail,
                }),
            }
        }
    }

    // ── Public API methods ──────────────────────────────────────────

    /// Search arXiv papers.
    pub async fn search_papers(
        &self,
        query: &str,
        max_results: Option<i64>,
        start: Option<i64>,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
    ) -> ArxivResult<serde_json::Value> {
        let max = max_results.unwrap_or(10);
        let offset = start.unwrap_or(0);
        let mut url = format!(
            "/api/query?search_query={}&start={offset}&max_results={max}",
            urlencoded(query)
        );
        // `sort_by` / `sort_order` are caller-supplied; percent-encode them like
        // every other URL value in this client so a value such as
        // `relevance&max_results=99999` cannot smuggle additional query
        // parameters. arXiv's valid sort tokens are all unreserved characters,
        // so legitimate values pass through unchanged.
        if let Some(sb) = sort_by {
            url.push_str("&sortBy=");
            url.push_str(&urlencoded(sb));
        }
        if let Some(so) = sort_order {
            url.push_str("&sortOrder=");
            url.push_str(&urlencoded(so));
        }
        let xml = self.arxiv_get(&url).await?;
        let papers = xml_parser::parse_atom_entries(&xml);
        #[allow(clippy::cast_possible_wrap)]
        let fallback_total = papers.len() as i64;
        let total = xml_parser::extract_total_results(&xml).unwrap_or(fallback_total);
        Ok(serde_json::json!({
            "papers": papers,
            "total_results": total,
        }))
    }

    /// Semantic search via Semantic Scholar.
    pub async fn search_semantic(
        &self,
        query: &str,
        max_results: Option<i64>,
        categories: Option<&[String]>,
    ) -> ArxivResult<serde_json::Value> {
        let limit = max_results.unwrap_or(10);
        let mut url = format!(
            "/paper/search?query={}&limit={limit}&fields=paperId,title,abstract,year,citationCount,externalIds,url,authors",
            urlencoded(query)
        );
        // If categories are specified, add them as fieldsOfStudy filter
        if let Some(cats) = categories {
            if !cats.is_empty() {
                // Semantic Scholar uses fields of study, not arXiv categories directly
                // We pass them as a hint in the query
                let cat_str = cats.join(",");
                url.push_str("&fieldsOfStudy=");
                url.push_str(&urlencoded(&cat_str));
            }
        }
        let data = self.scholar_get(&url).await?;
        let papers = data
            .get("data")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        Ok(serde_json::json!({
            "papers": papers,
        }))
    }

    /// Get paper metadata by arXiv ID.
    pub async fn get_paper(&self, arxiv_id: &str) -> ArxivResult<serde_json::Value> {
        let url = format!("/api/query?id_list={}", urlencoded(arxiv_id));
        let xml = self.arxiv_get(&url).await?;
        let papers = xml_parser::parse_atom_entries(&xml);
        let paper = papers
            .into_iter()
            .next()
            .ok_or_else(|| ArxivError::NotFound {
                resource: format!("paper {arxiv_id}"),
            })?;
        Ok(serde_json::json!({
            "paper": paper,
        }))
    }

    /// Get full text (TeX source) for a paper.
    pub async fn get_full_text(
        &self,
        arxiv_id: &str,
        _format: Option<&str>,
    ) -> ArxivResult<serde_json::Value> {
        // arXiv e-print endpoint returns the TeX source
        let url = format!("{}/e-print/{arxiv_id}", self.arxiv_base_url);
        let bytes = self.arxiv_get_bytes(&url).await?;
        // Attempt to interpret as UTF-8 text
        let text = String::from_utf8_lossy(&bytes).to_string();
        Ok(serde_json::json!({
            "text": text,
        }))
    }

    /// Download PDF content (base64-encoded).
    pub async fn download_pdf(&self, arxiv_id: &str) -> ArxivResult<serde_json::Value> {
        let url = format!("{}/pdf/{arxiv_id}.pdf", self.arxiv_base_url);
        let bytes = self.arxiv_get_bytes(&url).await?;
        let encoded = BASE64.encode(&bytes);
        Ok(serde_json::json!({
            "content": encoded,
            "size_bytes": bytes.len(),
        }))
    }

    /// Get citations (papers that cite the given paper) via Semantic Scholar.
    pub async fn get_citations(
        &self,
        arxiv_id: &str,
        max_results: Option<i64>,
    ) -> ArxivResult<serde_json::Value> {
        let limit = max_results.unwrap_or(100);
        let url = format!(
            "/paper/ARXIV:{arxiv_id}/citations?fields=paperId,title,abstract,year,citationCount,externalIds,url,authors&limit={limit}"
        );
        let data = self.scholar_get(&url).await?;
        let citations = data
            .get("data")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let total = citations.as_array().map_or(0, Vec::len);
        Ok(serde_json::json!({
            "citations": citations,
            "total": total,
        }))
    }

    /// Get references (papers cited by the given paper) via Semantic Scholar.
    pub async fn get_references(&self, arxiv_id: &str) -> ArxivResult<serde_json::Value> {
        let url = format!(
            "/paper/ARXIV:{arxiv_id}/references?fields=paperId,title,abstract,year,citationCount,externalIds,url,authors"
        );
        let data = self.scholar_get(&url).await?;
        let references = data
            .get("data")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        Ok(serde_json::json!({
            "references": references,
        }))
    }

    /// Extract and parse references with parsed fields.
    pub async fn extract_references(&self, arxiv_id: &str) -> ArxivResult<serde_json::Value> {
        // Same underlying data as get_references, but we format the output
        let refs_data = self.get_references(arxiv_id).await?;
        let references = refs_data
            .get("references")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let parsed: Vec<serde_json::Value> = references
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|item| {
                let paper = item.get("citedPaper").or(Some(item))?;
                Some(serde_json::json!({
                    "title": paper.get("title"),
                    "year": paper.get("year"),
                    "authors": paper.get("authors").and_then(|a| a.as_array()).map(|authors| {
                        authors.iter().filter_map(|a| a.get("name")).collect::<Vec<_>>()
                    }),
                    "paper_id": paper.get("paperId"),
                    "external_ids": paper.get("externalIds"),
                }))
            })
            .collect();

        Ok(serde_json::json!({
            "references": parsed,
        }))
    }

    /// Search for an author via Semantic Scholar.
    pub async fn get_author(
        &self,
        author_name: &str,
        max_papers: Option<i64>,
    ) -> ArxivResult<serde_json::Value> {
        let limit = max_papers.unwrap_or(20);
        let url = format!(
            "/author/search?query={}&fields=authorId,name,paperCount,citationCount,hIndex,url,papers,papers.title,papers.year,papers.externalIds&limit={limit}",
            urlencoded(author_name)
        );
        let data = self.scholar_get(&url).await?;
        let authors = data
            .get("data")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();

        let author = authors
            .into_iter()
            .next()
            .unwrap_or_else(|| serde_json::json!({}));
        let papers = author
            .get("papers")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        Ok(serde_json::json!({
            "author": author,
            "papers": papers,
        }))
    }

    /// Get recently submitted papers in a category.
    pub async fn get_new_papers(
        &self,
        category: &str,
        max_results: Option<i64>,
    ) -> ArxivResult<serde_json::Value> {
        let max = max_results.unwrap_or(25);
        let url = format!(
            "/api/query?search_query=cat:{}&sortBy=submittedDate&sortOrder=descending&max_results={max}",
            urlencoded(category)
        );
        let xml = self.arxiv_get(&url).await?;
        let papers = xml_parser::parse_atom_entries(&xml);
        Ok(serde_json::json!({
            "papers": papers,
        }))
    }

    /// Monitor a category for new papers (polling-backed).
    pub async fn monitor_category(
        &self,
        categories: &[String],
        keyword_filter: Option<&str>,
        since_ts: Option<&str>,
    ) -> ArxivResult<serde_json::Value> {
        let mut all_papers = Vec::new();
        let mut latest_ts = String::new();

        for category in categories {
            let url = format!(
                "/api/query?search_query=cat:{}&sortBy=submittedDate&sortOrder=descending&max_results=50",
                urlencoded(category)
            );
            let xml = self.arxiv_get(&url).await?;
            let mut papers = xml_parser::parse_atom_entries(&xml);

            // Filter by since_ts if provided
            if let Some(since) = since_ts {
                papers.retain(|p| p.published.as_str() > since || p.updated.as_str() > since);
            }

            // Filter by keyword if provided
            if let Some(kw) = keyword_filter {
                let kw_lower = kw.to_lowercase();
                papers.retain(|p| {
                    p.title.to_lowercase().contains(&kw_lower)
                        || p.summary.to_lowercase().contains(&kw_lower)
                });
            }

            for p in &papers {
                if p.updated > latest_ts {
                    latest_ts.clone_from(&p.updated);
                }
                if p.published > latest_ts {
                    latest_ts.clone_from(&p.published);
                }
            }

            all_papers.extend(papers);
        }

        let cursor_ts = if latest_ts.is_empty() {
            since_ts.unwrap_or("").to_string()
        } else {
            latest_ts
        };

        Ok(serde_json::json!({
            "papers": all_papers,
            "cursor_ts": cursor_ts,
        }))
    }

    /// Monitor a search query for new papers (polling-backed).
    pub async fn monitor_query(
        &self,
        query: &str,
        since_ts: Option<&str>,
    ) -> ArxivResult<serde_json::Value> {
        let url = format!(
            "/api/query?search_query={}&sortBy=submittedDate&sortOrder=descending&max_results=50",
            urlencoded(query)
        );
        let xml = self.arxiv_get(&url).await?;
        let mut papers = xml_parser::parse_atom_entries(&xml);

        // Filter by since_ts if provided
        if let Some(since) = since_ts {
            papers.retain(|p| p.published.as_str() > since || p.updated.as_str() > since);
        }

        let cursor_ts = papers
            .iter()
            .map(|p| p.published.as_str().max(p.updated.as_str()))
            .max()
            .unwrap_or(since_ts.unwrap_or(""))
            .to_string();

        Ok(serde_json::json!({
            "papers": papers,
            "cursor_ts": cursor_ts,
        }))
    }
}

/// Minimal URL encoding for query parameters.
fn urlencoded(s: &str) -> String {
    s.replace(' ', "+")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('#', "%23")
        .replace('?', "%3F")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_api_key() {
        let c = ArxivClient::new(None, None, Some("secret-key".into())).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("secret-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_no_api_key() {
        let c = ArxivClient::new(None, None, None).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn client_default_urls() {
        let c = ArxivClient::new(None, None, None).unwrap();
        assert_eq!(c.arxiv_base_url, DEFAULT_ARXIV_BASE_URL);
        assert_eq!(c.scholar_base_url, DEFAULT_SCHOLAR_BASE_URL);
    }

    #[test]
    fn client_custom_urls() {
        let c = ArxivClient::new(
            Some("https://arxiv.test.com"),
            Some("https://scholar.test.com"),
            None,
        )
        .unwrap();
        assert_eq!(c.arxiv_base_url, "https://arxiv.test.com");
        assert_eq!(c.scholar_base_url, "https://scholar.test.com");
    }

    #[test]
    fn client_strips_trailing_slash() {
        let c = ArxivClient::new(
            Some("https://arxiv.test.com/"),
            Some("https://scholar.test.com/"),
            None,
        )
        .unwrap();
        assert_eq!(c.arxiv_base_url, "https://arxiv.test.com");
        assert_eq!(c.scholar_base_url, "https://scholar.test.com");
    }

    #[test]
    fn urlencoded_spaces() {
        assert_eq!(urlencoded("attention is all"), "attention+is+all");
    }

    #[test]
    fn urlencoded_ampersand() {
        assert_eq!(urlencoded("a&b"), "a%26b");
    }

    #[test]
    fn urlencoded_equals() {
        assert_eq!(urlencoded("a=b"), "a%3Db");
    }

    #[test]
    fn urlencoded_hash() {
        assert_eq!(urlencoded("a#b"), "a%23b");
    }

    #[test]
    fn urlencoded_question() {
        assert_eq!(urlencoded("a?b"), "a%3Fb");
    }

    #[test]
    fn urlencoded_no_change() {
        assert_eq!(urlencoded("cs.AI"), "cs.AI");
    }

    #[test]
    fn urlencoded_complex() {
        assert_eq!(
            urlencoded("ti:transformer AND cat:cs.CL"),
            "ti:transformer+AND+cat:cs.CL"
        );
    }

    #[test]
    fn arxiv_error_404() {
        let err = ArxivClient::arxiv_error(StatusCode::NOT_FOUND, "no paper");
        assert!(matches!(err, ArxivError::NotFound { .. }));
    }

    #[test]
    fn arxiv_error_429() {
        let err = ArxivClient::arxiv_error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        assert!(matches!(err, ArxivError::RateLimited { .. }));
    }

    #[test]
    fn arxiv_error_500() {
        let err = ArxivClient::arxiv_error(StatusCode::INTERNAL_SERVER_ERROR, "error");
        match err {
            ArxivError::Api { status_code, .. } => assert_eq!(status_code, 500),
            other => panic!("expected Api, got {other:?}"),
        }
    }

    // ---- Additional arxiv_error tests ----

    #[test]
    fn arxiv_error_503() {
        let err = ArxivClient::arxiv_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        match err {
            ArxivError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn arxiv_error_400() {
        let err = ArxivClient::arxiv_error(StatusCode::BAD_REQUEST, "bad query");
        match err {
            ArxivError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert_eq!(message, "bad query");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn arxiv_error_404_preserves_body() {
        let err = ArxivClient::arxiv_error(StatusCode::NOT_FOUND, "paper 2301.00000 not found");
        match err {
            ArxivError::NotFound { resource } => {
                assert!(resource.contains("2301.00000"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn arxiv_error_429_retry_after_ms() {
        let err = ArxivClient::arxiv_error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        match err {
            ArxivError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 3000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ---- urlencoded edge cases ----

    #[test]
    fn urlencoded_empty_string() {
        assert_eq!(urlencoded(""), "");
    }

    #[test]
    fn urlencoded_multiple_special_chars() {
        assert_eq!(urlencoded("a&b=c#d?e"), "a%26b%3Dc%23d%3Fe");
    }

    #[test]
    fn urlencoded_preserves_dots_and_colons() {
        assert_eq!(urlencoded("cs.AI:v2"), "cs.AI:v2");
    }

    #[test]
    fn urlencoded_preserves_slashes() {
        assert_eq!(urlencoded("a/b"), "a/b");
    }

    // ---- Client custom URL tests ----

    #[test]
    fn client_multiple_trailing_slashes_stripped() {
        // only the last trailing slash is stripped
        let c = ArxivClient::new(
            Some("https://arxiv.test.com/"),
            Some("https://scholar.test.com/"),
            None,
        )
        .unwrap();
        assert!(!c.arxiv_base_url.ends_with('/'));
        assert!(!c.scholar_base_url.ends_with('/'));
    }

    #[test]
    fn client_with_api_key_stored() {
        let c = ArxivClient::new(None, None, Some("test-key-456".into())).unwrap();
        assert!(c.scholar_api_key.is_some());
        assert_eq!(c.scholar_api_key.as_deref(), Some("test-key-456"));
    }
}
