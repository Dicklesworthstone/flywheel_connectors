use serde::{Deserialize, Serialize};

// ── Search ──

/// Request body for POST /v2/search.
#[derive(Debug, Clone, Serialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    #[serde(rename = "scrapeOptions", skip_serializing_if = "Option::is_none")]
    pub scrape_options: Option<SearchScrapeOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(rename = "ignoreInvalidURLs", skip_serializing_if = "Option::is_none")]
    pub ignore_invalid_urls: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enterprise: Vec<String>,
}

impl SearchRequest {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            limit: None,
            sources: Vec::new(),
            categories: Vec::new(),
            scrape_options: None,
            timeout: None,
            country: None,
            location: None,
            ignore_invalid_urls: None,
            enterprise: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchScrapeOptions {
    pub formats: Vec<String>,
}

impl SearchScrapeOptions {
    #[must_use]
    pub fn markdown() -> Self {
        Self {
            formats: vec!["markdown".into()],
        }
    }
}

/// Response from POST /v2/search.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, rename = "creditsUsed")]
    pub credits_used: Option<u32>,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Scrape ──

/// Request body for POST /v2/scrape.
#[derive(Debug, Clone, Serialize)]
pub struct ScrapeRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<String>,
    #[serde(rename = "onlyMainContent", skip_serializing_if = "Option::is_none")]
    pub only_main_content: Option<bool>,
    #[serde(rename = "includeTags", skip_serializing_if = "Option::is_none")]
    pub include_tags: Option<Vec<String>>,
    #[serde(rename = "excludeTags", skip_serializing_if = "Option::is_none")]
    pub exclude_tags: Option<Vec<String>>,
    #[serde(rename = "waitFor", skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "maxAge", skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(rename = "storeInCache", skip_serializing_if = "Option::is_none")]
    pub store_in_cache: Option<bool>,
}

impl ScrapeRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            formats: vec!["markdown".into()],
            only_main_content: None,
            include_tags: None,
            exclude_tags: None,
            wait_for: None,
            timeout: None,
            max_age: None,
            proxy: None,
            store_in_cache: None,
        }
    }
}

/// Response from POST /v2/scrape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Option<ScrapeData>,
    #[serde(default)]
    pub error: Option<String>,
}

/// The data payload inside a successful scrape response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeData {
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub raw_html: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<ScrapeMetadata>,
}

/// Metadata returned from a scrape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeMetadata {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default, rename = "sourceURL")]
    pub source_url: Option<String>,
    #[serde(default, rename = "statusCode")]
    pub status_code: Option<u16>,
}

// ── Crawl ──

/// Request body for POST /v2/crawl.
#[derive(Debug, Clone, Serialize)]
pub struct CrawlRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(rename = "maxDiscoveryDepth", skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(rename = "excludePaths", skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
    #[serde(rename = "includePaths", skip_serializing_if = "Vec::is_empty")]
    pub include_paths: Vec<String>,
    #[serde(rename = "allowExternalLinks", skip_serializing_if = "Option::is_none")]
    pub allow_external_links: Option<bool>,
}

impl CrawlRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            limit: None,
            max_depth: None,
            exclude_paths: Vec::new(),
            include_paths: Vec::new(),
            allow_external_links: None,
        }
    }
}

/// Response from POST /v2/crawl (async job start).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlStartResponse {
    pub success: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Response from GET /v2/crawl/{id} (crawl status).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlStatusResponse {
    pub status: String,
    #[serde(default)]
    pub total: Option<u32>,
    #[serde(default)]
    pub completed: Option<u32>,
    #[serde(default, rename = "creditsUsed")]
    pub credits_used: Option<u32>,
    #[serde(default, rename = "expiresAt")]
    pub expires_at: Option<String>,
    /// Provider continuation for results not included in this response.
    /// Retained for active jobs; completed-job reads drain bounded continuations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(default)]
    pub data: Option<Vec<CrawlPageData>>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A single page result inside a crawl status response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlPageData {
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<ScrapeMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crawl_continuations_survive_round_trip_instead_of_disappearing() {
        let value = serde_json::json!({
            "status": "scraping", "next": "https://api.firecrawl.dev/v2/crawl/job-1?skip=2",
            "data": [],
        });
        let response: CrawlStatusResponse = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(response).unwrap()["next"], value["next"]);
        let response: CrawlStatusResponse = serde_json::from_value(serde_json::json!({
            "status": "completed", "next": null,
        })).unwrap();
        assert!(response.next.is_none());
        assert!(serde_json::to_value(response).unwrap().get("next").is_none());
    }

    #[test]
    fn search_request_serializes_minimal() {
        let req = SearchRequest::new("firecrawl docs");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["query"], "firecrawl docs");
        assert!(json.get("limit").is_none());
        assert!(json.get("sources").is_none());
        assert!(json.get("scrapeOptions").is_none());
    }

    #[test]
    fn search_request_serializes_v2_options() {
        let mut req = SearchRequest::new("firecrawl docs");
        req.limit = Some(25);
        req.sources = vec!["web".into(), "news".into()];
        req.categories = vec!["github".into()];
        req.scrape_options = Some(SearchScrapeOptions::markdown());
        req.timeout = Some(30_000);
        req.country = Some("US".into());
        req.location = Some("San Francisco,California,United States".into());
        req.ignore_invalid_urls = Some(true);
        req.enterprise = vec!["anon".into()];

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["limit"], 25);
        assert_eq!(json["sources"][0], "web");
        assert_eq!(json["sources"][1], "news");
        assert_eq!(json["categories"][0], "github");
        assert_eq!(json["scrapeOptions"]["formats"][0], "markdown");
        assert_eq!(json["timeout"], 30_000);
        assert_eq!(json["country"], "US");
        assert_eq!(json["location"], "San Francisco,California,United States");
        assert_eq!(json["ignoreInvalidURLs"], true);
        assert_eq!(json["enterprise"][0], "anon");
        assert!(json.get("scrape_options").is_none());
        assert!(json.get("ignore_invalid_urls").is_none());
    }

    #[test]
    fn search_response_deserializes_source_arrays() {
        let json = serde_json::json!({
            "success": true,
            "data": {
                "web": [
                    {
                        "url": "https://firecrawl.dev",
                        "title": "Firecrawl",
                        "description": "Web scraping API"
                    }
                ],
                "images": [
                    {
                        "url": "https://firecrawl.dev/logo.png",
                        "title": "Logo"
                    }
                ]
            },
            "warning": "partial",
            "id": "search-123",
            "creditsUsed": 2
        });
        let resp: SearchResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.warning.as_deref(), Some("partial"));
        assert_eq!(resp.id.as_deref(), Some("search-123"));
        assert_eq!(resp.credits_used, Some(2));
        let data = resp.data.unwrap();
        assert_eq!(data["web"][0]["url"], "https://firecrawl.dev");
        assert_eq!(data["images"][0]["title"], "Logo");
    }

    #[test]
    fn scrape_request_defaults() {
        let req = ScrapeRequest::new("https://example.com");
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.formats, vec!["markdown"]);
        assert!(req.only_main_content.is_none());
    }

    #[test]
    fn scrape_request_serializes() {
        let req = ScrapeRequest::new("https://example.com");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["formats"][0], "markdown");
        // optional fields should be absent
        assert!(json.get("onlyMainContent").is_none());
        assert!(json.get("only_main_content").is_none());
    }

    #[test]
    fn scrape_request_serializes_v2_options() {
        let mut req = ScrapeRequest::new("https://example.com");
        req.only_main_content = Some(false);
        req.include_tags = Some(vec!["main".into()]);
        req.exclude_tags = Some(vec!["nav".into()]);
        req.wait_for = Some(250);
        req.timeout = Some(10_000);
        req.max_age = Some(172_800_000);
        req.proxy = Some("auto".into());
        req.store_in_cache = Some(false);

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["onlyMainContent"], false);
        assert_eq!(json["includeTags"][0], "main");
        assert_eq!(json["excludeTags"][0], "nav");
        assert_eq!(json["waitFor"], 250);
        assert_eq!(json["timeout"], 10_000);
        assert_eq!(json["maxAge"], 172_800_000);
        assert_eq!(json["proxy"], "auto");
        assert_eq!(json["storeInCache"], false);
        assert!(json.get("only_main_content").is_none());
        assert!(json.get("include_tags").is_none());
        assert!(json.get("exclude_tags").is_none());
        assert!(json.get("wait_for").is_none());
        assert!(json.get("store_in_cache").is_none());
    }

    #[test]
    fn scrape_response_deserializes() {
        let json = serde_json::json!({
            "success": true,
            "data": {
                "markdown": "# Hello",
                "metadata": {
                    "title": "Hello",
                    "statusCode": 200
                }
            }
        });
        let resp: ScrapeResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        let data = resp.data.unwrap();
        assert_eq!(data.markdown.unwrap(), "# Hello");
        let meta = data.metadata.unwrap();
        assert_eq!(meta.title.unwrap(), "Hello");
        assert_eq!(meta.status_code.unwrap(), 200);
    }

    #[test]
    fn scrape_response_error_deserializes() {
        let json = serde_json::json!({
            "success": false,
            "error": "URL is not valid"
        });
        let resp: ScrapeResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.error.unwrap(), "URL is not valid");
    }

    #[test]
    fn crawl_request_defaults() {
        let req = CrawlRequest::new("https://example.com");
        assert_eq!(req.url, "https://example.com");
        assert!(req.limit.is_none());
        assert!(req.max_depth.is_none());
    }

    #[test]
    fn crawl_request_serializes_minimal() {
        let req = CrawlRequest::new("https://example.com");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["url"], "https://example.com");
        // empty vecs should not be present
        assert!(json.get("excludePaths").is_none());
        assert!(json.get("includePaths").is_none());
        assert!(json.get("exclude_paths").is_none());
        assert!(json.get("include_paths").is_none());
    }

    #[test]
    fn crawl_start_response_deserializes() {
        let json = serde_json::json!({
            "success": true,
            "id": "crawl-abc-123",
            "url": "https://api.firecrawl.dev/v2/crawl/crawl-abc-123"
        });
        let resp: CrawlStartResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.id.unwrap(), "crawl-abc-123");
    }

    #[test]
    fn crawl_status_response_completed() {
        let json = serde_json::json!({
            "status": "completed",
            "total": 5,
            "completed": 5,
            "creditsUsed": 5,
            "expiresAt": "2025-04-01T00:00:00Z",
            "data": [
                {
                    "markdown": "# Page 1",
                    "metadata": { "title": "Page 1", "sourceURL": "https://example.com/p1" }
                }
            ]
        });
        let resp: CrawlStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.total.unwrap(), 5);
        assert_eq!(resp.completed.unwrap(), 5);
        let pages = resp.data.unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].markdown.as_deref().unwrap(), "# Page 1");
    }

    #[test]
    fn crawl_status_response_scraping() {
        let json = serde_json::json!({
            "status": "scraping",
            "total": 10,
            "completed": 3
        });
        let resp: CrawlStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, "scraping");
        assert_eq!(resp.completed.unwrap(), 3);
        assert!(resp.data.is_none());
    }

    #[test]
    fn crawl_request_with_options() {
        let mut req = CrawlRequest::new("https://example.com");
        req.limit = Some(50);
        req.max_depth = Some(3);
        req.exclude_paths = vec!["/admin/*".into()];
        req.include_paths = vec!["/blog/*".into()];
        req.allow_external_links = Some(false);

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["limit"], 50);
        assert_eq!(json["maxDiscoveryDepth"], 3);
        assert_eq!(json["excludePaths"][0], "/admin/*");
        assert_eq!(json["includePaths"][0], "/blog/*");
        assert_eq!(json["allowExternalLinks"], false);
        assert!(json.get("max_depth").is_none());
        assert!(json.get("exclude_paths").is_none());
        assert!(json.get("include_paths").is_none());
        assert!(json.get("allow_external_links").is_none());
    }
}
