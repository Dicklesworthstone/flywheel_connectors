use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{FirecrawlError, FirecrawlResult};
use crate::types::{
    CrawlRequest, CrawlStartResponse, CrawlStatusResponse, ScrapeRequest, ScrapeResponse,
    SearchRequest, SearchResponse,
};

/// Maximum decoded HTTP body retained by one attempt, including chunked bodies.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplaySafety {
    ReadOnly,
    Billable,
}

/// Firecrawl API client with operation-aware retry support.
pub struct FirecrawlClient {
    client: Client,
    base_url: String,
    credential: String,
    retry_config: HttpRetryConfig,
    pub(crate) timeout: Duration,
}

impl std::fmt::Debug for FirecrawlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrawlClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

// Public async constructors mirror the connector lifecycle even when setup is local.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl FirecrawlClient {
    pub async fn new(
        base_url: &str,
        api_key: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> FirecrawlResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            // Keep retries in the shared SDK loop and never replay a POST via
            // a redirect (or disclose its credentials to another endpoint).
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(FirecrawlError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            credential: api_key.to_string(),
            retry_config,
            timeout,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.credential.trim().is_empty()
    }

    // ── Search ──

    pub async fn search(
        &self,
        runtime: &ConnectorRuntime,
        request: &SearchRequest,
    ) -> FirecrawlResult<SearchResponse> {
        self.post(runtime, "/v2/search", request).await
    }

    // ── Scrape ──

    pub async fn scrape(
        &self,
        runtime: &ConnectorRuntime,
        request: &ScrapeRequest,
    ) -> FirecrawlResult<ScrapeResponse> {
        self.post(runtime, "/v2/scrape", request).await
    }

    // ── Crawl ──

    pub async fn start_crawl(
        &self,
        runtime: &ConnectorRuntime,
        request: &CrawlRequest,
    ) -> FirecrawlResult<CrawlStartResponse> {
        let response: CrawlStartResponse = self.post(runtime, "/v2/crawl", request).await?;
        if response.success
            && response.id.as_deref().is_none_or(|id| validate_crawl_id(id).is_err())
        {
            // Success without a usable job identity cannot safely be resubmitted.
            return Err(FirecrawlError::OutcomeUnknown { status: Some(200) });
        }
        Ok(response)
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        endpoint: &'static str,
        request: &impl serde::Serialize,
    ) -> FirecrawlResult<T> {
        let url = format!("{}{endpoint}", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(request).map_err(FirecrawlError::Json)?;
        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            let body = &body;
            async move {
                debug!(attempt, endpoint, "Calling Firecrawl");
                let req = authenticate_request(self.client.post(url), &self.credential).json(body);
                handle_response::<T>(req, ReplaySafety::Billable, MAX_RESPONSE_BYTES).await
            }
        })
        .await
        .map(|(value, _)| value)
        .map_err(|error| match error {
            // The shared deadline can cancel after transmission. A context
            // failure does not prove the job or charge did not happen.
            FirecrawlError::Async(_) => FirecrawlError::OutcomeUnknown { status: None },
            other => other,
        })
    }

    pub async fn get_crawl_status(
        &self,
        runtime: &ConnectorRuntime,
        crawl_id: &str,
    ) -> FirecrawlResult<CrawlStatusResponse> {
        validate_crawl_id(crawl_id)?;
        let url = format!("{}/v2/crawl/{crawl_id}", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let credential = self.credential.clone();
            async move {
                debug!(attempt, crawl_id, "Checking crawl status");
                let req = authenticate_request(client.get(&url), &credential);
                handle_response::<CrawlStatusResponse>(req, ReplaySafety::ReadOnly, MAX_RESPONSE_BYTES).await
            }
        })
        .await
        .map(|(value, _)| value)
    }
}

// ── Free functions ──

/// Validate a crawl ID to prevent path injection.
fn validate_crawl_id(id: &str) -> FirecrawlResult<()> {
    if id.trim().is_empty() {
        return Err(FirecrawlError::InvalidInput(
            "crawl_id must not be empty".into(),
        ));
    }
    if id.len() > 512
        || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(FirecrawlError::InvalidInput(
            "crawl_id must contain only ASCII letters, digits, hyphens or underscores".into(),
        ));
    }
    Ok(())
}

fn authenticate_request(req: RequestBuilder, credential: &str) -> RequestBuilder {
    if credential.is_empty() {
        req
    } else {
        req.bearer_auth(credential)
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    safety: ReplaySafety,
    max_bytes: usize,
) -> AttemptOutcome<(T, usize), FirecrawlError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            if safety == ReplaySafety::Billable && transport_error_reached_service(&e) {
                return AttemptOutcome::Terminal(FirecrawlError::OutcomeUnknown { status: None });
            }
            let retryable = !e.is_builder() && (e.is_connect() || e.is_timeout());
            return AttemptOutcome::retryable_if_replayable(FirecrawlError::Http(e), None, retryable);
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: FirecrawlError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(60)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(FirecrawlError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(FirecrawlError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if safety == ReplaySafety::Billable
        && (status >= 500 || status == 408 || resp.status().is_redirection())
    {
        // A server/gateway error is not evidence that the billable POST never
        // ran. The non-retryable error survives conversion at the FCP boundary.
        return AttemptOutcome::Terminal(FirecrawlError::OutcomeUnknown { status: Some(status) });
    }

    if !resp.status().is_success() {
        let err = FirecrawlError::Api {
            status,
            // Provider error pages can echo credentials, URLs or scrape input.
            message: format!("request rejected (HTTP {status}); provider body omitted"),
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let bytes = match read_body(resp, max_bytes).await {
        Ok(bytes) => bytes,
        Err(_) if safety == ReplaySafety::Billable => {
            return AttemptOutcome::Terminal(FirecrawlError::OutcomeUnknown { status: Some(status) });
        }
        Err(error) => return AttemptOutcome::Terminal(error),
    };
    match serde_json::from_slice::<T>(&bytes) {
        Ok(value) => AttemptOutcome::Success((value, bytes.len())),
        Err(_) if safety == ReplaySafety::Billable => {
            AttemptOutcome::Terminal(FirecrawlError::OutcomeUnknown { status: Some(status) })
        }
        Err(_) => AttemptOutcome::Terminal(FirecrawlError::InvalidResponse("invalid JSON response")),
    }
}

async fn read_body(mut response: reqwest::Response, limit: usize) -> FirecrawlResult<Vec<u8>> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(FirecrawlError::InvalidResponse("response exceeds byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(FirecrawlError::InvalidResponse("response exceeds byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::FcpError;
    use fcp_sdk::ConnectorRuntimeConfig;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run<F: std::future::Future>(future: F) -> F::Output {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    fn runtime() -> ConnectorRuntime {
        ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(5)),
        )
    }

    async fn client(server: &MockServer) -> FirecrawlClient {
        FirecrawlClient::new(
            &server.uri(), "fc-private-test-key",
            HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 1,
                max_delay_ms: 1,
                ..HttpRetryConfig::default()
            },
            Duration::from_secs(5),
        ).await.unwrap()
    }

    fn assert_unknown(error: &FirecrawlError) {
        assert!(matches!(error, FirecrawlError::OutcomeUnknown { .. }));
        assert!(!error.is_retryable());
        assert!(matches!(error.to_fcp_error(), FcpError::External {
            retryable: false, retry_after: None, ..
        }));
        assert!(!error.to_string().contains("fc-private-test-key"));
    }

    #[test]
    fn all_billable_operations_refuse_ambiguous_http_replay() {
        run(async {
            for status in [408, 500, 502, 503, 504] {
                for endpoint in ["/v2/crawl", "/v2/scrape", "/v2/search"] {
                    let server = MockServer::start().await;
                    Mock::given(method("POST")).and(path(endpoint))
                        .respond_with(ResponseTemplate::new(status).set_body_string("provider-secret"))
                        .expect(1).mount(&server).await;
                    let client = client(&server).await;
                    let runtime = runtime();
                    let error = match endpoint {
                        "/v2/crawl" => client.start_crawl(&runtime, &CrawlRequest::new("https://example.com")).await.unwrap_err(),
                        "/v2/scrape" => client.scrape(&runtime, &ScrapeRequest::new("https://example.com")).await.unwrap_err(),
                        _ => client.search(&runtime, &SearchRequest::new("test query")).await.unwrap_err(),
                    };
                    assert_unknown(&error);
                    assert!(!error.to_string().contains("provider-secret"));
                    assert_eq!(server.received_requests().await.unwrap().len(), 1);
                }
            }
        });
    }

    #[test]
    fn unreadable_success_is_not_a_license_to_start_another_job() {
        run(async {
            for body in ["{", "{}", "null", r#"{"success":true}"#] {
                let server = MockServer::start().await;
                Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_string(body))
                    .expect(1).mount(&server).await;
                let error = client(&server).await.start_crawl(
                    &runtime(), &CrawlRequest::new("https://example.com"),
                ).await.unwrap_err();
                assert_unknown(&error);
                assert_eq!(server.received_requests().await.unwrap().len(), 1);
            }
        });
    }

    #[test]
    fn rate_limit_refusal_can_retry_without_disabling_useful_recovery() {
        run(async {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&calls);
            Mock::given(method("POST")).respond_with(move |_: &wiremock::Request| {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429).insert_header("Retry-After", "0")
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"success":true,"id":"job-1"}))
                }
            }).expect(2).mount(&server).await;
            let response = client(&server).await.start_crawl(
                &runtime(), &CrawlRequest::new("https://example.com"),
            ).await.unwrap();
            assert_eq!(response.id.as_deref(), Some("job-1"));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn read_only_status_recovers_from_a_transient_server_error() {
        run(async {
            let server = MockServer::start().await;
            let calls = AtomicUsize::new(0);
            Mock::given(method("GET")).respond_with(move |_: &wiremock::Request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":"completed","data":[]}))
                }
            }).expect(2).mount(&server).await;
            assert_eq!(client(&server).await.get_crawl_status(&runtime(), "job-1").await.unwrap().status, "completed");
        });
    }

    #[test]
    fn redirects_cannot_replay_a_post_or_disclose_its_credentials() {
        run(async {
            let source = MockServer::start().await;
            let destination = MockServer::start().await;
            Mock::given(method("POST")).respond_with(
                ResponseTemplate::new(307).insert_header("Location", format!("{}/capture", destination.uri())),
            ).expect(1).mount(&source).await;
            let error = client(&source).await.start_crawl(
                &runtime(), &CrawlRequest::new("https://example.com"),
            ).await.unwrap_err();
            assert_unknown(&error);
            assert!(destination.received_requests().await.unwrap().is_empty());
        });
    }

    #[test]
    fn response_byte_limits_preserve_post_uncertainty_and_accept_exact_bounds() {
        run(async {
            let server = MockServer::start().await;
            Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .mount(&server).await;
            let client = client(&server).await;
            for safety in [ReplaySafety::Billable, ReplaySafety::ReadOnly] {
                let result = handle_response::<serde_json::Value>(client.client.get(server.uri()), safety, 1).await;
                let AttemptOutcome::Terminal(error) = result else { panic!("oversized response accepted"); };
                if safety == ReplaySafety::Billable { assert_unknown(&error); }
                else { assert!(matches!(error, FirecrawlError::InvalidResponse(_))); }
            }
            assert!(matches!(handle_response::<serde_json::Value>(
                client.client.get(server.uri()), ReplaySafety::ReadOnly, 2,
            ).await, AttemptOutcome::Success((_, 2))));
        });
    }

    #[test]
    fn a_disconnected_response_after_transmission_is_not_retryable() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "no request reached fixture");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut byte = [0];
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() <= 16 * 1024);
            }
            // The request reached the server; close without response headers.
        });
        let error = run(async {
            let client = FirecrawlClient::new(&url, "key", HttpRetryConfig::default(), Duration::from_secs(5)).await.unwrap();
            client.start_crawl(&runtime(), &CrawlRequest::new("https://example.com")).await.unwrap_err()
        });
        server.join().unwrap();
        assert_unknown(&error);
    }

    #[test]
    fn invalid_ids_cannot_change_query_fragment_or_path() {
        for id in ["a?skip=100", "a#fragment", "a%3fskip=1", "a.b", "a b", "a\n", "é", "//other"] {
            assert!(validate_crawl_id(id).is_err(), "{id:?}");
        }
        assert!(validate_crawl_id(&"a".repeat(513)).is_err());
    }

    #[test]
    fn client_debug_redacts_api_key() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev",
                "fc-redacted-example",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fc-redacted-example"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev",
                "",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev",
                "fc-key",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev/",
                "key",
                HttpRetryConfig::default(),
                Duration::from_secs(30),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn validate_crawl_id_rejects_traversal() {
        assert!(validate_crawl_id("../admin").is_err());
        assert!(validate_crawl_id("foo/bar").is_err());
        assert!(validate_crawl_id("foo\\bar").is_err());
        assert!(validate_crawl_id("foo%2fbar").is_err());
        assert!(validate_crawl_id("foo%5Cbar").is_err());
        assert!(validate_crawl_id("").is_err());
        assert!(validate_crawl_id("  ").is_err());
    }

    #[test]
    fn validate_crawl_id_accepts_valid() {
        assert!(validate_crawl_id("crawl-abc-123").is_ok());
        assert!(validate_crawl_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn client_uses_configured_timeout() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            FirecrawlClient::new(
                "https://api.firecrawl.dev",
                "key",
                HttpRetryConfig::default(),
                Duration::from_millis(1_234),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.timeout, Duration::from_millis(1_234));
    }
}
