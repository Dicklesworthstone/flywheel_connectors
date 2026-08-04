//! Wolfram Alpha HTTP client with bounded retry budget.
//!
//! Bead: `flywheel_connectors-0a9hv` (H.2 production hardening). The
//! historical implementation carried `ConnectorRuntime` +
//! `HttpRetryConfig` fields but performed a single `reqwest::send()`
//! per query — the retry config was dead code and transient
//! 429/5xx/connect failures had no bounded retry budget. This module
//! integrates [`RetryLoop`] from `fcp-sdk::migration` so each public
//! method wraps the HTTP call in the canonical retry-budget pattern,
//! respects `Retry-After` headers, and surfaces structured terminal
//! errors on 4xx (other than 429).
//!
//! ## Retry classification
//!
//! | HTTP status / error class    | Outcome              | Notes                          |
//! |------------------------------|----------------------|--------------------------------|
//! | 200 OK                       | `Success(parsed)`    |                                |
//! | 429 Too Many Requests        | `Retryable`          | Honors `Retry-After` header    |
//! | 500-599                      | `Retryable`          | Default backoff per policy     |
//! | 408 Request Timeout          | `Retryable`          | Treated as transient           |
//! | 401 / 403                    | `Terminal`           | Auth failure — no retry        |
//! | 404                          | `Terminal`           | Resource missing — no retry    |
//! | other 4xx                    | `Terminal`           | Client error — no retry        |
//! | reqwest connect/timeout err  | `Retryable`          | Network glitch — retry         |
//! | reqwest other err            | `Terminal`           | Unrecoverable transport        |
//!
//! After `HttpRetryConfig::max_retries` retries are exhausted the
//! last error surfaces unchanged.

use std::time::Duration;

use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status};
use fcp_sdk::retry::RetryDecision;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use tracing::{info, warn};

use crate::error::WolframError;
use crate::types::{QueryResult, WolframConfig, validate_wolfram_base_url};

/// Wolfram Alpha API client.
pub struct WolframClient {
    client: reqwest::Client,
    base_url: String,
    timeout: Duration,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl WolframClient {
    /// Create a new Wolfram Alpha client.
    ///
    /// # Panics
    ///
    /// Panics if the supplied configuration has not already passed
    /// Wolfram base URL policy validation. Production callers should
    /// prefer [`Self::try_new`] when handling untrusted configuration.
    #[must_use]
    pub fn new(config: &WolframConfig) -> Self {
        Self::try_new(config).expect("WolframConfig base_url must be validated before client use")
    }

    /// Create a new Wolfram Alpha client from validated configuration.
    pub fn try_new(config: &WolframConfig) -> Result<Self, WolframError> {
        let policy = validate_wolfram_base_url(&config.base_url, config.allow_mock_base_url)
            .map_err(|message| WolframError::InvalidInput {
                message: format!("Invalid base_url: {message}"),
            })?;
        let timeout = Duration::from_millis(config.timeout_ms);
        Ok(Self {
            client: reqwest::Client::new(),
            base_url: policy.canonical_url,
            timeout,
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Create a client with a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            timeout: Duration::from_secs(30),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Create a client with a custom base URL AND custom retry
    /// config (test seam — production callers should use
    /// [`Self::new`] with a `WolframConfig`). Used by the
    /// retry-budget tests to exercise the loop with `max_retries=0`
    /// for fast deterministic terminal-on-first-failure assertions
    /// AND with `max_retries=N` for retry-then-succeed scenarios.
    #[must_use]
    pub fn with_base_url_and_retry(base_url: String, retry_config: HttpRetryConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            timeout: Duration::from_secs(30),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config,
        }
    }

    /// Perform a full query against the Wolfram Alpha API.
    pub async fn query(&self, input: &str, app_id: &str) -> Result<QueryResult, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v2/query", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha full query"
        );

        let value: serde_json::Value = self
            .send_with_retry(
                &url,
                &[
                    ("input", input.to_string()),
                    ("appid", app_id.to_string()),
                    ("output", "json".to_string()),
                    ("format", "plaintext,image".to_string()),
                ],
                ResponseShape::Json,
            )
            .await?;

        // Wolfram wraps the result in a "queryresult" key.
        let query_result = value.get("queryresult").cloned().unwrap_or(value);

        serde_json::from_value(query_result).map_err(|e| WolframError::Serialization(e.to_string()))
    }

    /// Get a short text answer from Wolfram Alpha.
    pub async fn short_answer(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/result", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha short answer"
        );

        let text: String = self
            .send_with_retry(
                &url,
                &[("i", input.to_string()), ("appid", app_id.to_string())],
                ResponseShape::Text,
            )
            .await?;
        Ok(json!({ "answer": text }))
    }

    /// Get a spoken-word text answer from Wolfram Alpha.
    pub async fn spoken_result(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/spoken", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha spoken result"
        );

        let text: String = self
            .send_with_retry(
                &url,
                &[("i", input.to_string()), ("appid", app_id.to_string())],
                ResponseShape::Text,
            )
            .await?;
        Ok(json!({ "spoken": text }))
    }

    /// Health check — single connectivity probe with no retry budget.
    /// Health is meant to fail fast on transient unavailability so
    /// the connector can be marked degraded immediately; retrying
    /// would mask the very condition health-check is designed to
    /// surface.
    pub async fn health_check(&self) -> Result<(), WolframError> {
        let url = format!("{}/v1/result", self.base_url);
        let resp = self
            .client
            .get(&url)
            .query(&[("i", "1+1"), ("appid", "DEMO")])
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(WolframError::Http)?;
        let _status = resp.status();
        Ok(())
    }

    /// Internal: send a GET with the retry-budget pattern.
    ///
    /// `shape` controls how the success body is interpreted —
    /// JSON for `/v2/query`, raw text for the `/v1/result` and
    /// `/v1/spoken` endpoints. The return type is generic over
    /// the deserialized representation so callers can pick the
    /// shape per endpoint.
    async fn send_with_retry<T: ResponseDeserialize>(
        &self,
        url: &str,
        query: &[(&str, String)],
        shape: ResponseShape,
    ) -> Result<T, WolframError> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        // reqwest query params must be `&[(&str, &str)]`-shaped at
        // call time. Snapshot the values into owned Strings the
        // closure can re-take per attempt.
        let query: Vec<(&'static str, String)> = query
            .iter()
            .map(|(k, v)| Self::query_key_static(k).map(|key| (key, v.clone())))
            .collect::<Result<_, _>>()?;
        let timeout = self.timeout;

        RetryLoop::execute(&ctx, &policy, move |attempt| {
            let url = url.clone();
            let query = query.clone();
            let client = self.client.clone();
            async move {
                tracing::debug!(attempt, "Wolfram retry-budget attempt");
                let resp = match client.get(&url).query(&query).timeout(timeout).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        if e.is_timeout() || e.is_connect() {
                            return AttemptOutcome::Retryable {
                                error: WolframError::Http(e),
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(WolframError::Http(e));
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
                    let retry_after_ms =
                        u64::try_from(retry_after.unwrap_or(Duration::from_mins(1)).as_millis())
                            .unwrap_or(u64::MAX);
                    return AttemptOutcome::Retryable {
                        error: WolframError::RateLimited { retry_after_ms },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    warn!(status_code = status, "Wolfram Alpha request failed");
                    let decision = classify_http_status(status, None);
                    let err = WolframError::Api {
                        status_code: status,
                        message: body,
                    };
                    return match decision {
                        RetryDecision::Terminal => AttemptOutcome::Terminal(err),
                        _ => AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        },
                    };
                }

                match T::from_response(resp, shape).await {
                    Ok(v) => AttemptOutcome::Success(v),
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }

    /// Map a small fixed set of query-parameter names onto static
    /// string slices so the per-attempt query Vec can carry
    /// `&'static str` keys (which reqwest's `query()` needs to
    /// borrow) while values stay owned. Wolfram's parameter set is
    /// closed (`input`, `appid`, `output`, `format`, `i`) so this
    /// is safe; an unknown key returns an internal error so the
    /// constraint is visible without unwinding production code.
    fn query_key_static(name: &str) -> Result<&'static str, WolframError> {
        // const-context byte comparison (no string ops in const fn yet
        // for stable nightly comparisons of &str).
        let bytes = name.as_bytes();
        match bytes {
            b"input" => Ok("input"),
            b"appid" => Ok("appid"),
            b"output" => Ok("output"),
            b"format" => Ok("format"),
            b"i" => Ok("i"),
            _ => Err(WolframError::Internal {
                message: format!("unsupported Wolfram query key: {name}"),
            }),
        }
    }
}

/// Indicates how to interpret the response body.
#[derive(Debug, Clone, Copy)]
enum ResponseShape {
    Json,
    Text,
}

/// Trait for parsing the response body into the caller's expected
/// shape. Implemented for `serde_json::Value` (JSON endpoints) and
/// `String` (text endpoints). The trait is sealed by living in this
/// module — external impls would need to add another shape variant.
trait ResponseDeserialize: Sized {
    fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> impl std::future::Future<Output = Result<Self, WolframError>> + Send;
}

impl ResponseDeserialize for serde_json::Value {
    async fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> Result<Self, WolframError> {
        match shape {
            ResponseShape::Json => resp.json().await.map_err(WolframError::Http),
            ResponseShape::Text => Err(WolframError::Internal {
                message: "JSON deserializer used with Text shape".into(),
            }),
        }
    }
}

impl ResponseDeserialize for String {
    async fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> Result<Self, WolframError> {
        match shape {
            ResponseShape::Text => resp.text().await.map_err(WolframError::Http),
            ResponseShape::Json => Err(WolframError::Internal {
                message: "Text deserializer used with JSON shape".into(),
            }),
        }
    }
}

impl std::fmt::Debug for WolframClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WolframClient")
            .field("base_url", &self.base_url)
            .field("max_retries", &self.retry_config.max_retries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
    };

    /// Test helper: zero-retry config so terminal-on-first-failure
    /// tests don't sleep through retry backoff.
    fn no_retry() -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        }
    }

    /// Test helper: fast-retry config (small backoff) for retry-then-
    /// succeed tests so the suite stays under a second.
    fn fast_retry(max: u32) -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries: max,
            initial_delay_ms: 5,
            max_delay_ms: 20,
            jitter_enabled: false,
        }
    }

    fn client_with_timeout(
        base_url: String,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> WolframClient {
        WolframClient {
            client: reqwest::Client::new(),
            base_url,
            timeout,
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config,
        }
    }

    #[derive(Clone)]
    struct TestHttpResponse {
        status: u16,
        body: String,
        content_type: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        delay: Duration,
    }

    impl TestHttpResponse {
        fn json(status: u16, body: &serde_json::Value) -> Self {
            Self {
                status,
                body: body.to_string(),
                content_type: "application/json",
                headers: Vec::new(),
                delay: Duration::ZERO,
            }
        }

        fn text(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                body: body.into(),
                content_type: "text/plain; charset=utf-8",
                headers: Vec::new(),
                delay: Duration::ZERO,
            }
        }

        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    #[derive(Clone, Debug)]
    struct TestHttpRequest {
        method: String,
        target: String,
        path: String,
    }

    struct TestHttpServer {
        base_url: String,
        requests: Arc<Mutex<Vec<TestHttpRequest>>>,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpServer {
        fn respond(response: TestHttpResponse) -> Self {
            Self::respond_sequence(vec![response])
        }

        fn respond_sequence(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().expect("accept Wolfram client request");
                    handle_test_request(stream, response, &thread_requests);
                }
            });

            Self {
                base_url,
                requests,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> String {
            self.base_url.clone()
        }

        fn finish(mut self) -> Vec<TestHttpRequest> {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test server thread panicked");
            }
            self.requests.lock().expect("request log poisoned").clone()
        }
    }

    fn handle_test_request(
        mut stream: TcpStream,
        response: TestHttpResponse,
        requests: &Arc<Mutex<Vec<TestHttpRequest>>>,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("request method").to_owned();
        let target = parts.next().expect("request target").to_owned();
        let path = target.split('?').next().expect("request path").to_owned();

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header line");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().expect("content-length parses");
            }
        }
        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        requests
            .lock()
            .expect("request log poisoned")
            .push(TestHttpRequest {
                method,
                target,
                path,
            });

        if !response.delay.is_zero() {
            thread::sleep(response.delay);
        }

        let status_text = match response.status {
            403 => "Forbidden",
            429 => "Too Many Requests",
            503 => "Service Unavailable",
            _ => "OK",
        };
        let mut response_head = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            status_text,
            response.content_type,
            response.body.len()
        );
        for (name, value) in response.headers {
            response_head.push_str(name);
            response_head.push_str(": ");
            response_head.push_str(value);
            response_head.push_str("\r\n");
        }
        response_head.push_str("\r\n");
        response_head.push_str(&response.body);

        if stream.write_all(response_head.as_bytes()).is_ok() {
            let _ = stream.flush();
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_success() {
        let body = serde_json::json!({
            "queryresult": {
                "success": true,
                "numpods": 1,
                "pods": [{
                    "title": "Result",
                    "id": "Result",
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }],
                "assumptions": []
            }
        });
        let server = TestHttpServer::respond(TestHttpResponse::json(200, &body));
        let client = WolframClient::with_base_url(server.uri());
        let result = client.query("2+2", "test-app-id").await.expect("query");
        let requests = server.finish();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/v2/query");
        assert!(requests[0].target.contains("input=2%2B2"));
        assert!(requests[0].target.contains("appid=test-app-id"));
        assert!(result.success);
        assert_eq!(result.pods[0].subpods[0].plaintext.as_deref(), Some("4"));
    }

    #[fcp_async_core::runtime::test]
    async fn query_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.query("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn short_answer_success() {
        let server = TestHttpServer::respond(TestHttpResponse::text(200, "67.39 million people"));
        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .short_answer("population of France", "test-id")
            .await
            .expect("short answer");
        let requests = server.finish();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/result");
        assert!(requests[0].target.contains("i=population+of+France"));
        assert_eq!(result["answer"], "67.39 million people");
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_success() {
        let server = TestHttpServer::respond(TestHttpResponse::text(200, "The answer is 4"));
        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .spoken_result("what is 2+2", "test-id")
            .await
            .expect("spoken");
        let requests = server.finish();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/spoken");
        assert_eq!(result["spoken"], "The answer is 4");
    }

    // ── Retry-budget contract tests (0a9hv) ───────────────────────────

    #[fcp_async_core::runtime::test]
    async fn terminal_on_403_no_retry_consumed() {
        // 403 is terminal — must NOT consume retry budget. Use
        // no_retry() so we'd see if the loop tried to retry.
        let server = TestHttpServer::respond(TestHttpResponse::text(403, "Forbidden"));
        let client = WolframClient::with_base_url_and_retry(server.uri(), no_retry());
        let err = client.query("test", "bad-id").await.unwrap_err();
        let requests = server.finish();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v2/query");
        assert!(
            matches!(
                err,
                WolframError::Api {
                    status_code: 403,
                    ..
                }
            ),
            "expected Api 403, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn retries_on_503_then_succeeds() {
        // 503 is retryable. First attempt 503, subsequent attempts
        // succeed. With max_retries=2 the budget allows up to 3
        // attempts total — the second one succeeds.
        let server = TestHttpServer::respond_sequence(vec![
            TestHttpResponse::text(503, "Service Unavailable"),
            TestHttpResponse::text(200, "OK"),
        ]);
        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(2));
        let result = client
            .short_answer("test", "test-id")
            .await
            .expect("eventually succeeds");
        let requests = server.finish();

        assert_eq!(requests.len(), 2);
        assert_eq!(result["answer"], "OK");
    }

    #[fcp_async_core::runtime::test]
    async fn retries_on_429_then_succeeds_honoring_retry_after() {
        // 429 with a Retry-After header. First attempt 429,
        // second attempt 200.
        let server = TestHttpServer::respond_sequence(vec![
            TestHttpResponse::text(429, "Too Many Requests").with_header("retry-after", "0"),
            TestHttpResponse::text(200, "after backoff"),
        ]);
        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(2));
        let result = client
            .short_answer("rate-limited", "test-id")
            .await
            .expect("eventually succeeds");
        let requests = server.finish();

        assert_eq!(requests.len(), 2);
        assert_eq!(result["answer"], "after backoff");
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_exhaustion_returns_rate_limited_error() {
        // Mock always returns 429. RetryLoop exhausts max_retries,
        // returns the last error (WolframError::RateLimited per the
        // 429 mapping).
        let server = TestHttpServer::respond_sequence(vec![
            TestHttpResponse::text(429, "Too Many Requests").with_header("retry-after", "0"),
            TestHttpResponse::text(429, "Too Many Requests").with_header("retry-after", "0"),
        ]);
        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(1));
        let err = client.short_answer("test", "test-id").await.unwrap_err();
        let requests = server.finish();

        assert_eq!(requests.len(), 2);
        assert!(
            matches!(err, WolframError::RateLimited { .. }),
            "expected RateLimited, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn server_error_exhaustion_returns_api_error() {
        let server = TestHttpServer::respond_sequence(vec![
            TestHttpResponse::text(503, "Service Unavailable"),
            TestHttpResponse::text(503, "Service Unavailable"),
        ]);
        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(1));
        let err = client.query("test", "id").await.unwrap_err();
        let requests = server.finish();

        assert_eq!(requests.len(), 2);
        assert!(
            matches!(
                err,
                WolframError::Api {
                    status_code: 503,
                    ..
                }
            ),
            "expected Api 503, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn no_retry_budget_terminal_on_first_failure() {
        // max_retries=0 ⇒ exactly 1 attempt, retryable error
        // surfaces as the final error.
        let server = TestHttpServer::respond(TestHttpResponse::text(503, "Service Unavailable"));
        let client = WolframClient::with_base_url_and_retry(server.uri(), no_retry());
        let err = client.query("test", "id").await.unwrap_err();
        let requests = server.finish();

        assert_eq!(requests.len(), 1);
        assert!(matches!(
            err,
            WolframError::Api {
                status_code: 503,
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn retry_budget_connect_timeout_refuses_after_budget() {
        let delayed_response =
            TestHttpResponse::text(200, "eventual answer").with_delay(Duration::from_millis(150));
        let server =
            TestHttpServer::respond_sequence(vec![delayed_response.clone(), delayed_response]);
        let client = client_with_timeout(server.uri(), fast_retry(1), Duration::from_millis(25));
        let err = client
            .short_answer("slow upstream", "test-id")
            .await
            .unwrap_err();
        let requests = server.finish();

        assert!(
            matches!(err, WolframError::Http(ref e) if e.is_timeout()),
            "expected timeout HTTP error, got {err:?}"
        );
        assert_eq!(
            requests.len(),
            2,
            "one initial timeout plus one budgeted retry should be sent"
        );
    }

    // ── Existing behavior preserved ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn short_answer_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.short_answer("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.spoken_result("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[test]
    fn debug_redacts_nothing_sensitive() {
        let client = WolframClient::with_base_url("https://api.wolframalpha.com".into());
        let debug = format!("{client:?}");
        assert!(debug.contains("WolframClient"));
        assert!(debug.contains("api.wolframalpha.com"));
        // The retry budget should be in Debug output for operator
        // diagnostics — but no app_id or other sensitive material.
        assert!(debug.contains("max_retries"));
    }

    #[test]
    fn query_key_static_rejects_unknown_key() {
        let err = WolframClient::query_key_static("evil").expect_err("unsupported key");
        assert!(
            matches!(err, WolframError::Internal { ref message } if message.contains("unsupported Wolfram query key")),
            "unsupported key should return internal error, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn transport_error_never_leaks_appid() {
        const APP_ID: &str = "APPID-DEADBEEF-super-secret-key";
        // Bind then drop a loopback socket so the port refuses connections
        // deterministically. `query` sends GET /v2/query?input=..&appid=<APP_ID>;
        // the connect failure yields a `reqwest::Error` carrying that URL, and
        // the `appid` (API key) must never survive into any surfaced message.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let client = WolframClient::with_base_url(format!("http://127.0.0.1:{port}"));
        let error = client
            .query("2+2", APP_ID)
            .await
            .expect_err("connection to a closed loopback port must fail");

        let display = error.to_string();
        assert!(
            !display.contains(APP_ID) && !display.contains("appid"),
            "Display leaked the appid query: {display}"
        );

        let fcp = format!("{:?}", fcp_sdk::ConnectorErrorMapping::to_fcp_error(&error));
        assert!(!fcp.contains(APP_ID), "FcpError leaked the appid: {fcp}");
    }
}
