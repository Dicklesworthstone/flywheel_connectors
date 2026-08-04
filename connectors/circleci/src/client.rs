//! CircleCI API client with retry support.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::types::{
    ApiErrorResponse, Job, MessageResponse, PaginatedResponse, Pipeline, Project, Workflow,
};

/// CircleCI API client with retry and runtime integration.
pub struct CircleCiClient {
    client: Client,
    base_url: String,
    api_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for CircleCiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleCiClient")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> Result<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment == "."
        || segment == ".."
    {
        return Err(Error::InvalidInput(format!(
            "Invalid path segment: {segment}"
        )));
    }
    Ok(segment)
}

impl CircleCiClient {
    /// Create a new CircleCI client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        api_token: &str,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
            retry_config,
        })
    }

    /// List pipelines for a project slug (e.g., "gh/org/repo").
    pub async fn list_pipelines(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Pipeline>> {
        // project_slug contains slashes by design (gh/org/repo), so we validate parts
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!("{}/project/{}/pipeline", self.base_url, project_slug);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a pipeline by ID.
    pub async fn get_pipeline(
        &self,
        runtime: &ConnectorRuntime,
        pipeline_id: &str,
    ) -> Result<Pipeline> {
        let id = sanitize_path_segment(pipeline_id)?;
        let url = format!("{}/pipeline/{id}", self.base_url);
        self.get_with_retry::<Pipeline>(runtime, &url, &[]).await
    }

    /// Trigger a new pipeline.
    pub async fn trigger_pipeline(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        body: &serde_json::Value,
    ) -> Result<Pipeline> {
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!("{}/project/{}/pipeline", self.base_url, project_slug);
        // NOT replay-safe: this queues a CI pipeline. Replaying it after a 5xx
        // runs the build a second time — real compute, and whatever the
        // pipeline itself deploys. Same shape as github's workflow_dispatch,
        // the confirmed case that opened br-kxd3e.
        self.post_with_retry(runtime, &url, body, false).await
    }

    /// List workflows for a pipeline.
    pub async fn list_workflows(
        &self,
        runtime: &ConnectorRuntime,
        pipeline_id: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Workflow>> {
        let id = sanitize_path_segment(pipeline_id)?;
        let url = format!("{}/pipeline/{id}/workflow", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a workflow by ID.
    pub async fn get_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
    ) -> Result<Workflow> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}", self.base_url);
        self.get_with_retry::<Workflow>(runtime, &url, &[]).await
    }

    /// Cancel a workflow.
    pub async fn cancel_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
    ) -> Result<MessageResponse> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/cancel", self.base_url);
        // Replay-safe: cancelling an already-cancelled workflow converges on
        // the same state rather than starting anything.
        self.post_with_retry(runtime, &url, &serde_json::json!({}), true)
            .await
    }

    /// Rerun a workflow.
    pub async fn rerun_workflow(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
        from_failed: bool,
    ) -> Result<MessageResponse> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/rerun", self.base_url);
        let body = serde_json::json!({ "from_failed": from_failed });
        // NOT replay-safe: a rerun creates a NEW workflow run, so a replay
        // costs a second one.
        self.post_with_retry(runtime, &url, &body, false).await
    }

    /// List jobs for a workflow.
    pub async fn list_jobs(
        &self,
        runtime: &ConnectorRuntime,
        workflow_id: &str,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Job>> {
        let id = sanitize_path_segment(workflow_id)?;
        let url = format!("{}/workflow/{id}/job", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a single job by project slug and job number.
    pub async fn get_job(
        &self,
        runtime: &ConnectorRuntime,
        project_slug: &str,
        job_number: u64,
    ) -> Result<Job> {
        for part in project_slug.split('/') {
            sanitize_path_segment(part)?;
        }
        let url = format!(
            "{}/project/{}/job/{}",
            self.base_url, project_slug, job_number
        );
        self.get_with_retry::<Job>(runtime, &url, &[]).await
    }

    /// List projects the user follows.
    pub async fn list_projects(
        &self,
        runtime: &ConnectorRuntime,
        page_token: Option<&str>,
    ) -> Result<PaginatedResponse<Project>> {
        let url = format!("{}/me/collaborations", self.base_url);
        let mut query = Vec::new();
        if let Some(token) = page_token {
            query.push(("page-token", token.to_string()));
        }
        // /me/collaborations returns a flat array, but we wrap it
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth_material = self.api_token.clone();
            let query = query.clone();
            async move {
                debug!(attempt, "GET {}", redact_url(&url));
                let mut req = client.get(&url).header("Circle-Token", &auth_material);
                for (k, v) in &query {
                    req = req.query(&[(k, v)]);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
                            retry_after: None,
                        };
                    }
                };
                handle_response_as_list(resp).await
            }
        })
        .await
    }

    /// Health check: validate API reachability.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/me", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Circle-Token", &self.api_token)
            .send()
            .await
            .map_err(Error::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(Error::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(Error::Unauthorized("Invalid API token".into()))
        } else {
            Err(Error::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.api_token.is_empty()
    }

    /// Generic GET with retry, returning deserialized JSON.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth_material = self.api_token.clone();
            let query: Vec<(String, String)> = query
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            async move {
                debug!(attempt, "GET {}", redact_url(&url));
                let mut req = client.get(&url).header("Circle-Token", &auth_material);
                for (k, v) in &query {
                    req = req.query(&[(k.as_str(), v.as_str())]);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: Error::Http(e),
                            retry_after: None,
                        };
                    }
                };
                // GET is idempotent per HTTP semantics, so replaying is safe.
                handle_response(resp, true).await
            }
        })
        .await
    }

    /// Generic POST with retry, returning deserialized JSON.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). CircleCI offers no idempotency key, so a POST
    /// that starts work must set it to `false`: a 5xx or a timeout can both be
    /// reported after CircleCI already queued the run.
    async fn post_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        replay_safe: bool,
    ) -> Result<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            let client = self.client.clone();
            let auth_material = self.api_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "POST {}", redact_url(&url));
                let resp = match client
                    .post(&url)
                    .header("Circle-Token", &auth_material)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        // Only a connect-phase failure proves the request never
                        // reached CircleCI.
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            Error::Http(e),
                            None,
                            replayable,
                        );
                    }
                };
                handle_response(resp, replay_safe).await
            }
        })
        .await
    }
}

/// Handle response: check status, parse JSON.
///
/// `replay_safe` gates only the post-transmission retry classes. A 429 is
/// always retryable: it was refused WITHOUT the work being started.
async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    replay_safe: bool,
) -> AttemptOutcome<T, Error> {
    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: Error::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 {
        return AttemptOutcome::Terminal(Error::Unauthorized("Invalid API token".into()));
    }

    if !resp.status().is_success() {
        let mut text = resp.text().await.unwrap_or_default();
        text.truncate(2048);
        warn!(status, "CircleCI request failed");
        let message = serde_json::from_str::<ApiErrorResponse>(&text)
            .map(|e| e.message)
            .unwrap_or(text);
        let decision = classify_http_status(status, None);
        let err = Error::Api { status, message };
        if !matches!(decision, RetryDecision::Terminal) {
            // A 5xx means CircleCI received the request and may have already
            // queued the pipeline; replaying it triggers a SECOND run.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(Error::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(r) => AttemptOutcome::Success(r),
        Err(e) => AttemptOutcome::Terminal(Error::Json(e)),
    }
}

/// Handle response returning a JSON array and wrapping it in a paginated envelope.
async fn handle_response_as_list<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> AttemptOutcome<PaginatedResponse<T>, Error> {
    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: Error::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 {
        return AttemptOutcome::Terminal(Error::Unauthorized("Invalid API token".into()));
    }

    if !resp.status().is_success() {
        let mut text = resp.text().await.unwrap_or_default();
        text.truncate(2048);
        warn!(status, "CircleCI request failed");
        let message = serde_json::from_str::<ApiErrorResponse>(&text)
            .map(|e| e.message)
            .unwrap_or(text);
        let decision = classify_http_status(status, None);
        let err = Error::Api { status, message };
        if !matches!(decision, RetryDecision::Terminal) {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    // Try paginated first, then raw array
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(Error::Http(e)),
    };

    if let Ok(paginated) = serde_json::from_str::<PaginatedResponse<T>>(&text) {
        return AttemptOutcome::Success(paginated);
    }

    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(items) => AttemptOutcome::Success(PaginatedResponse {
            items,
            next_page_token: None,
        }),
        Err(e) => AttemptOutcome::Terminal(Error::Json(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    #[derive(Clone, Copy)]
    struct ResponseSpec {
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
        delay_ms: u64,
    }

    impl ResponseSpec {
        const fn json(status: u16, body: &'static str) -> Self {
            Self {
                status,
                headers: &[("content-type", "application/json")],
                body,
                delay_ms: 0,
            }
        }

        const fn with_headers(
            status: u16,
            headers: &'static [(&'static str, &'static str)],
            body: &'static str,
        ) -> Self {
            Self {
                status,
                headers,
                body,
                delay_ms: 0,
            }
        }

        const fn delayed_json(status: u16, body: &'static str, delay_ms: u64) -> Self {
            Self {
                status,
                headers: &[("content-type", "application/json")],
                body,
                delay_ms,
            }
        }
    }

    #[derive(Debug)]
    struct RequestObservation {
        request_line: String,
        headers: Vec<String>,
    }

    impl RequestObservation {
        fn header_value(&self, name: &str) -> Option<&str> {
            self.headers.iter().find_map(|line| {
                let (header_name, value) = line.split_once(':')?;
                header_name.eq_ignore_ascii_case(name).then(|| value.trim())
            })
        }
    }

    struct LoopbackFixture {
        base_url: String,
        handle: Option<JoinHandle<Vec<RequestObservation>>>,
    }

    impl LoopbackFixture {
        fn start(responses: Vec<ResponseSpec>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
            let address = listener.local_addr().expect("read listener address");
            let handle = thread::spawn(move || {
                responses
                    .into_iter()
                    .map(|response| {
                        let (stream, _) = listener.accept().expect("accept request");
                        handle_request(stream, response)
                    })
                    .collect()
            });

            Self {
                base_url: format!("http://{address}"),
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn join(mut self) -> Vec<RequestObservation> {
            self.handle
                .take()
                .expect("loopback handle present")
                .join()
                .expect("loopback thread completed")
        }
    }

    fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set request read timeout");
        let raw = read_http_request(&mut stream);
        let header_end = find_header_end(&raw).expect("request contains header terminator");
        let request = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = request.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let headers = lines.map(str::to_string).collect::<Vec<_>>();

        if response.delay_ms > 0 {
            thread::sleep(Duration::from_millis(response.delay_ms));
        }
        write_response(&mut stream, response);

        RequestObservation {
            request_line,
            headers,
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let bytes_read = stream.read(&mut buffer).expect("read request");
            assert!(bytes_read > 0, "request should not close early");
            request.extend_from_slice(&buffer[..bytes_read]);
            if let Some(header_end) = find_header_end(&request) {
                let expected_body_len = content_length(&request[..header_end]);
                let body_bytes = request.len().saturating_sub(header_end + 4);
                if body_bytes >= expected_body_len {
                    return request;
                }
            }
        }
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    fn write_response(stream: &mut TcpStream, response: ResponseSpec) {
        if write!(
            stream,
            "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
            response.status,
            status_reason(response.status),
            response.body.len()
        )
        .is_err()
        {
            return;
        }
        for (name, value) in response.headers {
            if write!(stream, "{name}: {value}\r\n").is_err() {
                return;
            }
        }
        let _ = write!(stream, "\r\n{}", response.body);
    }

    const fn status_reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "Status",
        }
    }

    #[test]
    fn client_creation() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2/",
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_api_token() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "super_secret_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(!debug_output.contains("super_secret_token"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn non_secretless() {
        let client = CircleCiClient::new(
            "https://circleci.com/api/v2",
            "real_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(sanitize_path_segment("..").is_err());
        assert!(sanitize_path_segment(".").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(sanitize_path_segment("pipeline-123").is_ok());
        assert!(sanitize_path_segment("abc").is_ok());
        assert!(sanitize_path_segment("gh").is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let fixture = LoopbackFixture::start(vec![ResponseSpec::json(200, r#"{"id":"u1"}"#)]);

        let client = CircleCiClient::new(
            fixture.base_url(),
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
        assert_eq!(
            observations[0].header_value("circle-token"),
            Some("test_token")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_unauthorized() {
        let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, "")]);

        let client = CircleCiClient::new(
            fixture.base_url(),
            "bad_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_rate_limited() {
        let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
            429,
            &[("retry-after", "60")],
            "",
        )]);

        let client = CircleCiClient::new(
            fixture.base_url(),
            "test_token",
            HttpRetryConfig::default(),
            30_000,
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(
            err,
            Error::RateLimited {
                retry_after_ms: 60000
            }
        ));
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_respects_configured_timeout() {
        let fixture =
            LoopbackFixture::start(vec![ResponseSpec::delayed_json(200, r#"{"id":"u1"}"#, 250)]);

        let client = CircleCiClient::new(
            fixture.base_url(),
            "test_token",
            HttpRetryConfig::default(),
            50,
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, Error::Http(_)));
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
    }
}
