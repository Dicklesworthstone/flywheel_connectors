//! GitHub API client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{GitHubError, GitHubResult},
    types::{
        ApiErrorResponse, CodeSearchItem, CreateIssueRequest, CreatePullRequestRequest,
        FileContent, Issue, MergePullRequestRequest, MergeResult, PullRequest, Repository,
        SearchResults, WorkflowsResponse,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.github.com";

/// Characters that are NOT percent-encoded when encoding a single path segment.
/// We keep alphanumerics, hyphens, underscores, dots, and tildes (RFC 3986 unreserved).
/// Slashes are NOT included — they delimit path segments.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Validate that a GitHub owner or repo name contains only safe characters
/// (alphanumeric, hyphens, dots, underscores). Returns an error on invalid input.
fn validate_owner_repo(value: &str, label: &str) -> GitHubResult<()> {
    if value.is_empty() {
        return Err(GitHubError::ValidationError {
            message: format!("{label} must not be empty"),
        });
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err(GitHubError::ValidationError {
            message: format!(
                "{label} contains invalid characters (only alphanumeric, hyphens, dots, underscores allowed): {value:?}"
            ),
        });
    }
    Ok(())
}

/// Percent-encode a file path for use in a GitHub API URL.
/// Each segment between `/` separators is encoded individually, preserving the
/// path hierarchy. E.g. `"src/my file.rs"` → `"src/my%20file.rs"`.
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Authentication mode for the GitHub client.
#[derive(Clone)]
pub enum GitHubAuth {
    /// Direct credentials: personal access token or app token (Bearer auth).
    Token(String),
    /// Secretless credential injection via egress proxy.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for GitHubAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl GitHubAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// GitHub API client with retry logic and rate limit awareness.
pub struct GitHubClient {
    client: Client,
    auth: GitHubAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl GitHubClient {
    /// Create a new GitHub client with a personal access token or app token.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the HTTP client cannot be constructed.
    pub fn new(token: impl Into<String>) -> GitHubResult<Self> {
        Self::new_with_auth(GitHubAuth::Token(token.into()))
    }

    /// Create a new GitHub client with the given auth mode.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: GitHubAuth) -> GitHubResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-github/0.1.0")
            .build()
            .map_err(GitHubError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                initial_delay_ms: 1000,
                max_delay_ms: 60_000,
                ..HttpRetryConfig::default()
            },
            total_requests: AtomicU64::new(0),
        })
    }

    /// Apply auth headers to a request builder.
    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            GitHubAuth::Token(token) => builder.header("Authorization", format!("Bearer {token}")),
            GitHubAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Perform a health check by fetching the authenticated user.
    pub async fn health_check(&self) -> GitHubResult<serde_json::Value> {
        self.get("/user").await
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config.max_retries = max_retries;
        self.retry_config.initial_delay_ms = initial_delay_ms;
        self.retry_config.max_delay_ms = max_delay_ms;
        self
    }

    /// Gracefully shut down the client, cancelling background contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Issue operations ──────────────────────────────────────────

    /// Create an issue.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self, req))]
    pub async fn create_issue(
        &self,
        owner: &str,
        repo: &str,
        req: &CreateIssueRequest,
    ) -> GitHubResult<Issue> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.post(&format!("/repos/{owner}/{repo}/issues"), req)
            .await
    }

    /// Get a single issue.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn get_issue(
        &self,
        owner: &str,
        repo: &str,
        issue_number: u32,
    ) -> GitHubResult<Issue> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.get(&format!("/repos/{owner}/{repo}/issues/{issue_number}"))
            .await
    }

    /// Search issues and pull requests.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_issues(&self, query: &str) -> GitHubResult<SearchResults<Issue>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/issues?q={encoded}")).await
    }

    // ── Pull Request operations ───────────────────────────────────

    /// Create a pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self, req))]
    pub async fn create_pull_request(
        &self,
        owner: &str,
        repo: &str,
        req: &CreatePullRequestRequest,
    ) -> GitHubResult<PullRequest> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.post(&format!("/repos/{owner}/{repo}/pulls"), req)
            .await
    }

    /// Get a single pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn get_pull_request(
        &self,
        owner: &str,
        repo: &str,
        pull_number: u32,
    ) -> GitHubResult<PullRequest> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.get(&format!("/repos/{owner}/{repo}/pulls/{pull_number}"))
            .await
    }

    /// Merge a pull request.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self, req))]
    pub async fn merge_pull_request(
        &self,
        owner: &str,
        repo: &str,
        pull_number: u32,
        req: &MergePullRequestRequest,
    ) -> GitHubResult<MergeResult> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.put(
            &format!("/repos/{owner}/{repo}/pulls/{pull_number}/merge"),
            req,
        )
        .await
    }

    // ── Repository operations ─────────────────────────────────────

    /// Get repository metadata.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn get_repo(&self, owner: &str, repo: &str) -> GitHubResult<Repository> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.get(&format!("/repos/{owner}/{repo}")).await
    }

    /// Search repositories.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_repos(&self, query: &str) -> GitHubResult<SearchResults<Repository>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/repositories?q={encoded}")).await
    }

    // ── Actions operations ────────────────────────────────────────

    /// List workflows in a repository.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn list_workflows(&self, owner: &str, repo: &str) -> GitHubResult<WorkflowsResponse> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        self.get(&format!("/repos/{owner}/{repo}/actions/workflows"))
            .await
    }

    /// Trigger a workflow dispatch event.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn trigger_workflow(
        &self,
        owner: &str,
        repo: &str,
        workflow_id: &str,
        git_ref: &str,
    ) -> GitHubResult<()> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        let encoded_workflow_id =
            utf8_percent_encode(workflow_id, PATH_SEGMENT_ENCODE_SET).to_string();
        let body = serde_json::json!({ "ref": git_ref });
        let url = format!(
            "{}/repos/{owner}/{repo}/actions/workflows/{encoded_workflow_id}/dispatches",
            self.base_url
        );

        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            let body = &body;
            async move {
                debug!(attempt, "Triggering workflow dispatch");

                match self
                    .apply_auth(self.client.post(url))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .json(body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        if status == StatusCode::ACCEPTED {
                            return AttemptOutcome::Success(());
                        }
                        let retry_after_secs = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok());
                        let bytes = match response.bytes().await {
                            Ok(b) => b,
                            Err(e) => return AttemptOutcome::Terminal(GitHubError::Http(e)),
                        };
                        // `workflow_dispatch` CREATES a workflow run and takes
                        // no idempotency key. A 5xx means GitHub received the
                        // request — an edge 502 returned after the origin
                        // already accepted the dispatch would, on replay,
                        // produce a second run from one invoke.
                        let err = parse_error_response(status, &bytes, retry_after_secs);
                        if err.is_retryable() {
                            let retry_after = err.retry_after();
                            AttemptOutcome::retryable_if_replayable(err, retry_after, false)
                        } else {
                            AttemptOutcome::Terminal(err)
                        }
                    }
                    // Only a connect-phase failure proves the dispatch never
                    // left the client; a timeout can fire after the body was
                    // fully sent.
                    Err(e) => {
                        let replayable = !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            GitHubError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    // ── Content operations ────────────────────────────────────────

    /// Get file or directory content.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails or owner/repo are invalid.
    #[instrument(skip(self))]
    pub async fn get_file_content(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> GitHubResult<FileContent> {
        validate_owner_repo(owner, "owner")?;
        validate_owner_repo(repo, "repo")?;
        let encoded_path = encode_path(path);
        self.get(&format!("/repos/{owner}/{repo}/contents/{encoded_path}"))
            .await
    }

    // ── Code Search ───────────────────────────────────────────────

    /// Search code across repositories.
    ///
    /// # Errors
    /// Returns [`GitHubError`] if the API request fails.
    #[instrument(skip(self))]
    pub async fn search_code(&self, query: &str) -> GitHubResult<SearchResults<CodeSearchItem>> {
        let encoded = urlencoding::encode(query);
        self.get(&format!("/search/code?q={encoded}")).await
    }

    // ── HTTP primitives ───────────────────────────────────────────

    /// Make a GET request with retries via [`RetryLoop`].
    async fn get<R>(&self, endpoint: &str) -> GitHubResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "GitHub API GET");

                match self
                    .apply_auth(self.client.get(url))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .send()
                    .await
                {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: e.retry_after(),
                            error: e,
                        },
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: GitHubError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(GitHubError::Http(e)),
                }
            }
        })
        .await
    }

    /// Make a POST request with retries via [`RetryLoop`].
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> GitHubResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "GitHub API POST");

                match self
                    .apply_auth(self.client.post(url))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .json(body)
                    .send()
                    .await
                {
                    // POST is not idempotent and GitHub's REST API takes no
                    // idempotency key, so a failure that the service may
                    // already have acted on must NOT be replayed — a 5xx means
                    // the request was received, and a total-request timeout
                    // fires after the body was sent. Retrying either one can
                    // create the resource N times from one invoke.
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => {
                            let retry_after = e.retry_after();
                            AttemptOutcome::retryable_if_replayable(e, retry_after, false)
                        }
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) => {
                        let replayable = !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            GitHubError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    /// Make a PUT request with retries via [`RetryLoop`].
    async fn put<T, R>(&self, endpoint: &str, body: &T) -> GitHubResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "GitHub API PUT");

                match self
                    .apply_auth(self.client.put(url))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .json(body)
                    .send()
                    .await
                {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: e.retry_after(),
                            error: e,
                        },
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: GitHubError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(GitHubError::Http(e)),
                }
            }
        })
        .await
    }

    /// Handle a response, deserializing success or parsing errors.
    async fn handle_response<R>(&self, response: Response) -> GitHubResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();

        // Extract rate limit headers before consuming body
        let rate_limit_remaining = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());

        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let bytes = response.bytes().await.map_err(GitHubError::Http)?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(GitHubError::from)
        } else {
            // Check for secondary rate limit (403 with low remaining)
            if status == StatusCode::FORBIDDEN && rate_limit_remaining == Some(0) {
                let retry_ms = retry_after_secs.unwrap_or(60).saturating_mul(1000);
                return Err(GitHubError::RateLimited {
                    retry_after_ms: retry_ms,
                });
            }
            Err(parse_error_response(status, &bytes, retry_after_secs))
        }
    }
}

/// Parse an error response body.
fn parse_error_response(
    status: StatusCode,
    bytes: &Bytes,
    retry_after_secs: Option<u64>,
) -> GitHubError {
    if let Ok(err_resp) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
        if status == StatusCode::TOO_MANY_REQUESTS {
            return GitHubError::RateLimited {
                retry_after_ms: retry_after_secs.unwrap_or(60).saturating_mul(1000),
            };
        }
        if status == StatusCode::UNAUTHORIZED {
            return GitHubError::Unauthorized;
        }
        if status == StatusCode::NOT_FOUND {
            return GitHubError::NotFound {
                resource: err_resp.message,
            };
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            return GitHubError::ValidationError {
                message: err_resp.message,
            };
        }
        if status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::CONFLICT {
            return GitHubError::MergeConflict {
                message: err_resp.message,
            };
        }

        return GitHubError::Api {
            message: err_resp.message,
            status_code: Some(status.as_u16()),
            documentation_url: err_resp.documentation_url,
        };
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return GitHubError::RateLimited {
            retry_after_ms: retry_after_secs.unwrap_or(60).saturating_mul(1000),
        };
    }

    GitHubError::Api {
        message: String::from_utf8_lossy(bytes).into_owned(),
        status_code: Some(status.as_u16()),
        documentation_url: None,
    }
}

/// Fuzz-only entry points for GitHub client response parsers.
///
/// Exposed for `fuzz_github_api_error_response` so the fuzz crate can drive the
/// private REST error body parser across status-code and retry-after variants.
///
/// Bead flywheel_connectors-65lt5.
#[doc(hidden)]
pub mod __fuzz {
    use bytes::Bytes;
    use reqwest::StatusCode;

    use crate::error::GitHubError;

    use super::parse_error_response;

    /// Parse a raw GitHub API error body with a caller-supplied HTTP status.
    #[must_use]
    pub fn parse_api_error_response(
        status_code: u16,
        body: &[u8],
        retry_after_secs: Option<u64>,
    ) -> GitHubError {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        parse_error_response(status, &Bytes::copy_from_slice(body), retry_after_secs)
    }
}

/// URL-encode a query string.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_testkit::LogCapture;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
        time::Duration,
    };

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: serde_json::Value,
        expected_headers: Vec<(&'static str, &'static str)>,
        response_headers: Vec<(&'static str, &'static str)>,
        request_count: usize,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body,
                expected_headers: Vec::new(),
                response_headers: Vec::new(),
                request_count: 1,
            }
        }

        fn with_expected_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.expected_headers.push((name, value));
            self
        }

        fn with_response_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.response_headers.push((name, value));
            self
        }

        fn with_request_count(mut self, request_count: usize) -> Self {
            self.request_count = request_count;
            self
        }
    }

    struct TestApiServer {
        base_url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestApiServer {
        fn respond(response: TestHttpResponse) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let handle = thread::spawn(move || {
                for _ in 0..response.request_count {
                    let (stream, _) = listener.accept().expect("accept GitHub client request");
                    handle_test_request(stream, &response);
                }
            });

            Self {
                base_url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> String {
            self.base_url.clone()
        }

        fn finish(mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test server thread panicked");
            }
        }
    }

    fn handle_test_request(mut stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        let mut parts = request_line.split_whitespace();
        let request_method = parts.next().expect("request method");
        let raw_path = parts.next().expect("request path");
        let request_path = raw_path.split('?').next().expect("path before query");
        assert_eq!(request_method, response.method);
        assert_eq!(request_path, response.path);

        let mut headers = Vec::new();
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
            let value = value.trim().to_owned();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().expect("content-length parses");
            }
            headers.push((name.to_owned(), value));
        }

        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        for (name, expected) in &response.expected_headers {
            let actual = headers
                .iter()
                .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str());
            assert_eq!(actual, Some(*expected), "unexpected {name} header");
        }

        let body = response.body.to_string();
        let status_text = match response.status {
            200 => "OK",
            201 => "Created",
            401 => "Unauthorized",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        };

        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            status_text,
            body.len()
        )
        .expect("write response headers");
        for (name, value) in &response.response_headers {
            write!(stream, "{name}: {value}\r\n").expect("write response header");
        }
        write!(stream, "\r\n{body}").expect("write response body");
        stream.flush().expect("flush response");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_repo_success() {
        let server = TestApiServer::respond(
            TestHttpResponse::json(
                "GET",
                "/repos/octocat/hello-world",
                200,
                serde_json::json!({
                    "id": 1296269,
                    "name": "hello-world",
                    "full_name": "octocat/hello-world",
                    "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                    "description": "Test repo",
                    "private": false,
                    "fork": false,
                    "html_url": "https://github.com/octocat/hello-world",
                    "default_branch": "main",
                    "language": "Rust",
                    "stargazers_count": 42,
                    "forks_count": 10,
                    "open_issues_count": 5,
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-06-01T00:00:00Z"
                }),
            )
            .with_expected_header("Authorization", "Bearer test_token"),
        );

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());

        let repo = client.get_repo("octocat", "hello-world").await.unwrap();
        server.finish();
        assert_eq!(repo.name, "hello-world");
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.stargazers_count, 42);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue_success() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/repos/octocat/hello-world/issues/42",
            200,
            serde_json::json!({
                "id": 1,
                "number": 42,
                "title": "Found a bug",
                "state": "open",
                "body": "Bug description",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "labels": [],
                "assignees": [],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/issues/42",
                "comments": 3
            }),
        ));

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());

        let issue = client
            .get_issue("octocat", "hello-world", 42)
            .await
            .unwrap();
        server.finish();
        assert_eq!(issue.number, 42);
        assert_eq!(issue.title, "Found a bug");
        assert_eq!(issue.state, "open");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue_success() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "POST",
            "/repos/octocat/hello-world/issues",
            201,
            serde_json::json!({
                "id": 2,
                "number": 43,
                "title": "New issue",
                "state": "open",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "labels": [],
                "assignees": [],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/issues/43",
                "comments": 0
            }),
        ));

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());

        let issue = client
            .create_issue(
                "octocat",
                "hello-world",
                &CreateIssueRequest {
                    title: "New issue".into(),
                    body: Some("Description".into()),
                    assignees: None,
                    labels: None,
                    milestone: None,
                },
            )
            .await
            .unwrap();
        server.finish();
        assert_eq!(issue.number, 43);
        assert_eq!(issue.title, "New issue");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/repos/octocat/hello-world",
            401,
            serde_json::json!({
                "message": "Bad credentials",
                "documentation_url": "https://docs.github.com"
            }),
        ));

        let client = GitHubClient::new("bad_token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "hello-world").await;
        server.finish();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GitHubError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/repos/octocat/nonexistent",
            404,
            serde_json::json!({
                "message": "Not Found"
            }),
        ));

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "nonexistent").await;
        server.finish();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GitHubError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server = TestApiServer::respond(
            TestHttpResponse::json(
                "GET",
                "/repos/octocat/hello-world",
                429,
                serde_json::json!({
                    "message": "API rate limit exceeded"
                }),
            )
            .with_response_header("retry-after", "1")
            .with_request_count(2),
        );

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "hello-world").await;
        server.finish();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::RateLimited { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_pull_request_success() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/repos/octocat/hello-world/pulls/1",
            200,
            serde_json::json!({
                "id": 100,
                "number": 1,
                "title": "Fix typo",
                "state": "open",
                "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "head": { "label": "octocat:fix-typo", "ref": "fix-typo", "sha": "abc123" },
                "base": { "label": "octocat:main", "ref": "main", "sha": "def456" },
                "labels": [],
                "assignees": [],
                "merged": false,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "html_url": "https://github.com/octocat/hello-world/pull/1",
                "draft": false
            }),
        ));

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());

        let pr = client
            .get_pull_request("octocat", "hello-world", 1)
            .await
            .unwrap();
        server.finish();
        assert_eq!(pr.number, 1);
        assert_eq!(pr.title, "Fix typo");
        assert_eq!(pr.head.ref_name, "fix-typo");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_issues_success() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/search/issues",
            200,
            serde_json::json!({
                "total_count": 1,
                "incomplete_results": false,
                "items": [{
                    "id": 1,
                    "number": 42,
                    "title": "Found a bug",
                    "state": "open",
                    "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                    "labels": [],
                    "assignees": [],
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                    "html_url": "https://github.com/octocat/hello-world/issues/42",
                    "comments": 0
                }]
            }),
        ));

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());

        let results = client
            .search_issues("is:open is:issue repo:octocat/hello-world")
            .await
            .unwrap();
        server.finish();
        assert_eq!(results.total_count, 1);
        assert_eq!(results.items.len(), 1);
        assert_eq!(results.items[0].title, "Found a bug");
    }

    #[fcp_async_core::runtime::test(flavor = "current_thread")]
    async fn test_logs_redact_token() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/repos/octocat/hello-world",
            200,
            serde_json::json!({
                "id": 1, "name": "hello-world", "full_name": "octocat/hello-world",
                "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "private": false, "fork": false,
                "html_url": "https://github.com/octocat/hello-world",
                "default_branch": "main",
                "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"
            }),
        ));

        let client = GitHubClient::new("ghp_SECRET_TOKEN_12345")
            .unwrap()
            .with_base_url(server.uri());
        let _ = client.get_repo("octocat", "hello-world").await.unwrap();
        server.finish();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs captured"
        );
        assert!(
            !logs.contains("ghp_SECRET_TOKEN_12345"),
            "token should not appear in logs"
        );
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(
            urlencoding::encode("is:open is:issue"),
            "is%3Aopen%20is%3Aissue"
        );
        assert_eq!(urlencoding::encode("safe-text_here"), "safe-text_here");
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            GitHubError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!GitHubError::Unauthorized.is_retryable());
        assert!(
            !GitHubError::NotFound {
                resource: "test".into()
            }
            .is_retryable()
        );
    }

    // ─── GitHubAuth tests ───────────────────────────────────────────

    #[test]
    fn test_github_auth_token_debug_redacted() {
        let auth = GitHubAuth::Token("ghp_super_secret_token_12345".into());
        let debug = format!("{auth:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("ghp_super_secret_token_12345"));
    }

    #[test]
    fn test_github_auth_credential_id_debug_shows_id() {
        let auth = GitHubAuth::CredentialId(
            CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        );
        let debug = format!("{auth:?}");
        assert!(debug.contains("CredentialId"));
        assert!(debug.contains("11223344"));
    }

    #[test]
    fn test_github_auth_redacted_label_token() {
        let auth = GitHubAuth::Token("secret".into());
        assert_eq!(auth.redacted_label(), "token");
    }

    #[test]
    fn test_github_auth_redacted_label_credential_id() {
        let auth = GitHubAuth::CredentialId(
            CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        );
        assert_eq!(auth.redacted_label(), "credential_id");
    }

    #[test]
    fn test_github_auth_is_secretless_token() {
        let auth = GitHubAuth::Token("test".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn test_github_auth_is_secretless_credential_id() {
        let auth = GitHubAuth::CredentialId(
            CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        );
        assert!(auth.is_secretless());
    }

    #[test]
    fn test_github_auth_clone() {
        let original = GitHubAuth::Token("my_token".into());
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.redacted_label(), "token");
    }

    // ─── GitHubClient construction tests ────────────────────────────

    #[test]
    fn test_github_client_new() {
        let client = GitHubClient::new("ghp_test_token_123");
        assert!(client.is_ok());
    }

    #[test]
    fn test_github_client_new_with_auth() {
        let auth = GitHubAuth::Token("test_token".into());
        let client = GitHubClient::new_with_auth(auth);
        assert!(client.is_ok());
    }

    #[test]
    fn test_github_client_debug_redacted() {
        let client = GitHubClient::new("ghp_super_secret").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("GitHubClient"));
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("ghp_super_secret"));
    }

    #[test]
    fn test_github_client_with_base_url() {
        let client = GitHubClient::new("token")
            .unwrap()
            .with_base_url("https://github.example.com/api/v3");
        let debug = format!("{client:?}");
        assert!(debug.contains("github.example.com"));
    }

    #[test]
    fn test_github_client_with_retry_config() {
        let client = GitHubClient::new("token")
            .unwrap()
            .with_retry_config(5, 500, 30_000);
        let debug = format!("{client:?}");
        assert!(debug.contains("max_retries"));
    }

    #[test]
    fn test_github_client_total_requests_initial() {
        let client = GitHubClient::new("token").unwrap();
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn test_github_client_default_base_url() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.github.com");
    }

    // ─── urlencoding additional tests ───────────────────────────────

    #[test]
    fn test_urlencoding_empty_string() {
        assert_eq!(urlencoding::encode(""), "");
    }

    #[test]
    fn test_urlencoding_only_safe_chars() {
        assert_eq!(
            urlencoding::encode("abc-def_ghi.jkl~mno"),
            "abc-def_ghi.jkl~mno"
        );
    }

    #[test]
    fn test_urlencoding_special_chars() {
        assert_eq!(urlencoding::encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn test_urlencoding_unicode() {
        let encoded = urlencoding::encode("hello 世界");
        assert!(encoded.contains('%'));
        assert!(encoded.starts_with("hello%20"));
    }

    #[test]
    fn test_urlencoding_percent_encoding() {
        assert_eq!(urlencoding::encode("100%"), "100%25");
    }

    #[test]
    fn test_urlencoding_plus_sign() {
        assert_eq!(urlencoding::encode("a+b"), "a%2Bb");
    }

    #[test]
    fn test_urlencoding_slash() {
        assert_eq!(urlencoding::encode("path/to/file"), "path%2Fto%2Ffile");
    }

    #[test]
    fn test_urlencoding_hash() {
        assert_eq!(urlencoding::encode("a#b"), "a%23b");
    }

    #[test]
    fn test_urlencoding_question_mark() {
        assert_eq!(urlencoding::encode("q?a=1"), "q%3Fa%3D1");
    }

    // ─── parse_error_response tests ─────────────────────────────────

    // ─── URL injection prevention tests ──────────────────────────────

    #[test]
    fn test_validate_owner_repo_valid() {
        assert!(validate_owner_repo("octocat", "owner").is_ok());
        assert!(validate_owner_repo("my-org", "owner").is_ok());
        assert!(validate_owner_repo("my_repo", "repo").is_ok());
        assert!(validate_owner_repo("repo.name", "repo").is_ok());
        assert!(validate_owner_repo("a123", "owner").is_ok());
    }

    #[test]
    fn test_validate_owner_repo_rejects_slashes() {
        let result = validate_owner_repo("evil/../../etc", "owner");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::ValidationError { .. }
        ));
    }

    #[test]
    fn test_validate_owner_repo_rejects_empty() {
        let result = validate_owner_repo("", "owner");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::ValidationError { .. }
        ));
    }

    #[test]
    fn test_validate_owner_repo_rejects_spaces() {
        let result = validate_owner_repo("bad name", "owner");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_owner_repo_rejects_query_injection() {
        let result = validate_owner_repo("repo?admin=true", "repo");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_owner_repo_rejects_hash_fragment() {
        let result = validate_owner_repo("repo#fragment", "repo");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_owner_repo_rejects_unicode() {
        let result = validate_owner_repo("repo\u{0000}evil", "repo");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_path_simple() {
        assert_eq!(encode_path("src/main.rs"), "src/main.rs");
    }

    #[test]
    fn test_encode_path_with_spaces() {
        assert_eq!(encode_path("my dir/my file.rs"), "my%20dir/my%20file.rs");
    }

    #[test]
    fn test_encode_path_preserves_slashes() {
        assert_eq!(encode_path("a/b/c"), "a/b/c");
    }

    #[test]
    fn test_encode_path_special_chars() {
        assert_eq!(encode_path("dir/file#1.txt"), "dir/file%231.txt");
    }

    #[test]
    fn test_encode_path_traversal_dots_preserved() {
        // ".." segments are valid path segments in a repo file tree
        // and are preserved after encoding. The key protection is that
        // `/` separators are preserved but not injected into segments.
        let encoded = encode_path("../../../etc/passwd");
        assert_eq!(encoded, "../../../etc/passwd");
    }

    #[test]
    fn test_encode_path_query_injection() {
        let encoded = encode_path("file?admin=true");
        assert!(encoded.contains("%3F"));
        assert!(!encoded.contains('?'));
    }

    #[test]
    fn test_encode_path_unicode() {
        let encoded = encode_path("docs/日本語.md");
        assert!(encoded.starts_with("docs/"));
        assert!(encoded.contains('%'));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_repo_rejects_path_traversal() {
        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url("http://localhost:1234");

        let result = client.get_repo("../admin", "hello-world").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::ValidationError { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue_rejects_invalid_owner() {
        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url("http://localhost:1234");

        let result = client
            .create_issue(
                "evil/owner",
                "repo",
                &CreateIssueRequest {
                    title: "test".into(),
                    body: None,
                    assignees: None,
                    labels: None,
                    milestone: None,
                },
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitHubError::ValidationError { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_500() {
        let server = TestApiServer::respond(
            TestHttpResponse::json(
                "GET",
                "/repos/octocat/hello-world",
                500,
                serde_json::json!({
                    "message": "Internal Server Error"
                }),
            )
            .with_request_count(2),
        );

        let client = GitHubClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 10, 100);

        let result = client.get_repo("octocat", "hello-world").await;
        server.finish();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
    }
}
