//! Sentry API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SentryError, SentryResult},
    types::ApiErrorResponse,
};

/// Default Sentry API base URL.
pub const DEFAULT_BASE_URL: &str = "https://sentry.io/api/0";

/// Authentication mode for the Sentry API.
#[derive(Clone)]
pub enum SentryAuth {
    /// Bearer token (auth token or internal integration token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SentryAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SentryAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Sentry API client with retry support.
pub struct SentryClient {
    client: Client,
    auth: SentryAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SentryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentryClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SentryClient {
    /// Create a new Sentry client.
    pub fn new(auth: SentryAuth, base_url: Option<&str>) -> SentryResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-sentry/0.1.0")
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
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: SentryAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 0,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SentryAuth::BearerToken(token) => req.bearer_auth(token),
            SentryAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SentryResult<serde_json::Value> {
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
    ) -> SentryResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.detail)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SentryError::Unauthorized),
            403 => Err(SentryError::Forbidden),
            404 => Err(SentryError::NotFound { resource: detail }),
            429 => Err(SentryError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SentryError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Issue a request with retry.
    ///
    /// br-kxd3e: replay safety is derived from the verb, which is sound here
    /// because this client uses each one for its standard meaning — GET reads,
    /// PUT/PATCH set named fields to named values, DELETE converges, and only
    /// POST creates. A replay of a POST after a 5xx creates a second object or
    /// double-counts an ingested event.
    async fn request_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> SentryResult<serde_json::Value> {
        let replay_safe = http_method != "POST";
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "sentry request");

            let req = match http_method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "DELETE" => self.client.delete(url),
                _ => unreachable!(),
            };
            let req = if let Some(b) = body { req.json(b) } else { req };
            let req = self.add_auth(req);

            match req.send().await {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(val) => AttemptOutcome::Success(val),
                    Err(err) if err.is_retryable() => {
                        let replayable = replay_safe || err.replay_is_safe();
                        let retry_after = err.retry_after();
                        AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                    }
                    Err(err) => AttemptOutcome::Terminal(err),
                },
                Err(err) => {
                    let err = SentryError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SentryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> SentryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body)).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(&self, path: &str, body: &serde_json::Value) -> SentryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("PUT", &url, Some(body)).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> SentryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("DELETE", &url, None).await
    }

    // ── Projects ──────────────────────────────────────────────────────

    /// List projects in an organization.
    pub async fn list_projects(
        &self,
        org: &str,
        cursor: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let path = if let Some(cursor) = cursor {
            format!(
                "/organizations/{org}/projects/?cursor={}",
                encode_query_value(cursor)
            )
        } else {
            format!("/organizations/{org}/projects/")
        };
        self.get(&path).await
    }

    // ── Issues ────────────────────────────────────────────────────────

    /// List issues in a project.
    pub async fn list_issues(
        &self,
        org: &str,
        project: &str,
        query: Option<&str>,
        sort: Option<&str>,
        cursor: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project_seg = sanitize_path_segment(project);
        let mut params = Vec::new();
        params.push(format!("project={}", encode_query_value(project)));
        if let Some(q) = query {
            params.push(format!("query={}", encode_query_value(q)));
        }
        if let Some(s) = sort {
            params.push(format!("sort={}", encode_query_value(s)));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", encode_query_value(c)));
        }
        let qs = params.join("&");
        self.get(&format!("/projects/{org}/{project_seg}/issues/?{qs}"))
            .await
    }

    /// Get a single issue by ID.
    pub async fn get_issue(&self, issue_id: &str) -> SentryResult<serde_json::Value> {
        let issue_id = sanitize_path_segment(issue_id);
        self.get(&format!("/issues/{issue_id}/")).await
    }

    /// Search issues with structured filters.
    pub async fn search_issues(
        &self,
        org: &str,
        project: &str,
        query: Option<&str>,
        status: Option<&str>,
        assigned_to: Option<&str>,
        level: Option<&str>,
        first_seen_start: Option<&str>,
        first_seen_end: Option<&str>,
        sort: Option<&str>,
        cursor: Option<&str>,
        per_page: Option<u32>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project_seg = sanitize_path_segment(project);
        let mut parts = Vec::new();
        // Build the Sentry search query string from structured params
        if let Some(q) = query {
            parts.push(q.to_string());
        }
        if let Some(s) = status {
            parts.push(format!("is:{s}"));
        }
        if let Some(a) = assigned_to {
            parts.push(format!("assigned:{a}"));
        }
        if let Some(l) = level {
            parts.push(format!("level:{l}"));
        }
        if let Some(start) = first_seen_start {
            parts.push(format!("firstSeen:>{start}"));
        }
        if let Some(end) = first_seen_end {
            parts.push(format!("firstSeen:<{end}"));
        }
        let combined_query = parts.join(" ");

        let mut params = Vec::new();
        params.push(format!("project={}", encode_query_value(project)));
        if !combined_query.is_empty() {
            params.push(format!("query={}", encode_query_value(&combined_query)));
        }
        if let Some(s) = sort {
            params.push(format!("sort={}", encode_query_value(s)));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", encode_query_value(c)));
        }
        if let Some(pp) = per_page {
            params.push(format!("per_page={pp}"));
        }
        let qs = params.join("&");
        self.get(&format!("/projects/{org}/{project_seg}/issues/?{qs}"))
            .await
    }

    /// Get issue summary (concise metadata without full event data).
    pub async fn get_issue_summary(&self, issue_id: &str) -> SentryResult<serde_json::Value> {
        let issue_id = sanitize_path_segment(issue_id);
        self.get(&format!("/issues/{issue_id}/")).await
    }

    /// Update an issue (status, assignment, etc.).
    pub async fn update_issue(
        &self,
        issue_id: &str,
        update: &serde_json::Value,
    ) -> SentryResult<serde_json::Value> {
        let issue_id = sanitize_path_segment(issue_id);
        self.put(&format!("/issues/{issue_id}/"), update).await
    }

    /// Delete an issue permanently.
    pub async fn delete_issue(&self, issue_id: &str) -> SentryResult<serde_json::Value> {
        let issue_id = sanitize_path_segment(issue_id);
        self.delete(&format!("/issues/{issue_id}/")).await
    }

    // ── Events ────────────────────────────────────────────────────────

    /// List events for an issue.
    pub async fn list_issue_events(
        &self,
        issue_id: &str,
        full: bool,
        cursor: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let issue_id = sanitize_path_segment(issue_id);
        let mut params = Vec::new();
        if full {
            params.push("full=true".to_string());
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", encode_query_value(c)));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/issues/{issue_id}/events/{qs}")).await
    }

    /// Get a single event.
    pub async fn get_event(
        &self,
        org: &str,
        project: &str,
        event_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let event_id = sanitize_path_segment(event_id);
        self.get(&format!("/projects/{org}/{project}/events/{event_id}/"))
            .await
    }

    // ── Releases ──────────────────────────────────────────────────────

    /// List releases.
    pub async fn list_releases(
        &self,
        org: &str,
        project: Option<&str>,
        query: Option<&str>,
        cursor: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let mut params = Vec::new();
        if let Some(p) = project {
            params.push(format!("project={}", encode_query_value(p)));
        }
        if let Some(q) = query {
            params.push(format!("query={}", encode_query_value(q)));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", encode_query_value(c)));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/organizations/{org}/releases/{qs}"))
            .await
    }

    /// Get a single release.
    pub async fn get_release(&self, org: &str, version: &str) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let encoded_version = urlencoded(version);
        self.get(&format!("/organizations/{org}/releases/{encoded_version}/"))
            .await
    }

    /// Delete a release.
    pub async fn delete_release(
        &self,
        org: &str,
        version: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let encoded_version = urlencoded(version);
        self.delete(&format!("/organizations/{org}/releases/{encoded_version}/"))
            .await
    }

    /// List deploys for a release.
    pub async fn list_release_deploys(
        &self,
        org: &str,
        version: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let encoded_version = urlencoded(version);
        self.get(&format!(
            "/organizations/{org}/releases/{encoded_version}/deploys/"
        ))
        .await
    }

    // ── Discover ──────────────────────────────────────────────────────

    /// Run a Discover query.
    pub async fn discover_query(
        &self,
        org: &str,
        query: &str,
        fields: &[String],
        stats_period: Option<&str>,
        start: Option<&str>,
        end: Option<&str>,
        sort: Option<&str>,
        per_page: Option<u32>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let mut params = Vec::new();
        params.push(format!("query={}", encode_query_value(query)));
        for f in fields {
            params.push(format!("field={}", encode_query_value(f)));
        }
        if let Some(sp) = stats_period {
            params.push(format!("statsPeriod={}", encode_query_value(sp)));
        }
        if let Some(s) = start {
            params.push(format!("start={}", encode_query_value(s)));
        }
        if let Some(e) = end {
            params.push(format!("end={}", encode_query_value(e)));
        }
        if let Some(s) = sort {
            params.push(format!("sort={}", encode_query_value(s)));
        }
        if let Some(pp) = per_page {
            params.push(format!("per_page={pp}"));
        }
        let qs = params.join("&");
        self.get(&format!("/organizations/{org}/events/?{qs}"))
            .await
    }

    // ── Transactions ──────────────────────────────────────────────────

    /// Get a transaction event.
    pub async fn get_transaction(
        &self,
        org: &str,
        project: &str,
        event_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let event_id = sanitize_path_segment(event_id);
        self.get(&format!("/projects/{org}/{project}/events/{event_id}/"))
            .await
    }

    // ── Performance ──────────────────────────────────────────────────

    /// Query performance transactions using Discover.
    pub async fn query_transactions(
        &self,
        org: &str,
        project: &str,
        transaction: Option<&str>,
        environment: Option<&str>,
        start: Option<&str>,
        end: Option<&str>,
        sort: Option<&str>,
        per_page: Option<u32>,
        cursor: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let mut params = vec![
            format!("project={}", encode_query_value(project)),
            "field=transaction".to_string(),
            "field=count()".to_string(),
            "field=p50()".to_string(),
            "field=p95()".to_string(),
            "field=failure_rate()".to_string(),
        ];
        let mut query_parts = vec!["event.type:transaction".to_string()];
        if let Some(t) = transaction {
            query_parts.push(format!("transaction:{t}"));
        }
        if let Some(e) = environment {
            params.push(format!("environment={}", encode_query_value(e)));
        }
        let query = query_parts.join(" ");
        params.push(format!("query={}", encode_query_value(&query)));
        if let Some(s) = start {
            params.push(format!("start={}", encode_query_value(s)));
        }
        if let Some(e) = end {
            params.push(format!("end={}", encode_query_value(e)));
        }
        if let Some(s) = sort {
            params.push(format!("sort={}", encode_query_value(s)));
        }
        if let Some(pp) = per_page {
            params.push(format!("per_page={pp}"));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", encode_query_value(c)));
        }
        let qs = params.join("&");
        self.get(&format!("/organizations/{org}/events/?{qs}"))
            .await
    }

    /// Get performance summary for a transaction name.
    pub async fn get_transaction_summary(
        &self,
        org: &str,
        project: &str,
        transaction: &str,
        environment: Option<&str>,
        start: Option<&str>,
        end: Option<&str>,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let query_str = format!("event.type:transaction transaction:{transaction}");
        let mut params = vec![
            format!("project={}", encode_query_value(project)),
            "field=count()".to_string(),
            "field=p50(transaction.duration)".to_string(),
            "field=p75(transaction.duration)".to_string(),
            "field=p95(transaction.duration)".to_string(),
            "field=p99(transaction.duration)".to_string(),
            "field=failure_rate()".to_string(),
            "field=apdex()".to_string(),
            format!("query={}", encode_query_value(&query_str)),
        ];
        if let Some(e) = environment {
            params.push(format!("environment={}", encode_query_value(e)));
        }
        if let Some(s) = start {
            params.push(format!("start={}", encode_query_value(s)));
        }
        if let Some(e) = end {
            params.push(format!("end={}", encode_query_value(e)));
        }
        let qs = params.join("&");
        self.get(&format!("/organizations/{org}/events/?{qs}"))
            .await
    }

    /// Get trace summary.
    pub async fn get_trace_summary(
        &self,
        org: &str,
        trace_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let trace_id = sanitize_path_segment(trace_id);
        self.get(&format!("/organizations/{org}/events-trace/{trace_id}/"))
            .await
    }

    // ── Release Health ───────────────────────────────────────────────

    /// Get release health summary.
    pub async fn get_release_health(
        &self,
        org: &str,
        project: &str,
        version: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let qs = format!("project={}", encode_query_value(project));
        let encoded_version = urlencoded(version);
        self.get(&format!(
            "/organizations/{org}/releases/{encoded_version}/health/?{qs}"
        ))
        .await
    }

    /// Create a release.
    pub async fn create_release(
        &self,
        org: &str,
        body: &serde_json::Value,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        self.post(&format!("/organizations/{org}/releases/"), body)
            .await
    }

    // ── Alert Rules ───────────────────────────────────────────────────

    /// List alert rules for a project.
    pub async fn list_alert_rules(
        &self,
        org: &str,
        project: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        self.get(&format!("/projects/{org}/{project}/rules/")).await
    }

    /// Create an alert rule.
    pub async fn create_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule: &serde_json::Value,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        self.post(&format!("/projects/{org}/{project}/rules/"), rule)
            .await
    }

    /// Update an alert rule.
    pub async fn update_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule_id: &str,
        rule: &serde_json::Value,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let rule_id = sanitize_path_segment(rule_id);
        self.put(&format!("/projects/{org}/{project}/rules/{rule_id}/"), rule)
            .await
    }

    /// Delete an alert rule.
    pub async fn delete_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let rule_id = sanitize_path_segment(rule_id);
        self.delete(&format!("/projects/{org}/{project}/rules/{rule_id}/"))
            .await
    }

    /// Get a single alert rule by ID.
    pub async fn get_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let rule_id = sanitize_path_segment(rule_id);
        self.get(&format!("/projects/{org}/{project}/rules/{rule_id}/"))
            .await
    }

    /// Enable an alert rule.
    pub async fn enable_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let rule_id = sanitize_path_segment(rule_id);
        self.put(
            &format!("/projects/{org}/{project}/rules/{rule_id}/"),
            &serde_json::json!({"status": "active"}),
        )
        .await
    }

    /// Disable an alert rule.
    pub async fn disable_alert_rule(
        &self,
        org: &str,
        project: &str,
        rule_id: &str,
    ) -> SentryResult<serde_json::Value> {
        let org = sanitize_path_segment(org);
        let project = sanitize_path_segment(project);
        let rule_id = sanitize_path_segment(rule_id);
        self.put(
            &format!("/projects/{org}/{project}/rules/{rule_id}/"),
            &serde_json::json!({"status": "disabled"}),
        )
        .await
    }
}

/// Percent-encode a query parameter value.
fn encode_query_value(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Sanitize a path segment by rejecting slashes and other path-traversal characters.
fn sanitize_path_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Minimal, readability-preserving URL encoding for release version strings.
///
/// Sentry release versions are embedded as a path segment (e.g.
/// `/organizations/{org}/releases/{version}/`). Beyond the display-oriented
/// escapes (`%`, `+`, space, `@`), this also neutralizes the characters that
/// would otherwise let a caller-supplied `version` escape that segment:
/// `/`/`\` (segment splitting → `Url::parse` normalization), `..` (dot-segment
/// traversal, e.g. `delete_release` with `../../organizations/<victim>/...`),
/// and `?`/`#` (query/fragment injection against the API host). `%` is replaced
/// first so the encodings emitted here are not double-encoded.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace("..", "%2E%2E")
        .replace('/', "%2F")
        .replace('\\', "%5C")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace('+', "%2B")
        .replace(' ', "%20")
        .replace('@', "%40")
}

fn decode_success_body(status: StatusCode, body: &str) -> SentryResult<serde_json::Value> {
    if matches!(status, StatusCode::NO_CONTENT | StatusCode::ACCEPTED) {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SentryError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_value_special_chars() {
        let encoded = encode_query_value("hello world&foo=bar");
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn encode_query_value_empty() {
        assert_eq!(encode_query_value(""), "");
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            SentryError::Api {
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
            SentryError::Api {
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

    #[test]
    fn decode_success_body_allows_empty_accepted() {
        assert_eq!(
            decode_success_body(StatusCode::ACCEPTED, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_slashes() {
        let sanitized = sanitize_path_segment("my/org");
        assert!(!sanitized.contains('/'));
    }

    #[test]
    fn sanitize_path_segment_normal_input() {
        // Alphanumeric chars are preserved
        let sanitized = sanitize_path_segment("myorg123");
        assert_eq!(sanitized, "myorg123");
    }

    #[test]
    fn sanitize_path_segment_dots_and_dashes() {
        let sanitized = sanitize_path_segment("my-org.name");
        assert!(!sanitized.contains('.'));
        assert!(!sanitized.contains('-'));
    }

    #[test]
    fn url_encode_version_strings() {
        assert_eq!(urlencoded("backend@1.2.3"), "backend%401.2.3");
        assert_eq!(urlencoded("v1.0+build42"), "v1.0%2Bbuild42");
        assert_eq!(urlencoded("simple"), "simple");
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SentryAuth::BearerToken("supersecret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let bearer = SentryAuth::BearerToken("tok".into());
        assert!(!bearer.is_secretless());

        let cred = SentryAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    // ── Auth label ────────────────────────────────────────────────

    #[test]
    fn auth_bearer_token_redacted_label() {
        let auth = SentryAuth::BearerToken("sntrys_secret".into());
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_label() {
        let cred = SentryAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    // ── Auth clone ────────────────────────────────────────────────

    #[test]
    fn auth_bearer_clone() {
        let auth = SentryAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_id_clone() {
        let cred = SentryAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        assert!(cred.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_debug_credential_id_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = SentryAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&id_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_debug_bearer_no_leak() {
        let auth = SentryAuth::BearerToken("sntrys_very_secret_token_12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("sntrys_very_secret"));
        assert!(!dbg.contains("12345"));
        assert!(dbg.contains("BearerToken"));
    }

    // ── Client construction ───────────────────────────────────────

    #[test]
    fn client_new_default_url() {
        let client = SentryClient::new(SentryAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SentryClient::new(
            SentryAuth::BearerToken("tok".into()),
            Some("https://sentry.example.com/api/0"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://sentry.example.com/api/0");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = SentryClient::new(
            SentryAuth::BearerToken("tok".into()),
            Some("https://sentry.example.com/api/0/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://sentry.example.com/api/0");
    }

    #[test]
    fn client_debug_redacts_token() {
        let client =
            SentryClient::new(SentryAuth::BearerToken("supersecret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("SentryClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_with_client_trims_trailing_slash() {
        let inner = Client::new();
        let auth = SentryAuth::BearerToken("tok".into());
        let client = SentryClient::with_client(inner, auth, "https://example.com/");
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            SentryClient::new(SentryAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    // ── DEFAULT_BASE_URL ──────────────────────────────────────────

    #[test]
    fn default_base_url_constant() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
        assert!(DEFAULT_BASE_URL.contains("sentry.io"));
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    // ── urlencoded edge cases ─────────────────────────────────────

    #[test]
    fn url_encode_spaces() {
        assert_eq!(urlencoded("my version"), "my%20version");
    }

    #[test]
    fn url_encode_percent() {
        assert_eq!(urlencoded("100%"), "100%25");
    }

    #[test]
    fn url_encode_at_sign() {
        assert_eq!(urlencoded("user@host"), "user%40host");
    }

    #[test]
    fn url_encode_empty_string() {
        assert_eq!(urlencoded(""), "");
    }

    #[test]
    fn url_encode_no_special_chars() {
        assert_eq!(urlencoded("abc123"), "abc123");
    }

    #[test]
    fn url_encode_multiple_specials() {
        let result = urlencoded("a@b+c d%e");
        assert_eq!(result, "a%40b%2Bc%20d%25e");
    }

    #[test]
    fn urlencoded_neutralizes_path_traversal_and_injection() {
        // A release version must not be able to escape its path segment. Each of
        // these would otherwise redirect delete/get_release to another endpoint
        // or inject a query/fragment.
        let attack = "../../../organizations/victim/projects/proj";
        let encoded = urlencoded(attack);
        assert!(!encoded.contains('/'), "slash survived: {encoded}");
        assert!(!encoded.contains(".."), "dot-segment survived: {encoded}");

        assert_eq!(urlencoded("a/b"), "a%2Fb");
        assert_eq!(urlencoded("a\\b"), "a%5Cb");
        assert_eq!(urlencoded("v1?x=y"), "v1%3Fx=y");
        assert_eq!(urlencoded("v1#frag"), "v1%23frag");
        assert_eq!(urlencoded(".."), "%2E%2E");
        // A normal semver-style release is left readable.
        assert_eq!(urlencoded("v1.2.3"), "v1.2.3");
    }
}
