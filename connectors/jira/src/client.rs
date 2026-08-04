//! Jira REST API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{JiraError, JiraResult},
    types::{
        ApiErrorResponse, AutomationRuleListResponse, CommentListResponse, CreateIssueResponse,
        JiraAttachment, JiraAutomationRule, JiraComment, JiraDeployment, JiraIssue, JiraServerInfo,
        JiraWorklog, SearchResult, SprintListResponse, TransitionsResponse, WorklogListResponse,
    },
};

/// Default Jira REST API base URL template (append domain).
pub const DEFAULT_REST_BASE: &str = "https://{domain}.atlassian.net/rest/api/3";

/// Default Jira Agile API base URL template (append domain).
pub const DEFAULT_AGILE_BASE: &str = "https://{domain}.atlassian.net/rest/agile/1.0";

/// Authentication mode for the Jira client.
#[derive(Clone)]
pub enum JiraAuth {
    /// Direct credentials: email + API token (Basic auth).
    Token {
        domain: String,
        email: String,
        api_token: String,
    },
    /// Secretless credential injection via egress proxy.
    CredentialId {
        domain: String,
        credential_id: CredentialId,
    },
}

impl std::fmt::Debug for JiraAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { domain, email, .. } => f
                .debug_struct("Token")
                .field("domain", domain)
                .field("email", email)
                .field("api_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                domain,
                credential_id,
            } => f
                .debug_struct("CredentialId")
                .field("domain", domain)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl JiraAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Get the domain regardless of auth mode.
    #[must_use]
    pub fn domain(&self) -> &str {
        match self {
            Self::Token { domain, .. } | Self::CredentialId { domain, .. } => domain,
        }
    }
}

/// Default Jira Automation API base URL template (append domain).
pub const DEFAULT_AUTOMATION_BASE: &str =
    "https://{domain}.atlassian.net/rest/cb-automation/latest";

/// Validate a Jira issue key (e.g. `PROJ-123`).
///
/// Jira issue keys follow the pattern `[A-Za-z][A-Za-z0-9_]*-[0-9]+`.
/// This rejects empty strings, strings without a hyphen, and any character
/// outside the `[A-Za-z0-9_-]` set to prevent path injection.
fn validate_issue_key(key: &str) -> JiraResult<&str> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        || !key.contains('-')
    {
        return Err(JiraError::InvalidInput(format!("Invalid issue key: {key}")));
    }
    Ok(key)
}

/// Validate a Jira project key/ID (e.g. `PROJ` or numeric `10001`).
///
/// Allows only ASCII alphanumeric characters, hyphens, and underscores.
fn validate_project_key(key: &str) -> JiraResult<&str> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(JiraError::InvalidInput(format!(
            "Invalid project key: {key}"
        )));
    }
    Ok(key)
}

/// Validate an opaque ID (worklog, rule, etc.) for safe URL interpolation.
///
/// Allows only ASCII alphanumeric characters, hyphens, and underscores.
fn validate_id<'a>(id: &'a str, label: &str) -> JiraResult<&'a str> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(JiraError::InvalidInput(format!("Invalid {label}: {id}")));
    }
    Ok(id)
}

/// Jira REST API client with retry logic and rate limit awareness.
pub struct JiraClient {
    client: Client,
    auth: JiraAuth,
    deployment: JiraDeployment,
    base_url: String,
    agile_url: String,
    automation_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for JiraClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JiraClient")
            .field("auth", &self.auth)
            .field("deployment", &self.deployment)
            .field("base_url", &self.base_url)
            .field("agile_url", &self.agile_url)
            .field("automation_url", &self.automation_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl JiraClient {
    /// Create a new Jira client with basic auth (email + API token).
    pub fn new(domain: &str, email: &str, api_token: &str) -> JiraResult<Self> {
        Self::new_with_auth(JiraAuth::Token {
            domain: domain.to_string(),
            email: email.to_string(),
            api_token: api_token.to_string(),
        })
    }

    /// Create a new Jira client with the given auth mode (defaults to Cloud deployment).
    pub fn new_with_auth(auth: JiraAuth) -> JiraResult<Self> {
        Self::new_with_auth_and_deployment(auth, JiraDeployment::Cloud)
    }

    /// Create a new Jira client with the given auth mode and deployment type.
    pub fn new_with_auth_and_deployment(
        auth: JiraAuth,
        deployment: JiraDeployment,
    ) -> JiraResult<Self> {
        let mut headers = reqwest::header::HeaderMap::new();

        match &auth {
            JiraAuth::Token {
                email, api_token, ..
            } => {
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{email}:{api_token}"));
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {credentials}").parse().unwrap(),
                );
            }
            JiraAuth::CredentialId { credential_id, .. } => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    credential_id.to_string().parse().unwrap(),
                );
            }
        }

        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(reqwest::header::ACCEPT, "application/json".parse().unwrap());

        let domain = auth.domain();
        let api_version = deployment.api_version();
        let base_url = format!("https://{domain}.atlassian.net/rest/api/{api_version}");
        let agile_url = format!("https://{domain}.atlassian.net/rest/agile/1.0");
        let automation_url = format!("https://{domain}.atlassian.net/rest/cb-automation/latest");

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-jira/0.1.0")
            .build()
            .map_err(JiraError::Http)?;

        Ok(Self {
            client,
            auth,
            deployment,
            base_url,
            agile_url,
            automation_url,
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

    /// Perform a health check by fetching the current user.
    pub async fn health_check(&self) -> JiraResult<serde_json::Value> {
        let url = format!("{}/myself", self.base_url);
        self.get(&url).await
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set a custom agile URL (for testing).
    #[must_use]
    pub fn with_agile_url(mut self, url: &str) -> Self {
        self.agile_url = url.to_string();
        self
    }

    /// Set a custom automation API URL (for testing).
    #[must_use]
    pub fn with_automation_url(mut self, url: &str) -> Self {
        self.automation_url = url.to_string();
        self
    }

    /// Set the deployment type, adjusting the base URL API version accordingly.
    #[must_use]
    pub fn with_deployment(mut self, deployment: JiraDeployment) -> Self {
        self.deployment = deployment;
        // Rewrite the base_url to use the correct API version if it still uses
        // the default atlassian.net pattern.
        let old_versions = ["3", "2"];
        for old_ver in &old_versions {
            let old_segment = format!("/rest/api/{old_ver}");
            if self.base_url.contains(&old_segment) {
                let new_segment = format!("/rest/api/{}", deployment.api_version());
                self.base_url = self.base_url.replace(&old_segment, &new_segment);
                break;
            }
        }
        self
    }

    /// Return the REST API path prefix for the current deployment.
    ///
    /// Cloud uses `/rest/api/3`, Server/DC uses `/rest/api/2`.
    #[must_use]
    pub fn api_path(&self) -> String {
        format!("/rest/api/{}", self.deployment.api_version())
    }

    /// Return the current deployment type.
    #[must_use]
    pub const fn deployment(&self) -> JiraDeployment {
        self.deployment
    }

    /// Fetch server information from the Jira instance.
    ///
    /// This always uses the `/rest/api/2/serverInfo` endpoint, which is
    /// available on both Cloud and Server/DC.
    pub async fn server_info(&self) -> JiraResult<JiraServerInfo> {
        // serverInfo is available at /rest/api/2 on all deployments
        let host = self
            .base_url
            .split("/rest/")
            .next()
            .unwrap_or(&self.base_url);
        let url = format!("{host}/rest/api/2/serverInfo");
        self.get(&url).await
    }

    /// Auto-detect the deployment type by calling `/rest/api/2/serverInfo`.
    ///
    /// Returns `Cloud` if `deploymentType` is `"Cloud"`, otherwise `ServerDc`.
    pub async fn detect_deployment(&self) -> JiraResult<JiraDeployment> {
        let info = self.server_info().await?;
        let deployment = match info.deployment_type.as_deref() {
            Some("Cloud") => JiraDeployment::Cloud,
            _ => JiraDeployment::ServerDc,
        };
        Ok(deployment)
    }

    /// Set retry configuration.
    #[must_use]
    pub fn with_retry_config(
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

    // ── Issue operations ─────────────────────────────────────────

    /// Create a new issue.
    #[instrument(skip(self, input))]
    pub async fn create_issue(&self, input: &serde_json::Value) -> JiraResult<CreateIssueResponse> {
        self.post(&format!("{}/issue", self.base_url), input, false)
            .await
    }

    /// Get an issue by key or ID.
    #[instrument(skip(self))]
    pub async fn get_issue(
        &self,
        issue_key: &str,
        fields: Option<&str>,
        expand: Option<&str>,
    ) -> JiraResult<JiraIssue> {
        let issue_key = validate_issue_key(issue_key)?;
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        let mut sep = '?';
        if let Some(fields) = fields {
            let encoded =
                percent_encoding::utf8_percent_encode(fields, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}fields={encoded}");
            sep = '&';
        }
        if let Some(expand) = expand {
            let encoded =
                percent_encoding::utf8_percent_encode(expand, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}expand={encoded}");
        }

        self.get(&url).await
    }

    /// Update an issue's fields.
    #[instrument(skip(self, body))]
    pub async fn update_issue(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
        notify_users: bool,
    ) -> JiraResult<()> {
        let issue_key = validate_issue_key(issue_key)?;
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        if !notify_users {
            url.push_str("?notifyUsers=false");
        }

        self.put_no_content(&url, body).await
    }

    /// Delete an issue.
    #[instrument(skip(self))]
    pub async fn delete_issue(&self, issue_key: &str, delete_subtasks: bool) -> JiraResult<()> {
        let issue_key = validate_issue_key(issue_key)?;
        let mut url = format!("{}/issue/{issue_key}", self.base_url);
        if delete_subtasks {
            url.push_str("?deleteSubtasks=true");
        }

        self.delete(&url).await
    }

    // ── Search ───────────────────────────────────────────────────

    /// Search issues using JQL (POST method for complex queries).
    #[instrument(skip(self, body))]
    pub async fn search_jql(&self, body: &serde_json::Value) -> JiraResult<SearchResult> {
        self.post(&format!("{}/search", self.base_url), body, true)
            .await
    }

    // ── Transitions ──────────────────────────────────────────────

    /// List available transitions for an issue.
    #[instrument(skip(self))]
    pub async fn list_transitions(&self, issue_key: &str) -> JiraResult<TransitionsResponse> {
        let issue_key = validate_issue_key(issue_key)?;
        self.get(&format!("{}/issue/{issue_key}/transitions", self.base_url))
            .await
    }

    /// Execute a transition on an issue.
    #[instrument(skip(self, body))]
    pub async fn transition_issue(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
    ) -> JiraResult<()> {
        let issue_key = validate_issue_key(issue_key)?;
        // NOT replay-safe: a transition body may carry an `update.comment`,
        // and Jira permits self-loop transitions, so a replay can post a
        // second comment. Fail closed rather than reason about the workflow.
        self.post_no_content(
            &format!("{}/issue/{issue_key}/transitions", self.base_url),
            body,
            false,
        )
        .await
    }

    // ── Sprint operations ────────────────────────────────────────

    /// List sprints for a board.
    #[instrument(skip(self))]
    pub async fn list_sprints(
        &self,
        board_id: u64,
        state: Option<&str>,
        start_at: Option<u64>,
        max_results: Option<u64>,
    ) -> JiraResult<SprintListResponse> {
        let mut url = format!("{}/board/{board_id}/sprint", self.agile_url);
        let mut sep = '?';
        if let Some(state) = state {
            let encoded =
                percent_encoding::utf8_percent_encode(state, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}state={encoded}");
            sep = '&';
        }
        if let Some(start_at) = start_at {
            let _ = write!(url, "{sep}startAt={start_at}");
            sep = '&';
        }
        if let Some(max_results) = max_results {
            let _ = write!(url, "{sep}maxResults={max_results}");
        }

        self.get(&url).await
    }

    /// Move issues to a sprint.
    #[instrument(skip(self, body))]
    pub async fn move_to_sprint(&self, sprint_id: u64, body: &serde_json::Value) -> JiraResult<()> {
        // Replay-safe: sprint membership is a set, so moving the same
        // issues in twice leaves them in the sprint once.
        self.post_no_content(
            &format!("{}/sprint/{sprint_id}/issue", self.agile_url),
            body,
            true,
        )
        .await
    }

    // ── Comment operations ───────────────────────────────────────

    /// Add a comment to an issue.
    #[instrument(skip(self, body))]
    pub async fn add_comment(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraComment> {
        let issue_key = validate_issue_key(issue_key)?;
        // NOT replay-safe: a duplicate is a second comment on the issue.
        self.post(
            &format!("{}/issue/{issue_key}/comment", self.base_url),
            body,
            false,
        )
        .await
    }

    /// List comments on an issue.
    #[instrument(skip(self))]
    pub async fn list_comments(
        &self,
        issue_key: &str,
        start_at: Option<u64>,
        max_results: Option<u64>,
        order_by: Option<&str>,
    ) -> JiraResult<CommentListResponse> {
        let issue_key = validate_issue_key(issue_key)?;
        let mut url = format!("{}/issue/{issue_key}/comment", self.base_url);
        let mut sep = '?';
        if let Some(start_at) = start_at {
            let _ = write!(url, "{sep}startAt={start_at}");
            sep = '&';
        }
        if let Some(max_results) = max_results {
            let _ = write!(url, "{sep}maxResults={max_results}");
            sep = '&';
        }
        if let Some(order_by) = order_by {
            let encoded =
                percent_encoding::utf8_percent_encode(order_by, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{sep}orderBy={encoded}");
        }

        self.get(&url).await
    }

    // ── Worklog operations ────────────────────────────────────────

    /// List worklogs for an issue.
    #[instrument(skip(self))]
    pub async fn list_worklogs(
        &self,
        issue_key: &str,
        start_at: Option<u64>,
        max_results: Option<u64>,
    ) -> JiraResult<WorklogListResponse> {
        let issue_key = validate_issue_key(issue_key)?;
        let mut url = format!("{}/issue/{issue_key}/worklog", self.base_url);
        let mut sep = '?';
        if let Some(start_at) = start_at {
            let _ = write!(url, "{sep}startAt={start_at}");
            sep = '&';
        }
        if let Some(max_results) = max_results {
            let _ = write!(url, "{sep}maxResults={max_results}");
        }

        self.get(&url).await
    }

    /// Add a worklog entry to an issue.
    #[instrument(skip(self, body))]
    pub async fn add_worklog(
        &self,
        issue_key: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraWorklog> {
        let issue_key = validate_issue_key(issue_key)?;
        // NOT replay-safe: a duplicate worklog double-counts logged time,
        // which flows into billing and capacity reports.
        self.post(
            &format!("{}/issue/{issue_key}/worklog", self.base_url),
            body,
            false,
        )
        .await
    }

    /// Update a worklog entry.
    #[instrument(skip(self, body))]
    pub async fn update_worklog(
        &self,
        issue_key: &str,
        worklog_id: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraWorklog> {
        let issue_key = validate_issue_key(issue_key)?;
        let worklog_id = validate_id(worklog_id, "worklog_id")?;
        let url = format!("{}/issue/{issue_key}/worklog/{worklog_id}", self.base_url);
        self.put(&url, body).await
    }

    /// Delete a worklog entry.
    #[instrument(skip(self))]
    pub async fn delete_worklog(&self, issue_key: &str, worklog_id: &str) -> JiraResult<()> {
        let issue_key = validate_issue_key(issue_key)?;
        let worklog_id = validate_id(worklog_id, "worklog_id")?;
        self.delete(&format!(
            "{}/issue/{issue_key}/worklog/{worklog_id}",
            self.base_url
        ))
        .await
    }

    // ── Attachment operations ────────────────────────────────────

    /// Upload an attachment to an issue (multipart).
    #[instrument(skip(self, data))]
    pub async fn add_attachment(
        &self,
        issue_key: &str,
        filename: &str,
        data: &[u8],
    ) -> JiraResult<Vec<JiraAttachment>> {
        let issue_key = validate_issue_key(issue_key)?;
        let url = format!("{}/issue/{issue_key}/attachments", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, filename, "Jira attachment upload");

                let part = match reqwest::multipart::Part::bytes(data.to_vec())
                    .file_name(filename.to_string())
                    .mime_str("application/octet-stream")
                {
                    Ok(part) => part,
                    Err(error) => {
                        return AttemptOutcome::Terminal(JiraError::Api {
                            message: format!("invalid attachment MIME metadata: {error}"),
                            status_code: None,
                        });
                    }
                };

                let form = reqwest::multipart::Form::new().part("file", part);

                match self
                    .client
                    .post(url)
                    .header("X-Atlassian-Token", "no-check")
                    .multipart(form)
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        if let Some(retry_result) = Self::check_rate_limit(&response) {
                            return AttemptOutcome::Retryable {
                                error: JiraError::RateLimited {
                                    retry_after_ms: retry_result
                                        .map_or(60_000, |d| d.as_millis() as u64),
                                },
                                retry_after: retry_result,
                            };
                        }

                        let retry_after_ms = Self::extract_retry_after_ms(&response);
                        let bytes = match response.bytes().await {
                            Ok(bytes) => bytes,
                            Err(error) => return AttemptOutcome::Terminal(JiraError::Http(error)),
                        };

                        if status.is_success() {
                            return match serde_json::from_slice(&bytes) {
                                Ok(attachments) => AttemptOutcome::Success(attachments),
                                Err(error) => AttemptOutcome::Terminal(JiraError::from(error)),
                            };
                        }

                        let error = Self::parse_error(status, &bytes, retry_after_ms);
                        if error.is_retryable() {
                            AttemptOutcome::Retryable {
                                retry_after: error.retry_after(),
                                error,
                            }
                        } else {
                            AttemptOutcome::Terminal(error)
                        }
                    }
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            error: JiraError::Http(error),
                            retry_after: None,
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(JiraError::Http(error)),
                }
            }
        })
        .await
    }

    // ── Automation Rule operations ─────────────────────────────────

    /// List automation rules for a project.
    #[instrument(skip(self))]
    pub async fn list_automation_rules(
        &self,
        project_id: &str,
    ) -> JiraResult<AutomationRuleListResponse> {
        let project_id = validate_project_key(project_id)?;
        let url = format!("{}/project/{project_id}/rule", self.automation_url);
        self.get(&url).await
    }

    /// Get a single automation rule by ID.
    #[instrument(skip(self))]
    pub async fn get_automation_rule(&self, rule_id: &str) -> JiraResult<JiraAutomationRule> {
        let rule_id = validate_id(rule_id, "rule_id")?;
        let url = format!("{}/rule/{rule_id}", self.automation_url);
        self.get(&url).await
    }

    /// Create a new automation rule for a project.
    #[instrument(skip(self, body))]
    pub async fn create_automation_rule(
        &self,
        project_id: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraAutomationRule> {
        let project_id = validate_project_key(project_id)?;
        let url = format!("{}/project/{project_id}/rule", self.automation_url);
        self.post(&url, body, false).await
    }

    /// Update an automation rule.
    #[instrument(skip(self, body))]
    pub async fn update_automation_rule(
        &self,
        rule_id: &str,
        body: &serde_json::Value,
    ) -> JiraResult<JiraAutomationRule> {
        let rule_id = validate_id(rule_id, "rule_id")?;
        let url = format!("{}/rule/{rule_id}", self.automation_url);
        self.put(&url, body).await
    }

    /// Enable an automation rule.
    #[instrument(skip(self))]
    pub async fn enable_automation_rule(&self, rule_id: &str) -> JiraResult<()> {
        let rule_id = validate_id(rule_id, "rule_id")?;
        let url = format!("{}/rule/{rule_id}/enable", self.automation_url);
        self.put_no_content(&url, &serde_json::json!({})).await
    }

    /// Disable an automation rule.
    #[instrument(skip(self))]
    pub async fn disable_automation_rule(&self, rule_id: &str) -> JiraResult<()> {
        let rule_id = validate_id(rule_id, "rule_id")?;
        let url = format!("{}/rule/{rule_id}/disable", self.automation_url);
        self.put_no_content(&url, &serde_json::json!({})).await
    }

    /// Delete an automation rule.
    #[instrument(skip(self))]
    pub async fn delete_automation_rule(&self, rule_id: &str) -> JiraResult<()> {
        let rule_id = validate_id(rule_id, "rule_id")?;
        let url = format!("{}/rule/{rule_id}", self.automation_url);
        self.delete(&url).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get<R>(&self, url: &str) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API GET");

            match self.client.get(url).send().await {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: e.retry_after(),
                        error: e,
                    },
                    Err(e) => AttemptOutcome::Terminal(e),
                },
                Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                    error: JiraError::Http(e),
                    retry_after: None,
                },
                Err(e) => AttemptOutcome::Terminal(JiraError::Http(e)),
            }
        })
        .await
    }

    /// POST with retry, returning a deserialized body.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a side
    /// effect (br-kxd3e). Jira has no idempotency key, so a POST that creates
    /// an issue, comment, or worklog must pass `false`: a 5xx means Jira
    /// received it and may already have done the work.
    async fn post<R>(&self, url: &str, body: &serde_json::Value, replay_safe: bool) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API POST");

            match self.client.post(url).json(body).send().await {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) if e.is_retryable() => {
                        // `replay_is_safe()` keeps 429 retryable here — it was
                        // refused WITHOUT being performed — while a 5xx is
                        // gated on the caller's declaration.
                        let replayable = replay_safe || e.replay_is_safe();
                        let retry_after = e.retry_after();
                        AttemptOutcome::retryable_if_replayable(e, retry_after, replayable)
                    }
                    Err(e) => AttemptOutcome::Terminal(e),
                },
                // `is_timeout()` is the total request timeout and fires after
                // the body was fully written; only a connect-phase failure
                // proves the request never arrived.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(JiraError::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    /// POST with retry for endpoints that return no body.
    ///
    /// `replay_safe` carries the same meaning as in [`Self::post`].
    async fn post_no_content(
        &self,
        url: &str,
        body: &serde_json::Value,
        replay_safe: bool,
    ) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API POST (no content)");

            match self.client.post(url).json(body).send().await {
                Ok(response) => {
                    // 429 is checked before the replay gate: it was refused
                    // WITHOUT being performed, so it stays retryable.
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        return AttemptOutcome::Retryable {
                            error: JiraError::RateLimited {
                                retry_after_ms: retry_result
                                    .map_or(60_000, |d| d.as_millis() as u64),
                            },
                            retry_after: retry_result,
                        };
                    }
                    if response.status().is_success() {
                        return AttemptOutcome::Success(());
                    }
                    let status = response.status();
                    let retry_after_ms = Self::extract_retry_after_ms(&response);
                    let bytes = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => return AttemptOutcome::Terminal(JiraError::Http(e)),
                    };
                    let err = Self::parse_error(status, &bytes, retry_after_ms);
                    if err.is_retryable() {
                        let replayable = replay_safe || err.replay_is_safe();
                        let retry_after = err.retry_after();
                        AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                    } else {
                        AttemptOutcome::Terminal(err)
                    }
                }
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(JiraError::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    async fn put<R>(&self, url: &str, body: &serde_json::Value) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API PUT");

            match self.client.put(url).json(body).send().await {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: e.retry_after(),
                        error: e,
                    },
                    Err(e) => AttemptOutcome::Terminal(e),
                },
                Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                    error: JiraError::Http(e),
                    retry_after: None,
                },
                Err(e) => AttemptOutcome::Terminal(JiraError::Http(e)),
            }
        })
        .await
    }

    async fn put_no_content(&self, url: &str, body: &serde_json::Value) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API PUT (no content)");

            match self.client.put(url).json(body).send().await {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        return AttemptOutcome::Retryable {
                            error: JiraError::RateLimited {
                                retry_after_ms: retry_result
                                    .map_or(60_000, |d| d.as_millis() as u64),
                            },
                            retry_after: retry_result,
                        };
                    }
                    if response.status().is_success() {
                        return AttemptOutcome::Success(());
                    }
                    let status = response.status();
                    let retry_after_ms = Self::extract_retry_after_ms(&response);
                    let bytes = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => return AttemptOutcome::Terminal(JiraError::Http(e)),
                    };
                    let err = Self::parse_error(status, &bytes, retry_after_ms);
                    if err.is_retryable() {
                        AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    }
                }
                Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                    error: JiraError::Http(e),
                    retry_after: None,
                },
                Err(e) => AttemptOutcome::Terminal(JiraError::Http(e)),
            }
        })
        .await
    }

    async fn delete(&self, url: &str) -> JiraResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, url = %redact_url(url), "Jira API DELETE");

            match self.client.delete(url).send().await {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        return AttemptOutcome::Retryable {
                            error: JiraError::RateLimited {
                                retry_after_ms: retry_result
                                    .map_or(60_000, |d| d.as_millis() as u64),
                            },
                            retry_after: retry_result,
                        };
                    }
                    if response.status().is_success() {
                        return AttemptOutcome::Success(());
                    }
                    let status = response.status();
                    let retry_after_ms = Self::extract_retry_after_ms(&response);
                    let bytes = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => return AttemptOutcome::Terminal(JiraError::Http(e)),
                    };
                    let err = Self::parse_error(status, &bytes, retry_after_ms);
                    if err.is_retryable() {
                        AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        }
                    } else {
                        AttemptOutcome::Terminal(err)
                    }
                }
                Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                    error: JiraError::Http(e),
                    retry_after: None,
                },
                Err(e) => AttemptOutcome::Terminal(JiraError::Http(e)),
            }
        })
        .await
    }

    /// Handle a response, deserializing success or parsing errors.
    async fn handle_response<R>(&self, response: Response) -> JiraResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();

        if let Some(retry_result) = Self::check_rate_limit(&response) {
            return Err(JiraError::RateLimited {
                retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
            });
        }

        // Extract Retry-After header before consuming the response body.
        let retry_after_ms = Self::extract_retry_after_ms(&response);
        let bytes = response.bytes().await.map_err(JiraError::Http)?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(JiraError::from)
        } else {
            Err(Self::parse_error(status, &bytes, retry_after_ms))
        }
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }

    /// Extract the `Retry-After` header value in milliseconds from a response.
    ///
    /// Returns `None` if the header is missing or unparseable.
    fn extract_retry_after_ms(response: &Response) -> Option<u64> {
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|secs| secs * 1000)
    }

    fn parse_error(status: StatusCode, bytes: &[u8], retry_after_ms: Option<u64>) -> JiraError {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return JiraError::Unauthorized;
        }
        if status == StatusCode::NOT_FOUND {
            return JiraError::NotFound {
                resource: String::from_utf8_lossy(bytes).into_owned(),
            };
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return JiraError::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(60_000),
            };
        }

        if let Ok(err_resp) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
            let messages: Vec<String> = err_resp
                .error_messages
                .unwrap_or_default()
                .into_iter()
                .chain(
                    err_resp
                        .errors
                        .and_then(|e| {
                            if let serde_json::Value::Object(map) = e {
                                Some(
                                    map.into_iter()
                                        .map(|(k, v)| {
                                            format!("{k}: {}", v.as_str().unwrap_or(&v.to_string()))
                                        })
                                        .collect::<Vec<_>>(),
                                )
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default(),
                )
                .collect();

            return JiraError::Api {
                message: if messages.is_empty() {
                    format!("HTTP {status}")
                } else {
                    messages.join("; ")
                },
                status_code: Some(status.as_u16()),
            };
        }

        JiraError::Api {
            message: format!("HTTP {status}: {}", String::from_utf8_lossy(bytes)),
            status_code: Some(status.as_u16()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_contract_support::{HttpExchange, HttpResponse, HttpServer, method, path};

    fn test_client(base_url: &str) -> JiraClient {
        JiraClient::new("test", "user@example.com", "token")
            .unwrap()
            .with_base_url(base_url)
            .with_agile_url(base_url)
            .with_automation_url(base_url)
            .with_retry_config(1, 10, 100)
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-123"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": "10001",
                "key": "PROJ-123",
                "self": "https://example.atlassian.net/rest/api/3/issue/10001",
                "fields": {
                    "summary": "Test issue",
                    "status": { "name": "Open" }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let issue = client.get_issue("PROJ-123", None, None).await.unwrap();
        assert_eq!(issue.key, "PROJ-123");
        assert_eq!(issue.id, "10001");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("POST"))
            .and(path("/issue"))
            .respond_with(HttpResponse::new(201).set_body_json(serde_json::json!({
                "id": "10002",
                "key": "PROJ-124",
                "self": "https://example.atlassian.net/rest/api/3/issue/10002"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let resp = client
            .create_issue(&serde_json::json!({
                "fields": {
                    "project": { "key": "PROJ" },
                    "summary": "New issue",
                    "issuetype": { "name": "Task" }
                }
            }))
            .await
            .unwrap();
        assert_eq!(resp.key, "PROJ-124");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_jql() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("POST"))
            .and(path("/search"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "issues": [
                    { "id": "10001", "key": "PROJ-1", "fields": { "summary": "Bug" } },
                    { "id": "10002", "key": "PROJ-2", "fields": { "summary": "Feature" } }
                ],
                "total": 2,
                "maxResults": 50,
                "startAt": 0
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .search_jql(&serde_json::json!({ "jql": "project = PROJ" }))
            .await
            .unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.issues.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_transitions() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1/transitions"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "transitions": [
                    { "id": "11", "name": "To Do", "to": { "id": "1", "name": "To Do" } },
                    { "id": "21", "name": "In Progress", "to": { "id": "2", "name": "In Progress" } }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_transitions("PROJ-1").await.unwrap();
        assert_eq!(result.transitions.len(), 2);
        assert_eq!(result.transitions[0].name, "To Do");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_sprints() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/board/42/sprint"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "values": [
                    { "id": 1, "name": "Sprint 1", "state": "active" },
                    { "id": 2, "name": "Sprint 2", "state": "future" }
                ],
                "isLast": true,
                "maxResults": 50,
                "startAt": 0
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_sprints(42, None, None, None).await.unwrap();
        assert_eq!(result.values.len(), 2);
        assert_eq!(result.values[0].name, "Sprint 1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1/comment"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "comments": [
                    { "id": "100", "body": { "type": "doc", "content": [] }, "created": "2024-01-01T00:00:00.000+0000" }
                ],
                "total": 1,
                "startAt": 0,
                "maxResults": 50
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .list_comments("PROJ-1", None, None, None)
            .await
            .unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.comments.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1"))
            .respond_with(HttpResponse::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-999"))
            .respond_with(HttpResponse::new(404).set_body_json(serde_json::json!({
                "errorMessages": ["Issue does not exist or you do not have permission to see it."],
                "errors": {}
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-999", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1"))
            .respond_with(HttpResponse::new(429).insert_header("retry-after", "1"))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_issue("PROJ-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::RateLimited { .. }));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = JiraError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = JiraError::Unauthorized;
        assert!(!err.is_retryable());

        let err = JiraError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = JiraError::NotFound {
            resource: "test".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn auth_redacted_label_token() {
        let auth = JiraAuth::Token {
            domain: "test".into(),
            email: "a@b.com".into(),
            api_token: "secret".into(),
        };
        assert_eq!(auth.redacted_label(), "token");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let auth = JiraAuth::CredentialId {
            domain: "test".into(),
            credential_id: CredentialId::new(),
        };
        assert_eq!(auth.redacted_label(), "credential_id");
    }

    #[test]
    fn auth_is_secretless_false_for_token() {
        let auth = JiraAuth::Token {
            domain: "d".into(),
            email: "e".into(),
            api_token: "t".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_is_secretless_true_for_credential() {
        let auth = JiraAuth::CredentialId {
            domain: "d".into(),
            credential_id: CredentialId::new(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_domain_returns_correct_value() {
        let auth = JiraAuth::Token {
            domain: "mycompany".into(),
            email: "u@e.com".into(),
            api_token: "tok".into(),
        };
        assert_eq!(auth.domain(), "mycompany");

        let auth2 = JiraAuth::CredentialId {
            domain: "otherdomain".into(),
            credential_id: CredentialId::new(),
        };
        assert_eq!(auth2.domain(), "otherdomain");
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = JiraAuth::Token {
            domain: "test".into(),
            email: "user@example.com".into(),
            api_token: "super-secret-value".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("REDACTED"), "got: {dbg}");
        assert!(!dbg.contains("super-secret-value"), "token leaked: {dbg}");
        assert!(dbg.contains("Token"), "got: {dbg}");
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let auth = JiraAuth::CredentialId {
            domain: "test".into(),
            credential_id: CredentialId::new(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"), "got: {dbg}");
        assert!(dbg.contains("test"), "got: {dbg}");
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = JiraClient::new("test", "user@example.com", "token").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("JiraClient"), "got: {dbg}");
    }

    #[test]
    fn client_total_requests_initially_zero() {
        let client = JiraClient::new("test", "user@example.com", "token").unwrap();
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn default_rest_base_and_agile_base_urls() {
        assert!(DEFAULT_REST_BASE.contains("atlassian.net"));
        assert!(DEFAULT_AGILE_BASE.contains("atlassian.net"));
        assert!(DEFAULT_REST_BASE.contains("rest/api/3"));
        assert!(DEFAULT_AGILE_BASE.contains("agile/1.0"));
    }

    // ── Worklog operations ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_worklogs() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1/worklog"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "worklogs": [
                    {
                        "id": "100028",
                        "author": {"displayName": "Dev"},
                        "timeSpent": "3h",
                        "timeSpentSeconds": 10800,
                        "started": "2026-03-01T09:00:00.000+0000"
                    },
                    {
                        "id": "100029",
                        "timeSpent": "1h 30m",
                        "timeSpentSeconds": 5400
                    }
                ],
                "total": 2,
                "startAt": 0,
                "maxResults": 50
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_worklogs("PROJ-1", None, None).await.unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.worklogs.len(), 2);
        assert_eq!(result.worklogs[0].time_spent.as_deref(), Some("3h"));
        assert_eq!(result.worklogs[0].time_spent_seconds, Some(10800));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_worklogs_with_pagination() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1/worklog"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "worklogs": [{"id": "100030", "timeSpent": "2h", "timeSpentSeconds": 7200}],
                "total": 10,
                "startAt": 5,
                "maxResults": 1
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .list_worklogs("PROJ-1", Some(5), Some(1))
            .await
            .unwrap();
        assert_eq!(result.total, 10);
        assert_eq!(result.worklogs.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_worklog() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("POST"))
            .and(path("/issue/PROJ-1/worklog"))
            .respond_with(HttpResponse::new(201).set_body_json(serde_json::json!({
                "id": "100030",
                "self": "https://example.atlassian.net/rest/api/3/issue/10001/worklog/100030",
                "timeSpent": "2h",
                "timeSpentSeconds": 7200,
                "started": "2026-03-05T10:00:00.000+0000"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .add_worklog(
                "PROJ-1",
                &serde_json::json!({
                    "timeSpentSeconds": 7200,
                    "started": "2026-03-05T10:00:00.000+0000"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result.id.as_deref(), Some("100030"));
        assert_eq!(result.time_spent_seconds, Some(7200));
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_worklog() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("PUT"))
            .and(path("/issue/PROJ-1/worklog/100030"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": "100030",
                "timeSpent": "4h",
                "timeSpentSeconds": 14400,
                "started": "2026-03-05T10:00:00.000+0000"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client
            .update_worklog(
                "PROJ-1",
                "100030",
                &serde_json::json!({"timeSpentSeconds": 14400}),
            )
            .await
            .unwrap();
        assert_eq!(result.time_spent_seconds, Some(14400));
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_worklog() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("DELETE"))
            .and(path("/issue/PROJ-1/worklog/100030"))
            .respond_with(HttpResponse::new(204))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        client.delete_worklog("PROJ-1", "100030").await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_worklogs_unauthorized() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/issue/PROJ-1/worklog"))
            .respond_with(HttpResponse::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_worklogs("PROJ-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_worklog_not_found() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("DELETE"))
            .and(path("/issue/PROJ-1/worklog/999999"))
            .respond_with(HttpResponse::new(404).set_body_json(serde_json::json!({
                "errorMessages": ["Worklog with id '999999' is not found."],
                "errors": {}
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.delete_worklog("PROJ-1", "999999").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::NotFound { .. }));
    }

    // ── Automation Rule operations ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_automation_rules() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/project/10001/rule"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "rules": [
                    {"id": 1, "name": "Auto-assign", "state": "ENABLED", "enabled": true},
                    {"id": 2, "name": "Close stale", "state": "DISABLED", "enabled": false}
                ],
                "total": 2
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_automation_rules("10001").await.unwrap();
        let rules = result.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(result.total, Some(2));
        assert_eq!(rules[0].name.as_deref(), Some("Auto-assign"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rule/42"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "name": "Auto-assign on create",
                "state": "ENABLED",
                "enabled": true,
                "trigger": {"type": "jira.issue.created"},
                "actions": [{"type": "jira.issue.assign", "value": {"accountId": "abc"}}]
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let rule = client.get_automation_rule("42").await.unwrap();
        assert_eq!(rule.id, Some(42));
        assert_eq!(rule.name.as_deref(), Some("Auto-assign on create"));
        assert_eq!(rule.enabled, Some(true));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_automation_rule_not_found() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rule/99999"))
            .respond_with(HttpResponse::new(404).set_body_json(serde_json::json!({
                "errorMessages": ["Rule not found"],
                "errors": {}
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.get_automation_rule("99999").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("POST"))
            .and(path("/project/10001/rule"))
            .respond_with(HttpResponse::new(201).set_body_json(serde_json::json!({
                "id": 100,
                "name": "New rule",
                "state": "ENABLED",
                "enabled": true
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let body = serde_json::json!({
            "name": "New rule",
            "trigger": {"type": "jira.issue.created"},
            "actions": [{"type": "jira.issue.assign"}]
        });
        let rule = client.create_automation_rule("10001", &body).await.unwrap();
        assert_eq!(rule.id, Some(100));
        assert_eq!(rule.name.as_deref(), Some("New rule"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("PUT"))
            .and(path("/rule/42"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "name": "Updated rule",
                "state": "ENABLED",
                "enabled": true
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let body = serde_json::json!({"name": "Updated rule"});
        let rule = client.update_automation_rule("42", &body).await.unwrap();
        assert_eq!(rule.name.as_deref(), Some("Updated rule"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_enable_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("PUT"))
            .and(path("/rule/42/enable"))
            .respond_with(HttpResponse::new(204))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        client.enable_automation_rule("42").await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_disable_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("PUT"))
            .and(path("/rule/42/disable"))
            .respond_with(HttpResponse::new(204))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        client.disable_automation_rule("42").await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_automation_rule() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("DELETE"))
            .and(path("/rule/42"))
            .respond_with(HttpResponse::new(204))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        client.delete_automation_rule("42").await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_automation_rule_not_found() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("DELETE"))
            .and(path("/rule/99999"))
            .respond_with(HttpResponse::new(404).set_body_json(serde_json::json!({
                "errorMessages": ["Rule not found"],
                "errors": {}
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.delete_automation_rule("99999").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_enable_automation_rule_unauthorized() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("PUT"))
            .and(path("/rule/42/enable"))
            .respond_with(HttpResponse::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.enable_automation_rule("42").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JiraError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_automation_rules_empty() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/project/10001/rule"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "rules": [],
                "total": 0
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let result = client.list_automation_rules("10001").await.unwrap();
        assert!(result.rules.unwrap().is_empty());
        assert_eq!(result.total, Some(0));
    }

    #[test]
    fn test_with_automation_url() {
        let client = JiraClient::new("test", "user@example.com", "token")
            .unwrap()
            .with_automation_url("https://custom.example.com/automation");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.example.com/automation"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // Deployment support
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_default_deployment_is_cloud() {
        let client = JiraClient::new("test", "user@example.com", "token").unwrap();
        assert_eq!(client.deployment(), JiraDeployment::Cloud);
    }

    #[test]
    fn test_cloud_base_url_uses_api_v3() {
        let client = JiraClient::new("myco", "user@example.com", "token").unwrap();
        assert_eq!(client.api_path(), "/rest/api/3");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("/rest/api/3"), "got: {dbg}");
    }

    #[test]
    fn test_server_dc_base_url_uses_api_v2() {
        let client = JiraClient::new_with_auth_and_deployment(
            JiraAuth::Token {
                domain: "myco".into(),
                email: "user@example.com".into(),
                api_token: "token".into(),
            },
            JiraDeployment::ServerDc,
        )
        .unwrap();
        assert_eq!(client.deployment(), JiraDeployment::ServerDc);
        assert_eq!(client.api_path(), "/rest/api/2");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("/rest/api/2"), "got: {dbg}");
    }

    #[test]
    fn test_with_deployment_cloud_to_server() {
        let client = JiraClient::new("myco", "user@example.com", "token")
            .unwrap()
            .with_deployment(JiraDeployment::ServerDc);
        assert_eq!(client.deployment(), JiraDeployment::ServerDc);
        assert_eq!(client.api_path(), "/rest/api/2");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("/rest/api/2"), "got: {dbg}");
        // Should NOT contain /rest/api/3 anymore
        assert!(!dbg.contains("/rest/api/3"), "got: {dbg}");
    }

    #[test]
    fn test_with_deployment_server_to_cloud() {
        let client = JiraClient::new_with_auth_and_deployment(
            JiraAuth::Token {
                domain: "myco".into(),
                email: "user@example.com".into(),
                api_token: "token".into(),
            },
            JiraDeployment::ServerDc,
        )
        .unwrap()
        .with_deployment(JiraDeployment::Cloud);
        assert_eq!(client.deployment(), JiraDeployment::Cloud);
        assert_eq!(client.api_path(), "/rest/api/3");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("/rest/api/3"), "got: {dbg}");
    }

    #[test]
    fn test_with_deployment_idempotent() {
        let client = JiraClient::new("myco", "user@example.com", "token")
            .unwrap()
            .with_deployment(JiraDeployment::Cloud)
            .with_deployment(JiraDeployment::Cloud);
        assert_eq!(client.deployment(), JiraDeployment::Cloud);
        assert_eq!(client.api_path(), "/rest/api/3");
    }

    #[test]
    fn test_with_deployment_preserves_custom_base_url() {
        let client = JiraClient::new("myco", "user@example.com", "token")
            .unwrap()
            .with_base_url("http://localhost:8080/rest/api/3")
            .with_deployment(JiraDeployment::ServerDc);
        // Should update the version in the custom URL too
        let dbg = format!("{client:?}");
        assert!(dbg.contains("/rest/api/2"), "got: {dbg}");
    }

    #[test]
    fn test_debug_includes_deployment() {
        let client = JiraClient::new("test", "user@example.com", "token").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("deployment"), "got: {dbg}");
        assert!(dbg.contains("Cloud"), "got: {dbg}");
    }

    #[test]
    fn test_debug_includes_deployment_server_dc() {
        let client = JiraClient::new_with_auth_and_deployment(
            JiraAuth::Token {
                domain: "test".into(),
                email: "user@example.com".into(),
                api_token: "token".into(),
            },
            JiraDeployment::ServerDc,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("ServerDc"), "got: {dbg}");
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_info_cloud() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "baseUrl": "https://myco.atlassian.net",
                "version": "1001.0.0-SNAPSHOT",
                "versionNumbers": [1001, 0, 0],
                "deploymentType": "Cloud",
                "buildNumber": 100227,
                "serverTitle": "My Jira"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let info = client.server_info().await.unwrap();
        assert_eq!(info.deployment_type.as_deref(), Some("Cloud"));
        assert_eq!(info.version.as_deref(), Some("1001.0.0-SNAPSHOT"));
        assert_eq!(info.build_number, Some(100227));
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_info_server_dc() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "baseUrl": "https://jira.mycompany.com",
                "version": "9.4.7",
                "versionNumbers": [9, 4, 7],
                "deploymentType": "Server",
                "buildNumber": 90407
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let info = client.server_info().await.unwrap();
        assert_eq!(info.deployment_type.as_deref(), Some("Server"));
        assert_eq!(info.version.as_deref(), Some("9.4.7"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_detect_deployment_cloud() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "deploymentType": "Cloud"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let deployment = client.detect_deployment().await.unwrap();
        assert_eq!(deployment, JiraDeployment::Cloud);
    }

    #[fcp_async_core::runtime::test]
    async fn test_detect_deployment_server() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "deploymentType": "Server"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let deployment = client.detect_deployment().await.unwrap();
        assert_eq!(deployment, JiraDeployment::ServerDc);
    }

    #[fcp_async_core::runtime::test]
    async fn test_detect_deployment_missing_type_defaults_server() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "version": "9.0.0"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let deployment = client.detect_deployment().await.unwrap();
        assert_eq!(deployment, JiraDeployment::ServerDc);
    }

    #[fcp_async_core::runtime::test]
    async fn test_cloud_client_issue_url_uses_v3() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": "10001",
                "key": "PROJ-1"
            })))
            .mount(&mock_server)
            .await;

        // Cloud client points base_url at mock with /rest/api/3
        let client = JiraClient::new("test", "user@example.com", "token")
            .unwrap()
            .with_base_url(&format!("{}/rest/api/3", mock_server.uri()))
            .with_retry_config(1, 10, 100);

        let issue = client.get_issue("PROJ-1", None, None).await.unwrap();
        assert_eq!(issue.key, "PROJ-1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_dc_client_issue_url_uses_v2() {
        let mock_server = HttpServer::start().await;

        HttpExchange::given(method("GET"))
            .and(path("/rest/api/2/issue/PROJ-1"))
            .respond_with(HttpResponse::new(200).set_body_json(serde_json::json!({
                "id": "10001",
                "key": "PROJ-1"
            })))
            .mount(&mock_server)
            .await;

        // Server/DC client points base_url at mock with /rest/api/2
        let client = JiraClient::new_with_auth_and_deployment(
            JiraAuth::Token {
                domain: "test".into(),
                email: "user@example.com".into(),
                api_token: "token".into(),
            },
            JiraDeployment::ServerDc,
        )
        .unwrap()
        .with_base_url(&format!("{}/rest/api/2", mock_server.uri()))
        .with_retry_config(1, 10, 100);

        let issue = client.get_issue("PROJ-1", None, None).await.unwrap();
        assert_eq!(issue.key, "PROJ-1");
    }
}
