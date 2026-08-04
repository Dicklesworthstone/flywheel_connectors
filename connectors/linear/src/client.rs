//! Linear GraphQL API client.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{LinearError, LinearResult},
    types::{
        CommentCreatePayload, Cycle, GraphQLRequest, GraphQLResponse, Issue, IssueCreatePayload,
        IssueUpdatePayload, Project, Team,
    },
};

/// Default Linear GraphQL API URL.
pub const DEFAULT_API_URL: &str = "https://api.linear.app/graphql";

/// Authentication mode for the Linear API.
#[derive(Clone)]
pub enum LinearAuth {
    /// Direct API key.
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl LinearAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for LinearAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Linear GraphQL API client.
pub struct LinearClient {
    http: Client,
    auth: LinearAuth,
    api_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl LinearClient {
    /// Create a new Linear client with a direct API key.
    pub fn new(api_key: &str) -> LinearResult<Self> {
        Self::new_with_auth(LinearAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new Linear client with explicit auth mode.
    pub fn new_with_auth(auth: LinearAuth) -> LinearResult<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("fcp-linear/0.1.0")
            .build()
            .map_err(LinearError::Http)?;

        Ok(Self {
            http,
            auth,
            api_url: DEFAULT_API_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &LinearAuth {
        &self.auth
    }

    /// Get the API URL.
    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Perform a safe, read-only health check by querying the viewer.
    ///
    /// Validates that the API key is valid and the Linear API is reachable
    /// without any side effects.
    pub async fn health_check(&self) -> LinearResult<()> {
        let query = r"query { viewer { id } }";
        let _data = self.execute_graphql(query, None, true).await?;
        Ok(())
    }

    /// Apply authentication headers to a request builder.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            LinearAuth::ApiKey(key) => {
                builder.header(header::AUTHORIZATION, format!("Bearer {key}"))
            }
            LinearAuth::CredentialId(_) => {
                // Secretless: egress proxy injects credentials. Send without auth header.
                builder
            }
        }
    }

    fn parse_retry_after(headers: &header::HeaderMap) -> Option<Duration> {
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    // ── API Methods ──────────────────────────────────────────────

    /// Create a new issue.
    pub async fn create_issue(
        &self,
        title: &str,
        team_id: &str,
        description: Option<&str>,
    ) -> LinearResult<Issue> {
        let mut variables = serde_json::json!({
            "title": title,
            "teamId": team_id,
        });
        if let Some(desc) = description {
            variables.as_object_mut().unwrap().insert(
                "description".to_string(),
                serde_json::Value::String(desc.into()),
            );
        }

        let query = r"
            mutation IssueCreate($title: String!, $teamId: String!, $description: String) {
                issueCreate(input: { title: $title, teamId: $teamId, description: $description }) {
                    success
                    issue {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        // NOT replay-safe: `issueCreate` mutation — a replay files a
        // second issue. Linear has no idempotency-key header.
        let data = self.execute_graphql(query, Some(variables), false).await?;
        let payload: IssueCreatePayload = serde_json::from_value(data["issueCreate"].clone())?;

        payload.issue.ok_or(LinearError::Api {
            message: "Issue creation returned no issue".into(),
            status_code: None,
        })
    }

    /// Get an issue by ID.
    pub async fn get_issue(&self, issue_id: &str) -> LinearResult<Issue> {
        let query = r"
            query GetIssue($id: String!) {
                issue(id: $id) {
                    id identifier title description priority priorityLabel
                    state { id name color type }
                    assignee { id name displayName email }
                    team { id name key }
                    labels { nodes { id name color } }
                    createdAt updatedAt url
                }
            }
        ";

        let variables = serde_json::json!({ "id": issue_id });
        let data = self.execute_graphql(query, Some(variables), true).await?;

        if data["issue"].is_null() {
            return Err(LinearError::NotFound {
                resource: format!("issue:{issue_id}"),
            });
        }

        Ok(serde_json::from_value(data["issue"].clone())?)
    }

    /// Update an issue.
    pub async fn update_issue(
        &self,
        issue_id: &str,
        title: Option<&str>,
        state_id: Option<&str>,
        description: Option<&str>,
    ) -> LinearResult<Issue> {
        let mut input = serde_json::Map::new();
        if let Some(t) = title {
            input.insert("title".into(), serde_json::Value::String(t.into()));
        }
        if let Some(s) = state_id {
            input.insert("stateId".into(), serde_json::Value::String(s.into()));
        }
        if let Some(d) = description {
            input.insert("description".into(), serde_json::Value::String(d.into()));
        }

        let query = r"
            mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    success
                    issue {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "id": issue_id,
            "input": serde_json::Value::Object(input),
        });

        // Replay-safe: `issueUpdate` sets named fields to named values, so
        // applying it twice converges on the same issue.
        let data = self.execute_graphql(query, Some(variables), true).await?;
        let payload: IssueUpdatePayload = serde_json::from_value(data["issueUpdate"].clone())?;

        payload.issue.ok_or(LinearError::Api {
            message: "Issue update returned no issue".into(),
            status_code: None,
        })
    }

    /// Search issues by text query.
    pub async fn search_issues(&self, query_text: &str) -> LinearResult<Vec<Issue>> {
        let query = r"
            query SearchIssues($query: String!) {
                searchIssues(query: $query) {
                    nodes {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        let variables = serde_json::json!({ "query": query_text });
        let data = self.execute_graphql(query, Some(variables), true).await?;

        let nodes = data["searchIssues"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let issues: Vec<Issue> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(issues)
    }

    /// List all teams.
    pub async fn list_teams(&self) -> LinearResult<Vec<Team>> {
        let query = r"
            query ListTeams {
                teams {
                    nodes {
                        id name key description
                    }
                }
            }
        ";

        let data = self.execute_graphql(query, None, true).await?;

        let nodes = data["teams"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let teams: Vec<Team> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(teams)
    }

    /// List cycles for a team.
    pub async fn list_cycles(&self, team_id: &str) -> LinearResult<Vec<Cycle>> {
        let query = r"
            query ListCycles($teamId: String!) {
                team(id: $teamId) {
                    cycles {
                        nodes {
                            id number name startsAt endsAt completedAt
                        }
                    }
                }
            }
        ";

        let variables = serde_json::json!({ "teamId": team_id });
        let data = self.execute_graphql(query, Some(variables), true).await?;

        if data["team"].is_null() {
            return Err(LinearError::NotFound {
                resource: format!("team:{team_id}"),
            });
        }

        let nodes = data["team"]["cycles"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let cycles: Vec<Cycle> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(cycles)
    }

    /// Add a comment to an issue.
    pub async fn add_comment(
        &self,
        issue_id: &str,
        body: &str,
    ) -> LinearResult<crate::types::IssueComment> {
        let query = r"
            mutation CommentCreate($issueId: String!, $body: String!) {
                commentCreate(input: { issueId: $issueId, body: $body }) {
                    success
                    comment {
                        id body
                        user { id name displayName email }
                        createdAt updatedAt
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "issueId": issue_id,
            "body": body,
        });

        // NOT replay-safe: `commentCreate` mutation — a replay posts a
        // second comment on the issue.
        let data = self.execute_graphql(query, Some(variables), false).await?;
        let payload: CommentCreatePayload = serde_json::from_value(data["commentCreate"].clone())?;

        payload.comment.ok_or(LinearError::Api {
            message: "Comment creation returned no comment".into(),
            status_code: None,
        })
    }

    /// List projects.
    pub async fn list_projects(&self) -> LinearResult<Vec<Project>> {
        let query = r"
            query ListProjects {
                projects {
                    nodes {
                        id name description state progress createdAt updatedAt url
                    }
                }
            }
        ";

        let data = self.execute_graphql(query, None, true).await?;

        let nodes = data["projects"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let projects: Vec<Project> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(projects)
    }

    // ── Internal GraphQL helpers ─────────────────────────────────

    /// Execute a GraphQL document against Linear's single endpoint.
    ///
    /// `replay_safe` states whether repeating this document can duplicate a
    /// side effect (br-kxd3e). It has to be supplied per call because Linear
    /// speaks GraphQL: queries and mutations travel over the SAME `POST
    /// /graphql` request, so the HTTP verb carries no information about
    /// whether a replay is safe. Deciding it here rather than in the helper is
    /// the whole point — a mutation added later cannot inherit a query's
    /// retry behaviour by accident.
    ///
    /// Linear has no idempotency-key header. `issueCreate` and `commentCreate`
    /// do accept a client-supplied UUID `id`, which would make those retries
    /// genuinely safe rather than merely refused — recorded as a follow-up on
    /// the bead rather than done blind, because it needs Linear's real
    /// duplicate-id error shape to handle correctly.
    async fn execute_graphql(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
        replay_safe: bool,
    ) -> LinearResult<serde_json::Value> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };
        let ctx = self.runtime.request_context();
        let retry_ctx = ctx.clone();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = &request;
            let retry_ctx = retry_ctx.clone();
            async move {
                debug!(attempt, api_url = %redact_url(&self.api_url), "GraphQL request");

                let builder = self
                    .http
                    .post(&self.api_url)
                    .header(header::CONTENT_TYPE, "application/json");
                let builder = self.apply_auth(builder);

                match builder.json(request).send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(LinearError::Unauthorized);
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = Self::parse_retry_after(response.headers())
                                .unwrap_or_else(|| {
                                    Duration::from_millis(self.retry_config.max_delay_ms)
                                });
                            let error = LinearError::RateLimited {
                                retry_after_ms: u64::try_from(retry_after.as_millis())
                                    .unwrap_or(u64::MAX),
                            };
                            let within_retry_budget = attempt < self.retry_config.max_retries;
                            let within_time_budget = match retry_ctx.remaining_budget() {
                                Some(budget) => retry_after <= budget,
                                None => true,
                            };

                            return if within_retry_budget && within_time_budget {
                                AttemptOutcome::Retryable {
                                    error,
                                    retry_after: Some(retry_after),
                                }
                            } else {
                                AttemptOutcome::Terminal(error)
                            };
                        }

                        if status.is_server_error() {
                            // br-kxd3e: a 5xx means Linear RECEIVED the
                            // document. For a mutation that means the issue or
                            // comment may already exist. The 429 arm above is
                            // deliberately ahead of this one: a rate limit was
                            // refused WITHOUT executing, so it stays retryable
                            // for mutations too.
                            return AttemptOutcome::retryable_if_replayable(
                                LinearError::Api {
                                    message: format!("Server error: {status}"),
                                    status_code: Some(status.as_u16()),
                                },
                                None,
                                replay_safe,
                            );
                        }

                        match response.text().await {
                            Ok(body) if !status.is_success() => {
                                AttemptOutcome::Terminal(LinearError::Api {
                                    message: format!("HTTP {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                })
                            }
                            Ok(body) => match serde_json::from_str::<GraphQLResponse>(&body) {
                                Ok(gql_response) => {
                                    if let Some(errors) = gql_response.errors {
                                        if !errors.is_empty() {
                                            let messages: Vec<&str> =
                                                errors.iter().map(|e| e.message.as_str()).collect();
                                            return AttemptOutcome::Terminal(LinearError::Api {
                                                message: messages.join("; "),
                                                status_code: None,
                                            });
                                        }
                                    }

                                    match gql_response.data {
                                        Some(data) => AttemptOutcome::Success(data),
                                        None => AttemptOutcome::Terminal(LinearError::Api {
                                            message: "Empty response data".into(),
                                            status_code: None,
                                        }),
                                    }
                                }
                                Err(error) => AttemptOutcome::Terminal(LinearError::Json(error)),
                            },
                            // A body-read failure happens AFTER the request was
                            // fully sent, so it can never be proof of
                            // non-delivery.
                            Err(error) => AttemptOutcome::retryable_if_replayable(
                                LinearError::Http(error),
                                None,
                                replay_safe,
                            ),
                        }
                    }
                    // br-kxd3e: `is_timeout()` is the TOTAL request timeout and
                    // fires after the body was written; only a connect-phase
                    // failure proves Linear never saw the document.
                    Err(error) => {
                        let replayable = replay_safe || !transport_error_reached_service(&error);
                        AttemptOutcome::retryable_if_replayable(
                            LinearError::Http(error),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_retryable() {
        let err = LinearError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = LinearError::Unauthorized;
        assert!(!err.is_retryable());

        let err = LinearError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
