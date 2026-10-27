//! GitHub API types.

use serde::{Deserialize, Serialize};

/// GitHub user (author, assignee, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub login: String,
    pub id: u64,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(rename = "type", default)]
    pub user_type: String,
}

/// GitHub label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// GitHub milestone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Milestone {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
}

/// GitHub issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    pub user: User,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub assignees: Vec<User>,
    #[serde(default)]
    pub milestone: Option<Milestone>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub closed_at: Option<String>,
    pub html_url: String,
    #[serde(default)]
    pub comments: u32,
}

/// GitHub pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    pub user: User,
    pub head: PullRequestRef,
    pub base: PullRequestRef,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub assignees: Vec<User>,
    #[serde(default)]
    pub merged: bool,
    #[serde(default)]
    pub mergeable: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub merged_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
    pub html_url: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub additions: u32,
    #[serde(default)]
    pub deletions: u32,
    #[serde(default)]
    pub changed_files: u32,
}

/// Git ref in a pull request (head or base).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestRef {
    pub label: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub sha: String,
}

/// GitHub repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub owner: User,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub fork: bool,
    pub html_url: String,
    pub default_branch: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub stargazers_count: u32,
    #[serde(default)]
    pub forks_count: u32,
    #[serde(default)]
    pub open_issues_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// GitHub Actions workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: u64,
    pub name: String,
    pub path: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

/// File content from the repository contents API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    /// Symlink target, when GitHub returns the link rather than its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The origin of a submodule, including submodules hosted outside GitHub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submodule_git_url: Option<String>,
}

/// The contents endpoint returns an object for a file, symlink or submodule,
/// and an array for a directory. Preserve those provider shapes in FCP output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RepositoryContent {
    Entry(FileContent),
    Directory(Vec<FileContent>),
}

/// Explicit page selection. One invocation makes one bounded provider request;
/// callers can continue with the returned `next_page` and the same `per_page`.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest {
    pub page: u32,
    pub per_page: u32,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 100,
        }
    }
}

impl PageRequest {
    /// Reject invalid page sizes and offsets outside GitHub's search window.
    ///
    /// # Errors
    /// Returns a validation error before any request is sent.
    pub fn validate(self, search: bool) -> crate::error::GitHubResult<Self> {
        if self.page == 0 || !(1..=100).contains(&self.per_page) {
            return Err(crate::error::GitHubError::ValidationError {
                message: "page must be positive and per_page must be between 1 and 100".into(),
            });
        }
        if search && u64::from(self.page - 1) * u64::from(self.per_page) >= 1_000 {
            return Err(crate::error::GitHubError::ValidationError {
                message: "GitHub search exposes only the first 1000 results; narrow the query"
                    .into(),
            });
        }
        Ok(self)
    }

    /// Describe continuation without fetching more pages or hiding the provider
    /// total. An incomplete search remains separately visible in its response.
    #[must_use]
    pub fn metadata(self, total_count: u64, returned: usize, search: bool) -> Pagination {
        let accessible_total_count = if search {
            total_count.min(1_000)
        } else {
            total_count
        };
        let page_end = u64::from(self.page) * u64::from(self.per_page);
        Pagination {
            page: self.page,
            per_page: self.per_page,
            returned,
            next_page: (page_end < accessible_total_count)
                .then(|| self.page.checked_add(1))
                .flatten(),
            accessible_total_count,
            result_limit: search.then_some(1_000),
            result_limit_exceeded: search && total_count > 1_000,
        }
    }
}

/// Bounded continuation metadata for searches and workflow inventories.
#[derive(Debug, Clone, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub returned: usize,
    pub next_page: Option<u32>,
    pub accessible_total_count: u64,
    pub result_limit: Option<u32>,
    pub result_limit_exceeded: bool,
}

/// Search results wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchResults<T> {
    pub total_count: u64,
    pub incomplete_results: bool,
    pub items: Vec<T>,
}

/// Code search result item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchItem {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub html_url: String,
    pub repository: CodeSearchRepo,
}

/// Minimal repo info in code search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchRepo {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: String,
}

/// Workflows list response.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowsResponse {
    pub total_count: u32,
    pub workflows: Vec<Workflow>,
}

/// Merge result.
#[derive(Debug, Clone, Deserialize)]
pub struct MergeResult {
    pub sha: String,
    pub merged: bool,
    pub message: String,
}

/// GitHub API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
    #[serde(default)]
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub errors: Option<Vec<ApiValidationError>>,
}

/// Validation error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiValidationError {
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Request to create an issue.
#[derive(Debug, Clone, Serialize)]
pub struct CreateIssueRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub milestone: Option<u32>,
}

/// Request to create a pull request.
#[derive(Debug, Clone, Serialize)]
pub struct CreatePullRequestRequest {
    pub title: String,
    pub head: String,
    pub base: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft: Option<bool>,
}

/// Request to merge a pull request.
#[derive(Debug, Clone, Serialize)]
pub struct MergePullRequestRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
}

// ── Webhook Events ─────────────────────────────────────────────

/// GitHub webhook payload envelope.
///
/// The host verifies the HMAC-SHA256 signature before forwarding.
/// The connector receives the pre-verified, typed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// GitHub event type header (X-GitHub-Event).
    pub event_type: WebhookEventType,
    /// GitHub delivery ID (X-GitHub-Delivery) for deduplication.
    pub delivery_id: String,
    /// Event payload data — structure varies by event type.
    pub data: serde_json::Value,
    /// Repository context (if applicable).
    #[serde(default)]
    pub repository: Option<WebhookRepository>,
    /// Sender (actor who triggered the event).
    #[serde(default)]
    pub sender: Option<WebhookSender>,
}

/// Webhook event type discriminant (maps to X-GitHub-Event header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    Issues,
    IssueComment,
    PullRequest,
    PullRequestReview,
    Push,
    WorkflowRun,
    Create,
    Delete,
    Release,
    Ping,
}

impl std::fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issues => write!(f, "issues"),
            Self::IssueComment => write!(f, "issue_comment"),
            Self::PullRequest => write!(f, "pull_request"),
            Self::PullRequestReview => write!(f, "pull_request_review"),
            Self::Push => write!(f, "push"),
            Self::WorkflowRun => write!(f, "workflow_run"),
            Self::Create => write!(f, "create"),
            Self::Delete => write!(f, "delete"),
            Self::Release => write!(f, "release"),
            Self::Ping => write!(f, "ping"),
        }
    }
}

/// Webhook action discriminant (common across many event types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookAction {
    Opened,
    Closed,
    Reopened,
    Edited,
    Created,
    Deleted,
    Synchronize,
    Submitted,
    Completed,
    Requested,
    Published,
    Merged,
}

impl std::fmt::Display for WebhookAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opened => write!(f, "opened"),
            Self::Closed => write!(f, "closed"),
            Self::Reopened => write!(f, "reopened"),
            Self::Edited => write!(f, "edited"),
            Self::Created => write!(f, "created"),
            Self::Deleted => write!(f, "deleted"),
            Self::Synchronize => write!(f, "synchronize"),
            Self::Submitted => write!(f, "submitted"),
            Self::Completed => write!(f, "completed"),
            Self::Requested => write!(f, "requested"),
            Self::Published => write!(f, "published"),
            Self::Merged => write!(f, "merged"),
        }
    }
}

/// Lightweight repository reference in webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRepository {
    pub id: u64,
    pub full_name: String,
    pub html_url: String,
    #[serde(default)]
    pub private: bool,
}

/// Lightweight sender reference in webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSender {
    pub login: String,
    pub id: u64,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

impl WebhookEventType {
    /// Convert to FCP event topic string with optional action.
    #[must_use]
    pub fn to_topic(&self, action: Option<&str>) -> String {
        match action {
            Some(act) => format!("github.{self}.{act}"),
            None => format!("github.{self}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            login: "octocat".to_string(),
            id: 1,
            avatar_url: "https://github.com/images/error/octocat.gif".to_string(),
            user_type: "User".to_string(),
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"type\":\"User\""));
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.login, "octocat");
    }

    #[test]
    fn user_deserialize_defaults() {
        let json = r#"{"login":"bot","id":2}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.avatar_url, "");
        assert_eq!(user.user_type, "");
    }

    // ---- Issue ----

    #[test]
    fn issue_serde_with_defaults() {
        let json = json!({
            "id": 1,
            "number": 42,
            "title": "Bug report",
            "state": "open",
            "user": {"login": "alice", "id": 10},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-03-01T00:00:00Z",
            "html_url": "https://github.com/org/repo/issues/42"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.number, 42);
        assert!(issue.body.is_none());
        assert!(issue.labels.is_empty());
        assert!(issue.assignees.is_empty());
        assert_eq!(issue.comments, 0);
    }

    // ---- PullRequest ----

    #[test]
    fn pull_request_serde() {
        let json = json!({
            "id": 100,
            "number": 5,
            "title": "Add feature",
            "state": "open",
            "user": {"login": "dev", "id": 20},
            "head": {"label": "dev:feature", "ref": "feature", "sha": "abc123"},
            "base": {"label": "org:main", "ref": "main", "sha": "def456"},
            "created_at": "2026-03-01",
            "updated_at": "2026-03-02",
            "html_url": "https://github.com/org/repo/pull/5"
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        assert_eq!(pr.number, 5);
        assert_eq!(pr.head.ref_name, "feature");
        assert_eq!(pr.base.ref_name, "main");
        assert!(!pr.merged);
        assert!(!pr.draft);
        assert_eq!(pr.additions, 0);
    }

    // ---- Repository ----

    #[test]
    fn repository_serde() {
        let json = json!({
            "id": 1,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": {"login": "octocat", "id": 1},
            "html_url": "https://github.com/octocat/hello-world",
            "default_branch": "main",
            "created_at": "2026-01-01",
            "updated_at": "2026-03-01"
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert!(!repo.private);
        assert!(!repo.fork);
        assert_eq!(repo.stargazers_count, 0);
    }

    // ---- Label ----

    #[test]
    fn label_serde() {
        let label = Label {
            id: 1,
            name: "bug".to_string(),
            color: "d73a4a".to_string(),
            description: Some("Something isn't working".to_string()),
        };
        let json = serde_json::to_string(&label).unwrap();
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bug");
    }

    // ---- FileContent ----

    #[test]
    fn file_content_serde() {
        let json = json!({
            "name": "README.md",
            "path": "README.md",
            "sha": "abc123",
            "size": 1024,
            "type": "file",
            "content": "SGVsbG8=",
            "encoding": "base64",
            "html_url": "https://github.com/org/repo/blob/main/README.md"
        });
        let fc: FileContent = serde_json::from_value(json).unwrap();
        assert_eq!(fc.content_type, "file");
        assert_eq!(fc.content.as_deref(), Some("SGVsbG8="));
    }

    // ---- SearchResults ----

    #[test]
    fn search_results_deserialize() {
        let json = json!({
            "total_count": 2,
            "incomplete_results": false,
            "items": [{"id": 1, "number": 1, "title": "A", "state": "open",
                       "user": {"login": "a", "id": 1}, "created_at": "2026-01-01",
                       "updated_at": "2026-01-01", "html_url": "https://github.com/a/b/issues/1"}]
        });
        let results: SearchResults<Issue> = serde_json::from_value(json).unwrap();
        assert_eq!(results.total_count, 2);
        assert!(!results.incomplete_results);
        assert_eq!(results.items.len(), 1);
    }

    // ---- ApiErrorResponse ----

    #[test]
    fn api_error_response_deserialize() {
        let json = json!({
            "message": "Not Found",
            "documentation_url": "https://docs.github.com/",
            "errors": [{"resource": "Issue", "field": "title", "code": "missing"}]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Not Found");
        assert!(err.errors.is_some());
        assert_eq!(err.errors.unwrap()[0].code.as_deref(), Some("missing"));
    }

    // ---- CreateIssueRequest ----

    #[test]
    fn create_issue_request_serialize_minimal() {
        let req = CreateIssueRequest {
            title: "Bug".to_string(),
            body: None,
            assignees: None,
            labels: None,
            milestone: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("body"));
        assert!(!json.contains("assignees"));
    }

    // ---- CreatePullRequestRequest ----

    #[test]
    fn create_pr_request_serialize() {
        let req = CreatePullRequestRequest {
            title: "Feature".to_string(),
            head: "feature-branch".to_string(),
            base: "main".to_string(),
            body: Some("Adds feature".to_string()),
            draft: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"draft\":true"));
    }

    // ---- MergePullRequestRequest ----

    #[test]
    fn merge_pr_request_serialize_minimal() {
        let req = MergePullRequestRequest {
            commit_title: None,
            commit_message: None,
            merge_method: None,
            sha: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "{}");
    }

    // ---- MergeResult ----

    #[test]
    fn merge_result_deserialize() {
        let json = r#"{"sha":"abc123","merged":true,"message":"Pull Request successfully merged"}"#;
        let result: MergeResult = serde_json::from_str(json).unwrap();
        assert!(result.merged);
    }

    #[test]
    fn merge_result_not_merged() {
        let json = json!({
            "sha": "deadbeef",
            "merged": false,
            "message": "Pull Request was not merged"
        });
        let result: MergeResult = serde_json::from_value(json).unwrap();
        assert!(!result.merged);
        assert_eq!(result.sha, "deadbeef");
    }

    #[test]
    fn merge_result_clone_debug() {
        let result = MergeResult {
            sha: "abc".into(),
            merged: true,
            message: "OK".into(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.sha, "abc");
        let debug = format!("{result:?}");
        assert!(debug.contains("abc"));
    }

    // ---- Workflow ----

    #[test]
    fn workflow_serde() {
        let wf = Workflow {
            id: 1,
            name: "CI".to_string(),
            path: ".github/workflows/ci.yml".to_string(),
            state: "active".to_string(),
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-03-01".to_string(),
        };
        let json = serde_json::to_string(&wf).unwrap();
        let back: Workflow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "CI");
    }

    #[test]
    fn workflow_clone_debug() {
        let wf = Workflow {
            id: 99,
            name: "Deploy".into(),
            path: ".github/workflows/deploy.yml".into(),
            state: "disabled_manually".into(),
            created_at: "2026-01-01".into(),
            updated_at: "2026-03-01".into(),
        };
        let cloned = wf.clone();
        assert_eq!(cloned.id, 99);
        let debug = format!("{wf:?}");
        assert!(debug.contains("Deploy"));
    }

    // ---- WorkflowsResponse ----

    #[test]
    fn workflows_response_deserialize() {
        let json = json!({
            "total_count": 2,
            "workflows": [
                {
                    "id": 1,
                    "name": "CI",
                    "path": ".github/workflows/ci.yml",
                    "state": "active",
                    "created_at": "2026-01-01",
                    "updated_at": "2026-03-01"
                },
                {
                    "id": 2,
                    "name": "CD",
                    "path": ".github/workflows/cd.yml",
                    "state": "active",
                    "created_at": "2026-01-01",
                    "updated_at": "2026-03-01"
                }
            ]
        });
        let resp: WorkflowsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_count, 2);
        assert_eq!(resp.workflows.len(), 2);
        assert_eq!(resp.workflows[0].name, "CI");
    }

    #[test]
    fn workflows_response_empty() {
        let json = json!({
            "total_count": 0,
            "workflows": []
        });
        let resp: WorkflowsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total_count, 0);
        assert!(resp.workflows.is_empty());
    }

    // ---- User edge cases ----

    #[test]
    fn user_clone_debug() {
        let user = User {
            login: "alice".into(),
            id: 42,
            avatar_url: "https://example.com/avatar.png".into(),
            user_type: "User".into(),
        };
        let cloned = user.clone();
        assert_eq!(cloned.login, "alice");
        assert_eq!(cloned.id, 42);
        let debug = format!("{user:?}");
        assert!(debug.contains("alice"));
    }

    #[test]
    fn user_type_field_rename() {
        let user = User {
            login: "bot".into(),
            id: 1,
            avatar_url: String::new(),
            user_type: "Bot".into(),
        };
        let json = serde_json::to_value(&user).unwrap();
        // Should serialize as "type", not "user_type"
        assert_eq!(json["type"], "Bot");
        assert!(json.get("user_type").is_none());
    }

    #[test]
    fn user_roundtrip_preserves_all_fields() {
        let user = User {
            login: "octocat".into(),
            id: 123_456,
            avatar_url: "https://avatars.example.com/u/123456".into(),
            user_type: "Organization".into(),
        };
        let json_str = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.login, user.login);
        assert_eq!(back.id, user.id);
        assert_eq!(back.avatar_url, user.avatar_url);
        assert_eq!(back.user_type, user.user_type);
    }

    // ---- Label edge cases ----

    #[test]
    fn label_without_description() {
        let json = json!({"id": 1, "name": "enhancement", "color": "a2eeef"});
        let label: Label = serde_json::from_value(json).unwrap();
        assert!(label.description.is_none());
        assert_eq!(label.color, "a2eeef");
    }

    #[test]
    fn label_with_empty_color_default() {
        let json = json!({"id": 1, "name": "bug"});
        let label: Label = serde_json::from_value(json).unwrap();
        assert_eq!(label.color, "");
    }

    #[test]
    fn label_clone_debug() {
        let label = Label {
            id: 5,
            name: "priority:high".into(),
            color: "ff0000".into(),
            description: Some("High priority".into()),
        };
        let cloned = label.clone();
        assert_eq!(cloned.name, "priority:high");
        let debug = format!("{label:?}");
        assert!(debug.contains("priority:high"));
    }

    #[test]
    fn label_roundtrip() {
        let label = Label {
            id: 10,
            name: "wontfix".into(),
            color: "ffffff".into(),
            description: None,
        };
        let json = serde_json::to_string(&label).unwrap();
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 10);
        assert_eq!(back.name, "wontfix");
        assert!(back.description.is_none());
    }

    // ---- Milestone ----

    #[test]
    fn milestone_serde_roundtrip() {
        let ms = Milestone {
            id: 1,
            number: 3,
            title: "v1.0".into(),
            state: "open".into(),
        };
        let json = serde_json::to_string(&ms).unwrap();
        let back: Milestone = serde_json::from_str(&json).unwrap();
        assert_eq!(back.number, 3);
        assert_eq!(back.title, "v1.0");
    }

    #[test]
    fn milestone_clone_debug() {
        let ms = Milestone {
            id: 2,
            number: 5,
            title: "v2.0".into(),
            state: "closed".into(),
        };
        let cloned = ms.clone();
        assert_eq!(cloned.state, "closed");
        let debug = format!("{ms:?}");
        assert!(debug.contains("v2.0"));
    }

    // ---- Issue edge cases ----

    #[test]
    fn issue_with_all_optional_fields() {
        let json = json!({
            "id": 100,
            "number": 99,
            "title": "Full issue",
            "state": "closed",
            "body": "This is the body",
            "user": {"login": "alice", "id": 10, "avatar_url": "https://a.com/img.png", "type": "User"},
            "labels": [{"id": 1, "name": "bug", "color": "d73a4a"}],
            "assignees": [{"login": "bob", "id": 20}],
            "milestone": {"id": 1, "number": 1, "title": "v1.0", "state": "open"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-03-01T00:00:00Z",
            "closed_at": "2026-03-02T00:00:00Z",
            "html_url": "https://github.com/org/repo/issues/99",
            "comments": 5
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.body.as_deref(), Some("This is the body"));
        assert_eq!(issue.labels.len(), 1);
        assert_eq!(issue.labels[0].name, "bug");
        assert_eq!(issue.assignees.len(), 1);
        assert_eq!(issue.assignees[0].login, "bob");
        assert!(issue.milestone.is_some());
        assert_eq!(issue.milestone.unwrap().title, "v1.0");
        assert_eq!(issue.closed_at.as_deref(), Some("2026-03-02T00:00:00Z"));
        assert_eq!(issue.comments, 5);
    }

    #[test]
    fn issue_clone_debug() {
        let json = json!({
            "id": 1,
            "number": 1,
            "title": "Test",
            "state": "open",
            "user": {"login": "a", "id": 1},
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01",
            "html_url": "https://github.com/a/b/issues/1"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        let cloned = issue.clone();
        assert_eq!(cloned.title, "Test");
        let debug = format!("{issue:?}");
        assert!(debug.contains("Test"));
    }

    #[test]
    fn issue_roundtrip() {
        let json = json!({
            "id": 50,
            "number": 10,
            "title": "Roundtrip test",
            "state": "open",
            "user": {"login": "dev", "id": 7, "avatar_url": "", "type": "User"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "html_url": "https://github.com/org/repo/issues/10"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        let serialized = serde_json::to_string(&issue).unwrap();
        let back: Issue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.number, 10);
        assert_eq!(back.title, "Roundtrip test");
        assert_eq!(back.user.login, "dev");
    }

    // ---- PullRequest edge cases ----

    #[test]
    fn pull_request_with_all_optional_fields() {
        let json = json!({
            "id": 200,
            "number": 15,
            "title": "Full PR",
            "state": "closed",
            "body": "PR body text",
            "user": {"login": "dev", "id": 20, "avatar_url": "", "type": "User"},
            "head": {"label": "dev:feature", "ref": "feature", "sha": "aaa111"},
            "base": {"label": "org:main", "ref": "main", "sha": "bbb222"},
            "labels": [{"id": 1, "name": "enhancement", "color": "84b6eb"}],
            "assignees": [{"login": "reviewer", "id": 30}],
            "merged": true,
            "mergeable": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "merged_at": "2026-02-01T12:00:00Z",
            "closed_at": "2026-02-01T12:00:00Z",
            "html_url": "https://github.com/org/repo/pull/15",
            "draft": false,
            "additions": 100,
            "deletions": 50,
            "changed_files": 10
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        assert_eq!(pr.body.as_deref(), Some("PR body text"));
        assert!(pr.merged);
        assert_eq!(pr.mergeable, Some(true));
        assert_eq!(pr.merged_at.as_deref(), Some("2026-02-01T12:00:00Z"));
        assert_eq!(pr.additions, 100);
        assert_eq!(pr.deletions, 50);
        assert_eq!(pr.changed_files, 10);
        assert_eq!(pr.labels.len(), 1);
        assert_eq!(pr.assignees.len(), 1);
    }

    #[test]
    fn pull_request_mergeable_null() {
        let json = json!({
            "id": 201,
            "number": 16,
            "title": "PR with null mergeable",
            "state": "open",
            "user": {"login": "dev", "id": 20},
            "head": {"label": "dev:branch", "ref": "branch", "sha": "ccc"},
            "base": {"label": "org:main", "ref": "main", "sha": "ddd"},
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01",
            "html_url": "https://github.com/org/repo/pull/16",
            "mergeable": null
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        assert!(pr.mergeable.is_none());
    }

    #[test]
    fn pull_request_clone_debug() {
        let json = json!({
            "id": 300,
            "number": 20,
            "title": "Clone test PR",
            "state": "open",
            "user": {"login": "dev", "id": 1},
            "head": {"label": "dev:b", "ref": "b", "sha": "aaa"},
            "base": {"label": "org:main", "ref": "main", "sha": "bbb"},
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01",
            "html_url": "https://github.com/org/repo/pull/20"
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        let cloned = pr.clone();
        assert_eq!(cloned.number, 20);
        let debug = format!("{pr:?}");
        assert!(debug.contains("Clone test PR"));
    }

    #[test]
    fn pull_request_roundtrip() {
        let json = json!({
            "id": 400,
            "number": 25,
            "title": "Roundtrip PR",
            "state": "open",
            "user": {"login": "dev", "id": 1, "avatar_url": "", "type": "User"},
            "head": {"label": "dev:feat", "ref": "feat", "sha": "111"},
            "base": {"label": "org:main", "ref": "main", "sha": "222"},
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01",
            "html_url": "https://github.com/org/repo/pull/25",
            "draft": true
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        let serialized = serde_json::to_string(&pr).unwrap();
        let back: PullRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.number, 25);
        assert!(back.draft);
        assert_eq!(back.head.ref_name, "feat");
    }

    // ---- PullRequestRef ----

    #[test]
    fn pull_request_ref_serde() {
        let pr_ref = PullRequestRef {
            label: "owner:branch-name".into(),
            ref_name: "branch-name".into(),
            sha: "deadbeef".into(),
        };
        let json = serde_json::to_value(&pr_ref).unwrap();
        // "ref_name" should serialize as "ref"
        assert_eq!(json["ref"], "branch-name");
        assert!(json.get("ref_name").is_none());
        let back: PullRequestRef = serde_json::from_value(json).unwrap();
        assert_eq!(back.ref_name, "branch-name");
    }

    #[test]
    fn pull_request_ref_clone_debug() {
        let pr_ref = PullRequestRef {
            label: "a:b".into(),
            ref_name: "b".into(),
            sha: "abc".into(),
        };
        let cloned = pr_ref.clone();
        assert_eq!(cloned.sha, "abc");
        let debug = format!("{pr_ref:?}");
        assert!(debug.contains("abc"));
    }

    // ---- Repository edge cases ----

    #[test]
    fn repository_with_all_optional_fields() {
        let json = json!({
            "id": 1000,
            "name": "full-repo",
            "full_name": "org/full-repo",
            "owner": {"login": "org", "id": 100, "avatar_url": "", "type": "Organization"},
            "description": "A complete repository",
            "private": true,
            "fork": true,
            "html_url": "https://github.com/org/full-repo",
            "default_branch": "develop",
            "language": "Rust",
            "stargazers_count": 1000,
            "forks_count": 200,
            "open_issues_count": 15,
            "created_at": "2025-01-01",
            "updated_at": "2026-03-01"
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        assert_eq!(repo.description.as_deref(), Some("A complete repository"));
        assert!(repo.private);
        assert!(repo.fork);
        assert_eq!(repo.language.as_deref(), Some("Rust"));
        assert_eq!(repo.stargazers_count, 1000);
        assert_eq!(repo.forks_count, 200);
        assert_eq!(repo.open_issues_count, 15);
        assert_eq!(repo.default_branch, "develop");
    }

    #[test]
    fn repository_clone_debug() {
        let json = json!({
            "id": 1,
            "name": "test",
            "full_name": "org/test",
            "owner": {"login": "org", "id": 1},
            "html_url": "https://github.com/org/test",
            "default_branch": "main",
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01"
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        let cloned = repo.clone();
        assert_eq!(cloned.name, "test");
        let debug = format!("{repo:?}");
        assert!(debug.contains("org/test"));
    }

    #[test]
    fn repository_roundtrip() {
        let json = json!({
            "id": 5,
            "name": "round",
            "full_name": "org/round",
            "owner": {"login": "org", "id": 1, "avatar_url": "", "type": "User"},
            "html_url": "https://github.com/org/round",
            "default_branch": "main",
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01"
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        let serialized = serde_json::to_string(&repo).unwrap();
        let back: Repository = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.full_name, "org/round");
        assert!(!back.private);
        assert!(back.description.is_none());
    }

    // ---- FileContent edge cases ----

    #[test]
    fn file_content_without_content() {
        let json = json!({
            "name": "src",
            "path": "src",
            "sha": "abc123",
            "size": 0,
            "type": "dir",
            "html_url": "https://github.com/org/repo/tree/main/src"
        });
        let fc: FileContent = serde_json::from_value(json).unwrap();
        assert!(fc.content.is_none());
        assert!(fc.encoding.is_none());
        assert_eq!(fc.content_type, "dir");
        assert_eq!(fc.size, 0);
    }

    #[test]
    fn file_content_clone_debug() {
        let fc = FileContent {
            name: "lib.rs".into(),
            path: "src/lib.rs".into(),
            sha: "aabbcc".into(),
            size: 512,
            content_type: "file".into(),
            content: Some("base64data".into()),
            encoding: Some("base64".into()),
            html_url: Some("https://github.com/org/repo/blob/main/src/lib.rs".into()),
            target: None,
            submodule_git_url: None,
        };
        let cloned = fc.clone();
        assert_eq!(cloned.name, "lib.rs");
        let debug = format!("{fc:?}");
        assert!(debug.contains("lib.rs"));
    }

    #[test]
    fn file_content_roundtrip() {
        let fc = FileContent {
            name: "README.md".into(),
            path: "README.md".into(),
            sha: "deadbeef".into(),
            size: 2048,
            content_type: "file".into(),
            content: Some("SGVsbG8gV29ybGQ=".into()),
            encoding: Some("base64".into()),
            html_url: Some("https://github.com/org/repo/blob/main/README.md".into()),
            target: None,
            submodule_git_url: None,
        };
        let serialized = serde_json::to_string(&fc).unwrap();
        let back: FileContent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "README.md");
        assert_eq!(back.content.as_deref(), Some("SGVsbG8gV29ybGQ="));
        assert_eq!(back.content_type, "file");
    }

    // ---- CodeSearchItem + CodeSearchRepo ----

    #[test]
    fn code_search_item_serde() {
        let json = json!({
            "name": "main.rs",
            "path": "src/main.rs",
            "sha": "abc123",
            "html_url": "https://github.com/org/repo/blob/main/src/main.rs",
            "repository": {
                "id": 1,
                "name": "repo",
                "full_name": "org/repo",
                "html_url": "https://github.com/org/repo"
            }
        });
        let item: CodeSearchItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.name, "main.rs");
        assert_eq!(item.repository.full_name, "org/repo");
    }

    #[test]
    fn code_search_item_clone_debug() {
        let item = CodeSearchItem {
            name: "test.rs".into(),
            path: "tests/test.rs".into(),
            sha: "ff00ff".into(),
            html_url: "https://github.com/a/b/blob/main/tests/test.rs".into(),
            repository: CodeSearchRepo {
                id: 42,
                name: "b".into(),
                full_name: "a/b".into(),
                html_url: "https://github.com/a/b".into(),
            },
        };
        let cloned = item.clone();
        assert_eq!(cloned.repository.id, 42);
        let debug = format!("{item:?}");
        assert!(debug.contains("test.rs"));
    }

    #[test]
    fn code_search_item_roundtrip() {
        let item = CodeSearchItem {
            name: "lib.rs".into(),
            path: "src/lib.rs".into(),
            sha: "aabbcc".into(),
            html_url: "https://github.com/o/r/blob/main/src/lib.rs".into(),
            repository: CodeSearchRepo {
                id: 10,
                name: "r".into(),
                full_name: "o/r".into(),
                html_url: "https://github.com/o/r".into(),
            },
        };
        let serialized = serde_json::to_string(&item).unwrap();
        let back: CodeSearchItem = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.path, "src/lib.rs");
        assert_eq!(back.repository.name, "r");
    }

    #[test]
    fn code_search_repo_clone_debug() {
        let repo = CodeSearchRepo {
            id: 7,
            name: "project".into(),
            full_name: "user/project".into(),
            html_url: "https://github.com/user/project".into(),
        };
        let cloned = repo.clone();
        assert_eq!(cloned.full_name, "user/project");
        let debug = format!("{repo:?}");
        assert!(debug.contains("user/project"));
    }

    // ---- SearchResults edge cases ----

    #[test]
    fn search_results_empty() {
        let json = json!({
            "total_count": 0,
            "incomplete_results": false,
            "items": []
        });
        let results: SearchResults<Issue> = serde_json::from_value(json).unwrap();
        assert_eq!(results.total_count, 0);
        assert!(results.items.is_empty());
    }

    #[test]
    fn search_results_incomplete() {
        let json = json!({
            "total_count": 10000,
            "incomplete_results": true,
            "items": []
        });
        let results: SearchResults<Repository> = serde_json::from_value(json).unwrap();
        assert!(results.incomplete_results);
        assert_eq!(results.total_count, 10000);
    }

    #[test]
    fn search_results_clone_debug() {
        let json = json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [{
                "id": 1, "name": "r", "full_name": "o/r",
                "owner": {"login": "o", "id": 1},
                "html_url": "https://github.com/o/r",
                "default_branch": "main",
                "created_at": "2026-01-01",
                "updated_at": "2026-01-01"
            }]
        });
        let results: SearchResults<Repository> = serde_json::from_value(json).unwrap();
        let cloned = results.clone();
        assert_eq!(cloned.items.len(), 1);
        let debug = format!("{results:?}");
        assert!(debug.contains("total_count"));
    }

    // ---- ApiErrorResponse edge cases ----

    #[test]
    fn api_error_response_minimal() {
        let json = json!({"message": "Something went wrong"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Something went wrong");
        assert!(err.documentation_url.is_none());
        assert!(err.errors.is_none());
    }

    #[test]
    fn api_error_response_clone_debug() {
        let err = ApiErrorResponse {
            message: "Not Found".into(),
            documentation_url: Some("https://docs.github.com/".into()),
            errors: None,
        };
        let cloned = err.clone();
        assert_eq!(cloned.message, "Not Found");
        let debug = format!("{err:?}");
        assert!(debug.contains("Not Found"));
    }

    #[test]
    fn api_error_response_with_multiple_errors() {
        let json = json!({
            "message": "Validation Failed",
            "errors": [
                {"resource": "Issue", "field": "title", "code": "missing_field"},
                {"resource": "Issue", "field": "body", "code": "too_long", "message": "Body is too long"}
            ]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let errors = err.errors.unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].field.as_deref(), Some("title"));
        assert_eq!(errors[1].message.as_deref(), Some("Body is too long"));
    }

    // ---- ApiValidationError ----

    #[test]
    fn api_validation_error_all_none() {
        let json = json!({});
        let err: ApiValidationError = serde_json::from_value(json).unwrap();
        assert!(err.resource.is_none());
        assert!(err.field.is_none());
        assert!(err.code.is_none());
        assert!(err.message.is_none());
    }

    #[test]
    fn api_validation_error_clone_debug() {
        let err = ApiValidationError {
            resource: Some("PullRequest".into()),
            field: Some("head".into()),
            code: Some("invalid".into()),
            message: Some("Head does not exist".into()),
        };
        let cloned = err.clone();
        assert_eq!(cloned.resource.as_deref(), Some("PullRequest"));
        let debug = format!("{err:?}");
        assert!(debug.contains("PullRequest"));
    }

    // ---- CreateIssueRequest edge cases ----

    #[test]
    fn create_issue_request_with_all_fields() {
        let req = CreateIssueRequest {
            title: "Full issue".into(),
            body: Some("Body text".into()),
            assignees: Some(vec!["alice".into(), "bob".into()]),
            labels: Some(vec!["bug".into(), "urgent".into()]),
            milestone: Some(5),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"body\":\"Body text\""));
        assert!(json.contains("\"assignees\""));
        assert!(json.contains("\"labels\""));
        assert!(json.contains("\"milestone\":5"));
    }

    #[test]
    fn create_issue_request_skip_serializing_none() {
        let req = CreateIssueRequest {
            title: "Minimal".into(),
            body: None,
            assignees: None,
            labels: None,
            milestone: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("body"));
        assert!(!json.contains("assignees"));
        assert!(!json.contains("labels"));
        assert!(!json.contains("milestone"));
        // Only title should remain
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val.as_object().unwrap().len(), 1);
    }

    #[test]
    fn create_issue_request_clone_debug() {
        let req = CreateIssueRequest {
            title: "Test".into(),
            body: None,
            assignees: None,
            labels: None,
            milestone: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.title, "Test");
        let debug = format!("{req:?}");
        assert!(debug.contains("Test"));
    }

    // ---- CreatePullRequestRequest edge cases ----

    #[test]
    fn create_pr_request_minimal() {
        let req = CreatePullRequestRequest {
            title: "PR".into(),
            head: "feature".into(),
            base: "main".into(),
            body: None,
            draft: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("body"));
        assert!(!json.contains("draft"));
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val.as_object().unwrap().len(), 3);
    }

    #[test]
    fn create_pr_request_with_all_fields() {
        let req = CreatePullRequestRequest {
            title: "Feature PR".into(),
            head: "feat-branch".into(),
            base: "develop".into(),
            body: Some("Adds a new feature".into()),
            draft: Some(false),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"body\":\"Adds a new feature\""));
        assert!(json.contains("\"draft\":false"));
    }

    #[test]
    fn create_pr_request_clone_debug() {
        let req = CreatePullRequestRequest {
            title: "T".into(),
            head: "h".into(),
            base: "b".into(),
            body: None,
            draft: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.head, "h");
        let debug = format!("{req:?}");
        assert!(debug.contains("\"h\""));
    }

    // ---- MergePullRequestRequest edge cases ----

    #[test]
    fn merge_pr_request_with_all_fields() {
        let req = MergePullRequestRequest {
            commit_title: Some("Merge PR #5".into()),
            commit_message: Some("Merging feature branch".into()),
            merge_method: Some("squash".into()),
            sha: Some("abc123".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"commit_title\":\"Merge PR #5\""));
        assert!(json.contains("\"merge_method\":\"squash\""));
        assert!(json.contains("\"sha\":\"abc123\""));
    }

    #[test]
    fn merge_pr_request_skip_serializing_none() {
        let req = MergePullRequestRequest {
            commit_title: None,
            commit_message: None,
            merge_method: None,
            sha: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn merge_pr_request_partial_fields() {
        let req = MergePullRequestRequest {
            commit_title: None,
            commit_message: None,
            merge_method: Some("rebase".into()),
            sha: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("merge_method"));
        assert!(!json.contains("commit_title"));
        assert!(!json.contains("sha"));
    }

    #[test]
    fn merge_pr_request_clone_debug() {
        let req = MergePullRequestRequest {
            commit_title: Some("title".into()),
            commit_message: None,
            merge_method: None,
            sha: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.commit_title.as_deref(), Some("title"));
        let debug = format!("{req:?}");
        assert!(debug.contains("title"));
    }

    // ════════════════════════════════════════════════════════════════
    // Webhook types
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn webhook_event_type_serde_roundtrip() {
        for (et, expected) in [
            (WebhookEventType::Issues, "\"issues\""),
            (WebhookEventType::IssueComment, "\"issue_comment\""),
            (WebhookEventType::PullRequest, "\"pull_request\""),
            (
                WebhookEventType::PullRequestReview,
                "\"pull_request_review\"",
            ),
            (WebhookEventType::Push, "\"push\""),
            (WebhookEventType::WorkflowRun, "\"workflow_run\""),
            (WebhookEventType::Create, "\"create\""),
            (WebhookEventType::Delete, "\"delete\""),
            (WebhookEventType::Release, "\"release\""),
            (WebhookEventType::Ping, "\"ping\""),
        ] {
            let json = serde_json::to_string(&et).unwrap();
            assert_eq!(json, expected, "serde for {et:?}");
            let back: WebhookEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(et, back);
        }
    }

    #[test]
    fn webhook_event_type_display() {
        assert_eq!(WebhookEventType::Issues.to_string(), "issues");
        assert_eq!(WebhookEventType::PullRequest.to_string(), "pull_request");
        assert_eq!(WebhookEventType::WorkflowRun.to_string(), "workflow_run");
    }

    #[test]
    fn webhook_event_type_to_topic_with_action() {
        assert_eq!(
            WebhookEventType::Issues.to_topic(Some("opened")),
            "github.issues.opened"
        );
        assert_eq!(
            WebhookEventType::PullRequest.to_topic(Some("closed")),
            "github.pull_request.closed"
        );
    }

    #[test]
    fn webhook_event_type_to_topic_without_action() {
        assert_eq!(WebhookEventType::Push.to_topic(None), "github.push");
        assert_eq!(WebhookEventType::Ping.to_topic(None), "github.ping");
    }

    #[test]
    fn webhook_action_serde_roundtrip() {
        for (action, expected) in [
            (WebhookAction::Opened, "\"opened\""),
            (WebhookAction::Closed, "\"closed\""),
            (WebhookAction::Reopened, "\"reopened\""),
            (WebhookAction::Edited, "\"edited\""),
            (WebhookAction::Created, "\"created\""),
            (WebhookAction::Deleted, "\"deleted\""),
            (WebhookAction::Synchronize, "\"synchronize\""),
            (WebhookAction::Submitted, "\"submitted\""),
            (WebhookAction::Completed, "\"completed\""),
            (WebhookAction::Requested, "\"requested\""),
            (WebhookAction::Published, "\"published\""),
            (WebhookAction::Merged, "\"merged\""),
        ] {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(json, expected, "serde for {action:?}");
            let back: WebhookAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn webhook_payload_minimal_deserialization() {
        let json = json!({
            "event_type": "issues",
            "delivery_id": "d-123",
            "data": {"action": "opened", "issue": {"number": 42}}
        });
        let payload: WebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, WebhookEventType::Issues);
        assert_eq!(payload.delivery_id, "d-123");
        assert!(payload.repository.is_none());
        assert!(payload.sender.is_none());
    }

    #[test]
    fn webhook_payload_full_deserialization() {
        let json = json!({
            "event_type": "pull_request",
            "delivery_id": "d-456",
            "data": {"action": "opened", "number": 10},
            "repository": {
                "id": 12345,
                "full_name": "octocat/hello",
                "html_url": "https://github.com/octocat/hello",
                "private": false
            },
            "sender": {
                "login": "octocat",
                "id": 1,
                "avatar_url": "https://avatars.githubusercontent.com/u/1"
            }
        });
        let payload: WebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, WebhookEventType::PullRequest);
        assert_eq!(
            payload.repository.as_ref().unwrap().full_name,
            "octocat/hello"
        );
        assert_eq!(payload.sender.as_ref().unwrap().login, "octocat");
    }

    #[test]
    fn webhook_payload_serialization_roundtrip() {
        let payload = WebhookPayload {
            event_type: WebhookEventType::Push,
            delivery_id: "d-789".into(),
            data: json!({"ref": "refs/heads/main", "commits": []}),
            repository: Some(WebhookRepository {
                id: 100,
                full_name: "test/repo".into(),
                html_url: "https://github.com/test/repo".into(),
                private: true,
            }),
            sender: Some(WebhookSender {
                login: "alice".into(),
                id: 42,
                avatar_url: None,
            }),
        };
        let json_str = serde_json::to_string(&payload).unwrap();
        let back: WebhookPayload = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.event_type, WebhookEventType::Push);
        assert_eq!(back.delivery_id, "d-789");
        assert!(back.repository.unwrap().private);
    }

    #[test]
    fn webhook_repository_deserialization() {
        let json = json!({
            "id": 999,
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo"
        });
        let repo: WebhookRepository = serde_json::from_value(json).unwrap();
        assert_eq!(repo.id, 999);
        assert!(!repo.private); // default
    }

    #[test]
    fn webhook_sender_deserialization() {
        let json = json!({
            "login": "bot",
            "id": 7
        });
        let sender: WebhookSender = serde_json::from_value(json).unwrap();
        assert_eq!(sender.login, "bot");
        assert!(sender.avatar_url.is_none());
    }
}
