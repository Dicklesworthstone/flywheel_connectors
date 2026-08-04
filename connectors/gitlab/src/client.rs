//! `GitLab` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

/// Characters that are NOT percent-encoded when encoding a single path segment.
/// Keeps alphanumerics, hyphens, underscores, dots, and tildes (RFC 3986 unreserved).
/// Slashes are NOT included — they must be encoded when a project ID is a namespace path.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode a value for use as a single URL path segment.
///
/// GitLab project IDs can be numeric (`12345`) or namespace paths (`group/subgroup/project`).
/// When used in a URL like `/projects/{id}/issues`, the slashes must be encoded to
/// `group%2Fsubgroup%2Fproject` so they aren't interpreted as path separators.
///
/// Because slashes are encoded, the only residual traversal vector is a bare
/// `.`/`..` segment that the server would normalize to a sibling endpoint (e.g.
/// `list_issues("..")` → `/projects/../issues` → `/issues`, silently widening
/// scope to every project the token can see). GitLab paths never legitimately
/// contain consecutive dots, so such values are rejected outright.
fn encode_path_segment(value: &str) -> GitLabResult<String> {
    if value.is_empty() {
        return Err(GitLabError::InvalidInput(
            "path segment must not be empty".into(),
        ));
    }
    if value == "." || value.contains("..") {
        return Err(GitLabError::InvalidInput(
            "path segment must not contain traversal sequences".into(),
        ));
    }
    Ok(utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string())
}

use crate::{
    error::{GitLabError, GitLabResult},
    types::ApiErrorResponse,
};

/// Default `GitLab` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://gitlab.com/api/v4";

/// Authentication mode for the `GitLab` API.
#[derive(Clone)]
pub enum GitLabAuth {
    /// Personal access token (PRIVATE-TOKEN header).
    PrivateToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl GitLabAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::PrivateToken(_) => "private_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for GitLabAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateToken(_) => f.debug_tuple("PrivateToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `GitLab` API client.
pub struct GitLabClient {
    client: Client,
    auth: GitLabAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for GitLabClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitLabClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl GitLabClient {
    /// Create a new `GitLab` client.
    pub fn new(auth: GitLabAuth, base_url: Option<&str>) -> GitLabResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-gitlab/0.1.0")
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
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: GitLabAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            GitLabAuth::PrivateToken(token) => req.header("PRIVATE-TOKEN", token),
            GitLabAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> GitLabResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.trim().is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> GitLabResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error.or_else(|| e.message.map(|m| m.to_string())))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(GitLabError::Unauthorized),
            403 => Err(GitLabError::Forbidden),
            404 => Err(GitLabError::NotFound { resource: detail }),
            429 => Err(GitLabError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(GitLabError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> GitLabResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> GitLabResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self.add_auth(self.client.post(&url).json(body));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Projects --

    /// List projects.
    pub async fn list_projects(&self, per_page: Option<i64>) -> GitLabResult<serde_json::Value> {
        let qs = per_page.map_or_else(String::new, |pp| format!("?per_page={pp}"));
        self.get(&format!("/projects{qs}")).await
    }

    // -- Issues --

    /// List issues in a project.
    pub async fn list_issues(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        let encoded = encode_path_segment(project_id)?;
        self.get(&format!("/projects/{encoded}/issues")).await
    }

    /// Create an issue.
    pub async fn create_issue(
        &self,
        project_id: &str,
        body: &serde_json::Value,
    ) -> GitLabResult<serde_json::Value> {
        let encoded = encode_path_segment(project_id)?;
        self.post(&format!("/projects/{encoded}/issues"), body)
            .await
    }

    // -- Merge Requests --

    /// List merge requests.
    pub async fn list_merge_requests(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        let encoded = encode_path_segment(project_id)?;
        self.get(&format!("/projects/{encoded}/merge_requests"))
            .await
    }

    // -- Pipelines --

    /// List pipelines.
    pub async fn list_pipelines(&self, project_id: &str) -> GitLabResult<serde_json::Value> {
        let encoded = encode_path_segment(project_id)?;
        self.get(&format!("/projects/{encoded}/pipelines")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = GitLabAuth::PrivateToken("glpat-secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("glpat-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = GitLabAuth::PrivateToken("tok".into());
        assert!(!token.is_secretless());
        let cred = GitLabAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = GitLabAuth::PrivateToken("tok".into());
        assert_eq!(token.redacted_label(), "private_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = GitLabAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains(&id_str));
    }

    #[test]
    fn auth_debug_credential_id_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = GitLabAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&id_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone_private_token() {
        let auth = GitLabAuth::PrivateToken("glpat-test".into());
        let cloned = auth.clone();
        assert!(!auth.is_secretless());
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "private_token:redacted");
    }

    #[test]
    fn auth_clone_credential_id() {
        let auth = GitLabAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
        assert!(cloned.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = GitLabClient::new(GitLabAuth::PrivateToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = GitLabClient::new(
            GitLabAuth::PrivateToken("tok".into()),
            Some("https://gitlab.example.com/api/v4/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://gitlab.example.com/api/v4");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = GitLabClient::new(
            GitLabAuth::PrivateToken("tok".into()),
            Some("https://test.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.com");
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = GitLabClient::new(GitLabAuth::PrivateToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GitLabClient"));
        assert!(dbg.contains("base_url"));
        assert!(dbg.contains("gitlab.com"));
    }

    #[test]
    fn client_debug_redacts_token() {
        let client =
            GitLabClient::new(GitLabAuth::PrivateToken("glpat-secret123".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("glpat-secret123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_no_trailing_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn default_base_url_contains_v4() {
        assert!(DEFAULT_BASE_URL.contains("v4"));
    }

    #[test]
    fn client_with_client_trims_trailing_slash() {
        let http_client = Client::new();
        let client = GitLabClient::with_client(
            http_client,
            GitLabAuth::PrivateToken("tok".into()),
            "https://test.com/",
        );
        assert_eq!(client.base_url, "https://test.com");
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            GitLabClient::new(GitLabAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_empty_url() {
        let client = GitLabClient::new(GitLabAuth::PrivateToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = GitLabClient::new(
            GitLabAuth::PrivateToken("tok".into()),
            Some("https://x.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    // ── encode_path_segment tests ───────────────────────────────
    #[test]
    fn encode_path_segment_numeric_id_unchanged() {
        assert_eq!(encode_path_segment("12345").unwrap(), "12345");
    }

    #[test]
    fn encode_path_segment_encodes_slashes() {
        assert_eq!(
            encode_path_segment("group/subgroup/project").unwrap(),
            "group%2Fsubgroup%2Fproject"
        );
    }

    #[test]
    fn encode_path_segment_encodes_spaces() {
        assert_eq!(encode_path_segment("my project").unwrap(), "my%20project");
    }

    #[test]
    fn encode_path_segment_preserves_hyphens_underscores() {
        assert_eq!(
            encode_path_segment("my-project_v2").unwrap(),
            "my-project_v2"
        );
    }

    #[test]
    fn encode_path_segment_encodes_special_chars() {
        assert_eq!(encode_path_segment("a?b#c").unwrap(), "a%3Fb%23c");
    }

    #[test]
    fn encode_path_segment_rejects_traversal() {
        // A bare `..`/`.` project id would normalize to a sibling endpoint
        // (`/projects/../issues` → `/issues`), widening the authorization scope.
        for evil in ["..", ".", "../..", "a..b", ""] {
            assert!(
                matches!(encode_path_segment(evil), Err(GitLabError::InvalidInput(_))),
                "path segment {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn auth_debug_no_token_leak() {
        let auth = GitLabAuth::PrivateToken("glpat-ABCDEF1234567890".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("ABCDEF"));
        assert!(!dbg.contains("glpat-"));
        assert!(dbg.contains("PrivateToken"));
    }
}
