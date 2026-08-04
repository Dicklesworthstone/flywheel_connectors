//! `Bitbucket` Cloud API client.

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
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode a value for use as a single URL path segment.
///
/// Slashes are encoded, so the only residual traversal vector is a bare `.`/`..`
/// segment that the server would normalize to a sibling endpoint (e.g.
/// `list_repositories("..")` → `/2.0/repositories/../…` → `/2.0/…`). Workspace
/// slugs, repo slugs, and PR ids never legitimately contain consecutive dots, so
/// such values are rejected outright.
fn encode_path_segment(value: &str) -> BitbucketResult<String> {
    if value.is_empty() {
        return Err(BitbucketError::InvalidInput(
            "path segment must not be empty".into(),
        ));
    }
    if value == "." || value.contains("..") {
        return Err(BitbucketError::InvalidInput(
            "path segment must not contain traversal sequences".into(),
        ));
    }
    Ok(utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string())
}

use crate::{
    error::{BitbucketError, BitbucketResult},
    types::ApiErrorResponse,
};

/// Default `Bitbucket` Cloud REST API v2 base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.bitbucket.org/2.0";

/// Authentication mode for the `Bitbucket` API.
#[derive(Clone)]
pub enum BitbucketAuth {
    /// App Password authentication (HTTP Basic auth: `username:app_password`).
    AppPassword {
        /// `Bitbucket` username.
        username: String,
        /// `Bitbucket` app password.
        app_password: String,
    },
    /// `OAuth2` access token (passed as `Authorization: Bearer <token>`).
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl BitbucketAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AppPassword { username, .. } => format!("app_password:{username}:redacted"),
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for BitbucketAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppPassword { username, .. } => f
                .debug_struct("AppPassword")
                .field("username", username)
                .field("app_password", &"<redacted>")
                .finish(),
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Bitbucket` Cloud API client.
pub struct BitbucketClient {
    client: Client,
    auth: BitbucketAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for BitbucketClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitbucketClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BitbucketClient {
    /// Create a new `Bitbucket` client.
    pub fn new(auth: BitbucketAuth, base_url: Option<&str>) -> BitbucketResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-bitbucket/0.1.0 (FCP connector)")
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

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            BitbucketAuth::AppPassword {
                username,
                app_password,
            } => req.basic_auth(username, Some(app_password)),
            BitbucketAuth::AccessToken(token) => req.bearer_auth(token),
            BitbucketAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> BitbucketResult<serde_json::Value> {
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
    ) -> BitbucketResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Bitbucket returns {"error": {"message": "...", "detail": "..."}} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| {
                // Prefer message, fall back to detail.
                e.message.or(e.detail)
            })
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(BitbucketError::Unauthorized),
            403 => Err(BitbucketError::Forbidden),
            404 => Err(BitbucketError::NotFound { resource: detail }),
            429 => Err(BitbucketError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(BitbucketError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> BitbucketResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> BitbucketResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- User --

    /// Get the authenticated user.
    pub async fn get_user(&self) -> BitbucketResult<serde_json::Value> {
        self.get("/user").await
    }

    // -- Workspaces --

    /// List workspaces accessible by the authenticated user.
    pub async fn list_workspaces(&self) -> BitbucketResult<serde_json::Value> {
        self.get("/workspaces").await
    }

    // -- Repositories --

    /// List repositories in a workspace.
    pub async fn list_repositories(&self, workspace: &str) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        self.get(&format!("/repositories/{ws}")).await
    }

    /// Get a single repository.
    pub async fn get_repository(
        &self,
        workspace: &str,
        repo_slug: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.get(&format!("/repositories/{ws}/{repo}")).await
    }

    // -- Pull Requests --

    /// List pull requests in a repository.
    pub async fn list_pull_requests(
        &self,
        workspace: &str,
        repo_slug: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.get(&format!("/repositories/{ws}/{repo}/pullrequests"))
            .await
    }

    /// Get a single pull request.
    pub async fn get_pull_request(
        &self,
        workspace: &str,
        repo_slug: &str,
        pr_id: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        let id = encode_path_segment(pr_id)?;
        self.get(&format!("/repositories/{ws}/{repo}/pullrequests/{id}"))
            .await
    }

    /// Create a pull request.
    pub async fn create_pull_request(
        &self,
        workspace: &str,
        repo_slug: &str,
        body: &serde_json::Value,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.post(&format!("/repositories/{ws}/{repo}/pullrequests"), body)
            .await
    }

    // -- Branches --

    /// List branches in a repository.
    pub async fn list_branches(
        &self,
        workspace: &str,
        repo_slug: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.get(&format!("/repositories/{ws}/{repo}/refs/branches"))
            .await
    }

    // -- Commits --

    /// List commits in a repository.
    pub async fn list_commits(
        &self,
        workspace: &str,
        repo_slug: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.get(&format!("/repositories/{ws}/{repo}/commits"))
            .await
    }

    // -- Pipelines --

    /// List pipelines in a repository.
    pub async fn list_pipelines(
        &self,
        workspace: &str,
        repo_slug: &str,
    ) -> BitbucketResult<serde_json::Value> {
        let ws = encode_path_segment(workspace)?;
        let repo = encode_path_segment(repo_slug)?;
        self.get(&format!("/repositories/{ws}/{repo}/pipelines"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode_path_segment tests ───────────────────────────────
    #[test]
    fn encode_path_segment_simple_slug_unchanged() {
        assert_eq!(encode_path_segment("my-team").unwrap(), "my-team");
    }

    #[test]
    fn encode_path_segment_encodes_slashes() {
        assert_eq!(encode_path_segment("a/b/c").unwrap(), "a%2Fb%2Fc");
    }

    #[test]
    fn encode_path_segment_encodes_spaces() {
        assert_eq!(encode_path_segment("my team").unwrap(), "my%20team");
    }

    #[test]
    fn encode_path_segment_encodes_special_chars() {
        assert_eq!(encode_path_segment("repo?q=1").unwrap(), "repo%3Fq%3D1");
    }

    #[test]
    fn encode_path_segment_rejects_traversal() {
        // A bare `..`/`.` workspace or repo slug would normalize to a sibling
        // endpoint (`/repositories/../…` → `/…`), changing the intended target.
        for evil in ["..", ".", "../..", "a..b", ""] {
            assert!(
                matches!(
                    encode_path_segment(evil),
                    Err(BitbucketError::InvalidInput(_))
                ),
                "path segment {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn auth_debug_redacts_access_token() {
        let auth = BitbucketAuth::AccessToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_redacts_app_password() {
        let auth = BitbucketAuth::AppPassword {
            username: "user".into(),
            app_password: "secret-pass".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-pass"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("user"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = BitbucketAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());
        let app = BitbucketAuth::AppPassword {
            username: "u".into(),
            app_password: "p".into(),
        };
        assert!(!app.is_secretless());
        let cred = BitbucketAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_access_token() {
        let token = BitbucketAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_redacted_label_app_password() {
        let auth = BitbucketAuth::AppPassword {
            username: "myuser".into(),
            app_password: "secret".into(),
        };
        assert_eq!(auth.redacted_label(), "app_password:myuser:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = BitbucketAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = BitbucketClient::new(BitbucketAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = BitbucketClient::new(
            BitbucketAuth::AccessToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            BitbucketClient::new(BitbucketAuth::AccessToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_new_with_app_password() {
        let client = BitbucketClient::new(
            BitbucketAuth::AppPassword {
                username: "user".into(),
                app_password: "pass".into(),
            },
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_app_password_redacts() {
        let client = BitbucketClient::new(
            BitbucketAuth::AppPassword {
                username: "user".into(),
                app_password: "supersecret".into(),
            },
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("user"));
    }

    #[test]
    fn auth_access_token_redacted_label_value() {
        let auth = BitbucketAuth::AccessToken("my_token_xyz".into());
        let label = auth.redacted_label();
        assert_eq!(label, "access_token:redacted");
        assert!(!label.contains("my_token_xyz"));
    }

    #[test]
    fn auth_app_password_redacted_label_contains_username() {
        let auth = BitbucketAuth::AppPassword {
            username: "myuser".into(),
            app_password: "mypass".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("myuser"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("mypass"));
    }

    #[test]
    fn auth_credential_id_secretless_verified() {
        let cred_id = CredentialId::new();
        let auth = BitbucketAuth::CredentialId(cred_id);
        assert!(auth.is_secretless());
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = BitbucketClient::new(
            BitbucketAuth::AccessToken("tok".into()),
            Some("https://example.com/api///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = BitbucketClient::new(
            BitbucketAuth::AccessToken("tok".into()),
            Some("https://custom.example.com/v2"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.example.com"));
    }

    #[test]
    fn auth_debug_credential_id_format() {
        let cred = BitbucketAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(!dbg.contains("redacted"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_contains_bitbucket() {
        assert!(DEFAULT_BASE_URL.contains("bitbucket.org"));
    }

    #[test]
    fn default_base_url_has_v2() {
        assert!(DEFAULT_BASE_URL.contains("/2.0"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let client =
            BitbucketClient::new(BitbucketAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_credential_id() {
        let client =
            BitbucketClient::new(BitbucketAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains("BitbucketClient"));
    }

    #[test]
    fn auth_app_password_is_not_secretless() {
        let auth = BitbucketAuth::AppPassword {
            username: "u".into(),
            app_password: "p".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_access_token_is_not_secretless() {
        let auth = BitbucketAuth::AccessToken("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = BitbucketAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let client = BitbucketClient::new(
            BitbucketAuth::AccessToken("tok".into()),
            Some("https://example.com/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com/api");
    }
}
