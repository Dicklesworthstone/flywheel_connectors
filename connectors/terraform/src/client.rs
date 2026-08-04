//! Terraform Cloud API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{TerraformError, TerraformResult},
    types::ApiErrorResponse,
};

/// Default Terraform Cloud API base URL.
pub const DEFAULT_BASE_URL: &str = "https://app.terraform.io/api/v2";

/// Authentication mode for the Terraform Cloud API.
#[derive(Clone)]
pub enum TerraformAuth {
    /// Bearer API token (`Authorization: Bearer {token}`).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl TerraformAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for TerraformAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Terraform Cloud API client.
pub struct TerraformClient {
    client: Client,
    auth: TerraformAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for TerraformClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerraformClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl TerraformClient {
    /// Create a new Terraform Cloud client.
    pub fn new(auth: TerraformAuth, base_url: Option<&str>) -> TerraformResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-terraform/0.1.0 (FCP connector)")
            .build()?;

        let request_timeout = Duration::from_secs(60);
        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            TerraformAuth::BearerToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            TerraformAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> TerraformResult<serde_json::Value> {
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
    ) -> TerraformResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        // Terraform Cloud returns {"errors": [{"status": "...", "title": "...", "detail": "..."}]}
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.errors)
            .and_then(|errs| {
                errs.first()
                    .and_then(|e| e.detail.clone().or_else(|| e.title.clone()))
            })
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(TerraformError::Unauthorized),
            403 => Err(TerraformError::Forbidden),
            404 => Err(TerraformError::NotFound { resource: detail }),
            409 => Err(TerraformError::Conflict { message: detail }),
            429 => Err(TerraformError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(30) * 1000,
            }),
            code => Err(TerraformError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> TerraformResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/vnd.api+json")
            .header("Content-Type", "application/vnd.api+json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> TerraformResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/vnd.api+json")
            .header("Content-Type", "application/vnd.api+json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Workspaces --

    /// List workspaces in an organization.
    pub async fn list_workspaces(&self, org_name: &str) -> TerraformResult<serde_json::Value> {
        let org_name = sanitize_path_segment(org_name, "organization")?;
        self.get(&format!("/organizations/{org_name}/workspaces"))
            .await
    }

    /// Get a workspace by ID.
    pub async fn get_workspace(&self, workspace_id: &str) -> TerraformResult<serde_json::Value> {
        let workspace_id = sanitize_path_segment(workspace_id, "workspace_id")?;
        self.get(&format!("/workspaces/{workspace_id}")).await
    }

    /// Get a workspace by organization name and workspace name.
    pub async fn get_workspace_by_name(
        &self,
        org_name: &str,
        workspace_name: &str,
    ) -> TerraformResult<serde_json::Value> {
        let org_name = sanitize_path_segment(org_name, "organization")?;
        let workspace_name = sanitize_path_segment(workspace_name, "workspace_name")?;
        self.get(&format!(
            "/organizations/{org_name}/workspaces/{workspace_name}"
        ))
        .await
    }

    // -- Runs --

    /// Create a run in a workspace.
    pub async fn create_run(&self, body: &serde_json::Value) -> TerraformResult<serde_json::Value> {
        self.post("/runs", body).await
    }

    /// Get a run by ID.
    pub async fn get_run(&self, run_id: &str) -> TerraformResult<serde_json::Value> {
        let run_id = sanitize_path_segment(run_id, "run_id")?;
        self.get(&format!("/runs/{run_id}")).await
    }

    /// Apply a run (confirm apply).
    pub async fn apply_run(
        &self,
        run_id: &str,
        comment: Option<&str>,
    ) -> TerraformResult<serde_json::Value> {
        let run_id = sanitize_path_segment(run_id, "run_id")?;
        let body = serde_json::json!({
            "comment": comment.unwrap_or("Applied via FCP Terraform connector")
        });
        self.post(&format!("/runs/{run_id}/actions/apply"), &body)
            .await
    }

    /// Discard a run.
    pub async fn discard_run(
        &self,
        run_id: &str,
        comment: Option<&str>,
    ) -> TerraformResult<serde_json::Value> {
        let run_id = sanitize_path_segment(run_id, "run_id")?;
        let body = serde_json::json!({
            "comment": comment.unwrap_or("Discarded via FCP Terraform connector")
        });
        self.post(&format!("/runs/{run_id}/actions/discard"), &body)
            .await
    }

    /// List runs in a workspace.
    pub async fn list_runs(&self, workspace_id: &str) -> TerraformResult<serde_json::Value> {
        let workspace_id = sanitize_path_segment(workspace_id, "workspace_id")?;
        self.get(&format!("/workspaces/{workspace_id}/runs")).await
    }

    // -- Plans --

    /// Get a plan by ID.
    pub async fn get_plan(&self, plan_id: &str) -> TerraformResult<serde_json::Value> {
        let plan_id = sanitize_path_segment(plan_id, "plan_id")?;
        self.get(&format!("/plans/{plan_id}")).await
    }

    /// Get plan JSON output (structured plan output).
    pub async fn get_plan_json_output(&self, plan_id: &str) -> TerraformResult<serde_json::Value> {
        let plan_id = sanitize_path_segment(plan_id, "plan_id")?;
        self.get(&format!("/plans/{plan_id}/json-output")).await
    }

    // -- State Versions --

    /// Get current state version for a workspace.
    pub async fn get_current_state_version(
        &self,
        workspace_id: &str,
    ) -> TerraformResult<serde_json::Value> {
        let workspace_id = sanitize_path_segment(workspace_id, "workspace_id")?;
        self.get(&format!("/workspaces/{workspace_id}/current-state-version"))
            .await
    }

    /// List state version outputs.
    pub async fn list_state_version_outputs(
        &self,
        state_version_id: &str,
    ) -> TerraformResult<serde_json::Value> {
        let state_version_id = sanitize_path_segment(state_version_id, "state_version_id")?;
        self.get(&format!("/state-versions/{state_version_id}/outputs"))
            .await
    }

    // -- Configuration Versions --

    /// List configuration versions for a workspace.
    pub async fn list_configuration_versions(
        &self,
        workspace_id: &str,
    ) -> TerraformResult<serde_json::Value> {
        let workspace_id = sanitize_path_segment(workspace_id, "workspace_id")?;
        self.get(&format!(
            "/workspaces/{workspace_id}/configuration-versions"
        ))
        .await
    }

    // -- State Version Resources --

    /// List resources in a state version.
    pub async fn list_state_resources(
        &self,
        state_version_id: &str,
    ) -> TerraformResult<serde_json::Value> {
        let state_version_id = sanitize_path_segment(state_version_id, "state_version_id")?;
        self.get(&format!("/state-versions/{state_version_id}/resources"))
            .await
    }
}

/// Validate that a caller-supplied Terraform Cloud identifier is safe to
/// interpolate into a URL path segment.
///
/// Terraform organization names, workspace names, and prefixed resource IDs
/// (`ws-…`, `run-…`, `plan-…`, `sv-…`) are all `[A-Za-z0-9_-]`-shaped, so this
/// never rejects a legitimate value. Without it, a `run_id` of
/// `../../workspaces/<victim>/runs` on the destructive `apply_run`/`discard_run`
/// endpoints normalizes (via `Url::parse`) to a different run than intended, and
/// an embedded `?`/`#` injects a query/fragment against the API host.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> TerraformResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TerraformError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(TerraformError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

fn decode_success_body(status: StatusCode, body: &str) -> TerraformResult<serde_json::Value> {
    if matches!(status, StatusCode::NO_CONTENT | StatusCode::ACCEPTED) {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(TerraformError::Api {
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
    fn auth_debug_redacts_token() {
        let auth = TerraformAuth::BearerToken("secret-api-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal_and_control_chars() {
        for bad in [
            "",
            "   ",
            "../../workspaces/victim/runs",
            "..",
            "run-abc/../../runs",
            "a/b",
            "a\\b",
            "run-abc?x=y",
            "run-abc#frag",
            "a%2f..%2fb",
            "a%5cb",
        ] {
            assert!(
                sanitize_path_segment(bad, "run_id").is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn sanitize_path_segment_accepts_real_identifiers() {
        assert_eq!(
            sanitize_path_segment("run-CZcmD7eagjhyX0vN", "run_id").unwrap(),
            "run-CZcmD7eagjhyX0vN"
        );
        assert_eq!(
            sanitize_path_segment(" my-org_1 ", "organization").unwrap(),
            "my-org_1"
        );
        assert_eq!(
            sanitize_path_segment("ws-SihZTyXKfNXUWuUa", "workspace_id").unwrap(),
            "ws-SihZTyXKfNXUWuUa"
        );
    }

    #[test]
    fn auth_secretless_detection() {
        let token = TerraformAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = TerraformAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = TerraformAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = TerraformAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            TerraformError::Api {
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
            TerraformError::Api {
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
    fn client_new_default_url() {
        let client = TerraformClient::new(TerraformAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = TerraformClient::new(
            TerraformAuth::BearerToken("tok".into()),
            Some("https://tfe.example.com/api/v2/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://tfe.example.com/api/v2");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            TerraformClient::new(TerraformAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = TerraformAuth::BearerToken("my-token".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = TerraformAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = TerraformClient::new(
            TerraformAuth::BearerToken("tok".into()),
            Some("https://tfe.example.com/api/v2///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_clone_bearer() {
        let auth = TerraformAuth::BearerToken("tok123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = TerraformAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = TerraformClient::new(TerraformAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("TerraformClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let client = TerraformClient::new(
            TerraformAuth::BearerToken("tok".into()),
            Some("https://tfe.example.com/api/v2"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://tfe.example.com/api/v2");
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = TerraformClient::new(TerraformAuth::CredentialId(cred), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn default_base_url_contains_terraform() {
        assert!(DEFAULT_BASE_URL.contains("terraform"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_contains_api_v2() {
        assert!(DEFAULT_BASE_URL.contains("/api/v2"));
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = TerraformAuth::BearerToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = TerraformAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }
}
