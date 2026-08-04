//! `Evernote` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{EvernoteError, EvernoteResult},
    types::ApiErrorResponse,
};

/// Default `Evernote` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.evernote.com/v1";

/// Authentication mode for the `Evernote` API.
#[derive(Clone)]
pub enum EvernoteAuth {
    /// `OAuth` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl EvernoteAuth {
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

impl fmt::Debug for EvernoteAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> EvernoteResult<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
        || segment.contains('?')
        || segment.contains('#')
    {
        return Err(EvernoteError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

/// `Evernote` API client.
pub struct EvernoteClient {
    client: Client,
    auth: EvernoteAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for EvernoteClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvernoteClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl EvernoteClient {
    /// Create a new `Evernote` client.
    pub fn new(auth: EvernoteAuth, base_url: Option<&str>) -> EvernoteResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-evernote/0.1.0 (FCP connector)")
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
            EvernoteAuth::BearerToken(token) => req.bearer_auth(token),
            EvernoteAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> EvernoteResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if status == StatusCode::NO_CONTENT {
                return Ok(serde_json::json!({}));
            }
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
    ) -> EvernoteResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(EvernoteError::Unauthorized),
            403 => Err(EvernoteError::Forbidden),
            404 => Err(EvernoteError::NotFound { resource: detail }),
            429 => Err(EvernoteError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(EvernoteError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> EvernoteResult<serde_json::Value> {
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
    ) -> EvernoteResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> EvernoteResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Notebooks --

    /// List all notebooks.
    pub async fn list_notebooks(&self) -> EvernoteResult<serde_json::Value> {
        self.get("/notebooks").await
    }

    // -- Notes --

    /// List notes in a notebook.
    pub async fn list_notes(&self, notebook_id: &str) -> EvernoteResult<serde_json::Value> {
        let notebook_id = sanitize_path_segment(notebook_id)?;
        self.get(&format!("/notebooks/{notebook_id}/notes")).await
    }

    /// Get a single note.
    pub async fn get_note(&self, note_id: &str) -> EvernoteResult<serde_json::Value> {
        let note_id = sanitize_path_segment(note_id)?;
        self.get(&format!("/notes/{note_id}")).await
    }

    /// Create a note.
    pub async fn create_note(&self, body: &serde_json::Value) -> EvernoteResult<serde_json::Value> {
        self.post("/notes", body).await
    }

    /// Delete a note.
    pub async fn delete_note(&self, note_id: &str) -> EvernoteResult<serde_json::Value> {
        let note_id = sanitize_path_segment(note_id)?;
        self.delete(&format!("/notes/{note_id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = EvernoteAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn sanitize_path_segment_valid() {
        assert!(sanitize_path_segment("abc123").is_ok());
        assert!(sanitize_path_segment("note-guid-456").is_ok());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../etc/passwd").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("foo\\bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("   ").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
        assert!(sanitize_path_segment("foo?bar=1").is_err());
        assert!(sanitize_path_segment("foo#frag").is_err());
    }

    #[test]
    fn auth_secretless_detection() {
        let token = EvernoteAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = EvernoteAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_bearer() {
        let token = EvernoteAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = EvernoteAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = EvernoteAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(!dbg.contains("redacted"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        assert!(!EvernoteAuth::BearerToken("token".into()).is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        assert!(EvernoteAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.evernote.com/v1");
    }

    #[test]
    fn client_new_with_defaults() {
        let client = EvernoteClient::new(EvernoteAuth::BearerToken("test".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_with_custom_url() {
        let client = EvernoteClient::new(
            EvernoteAuth::BearerToken("test".into()),
            Some("https://custom.evernote.com/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.evernote.com/api");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = EvernoteClient::new(
            EvernoteAuth::BearerToken("test".into()),
            Some("https://custom.evernote.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.evernote.com/api");
    }

    #[test]
    fn client_debug_format() {
        let client = EvernoteClient::new(EvernoteAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("EvernoteClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn auth_clone() {
        let auth = EvernoteAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), cloned.redacted_label());
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = EvernoteAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = cred.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = EvernoteClient::new(EvernoteAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("EvernoteClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = EvernoteClient::new(
            EvernoteAuth::BearerToken("tok".into()),
            Some("https://custom.api.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.api.com"));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = EvernoteClient::new(
            EvernoteAuth::BearerToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_debug_bearer_shows_tuple() {
        let auth = EvernoteAuth::BearerToken("secret-value".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.starts_with("BearerToken("));
    }

    #[test]
    fn auth_redacted_label_does_not_leak_token() {
        let auth = EvernoteAuth::BearerToken("super-secret-token-value".into());
        let label = auth.redacted_label();
        assert!(!label.contains("super-secret-token-value"));
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn client_new_with_localhost() {
        let client = EvernoteClient::new(
            EvernoteAuth::BearerToken("tok".into()),
            Some("http://127.0.0.1:8080/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:8080/api");
    }

    #[test]
    fn auth_debug_credential_does_not_say_redacted() {
        let cred = EvernoteAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("redacted"));
    }
}
