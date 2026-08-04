//! `Metabase` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{MetabaseError, MetabaseResult},
    types::ApiErrorResponse,
};

/// Authentication mode for the `Metabase` API.
#[derive(Clone)]
pub enum MetabaseAuth {
    /// Session token (passed as `X-Metabase-Session: <token>`).
    SessionToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MetabaseAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::SessionToken(_) => "session_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for MetabaseAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionToken(_) => f.debug_tuple("SessionToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Metabase` API client.
pub struct MetabaseClient {
    client: Client,
    auth: MetabaseAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MetabaseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetabaseClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl MetabaseClient {
    /// Create a new `Metabase` client.
    ///
    /// `base_url` is required since `Metabase` is self-hosted; there is no
    /// default API base URL.
    pub fn new(auth: MetabaseAuth, base_url: &str) -> MetabaseResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-metabase/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
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
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MetabaseAuth::SessionToken(token) => req.header("X-Metabase-Session", token),
            // `credential_id` is a host-side reference and must not leak upstream.
            MetabaseAuth::CredentialId(_) => req,
        }
    }

    async fn handle_response(&self, resp: Response) -> MetabaseResult<serde_json::Value> {
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
    ) -> MetabaseResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Metabase returns {"message": "...", "errors": {...}} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MetabaseError::Unauthorized),
            403 => Err(MetabaseError::Forbidden),
            404 => Err(MetabaseError::NotFound { resource: detail }),
            429 => Err(MetabaseError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MetabaseError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> MetabaseResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn post_empty(&self, path: &str) -> MetabaseResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request (empty body)");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Dashboards --

    /// List all dashboards.
    pub async fn list_dashboards(&self) -> MetabaseResult<serde_json::Value> {
        self.get("/dashboard").await
    }

    // -- Cards (Questions) --

    /// List all saved questions (cards).
    pub async fn list_cards(&self) -> MetabaseResult<serde_json::Value> {
        self.get("/card").await
    }

    /// Run a saved question (card) and return query results.
    pub async fn run_card(&self, card_id: &str) -> MetabaseResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(card_id, "card_id")?;
        self.post_empty(&format!("/card/{safe_id}/query")).await
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path-traversal sequences, slashes, and their
/// percent-encoded equivalents. Metabase card IDs are integers, but the host
/// passes them through as strings, so hostile input must be refused before it
/// reaches the URL (`reqwest` normalizes `..` segments, which would otherwise
/// let `card_id` reach a sibling endpoint under the same host).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> MetabaseResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MetabaseError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(MetabaseError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

fn decode_success_body(status: StatusCode, body: &str) -> MetabaseResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(MetabaseError::Api {
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
        let auth = MetabaseAuth::SessionToken("secret-session-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-session-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = MetabaseAuth::SessionToken("tok".into());
        assert!(!token.is_secretless());
        let cred = MetabaseAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = MetabaseAuth::SessionToken("tok".into());
        assert_eq!(token.redacted_label(), "session_token:redacted");
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            MetabaseError::Api {
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
            MetabaseError::Api {
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
    fn auth_credential_label() {
        let cred = MetabaseAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_with_url() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "https://metabase.example.com/api",
        )
        .unwrap();
        assert_eq!(client.base_url, "https://metabase.example.com/api");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "https://metabase.example.com/api/",
        )
        .unwrap();
        assert_eq!(client.base_url, "https://metabase.example.com/api");
    }

    #[test]
    fn client_new_localhost() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "http://localhost:3000/api",
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:3000/api");
    }

    #[test]
    fn add_auth_credential_id_does_not_leak_header() {
        let client = MetabaseClient::new(
            MetabaseAuth::CredentialId(CredentialId::new()),
            "https://metabase.example.com/api",
        )
        .unwrap();

        let request = client
            .add_auth(
                client
                    .client
                    .get("https://metabase.example.com/api/dashboard"),
            )
            .build()
            .unwrap();

        assert!(request.headers().get("X-FCP-Credential-Id").is_none());
        assert!(request.headers().get("X-Metabase-Session").is_none());
    }

    #[test]
    fn client_debug_redacts() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("secret".into()),
            "http://localhost:3000/api",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_session_token_clone() {
        let auth = MetabaseAuth::SessionToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "session_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let auth = MetabaseAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_new_strips_multiple_trailing_slashes() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "https://metabase.example.com/api///",
        )
        .unwrap();
        // Only strips one trailing slash at a time, so we get "api//"
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "http://mb.local/api",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("MetabaseClient"));
        assert!(dbg.contains("mb.local"));
    }

    #[test]
    fn client_debug_with_credential_id() {
        let client = MetabaseClient::new(
            MetabaseAuth::CredentialId(CredentialId::new()),
            "http://mb.local/api",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_debug_credential_id_shows_id() {
        let cid = CredentialId::new();
        let auth = MetabaseAuth::CredentialId(cid);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId("));
    }

    #[test]
    fn auth_session_debug_shows_redacted() {
        let auth = MetabaseAuth::SessionToken("my-secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("SessionToken"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-secret-token"));
    }

    #[test]
    fn client_new_with_port() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "http://192.168.1.100:3000/api",
        )
        .unwrap();
        assert_eq!(client.base_url, "http://192.168.1.100:3000/api");
    }

    #[test]
    fn client_new_https() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("tok".into()),
            "https://metabase.company.com/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url, "https://metabase.company.com/api/v1");
    }

    #[test]
    fn client_new_empty_url() {
        let client = MetabaseClient::new(MetabaseAuth::SessionToken("tok".into()), "").unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn auth_redacted_label_does_not_leak_token() {
        let auth = MetabaseAuth::SessionToken("xyzzy-secret-session-42".into());
        let label = auth.redacted_label();
        assert!(!label.contains("xyzzy-secret-session-42"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn client_debug_does_not_leak_session_token_value() {
        let client = MetabaseClient::new(
            MetabaseAuth::SessionToken("super-secret-session-tok-99".into()),
            "http://localhost:3000/api",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-session-tok-99"));
        assert!(dbg.contains("MetabaseClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn auth_credential_id_redacted_label_format() {
        let cred = MetabaseAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(!label.contains("redacted"));
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn sanitize_path_segment_accepts_numeric_id() {
        assert_eq!(sanitize_path_segment("42", "card_id").unwrap(), "42");
    }

    #[test]
    fn sanitize_path_segment_trims_whitespace() {
        assert_eq!(sanitize_path_segment("  7 ", "card_id").unwrap(), "7");
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("   ", "card_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("1/../admin", "card_id").is_err());
        assert!(sanitize_path_segment("..", "card_id").is_err());
        assert!(sanitize_path_segment("a%2Fb", "card_id").is_err());
        assert!(sanitize_path_segment("a\\b", "card_id").is_err());
    }
}
