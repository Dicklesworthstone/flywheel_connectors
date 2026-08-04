//! Mixpanel API client.

#![allow(clippy::doc_markdown)]

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{MixpanelError, MixpanelResult},
    types::ApiErrorResponse,
};

/// Default Mixpanel REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://mixpanel.com/api/2.0";

/// Authentication mode for the Mixpanel API.
#[derive(Clone)]
pub enum MixpanelAuth {
    /// Service account credentials (Basic auth with username:secret).
    ServiceAccount { username: String, secret: String },
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MixpanelAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ServiceAccount { username, .. } => {
                format!("service_account:{username}:redacted")
            }
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for MixpanelAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceAccount { username, .. } => f
                .debug_struct("ServiceAccount")
                .field("username", username)
                .field("secret", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Mixpanel API client.
pub struct MixpanelClient {
    client: Client,
    auth: MixpanelAuth,
    base_url: String,
    project_id: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MixpanelClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MixpanelClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl MixpanelClient {
    /// Create a new Mixpanel client.
    pub fn new(
        auth: MixpanelAuth,
        project_id: &str,
        base_url: Option<&str>,
    ) -> MixpanelResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-mixpanel/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            project_id: project_id.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(60)),
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
            MixpanelAuth::ServiceAccount { username, secret } => {
                let encoded = BASE64.encode(format!("{username}:{secret}"));
                req.header("Authorization", format!("Basic {encoded}"))
            }
            MixpanelAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> MixpanelResult<serde_json::Value> {
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
    ) -> MixpanelResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error.or(e.message))
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MixpanelError::Unauthorized),
            403 => Err(MixpanelError::Forbidden),
            404 => Err(MixpanelError::NotFound { resource: detail }),
            429 => Err(MixpanelError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MixpanelError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Issue a request with retry.
    ///
    /// br-kxd3e: replay safety is derived from the verb. Only POST ingests, and
    /// a replay after a 5xx DOUBLE-COUNTS the event in every downstream
    /// dashboard and funnel. These providers offer a per-event dedup id
    /// (`messageId` / `$insert_id`) that would make the retry genuinely safe,
    /// but the events are caller-supplied here so the key may be absent —
    /// recorded as a follow-up rather than assumed present.
    async fn request_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> MixpanelResult<serde_json::Value> {
        let replay_safe = http_method != "POST";
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "mixpanel request");

            let req = match http_method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                _ => unreachable!(),
            };
            let req = self.add_auth(req).header("Accept", "application/json");
            let req = if let Some(b) = body { req.json(b) } else { req };

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
                    let err = MixpanelError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> MixpanelResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> MixpanelResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body)).await
    }

    // -- Events --

    /// Query events via the Insights API.
    pub async fn query_events(
        &self,
        from_date: &str,
        to_date: &str,
        event: Option<&str>,
    ) -> MixpanelResult<serde_json::Value> {
        let mut body = serde_json::json!({
            "project_id": self.project_id.parse::<u64>().unwrap_or(0),
            "from_date": from_date,
            "to_date": to_date,
        });
        if let Some(event_name) = event {
            body["event"] = serde_json::json!(event_name);
        }
        self.post("/insights", &body).await
    }

    // -- Funnels --

    /// List saved funnels.
    pub async fn list_funnels(&self) -> MixpanelResult<serde_json::Value> {
        let safe_pid = sanitize_path_segment(&self.project_id, "project_id")?;
        self.get(&format!("/funnels/list?project_id={safe_pid}"))
            .await
    }

    // -- Insights --

    /// Run an Insights query by bookmark ID.
    pub async fn query_insights(&self, bookmark_id: &str) -> MixpanelResult<serde_json::Value> {
        let body = serde_json::json!({
            "project_id": self.project_id.parse::<u64>().unwrap_or(0),
            "bookmark_id": bookmark_id,
        });
        self.post("/insights", &body).await
    }
}

/// Validate a value intended for use as a URL path segment.
///
/// Rejects empty strings, path traversal sequences, slashes,
/// and percent-encoded equivalents.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> MixpanelResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MixpanelError::InvalidInput(format!(
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
        return Err(MixpanelError::InvalidInput(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(trimmed)
}

fn decode_success_body(status: StatusCode, body: &str) -> MixpanelResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(MixpanelError::Api {
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
    fn auth_debug_redacts_secret() {
        let auth = MixpanelAuth::ServiceAccount {
            username: "sa_user".into(),
            secret: "super-secret-value".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("sa_user"));
    }

    #[test]
    fn auth_secretless_detection() {
        let sa = MixpanelAuth::ServiceAccount {
            username: "u".into(),
            secret: "s".into(),
        };
        assert!(!sa.is_secretless());
        let cred = MixpanelAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_service_account() {
        let auth = MixpanelAuth::ServiceAccount {
            username: "myuser".into(),
            secret: "mysecret".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("myuser"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("mysecret"));
    }

    #[test]
    fn auth_credential_label() {
        let cred = MixpanelAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            MixpanelError::Api {
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
            MixpanelError::Api {
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
    fn client_new_default_url() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "u".into(),
                secret: "s".into(),
            },
            "12345",
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
        assert_eq!(client.project_id, "12345");
    }

    #[test]
    fn client_new_custom_url() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "u".into(),
                secret: "s".into(),
            },
            "99",
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "user".into(),
                secret: "secret123".into(),
            },
            "12345",
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn basic_auth_encoding() {
        let encoded = BASE64.encode("myuser:mysecret");
        assert_eq!(encoded, "bXl1c2VyOm15c2VjcmV0");
    }

    #[test]
    fn auth_clone() {
        let auth = MixpanelAuth::ServiceAccount {
            username: "u".into(),
            secret: "s".into(),
        };
        let auth2 = auth.clone();
        assert_eq!(auth.redacted_label(), auth2.redacted_label());
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = MixpanelAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_new_trailing_slash_stripped() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "u".into(),
                secret: "s".into(),
            },
            "1",
            Some("https://example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "u".into(),
                secret: "s".into(),
            },
            "12345",
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("MixpanelClient"));
        assert!(dbg.contains("mixpanel.com"));
    }

    #[test]
    fn client_debug_shows_project_id() {
        let client = MixpanelClient::new(
            MixpanelAuth::ServiceAccount {
                username: "u".into(),
                secret: "s".into(),
            },
            "proj_42",
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("proj_42"));
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
    fn auth_service_account_redacted_label_format() {
        let auth = MixpanelAuth::ServiceAccount {
            username: "test_user".into(),
            secret: "test_secret".into(),
        };
        let label = auth.redacted_label();
        assert_eq!(label, "service_account:test_user:redacted");
    }

    #[test]
    fn base64_encoding_empty_string() {
        let encoded = BASE64.encode("");
        assert_eq!(encoded, "");
    }

    #[test]
    fn base64_encoding_special_chars() {
        let encoded = BASE64.encode("user:p@ss:w0rd!");
        assert!(!encoded.is_empty());
        // Should be valid base64 (only contains [A-Za-z0-9+/=])
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("12345", "project_id").unwrap(),
            "12345"
        );
    }

    #[test]
    fn sanitize_path_segment_trims_whitespace() {
        assert_eq!(sanitize_path_segment("  abc  ", "f").unwrap(), "abc");
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        assert!(sanitize_path_segment("   ", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        assert!(sanitize_path_segment("../etc/passwd", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        assert!(sanitize_path_segment("foo\\bar", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        assert!(sanitize_path_segment("foo..bar", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        assert!(sanitize_path_segment("foo%2fbar", "project_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        assert!(sanitize_path_segment("foo%5Cbar", "project_id").is_err());
    }
}
