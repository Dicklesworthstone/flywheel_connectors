//! Segment API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SegmentError, SegmentResult},
    types::ApiErrorResponse,
};

/// Default Segment REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.segmentapis.com/v2";

/// Authentication mode for the Segment API.
#[derive(Clone)]
pub enum SegmentAuth {
    /// Bearer token (passed as `Authorization: Bearer <token>`).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SegmentAuth {
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

impl fmt::Debug for SegmentAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Segment API client.
pub struct SegmentClient {
    client: Client,
    auth: SegmentAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SegmentClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SegmentClient {
    /// Create a new Segment client.
    pub fn new(auth: SegmentAuth, base_url: Option<&str>) -> SegmentResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-segment/0.1.0 (FCP connector)")
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

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SegmentAuth::BearerToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            SegmentAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SegmentResult<serde_json::Value> {
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
    ) -> SegmentResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Segment returns {"error": {"message": "...", "code": "..."}} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(SegmentError::Unauthorized),
            403 => Err(SegmentError::Forbidden),
            404 => Err(SegmentError::NotFound { resource: detail }),
            429 => Err(SegmentError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SegmentError::Api {
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
    ) -> SegmentResult<serde_json::Value> {
        let replay_safe = http_method != "POST";
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "segment request");

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
                    let err = SegmentError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SegmentResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> SegmentResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body)).await
    }

    // -- Sources --

    /// List all sources in the workspace.
    pub async fn list_sources(&self) -> SegmentResult<serde_json::Value> {
        self.get("/sources").await
    }

    // -- Destinations --

    /// List all destinations for a source.
    pub async fn list_destinations(&self, source_id: &str) -> SegmentResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(source_id, "source_id")?;
        self.get(&format!("/sources/{safe_id}/destinations")).await
    }

    // -- Track --

    /// Send a track event.
    pub async fn track(&self, event_body: &serde_json::Value) -> SegmentResult<serde_json::Value> {
        self.post("/track", event_body).await
    }
}

fn decode_success_body(status: StatusCode, body: &str) -> SegmentResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SegmentError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path traversal sequences, slashes,
/// and percent-encoded equivalents.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SegmentResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SegmentError::InvalidInput(format!(
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
        return Err(SegmentError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SegmentAuth::BearerToken("secret-bearer-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-bearer-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = SegmentAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = SegmentAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = SegmentAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = SegmentAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            SegmentError::Api {
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
            SegmentError::Api {
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
        let client = SegmentClient::new(SegmentAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SegmentClient::new(
            SegmentAuth::BearerToken("tok".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = SegmentClient::new(SegmentAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_clone() {
        let auth = SegmentAuth::BearerToken("tok".into());
        let auth2 = auth.clone();
        assert_eq!(auth.redacted_label(), auth2.redacted_label());
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = SegmentAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_new_trailing_slash_stripped() {
        let client = SegmentClient::new(
            SegmentAuth::BearerToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = SegmentClient::new(SegmentAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SegmentClient"));
        assert!(dbg.contains("segmentapis.com"));
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
    fn auth_bearer_token_not_in_label() {
        let auth = SegmentAuth::BearerToken("super-secret-123".into());
        let label = auth.redacted_label();
        assert!(!label.contains("super-secret-123"));
    }

    #[test]
    fn auth_credential_id_not_secretless_bearer() {
        let auth = SegmentAuth::BearerToken("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = SegmentAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("src_abc123", "source_id").unwrap(),
            "src_abc123"
        );
    }

    #[test]
    fn sanitize_path_segment_trims_whitespace() {
        assert_eq!(sanitize_path_segment("  abc  ", "f").unwrap(), "abc");
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        assert!(sanitize_path_segment("   ", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        assert!(sanitize_path_segment("../etc/passwd", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        assert!(sanitize_path_segment("foo\\bar", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        assert!(sanitize_path_segment("foo..bar", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        assert!(sanitize_path_segment("foo%2fbar", "source_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        assert!(sanitize_path_segment("foo%5Cbar", "source_id").is_err());
    }
}
