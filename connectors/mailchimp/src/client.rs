//! Mailchimp API client.

#![allow(clippy::doc_markdown)]

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{MailchimpError, MailchimpResult},
    types::ApiErrorResponse,
};

/// Default Mailchimp REST API base URL prefix and suffix.
/// Combined with the data center code to form `https://{dc}.api.mailchimp.com/3.0`.
const BASE_URL_PREFIX: &str = "https://";
const BASE_URL_SUFFIX: &str = ".api.mailchimp.com/3.0";

/// Authentication mode for the Mailchimp API.
#[derive(Clone)]
pub enum MailchimpAuth {
    /// API key (Basic auth with `any_user:{api_key}`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MailchimpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for MailchimpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Extract the data center suffix from a Mailchimp API key.
///
/// Mailchimp API keys have the format `{key}-{dc}` where `dc` is like `us1`, `us2`, etc.
pub fn extract_dc(api_key: &str) -> Option<&str> {
    api_key.rsplit('-').next().filter(|dc| !dc.is_empty())
}

/// Build the base URL from a data center code.
#[must_use]
pub fn base_url_for_dc(dc: &str) -> String {
    format!("{BASE_URL_PREFIX}{dc}{BASE_URL_SUFFIX}")
}

/// Mailchimp API client.
pub struct MailchimpClient {
    client: Client,
    auth: MailchimpAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MailchimpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailchimpClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl MailchimpClient {
    /// Create a new Mailchimp client.
    ///
    /// If `base_url` is provided, it overrides the auto-derived URL from the API key.
    /// If `base_url` is `None` and auth is `ApiKey`, the data center is extracted from
    /// the key to form the URL.
    pub fn new(auth: MailchimpAuth, base_url: Option<&str>) -> MailchimpResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-mailchimp/0.1.0 (FCP connector)")
            .build()?;

        let resolved_url = match base_url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => match &auth {
                MailchimpAuth::ApiKey(key) => {
                    let dc = extract_dc(key).unwrap_or("us1");
                    base_url_for_dc(dc)
                }
                MailchimpAuth::CredentialId(_) => base_url_for_dc("us1"),
            },
        };

        Ok(Self {
            client,
            auth,
            base_url: resolved_url,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Get the base URL for this client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MailchimpAuth::ApiKey(key) => {
                let credentials = format!("anyuser:{key}");
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
                req.header("Authorization", format!("Basic {encoded}"))
            }
            MailchimpAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> MailchimpResult<serde_json::Value> {
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
    ) -> MailchimpResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Mailchimp returns {"title": "...", "detail": "...", "status": N} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.detail)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MailchimpError::Unauthorized),
            403 => Err(MailchimpError::Forbidden),
            404 => Err(MailchimpError::NotFound { resource: detail }),
            429 => Err(MailchimpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MailchimpError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> MailchimpResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn post_empty(&self, path: &str) -> MailchimpResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request (empty body)");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> MailchimpResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Lists (Audiences) --

    /// List all audiences.
    pub async fn list_lists(&self) -> MailchimpResult<serde_json::Value> {
        self.get("/lists").await
    }

    // -- Members --

    /// List members of an audience.
    pub async fn list_members(&self, list_id: &str) -> MailchimpResult<serde_json::Value> {
        let list_id = sanitize_path_segment(list_id, "list_id")?;
        self.get(&format!("/lists/{list_id}/members")).await
    }

    /// Delete a member from an audience.
    pub async fn delete_member(
        &self,
        list_id: &str,
        subscriber_hash: &str,
    ) -> MailchimpResult<serde_json::Value> {
        let list_id = sanitize_path_segment(list_id, "list_id")?;
        let subscriber_hash = sanitize_path_segment(subscriber_hash, "subscriber_hash")?;
        self.delete(&format!("/lists/{list_id}/members/{subscriber_hash}"))
            .await
    }

    // -- Campaigns --

    /// List all campaigns.
    pub async fn list_campaigns(&self) -> MailchimpResult<serde_json::Value> {
        self.get("/campaigns").await
    }

    /// Send a campaign.
    pub async fn send_campaign(&self, campaign_id: &str) -> MailchimpResult<serde_json::Value> {
        let campaign_id = sanitize_path_segment(campaign_id, "campaign_id")?;
        self.post_empty(&format!("/campaigns/{campaign_id}/actions/send"))
            .await
    }
}

/// Validate that a caller-supplied ID is safe to interpolate into a URL path
/// segment.
///
/// Rejects empty strings, path-traversal sequences, slashes, query/fragment
/// delimiters, and percent-encoded slash equivalents. Without this, a
/// `subscriber_hash` of `../../../lists/<victim>` on `delete_member` normalizes
/// (via `Url::parse`) to `DELETE /lists/<victim>` — deleting an arbitrary
/// audience instead of one member. Mailchimp list IDs, subscriber hashes, and
/// campaign IDs are all `[A-Za-z0-9]`-shaped, so a legitimate value never trips
/// these checks.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> MailchimpResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MailchimpError::InvalidInput(format!(
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
        return Err(MailchimpError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

fn decode_success_body(status: StatusCode, body: &str) -> MailchimpResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = MailchimpAuth::ApiKey("secret-api-key-us1".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key-us1"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = MailchimpAuth::ApiKey("key-us1".into());
        assert!(!key.is_secretless());
        let cred = MailchimpAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let key = MailchimpAuth::ApiKey("key-us1".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = MailchimpAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn extract_dc_from_key() {
        assert_eq!(extract_dc("abc123def456-us1"), Some("us1"));
        assert_eq!(extract_dc("abc123def456-us21"), Some("us21"));
        assert_eq!(extract_dc("abc123def456-eu1"), Some("eu1"));
    }

    #[test]
    fn extract_dc_no_dash() {
        // With no dash, rsplit returns the whole string which is non-empty
        assert_eq!(extract_dc("nodash"), Some("nodash"));
    }

    #[test]
    fn extract_dc_trailing_dash() {
        assert_eq!(extract_dc("key-"), None);
    }

    #[test]
    fn base_url_for_dc_us1() {
        assert_eq!(base_url_for_dc("us1"), "https://us1.api.mailchimp.com/3.0");
    }

    #[test]
    fn base_url_for_dc_eu1() {
        assert_eq!(base_url_for_dc("eu1"), "https://eu1.api.mailchimp.com/3.0");
    }

    #[test]
    fn client_new_default_url_from_key() {
        let client =
            MailchimpClient::new(MailchimpAuth::ApiKey("testkey-us7".into()), None).unwrap();
        assert_eq!(client.base_url, "https://us7.api.mailchimp.com/3.0");
    }

    #[test]
    fn client_new_custom_url() {
        let client = MailchimpClient::new(
            MailchimpAuth::ApiKey("key-us1".into()),
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            MailchimpClient::new(MailchimpAuth::ApiKey("secret-us1".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal_and_control_chars() {
        for bad in [
            "",
            "  ",
            "../../../lists/victim",
            "a/b",
            "a\\b",
            "id?query=x",
            "id#frag",
            "a%2f..%2fb",
            "a%5cb",
        ] {
            assert!(
                sanitize_path_segment(bad, "subscriber_hash").is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn sanitize_path_segment_accepts_real_ids() {
        assert_eq!(
            sanitize_path_segment("9e67587f98a6f0d1a2b3c4d5", "subscriber_hash").unwrap(),
            "9e67587f98a6f0d1a2b3c4d5"
        );
        assert_eq!(
            sanitize_path_segment(" a1b2c3 ", "list_id").unwrap(),
            "a1b2c3"
        );
    }

    #[test]
    fn decode_success_body_coerces_empty_ok_to_empty_object() {
        // Contract (commit 506b45904): a 2xx with an empty body is a successful
        // no-content response and decodes to `{}` rather than failing closed.
        assert_eq!(
            decode_success_body(StatusCode::OK, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn decode_success_body_coerces_whitespace_ok_to_empty_object() {
        assert_eq!(
            decode_success_body(StatusCode::OK, "  \n\t").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn client_base_url_accessor() {
        let client = MailchimpClient::new(MailchimpAuth::ApiKey("key-us3".into()), None).unwrap();
        assert_eq!(client.base_url(), "https://us3.api.mailchimp.com/3.0");
    }

    // -- Additional client tests --

    #[test]
    fn client_credential_default_url() {
        let client =
            MailchimpClient::new(MailchimpAuth::CredentialId(CredentialId::new()), None).unwrap();
        assert_eq!(client.base_url(), "https://us1.api.mailchimp.com/3.0");
    }

    #[test]
    fn client_credential_custom_url() {
        let client = MailchimpClient::new(
            MailchimpAuth::CredentialId(CredentialId::new()),
            Some("https://custom.api.mailchimp.com/3.0/"),
        )
        .unwrap();
        assert_eq!(client.base_url(), "https://custom.api.mailchimp.com/3.0");
    }

    #[test]
    fn client_debug_shows_credential_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let client = MailchimpClient::new(MailchimpAuth::CredentialId(cred), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(&cred_str));
        assert!(dbg.contains("MailchimpClient"));
    }

    #[test]
    fn auth_clone() {
        let auth = MailchimpAuth::ApiKey("key-us1".into());
        let cloned = auth.clone();
        assert!(!auth.is_secretless());
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = MailchimpAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let auth = MailchimpAuth::CredentialId(cred);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&cred_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn extract_dc_multiple_dashes() {
        assert_eq!(extract_dc("abc-def-us5"), Some("us5"));
    }

    #[test]
    fn extract_dc_single_char() {
        assert_eq!(extract_dc("key-a"), Some("a"));
    }

    #[test]
    fn base_url_for_dc_us21() {
        assert_eq!(
            base_url_for_dc("us21"),
            "https://us21.api.mailchimp.com/3.0"
        );
    }

    #[test]
    fn client_no_dc_in_key_defaults_us1() {
        // A key with no dash: rsplit returns the whole string
        let client = MailchimpClient::new(MailchimpAuth::ApiKey("nodash".into()), None).unwrap();
        // extract_dc("nodash") returns Some("nodash")
        assert!(client.base_url().contains("nodash"));
    }

    #[test]
    fn client_key_trailing_dash_defaults_us1() {
        // A key ending with dash: extract_dc returns None, defaults to us1
        let client = MailchimpClient::new(MailchimpAuth::ApiKey("mykey-".into()), None).unwrap();
        assert_eq!(client.base_url(), "https://us1.api.mailchimp.com/3.0");
    }

    #[test]
    fn base_url_prefix_suffix() {
        // Verify the combined URL format
        let url = base_url_for_dc("eu2");
        assert!(url.starts_with("https://"));
        assert!(url.ends_with(".api.mailchimp.com/3.0"));
        assert!(url.contains("eu2"));
    }
}
