//! `SendGrid` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SendGridError, SendGridResult},
    types::ApiErrorResponse,
};

/// Default `SendGrid` REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.sendgrid.com/v3";

/// Authentication mode for the `SendGrid` API.
#[derive(Clone)]
pub enum SendGridAuth {
    /// API key (passed as `Authorization: Bearer <api_key>`).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SendGridAuth {
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

impl fmt::Debug for SendGridAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `SendGrid` API client.
pub struct SendGridClient {
    client: Client,
    auth: SendGridAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SendGridClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendGridClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SendGridClient {
    /// Create a new `SendGrid` client.
    pub fn new(auth: SendGridAuth, base_url: Option<&str>) -> SendGridResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-sendgrid/0.1.0 (FCP connector)")
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
            SendGridAuth::ApiKey(key) => req.header("Authorization", format!("Bearer {key}")),
            SendGridAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SendGridResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            // A 2xx with an empty body is a successful no-content response
            // (e.g. POST/PUT/DELETE that returns no payload); coerce to `{}`
            // rather than failing closed. See workspace commit 506b45904.
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
    ) -> SendGridResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        // SendGrid returns {"errors": [{"message": "...", "field": "...", "help": "..."}]}
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.errors)
            .and_then(|errs| {
                errs.into_iter()
                    .filter_map(|e| e.message)
                    .collect::<Vec<_>>()
                    .first()
                    .cloned()
            })
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(SendGridError::Unauthorized),
            403 => Err(SendGridError::Forbidden),
            404 => Err(SendGridError::NotFound { resource: detail }),
            429 => Err(SendGridError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SendGridError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SendGridResult<serde_json::Value> {
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
    ) -> SendGridResult<serde_json::Value> {
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
    async fn delete(&self, path: &str) -> SendGridResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Mail --

    /// Send a transactional email.
    ///
    /// `SendGrid` returns 202 Accepted with an empty body on success.
    pub async fn send_mail(&self, body: &serde_json::Value) -> SendGridResult<serde_json::Value> {
        self.post("/mail/send", body).await
    }

    // -- Contacts --

    /// List all marketing contacts.
    pub async fn list_contacts(&self) -> SendGridResult<serde_json::Value> {
        self.get("/marketing/contacts").await
    }

    /// Search marketing contacts.
    pub async fn search_contacts(
        &self,
        body: &serde_json::Value,
    ) -> SendGridResult<serde_json::Value> {
        self.post("/marketing/contacts/search", body).await
    }

    /// Get a single contact by ID.
    pub async fn get_contact(&self, id: &str) -> SendGridResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(id, "contact_id")?;
        self.get(&format!("/marketing/contacts/{safe_id}")).await
    }

    // -- Lists --

    /// List all marketing lists.
    pub async fn list_lists(&self) -> SendGridResult<serde_json::Value> {
        self.get("/marketing/lists").await
    }

    /// Create a marketing list.
    pub async fn create_list(&self, body: &serde_json::Value) -> SendGridResult<serde_json::Value> {
        self.post("/marketing/lists", body).await
    }

    /// Delete a marketing list.
    pub async fn delete_list(&self, list_id: &str) -> SendGridResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(list_id, "list_id")?;
        self.delete(&format!("/marketing/lists/{safe_id}")).await
    }

    // -- Templates --

    /// List dynamic email templates.
    pub async fn list_templates(&self) -> SendGridResult<serde_json::Value> {
        self.get("/templates?generations=dynamic").await
    }

    /// Get a single template by ID.
    pub async fn get_template(&self, template_id: &str) -> SendGridResult<serde_json::Value> {
        let safe_id = sanitize_path_segment(template_id, "template_id")?;
        self.get(&format!("/templates/{safe_id}")).await
    }

    // -- Stats --

    /// Get email delivery statistics for a date range.
    ///
    /// `start_date` is required; `end_date` is optional. Both values are
    /// percent-encoded before being placed in the query string so that hostile
    /// input (e.g. a `start_date` carrying `&aggregated_by=...`) cannot inject
    /// additional query parameters.
    pub async fn get_stats(
        &self,
        start_date: &str,
        end_date: Option<&str>,
    ) -> SendGridResult<serde_json::Value> {
        let safe_start = encode_query_value(start_date, "start_date")?;
        let mut path = format!("/stats?start_date={safe_start}");
        if let Some(end_date) = end_date {
            let safe_end = encode_query_value(end_date, "end_date")?;
            path.push_str("&end_date=");
            path.push_str(&safe_end);
        }
        self.get(&path).await
    }
}

/// Hex digits used by [`encode_query_value`] when percent-encoding a byte.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path-traversal sequences, slashes, and their
/// percent-encoded equivalents. `reqwest` normalizes `..` segments, so an
/// unsanitized id could otherwise reach a sibling endpoint under the same host.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SendGridResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SendGridError::InvalidInput(format!(
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
        return Err(SendGridError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

/// Percent-encode a value for safe inclusion in a URL query string.
///
/// Rejects empty values and encodes every character outside the unreserved set
/// (`A-Z a-z 0-9 - _ . ~`), including `%`, so a value cannot alter the URL's
/// query structure or smuggle additional parameters.
fn encode_query_value(value: &str, field: &str) -> SendGridResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SendGridError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let mut encoded = String::with_capacity(trimmed.len() * 2);
    for byte in trimmed.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(HEX_UPPER[(byte >> 4) as usize] as char);
                encoded.push(HEX_UPPER[(byte & 0x0F) as usize] as char);
            }
        }
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = SendGridAuth::ApiKey("SG.secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("SG.secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = SendGridAuth::ApiKey("SG.key".into());
        assert!(!key.is_secretless());
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let key = SendGridAuth::ApiKey("SG.key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://test.example.com/v3/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v3");
    }

    #[test]
    fn client_debug_redacts() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("SG.secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_api_key_clone() {
        let auth = SendGridAuth::ApiKey("SG.key".into());
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn auth_credential_id_clone() {
        let auth = SendGridAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SendGridClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://custom.sendgrid.com/v3"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.sendgrid.com"));
    }

    #[test]
    fn auth_debug_contains_api_key_type() {
        let auth = SendGridAuth::ApiKey("SG.secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn auth_debug_credential_id_contains_type() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_is_sendgrid_v3() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.sendgrid.com/v3");
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = SendGridClient::new(
            SendGridAuth::ApiKey("SG.key".into()),
            Some("https://api.sendgrid.com/v3///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_with_empty_custom_url() {
        let client = SendGridClient::new(SendGridAuth::ApiKey("SG.key".into()), Some("")).unwrap();
        assert!(client.base_url.is_empty());
    }

    #[test]
    fn auth_credential_debug_does_not_contain_redacted_tag() {
        let cred = SendGridAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("<redacted>"));
    }

    #[test]
    fn sanitize_path_segment_accepts_uuid() {
        let id = "3b1c8a4e-9f2d-4c6b-8e1a-0f5d2c7b9a13";
        assert_eq!(sanitize_path_segment(id, "contact_id").unwrap(), id);
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("  ", "contact_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("a/../b", "list_id").is_err());
        assert!(sanitize_path_segment("..", "list_id").is_err());
        assert!(sanitize_path_segment("a%2Fb", "list_id").is_err());
        assert!(sanitize_path_segment("a\\b", "template_id").is_err());
    }

    #[test]
    fn encode_query_value_passes_plain_date() {
        assert_eq!(
            encode_query_value("2026-01-01", "start_date").unwrap(),
            "2026-01-01"
        );
    }

    #[test]
    fn encode_query_value_encodes_param_injection() {
        let encoded = encode_query_value("2026-01-01&aggregated_by=day", "start_date").unwrap();
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }

    #[test]
    fn encode_query_value_encodes_percent_and_hash() {
        let encoded = encode_query_value("a%b#c", "start_date").unwrap();
        assert!(encoded.contains("%25"));
        assert!(encoded.contains("%23"));
    }

    #[test]
    fn encode_query_value_rejects_empty() {
        assert!(encode_query_value("   ", "start_date").is_err());
    }
}
