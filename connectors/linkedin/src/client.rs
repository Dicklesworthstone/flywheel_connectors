//! LinkedIn API client.

#![allow(clippy::doc_markdown)]

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{LinkedInError, LinkedInResult},
    types::ApiErrorResponse,
};

/// Default LinkedIn REST API v2 base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.linkedin.com/v2";

/// Hex digits used by [`percent_encode_all`].
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Percent-encode every character outside the unreserved set
/// (`A-Z a-z 0-9 - _ . ~`), including `%`.
///
/// LinkedIn URNs are interpolated as a single URL path segment
/// (`/ugcPosts/{urn}`) and into query values (`organizationalEntity=`,
/// `keywords=`). The previous `.replace(':', "%3A")` / `.replace(' ', "%20")`
/// approach only handled a couple of characters, leaving `/` unencoded in the
/// path (injecting extra segments / traversal) and `&`/`=` unencoded in query
/// values (parameter smuggling). Encoding the full unreserved-complement closes
/// both vectors; a normal `urn:li:share:123` still encodes to the same bytes
/// LinkedIn expects.
fn percent_encode_all(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
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
    encoded
}

/// LinkedIn REST-li protocol version header value.
const RESTLI_PROTOCOL_VERSION: &str = "2.0.0";

/// Authentication mode for the LinkedIn API.
#[derive(Clone)]
pub enum LinkedInAuth {
    /// OAuth2 access token (passed as `Authorization: Bearer <token>`).
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl LinkedInAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for LinkedInAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// LinkedIn API client.
pub struct LinkedInClient {
    client: Client,
    auth: LinkedInAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for LinkedInClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkedInClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl LinkedInClient {
    /// Create a new LinkedIn client.
    pub fn new(auth: LinkedInAuth, base_url: Option<&str>) -> LinkedInResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-linkedin/0.1.0 (FCP connector)")
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
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            LinkedInAuth::AccessToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            LinkedInAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    fn add_restli_header(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("X-Restli-Protocol-Version", RESTLI_PROTOCOL_VERSION)
    }

    async fn handle_response(&self, resp: Response) -> LinkedInResult<serde_json::Value> {
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
    ) -> LinkedInResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // LinkedIn returns {"message": "...", "serviceErrorCode": 123, "status": 401} on errors.
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
            401 => Err(LinkedInError::Unauthorized),
            403 => Err(LinkedInError::Forbidden),
            404 => Err(LinkedInError::NotFound { resource: detail }),
            429 => Err(LinkedInError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(LinkedInError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> LinkedInResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = Self::add_restli_header(self.add_auth(self.client.get(&url)))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> LinkedInResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = Self::add_restli_header(self.add_auth(self.client.post(&url)))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> LinkedInResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = Self::add_restli_header(self.add_auth(self.client.delete(&url)))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Profile --

    /// Get the current authenticated user's profile.
    pub async fn get_profile(&self) -> LinkedInResult<serde_json::Value> {
        self.get("/me").await
    }

    /// Get a profile by person ID.
    pub async fn get_profile_by_id(&self, person_id: &str) -> LinkedInResult<serde_json::Value> {
        self.get(&format!("/people/(id:{person_id})")).await
    }

    // -- Connections --

    /// List the authenticated user's connections.
    pub async fn list_connections(&self) -> LinkedInResult<serde_json::Value> {
        self.get("/connections?q=viewer&start=0&count=50").await
    }

    // -- Organizations --

    /// Get a company/organization by ID.
    pub async fn get_company(&self, company_id: &str) -> LinkedInResult<serde_json::Value> {
        self.get(&format!("/organizations/{company_id}")).await
    }

    /// Get follower statistics for a company.
    pub async fn list_company_followers(
        &self,
        company_id: &str,
    ) -> LinkedInResult<serde_json::Value> {
        self.get(&format!(
            "/organizationalEntityFollowerStatistics?q=organizationalEntity&organizationalEntity=urn:li:organization:{company_id}"
        ))
        .await
    }

    // -- Posts (UGC) --

    /// Create a new UGC post.
    pub async fn create_post(&self, body: &serde_json::Value) -> LinkedInResult<serde_json::Value> {
        self.post("/ugcPosts", body).await
    }

    /// Delete a UGC post by its URN.
    pub async fn delete_post(&self, post_urn: &str) -> LinkedInResult<serde_json::Value> {
        let encoded = percent_encode_all(post_urn);
        self.delete(&format!("/ugcPosts/{encoded}")).await
    }

    /// Get a UGC post by its URN.
    pub async fn get_post(&self, post_urn: &str) -> LinkedInResult<serde_json::Value> {
        let encoded = percent_encode_all(post_urn);
        self.get(&format!("/ugcPosts/{encoded}")).await
    }

    // -- Analytics --

    /// Get share statistics for an organizational entity.
    pub async fn share_statistics(&self, share_urn: &str) -> LinkedInResult<serde_json::Value> {
        let encoded = percent_encode_all(share_urn);
        self.get(&format!(
            "/organizationalEntityShareStatistics?q=organizationalEntity&organizationalEntity={encoded}"
        ))
        .await
    }

    // -- Search --

    /// Search for companies by keywords.
    pub async fn search_companies(&self, keywords: &str) -> LinkedInResult<serde_json::Value> {
        let encoded_kw = percent_encode_all(keywords);
        self.get(&format!(
            "/search/blended?q=all&keywords={encoded_kw}&types=List(COMPANY)"
        ))
        .await
    }
}

fn decode_success_body(status: StatusCode, body: &str) -> LinkedInResult<serde_json::Value> {
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
    fn percent_encode_all_passes_unreserved() {
        assert_eq!(percent_encode_all("technology"), "technology");
        assert_eq!(percent_encode_all("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn percent_encode_all_encodes_urn_for_path() {
        // A normal URN encodes to the same bytes the old `:`-only replace produced…
        assert_eq!(
            percent_encode_all("urn:li:share:12345"),
            "urn%3Ali%3Ashare%3A12345"
        );
        // …but a `/` in the URN is now encoded instead of splitting the path.
        assert!(percent_encode_all("urn:li:share:a/b").contains("%2F"));
    }

    #[test]
    fn percent_encode_all_blocks_query_smuggling() {
        let encoded = percent_encode_all("trending&types=List(ADMIN)");
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = LinkedInAuth::AccessToken("secret-access-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-access-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = LinkedInAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());
        let cred = LinkedInAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = LinkedInAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = LinkedInAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = LinkedInClient::new(LinkedInAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = LinkedInClient::new(
            LinkedInAuth::AccessToken("tok".into()),
            Some("https://test.example.com/v2/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v2");
    }

    #[test]
    fn client_debug_redacts() {
        let client = LinkedInClient::new(LinkedInAuth::AccessToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
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
    fn default_base_url_is_linkedin_v2() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.linkedin.com/v2");
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = LinkedInAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = LinkedInClient::new(
            LinkedInAuth::AccessToken("tok".into()),
            Some("https://api.linkedin.com/v2///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_access_token_clone() {
        let auth = LinkedInAuth::AccessToken("my-token".into());
        let cloned = LinkedInAuth::clone(&auth);
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let auth = LinkedInAuth::CredentialId(CredentialId::new());
        let cloned = LinkedInAuth::clone(&auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = LinkedInClient::new(
            LinkedInAuth::AccessToken("tok".into()),
            Some("https://custom.linkedin.com/v2"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.linkedin.com"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = LinkedInClient::new(LinkedInAuth::AccessToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("LinkedInClient"));
    }

    #[test]
    fn auth_debug_access_token_contains_type_name() {
        let auth = LinkedInAuth::AccessToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("AccessToken"));
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn client_with_empty_custom_url() {
        let client =
            LinkedInClient::new(LinkedInAuth::AccessToken("tok".into()), Some("")).unwrap();
        assert!(client.base_url.is_empty());
    }

    #[test]
    fn auth_credential_debug_does_not_contain_redacted() {
        let cred = LinkedInAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        // CredentialId debug shows the UUID, not "redacted"
        assert!(!dbg.contains("<redacted>"));
    }

    #[test]
    fn client_multiple_trailing_slashes_stripped() {
        let client = LinkedInClient::new(
            LinkedInAuth::AccessToken("tok".into()),
            Some("https://api.linkedin.com////"),
        )
        .unwrap();
        // trim_end_matches('/') removes all trailing slashes
        assert!(!client.base_url.ends_with('/'));
    }
}
