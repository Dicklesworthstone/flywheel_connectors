//! `Salesforce` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SalesforceError, SalesforceResult},
    types::ApiErrorResponse,
};

/// Default `Salesforce` instance URL.
pub const DEFAULT_BASE_URL: &str = "https://login.salesforce.com";

/// Default `Salesforce` REST API version.
///
/// Verified against Salesforce's Spring '26 REST API docs (API version 66.0).
pub const DEFAULT_API_VERSION: &str = "66.0";

/// Default API version path prefix for the `Salesforce` REST API.
pub const DEFAULT_API_PATH: &str = "/services/data/v66.0";

fn is_valid_api_version(version: &str) -> bool {
    let mut parts = version.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(major), Some(minor), None) => {
            !major.is_empty()
                && !minor.is_empty()
                && major.chars().all(|ch| ch.is_ascii_digit())
                && minor.chars().all(|ch| ch.is_ascii_digit())
        }
        _ => false,
    }
}

pub(crate) fn normalize_api_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if !is_valid_api_version(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn api_path_from_version(version: &str) -> String {
    format!("/services/data/v{version}")
}

fn api_version_from_path(path: &str) -> Option<&str> {
    let version = path.strip_prefix("/services/data/v")?.trim();
    if !is_valid_api_version(version) {
        return None;
    }
    Some(version)
}

/// Resolve the Salesforce API path to use.
///
/// Precedence: explicit `api_path` override > explicit `api_version` override >
/// `FCP_SALESFORCE_API_PATH` > `FCP_SALESFORCE_API_VERSION` > compiled default.
fn resolve_salesforce_api_path(
    api_path_override: Option<&str>,
    api_version_override: Option<&str>,
) -> String {
    if let Some(path) = api_path_override.map(str::trim).filter(|s| !s.is_empty())
        && api_version_from_path(path).is_some()
    {
        return path.to_string();
    }
    if let Some(version) = api_version_override.and_then(normalize_api_version) {
        return api_path_from_version(&version);
    }
    if let Ok(path) = std::env::var("FCP_SALESFORCE_API_PATH") {
        let path = path.trim();
        if !path.is_empty() && api_version_from_path(path).is_some() {
            return path.to_string();
        }
    }
    if let Ok(version) = std::env::var("FCP_SALESFORCE_API_VERSION")
        && let Some(version) = normalize_api_version(&version)
    {
        return api_path_from_version(&version);
    }
    DEFAULT_API_PATH.to_string()
}

/// Authentication mode for the `Salesforce` API.
#[derive(Clone)]
pub enum SalesforceAuth {
    /// `OAuth2` Bearer access token.
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SalesforceAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SalesforceAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Escape a string for safe interpolation into a SOQL single-quoted literal.
///
/// SOQL escapes single quotes by doubling them and backslashes by doubling them.
fn escape_soql_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Validate a user-supplied SOQL field reference.
///
/// The `fields` list is interpolated verbatim into the `SELECT` clause (and into
/// the `?fields=` query parameter for `get_account`); neither is escaped at the
/// SOQL or URL layer. An unrestricted field name therefore allows SOQL injection
/// (breaking out of the column list to change the queried object, add subqueries,
/// or widen the `WHERE`) and query-parameter smuggling. A legitimate SOQL field
/// reference is an identifier or a relationship dot-path (e.g. `Account.Name`),
/// so restricting to `[A-Za-z0-9_.]` preserves real usage while rejecting every
/// injection vector. The exact (untrimmed) bytes are checked because those are
/// the bytes that get interpolated.
fn validate_soql_field(field: &str) -> SalesforceResult<()> {
    if field.is_empty() {
        return Err(SalesforceError::InvalidInput(
            "field name must not be empty".into(),
        ));
    }
    if !field
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err(SalesforceError::InvalidInput(format!(
            "field '{field}' is not a valid SOQL field reference"
        )));
    }
    Ok(())
}

/// Validate every entry of an optional user-supplied field list.
fn validate_soql_fields(fields: Option<&[String]>) -> SalesforceResult<()> {
    if let Some(fields) = fields {
        for field in fields {
            validate_soql_field(field)?;
        }
    }
    Ok(())
}

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SalesforceResult<&'a str> {
    if value.trim().is_empty() {
        return Err(SalesforceError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(SalesforceError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// `Salesforce` API client.
pub struct SalesforceClient {
    client: Client,
    auth: SalesforceAuth,
    base_url: String,
    api_path: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SalesforceClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalesforceClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("api_path", &self.api_path)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SalesforceClient {
    /// Create a new `Salesforce` client.
    pub fn new(auth: SalesforceAuth, base_url: Option<&str>) -> SalesforceResult<Self> {
        Self::new_with_overrides(auth, base_url, None, None)
    }

    /// Create a new `Salesforce` client with an optional API path override.
    pub fn new_with_api_path(
        auth: SalesforceAuth,
        base_url: Option<&str>,
        api_path_override: Option<&str>,
    ) -> SalesforceResult<Self> {
        Self::new_with_overrides(auth, base_url, api_path_override, None)
    }

    /// Create a new `Salesforce` client with an optional API version override.
    pub fn new_with_api_version(
        auth: SalesforceAuth,
        base_url: Option<&str>,
        api_version_override: Option<&str>,
    ) -> SalesforceResult<Self> {
        Self::new_with_overrides(auth, base_url, None, api_version_override)
    }

    fn new_with_overrides(
        auth: SalesforceAuth,
        base_url: Option<&str>,
        api_path_override: Option<&str>,
        api_version_override: Option<&str>,
    ) -> SalesforceResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-salesforce/0.1.0")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            api_path: resolve_salesforce_api_path(api_path_override, api_version_override),
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
    pub fn with_client(client: Client, auth: SalesforceAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_path: resolve_salesforce_api_path(None, None),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the API path prefix used for requests.
    #[must_use]
    pub fn api_path(&self) -> &str {
        &self.api_path
    }

    /// Get the resolved REST API version used for requests.
    #[must_use]
    pub fn api_version(&self) -> &str {
        api_version_from_path(&self.api_path).unwrap_or(DEFAULT_API_VERSION)
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SalesforceAuth::AccessToken(token) => req.bearer_auth(token),
            SalesforceAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SalesforceResult<serde_json::Value> {
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
    ) -> SalesforceResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        // Salesforce can return either an array of errors or a single message object.
        let detail = serde_json::from_str::<Vec<crate::types::ApiErrorItem>>(&body)
            .ok()
            .and_then(|items| items.first().and_then(|e| e.message.clone()))
            .or_else(|| {
                serde_json::from_str::<ApiErrorResponse>(&body)
                    .ok()
                    .and_then(|e| {
                        e.message
                            .or_else(|| e.errors.first().and_then(|i| i.message.clone()))
                    })
            })
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SalesforceError::Unauthorized),
            403 => Err(SalesforceError::Forbidden),
            404 => Err(SalesforceError::NotFound { resource: detail }),
            429 => Err(SalesforceError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SalesforceError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// GET request to the `Salesforce` API.
    #[instrument(skip(self), fields(url))]
    pub async fn get(&self, path: &str) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{}{path}", self.base_url, self.api_path);
        debug!(url = %redact_url(&url), "GET request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// POST request to the `Salesforce` API.
    #[instrument(skip(self, body), fields(url))]
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{}{path}", self.base_url, self.api_path);
        debug!(url = %redact_url(&url), "POST request");
        let req = self.add_auth(self.client.post(&url).json(body));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// DELETE request to the `Salesforce` API.
    #[instrument(skip(self), fields(url))]
    pub async fn delete(&self, path: &str) -> SalesforceResult<serde_json::Value> {
        let url = format!("{}{}{path}", self.base_url, self.api_path);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self.add_auth(self.client.delete(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Accounts --

    /// Get a single account by ID.
    pub async fn get_account(
        &self,
        account_id: &str,
        fields: Option<&[String]>,
    ) -> SalesforceResult<serde_json::Value> {
        let account_id = sanitize_path_segment(account_id, "account_id")?;
        validate_soql_fields(fields)?;
        let qs = fields.map_or_else(String::new, |f| format!("?fields={}", f.join(",")));
        self.get(&format!("/sobjects/Account/{account_id}{qs}"))
            .await
    }

    /// Query accounts via SOQL.
    pub async fn list_accounts(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
    ) -> SalesforceResult<serde_json::Value> {
        validate_soql_fields(fields)?;
        let cols = fields.map_or_else(|| "Id, Name, Industry".to_string(), |f| f.join(", "));
        let mut query = format!("SELECT {cols} FROM Account");
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    // -- Contacts --

    /// Query contacts via SOQL.
    pub async fn list_contacts(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        account_id: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        validate_soql_fields(fields)?;
        let cols = fields.map_or_else(
            || "Id, FirstName, LastName, Email".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Contact");
        if let Some(aid) = account_id {
            let escaped = escape_soql_string(aid);
            let _ = write!(query, " WHERE AccountId = '{escaped}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create a contact.
    pub async fn create_contact(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Contact", body).await
    }

    /// Delete a contact.
    pub async fn delete_contact(&self, contact_id: &str) -> SalesforceResult<serde_json::Value> {
        let contact_id = sanitize_path_segment(contact_id, "contact_id")?;
        self.delete(&format!("/sobjects/Contact/{contact_id}"))
            .await
    }

    // -- Leads --

    /// Query leads via SOQL.
    pub async fn list_leads(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        status: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        validate_soql_fields(fields)?;
        let cols = fields.map_or_else(
            || "Id, FirstName, LastName, Company, Status".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Lead");
        if let Some(s) = status {
            let escaped = escape_soql_string(s);
            let _ = write!(query, " WHERE Status = '{escaped}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Convert a lead via the actions endpoint.
    pub async fn convert_lead(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/actions/standard/convertLead", body).await
    }

    // -- Opportunities --

    /// Query opportunities via SOQL.
    pub async fn list_opportunities(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        stage: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        validate_soql_fields(fields)?;
        let cols = fields.map_or_else(
            || "Id, Name, StageName, Amount, CloseDate".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Opportunity");
        if let Some(s) = stage {
            let escaped = escape_soql_string(s);
            let _ = write!(query, " WHERE StageName = '{escaped}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create an opportunity.
    pub async fn create_opportunity(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Opportunity", body).await
    }

    // -- Cases --

    /// Query cases via SOQL.
    pub async fn list_cases(
        &self,
        fields: Option<&[String]>,
        limit: Option<i64>,
        status: Option<&str>,
    ) -> SalesforceResult<serde_json::Value> {
        validate_soql_fields(fields)?;
        let cols = fields.map_or_else(
            || "Id, Subject, Status, Priority".to_string(),
            |f| f.join(", "),
        );
        let mut query = format!("SELECT {cols} FROM Case");
        if let Some(s) = status {
            let escaped = escape_soql_string(s);
            let _ = write!(query, " WHERE Status = '{escaped}'");
        }
        if let Some(l) = limit {
            let _ = write!(query, " LIMIT {l}");
        }
        self.soql_query(&query).await
    }

    /// Create a case.
    pub async fn create_case(
        &self,
        body: &serde_json::Value,
    ) -> SalesforceResult<serde_json::Value> {
        self.post("/sobjects/Case", body).await
    }

    // -- SOQL --

    /// Execute a raw SOQL query.
    pub async fn soql_query(&self, query: &str) -> SalesforceResult<serde_json::Value> {
        let encoded = urlencoding_encode(query);
        self.get(&format!("/query?q={encoded}")).await
    }

    // -- Reports --

    /// Get a report by ID.
    pub async fn get_report(
        &self,
        report_id: &str,
        include_details: bool,
    ) -> SalesforceResult<serde_json::Value> {
        let report_id = sanitize_path_segment(report_id, "report_id")?;
        let qs = if include_details {
            "?includeDetails=true"
        } else {
            ""
        };
        self.get(&format!("/analytics/reports/{report_id}{qs}"))
            .await
    }
}

fn decode_success_body(status: StatusCode, body: &str) -> SalesforceResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SalesforceError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

/// Minimal URL-encoding for SOQL query strings.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                let _ = write!(out, "{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SalesforceAuth::AccessToken("00Dxx0000001secret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("00Dxx0000001secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = SalesforceAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());

        let cred = SalesforceAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = SalesforceAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");

        let cred = SalesforceAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            SalesforceError::Api {
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
            SalesforceError::Api {
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
    fn urlencoding_basic() {
        assert_eq!(
            urlencoding_encode("SELECT Id FROM Account"),
            "SELECT+Id+FROM+Account"
        );
    }

    #[test]
    fn urlencoding_special_chars() {
        let encoded = urlencoding_encode("WHERE Name = 'Acme'");
        assert!(encoded.contains("%27"));
        assert!(encoded.contains('+'));
    }

    // -- Additional client tests --

    #[test]
    fn client_new_default_url() {
        let client =
            SalesforceClient::new(SalesforceAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
        assert_eq!(client.api_version(), DEFAULT_API_VERSION);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("tok".into()),
            Some("https://myorg.salesforce.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://myorg.salesforce.com");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("tok".into()),
            Some("https://example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_with_client_trims_slash() {
        let inner = Client::builder().build().unwrap();
        let client = SalesforceClient::with_client(
            inner,
            SalesforceAuth::AccessToken("tok".into()),
            "https://x.com/",
        );
        assert_eq!(client.base_url, "https://x.com");
        assert_eq!(client.api_version(), DEFAULT_API_VERSION);
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = SalesforceClient::new(
            SalesforceAuth::AccessToken("super_secret_token_123".into()),
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super_secret_token_123"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("SalesforceClient"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_debug_shows_credential_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let client = SalesforceClient::new(SalesforceAuth::CredentialId(cred), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(&cred_str));
    }

    #[test]
    fn auth_clone() {
        let auth = SalesforceAuth::AccessToken("tok".into());
        let cloned = auth.clone();
        assert!(!auth.is_secretless());
        assert_eq!(cloned.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = CredentialId::new();
        let cred_str = cred.to_string();
        let auth = SalesforceAuth::CredentialId(cred);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&cred_str));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn urlencoding_empty_string() {
        assert_eq!(urlencoding_encode(""), "");
    }

    #[test]
    fn urlencoding_unreserved_chars_pass_through() {
        let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
        assert_eq!(urlencoding_encode(input), input);
    }

    #[test]
    fn urlencoding_percent_encoded() {
        let encoded = urlencoding_encode("a=b&c=d");
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn urlencoding_slash_encoded() {
        let encoded = urlencoding_encode("/path/to");
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://login.salesforce.com");
    }

    #[test]
    fn default_api_path_value() {
        assert_eq!(DEFAULT_API_PATH, "/services/data/v66.0");
        assert_eq!(DEFAULT_API_VERSION, "66.0");
    }

    #[test]
    fn client_new_with_api_version_override() {
        let client = SalesforceClient::new_with_api_version(
            SalesforceAuth::AccessToken("tok".into()),
            None,
            Some("65.0"),
        )
        .unwrap();
        assert_eq!(client.api_path(), "/services/data/v65.0");
        assert_eq!(client.api_version(), "65.0");
    }

    #[test]
    fn client_new_with_api_version_normalizes_prefix() {
        let client = SalesforceClient::new_with_api_version(
            SalesforceAuth::AccessToken("tok".into()),
            None,
            Some("v64.0"),
        )
        .unwrap();
        assert_eq!(client.api_path(), "/services/data/v64.0");
        assert_eq!(client.api_version(), "64.0");
    }

    #[test]
    fn client_new_with_api_version_accepts_uppercase_prefix() {
        let client = SalesforceClient::new_with_api_version(
            SalesforceAuth::AccessToken("tok".into()),
            None,
            Some("V63.0"),
        )
        .unwrap();
        assert_eq!(client.api_path(), "/services/data/v63.0");
        assert_eq!(client.api_version(), "63.0");
    }

    #[test]
    fn normalize_api_version_rejects_malformed_values() {
        assert_eq!(normalize_api_version("66"), None);
        assert_eq!(normalize_api_version("66..0"), None);
        assert_eq!(normalize_api_version("vv66.0"), None);
    }

    // -- sanitize_path_segment tests --

    #[test]
    fn sanitize_path_segment_valid() {
        assert_eq!(
            sanitize_path_segment("001Abc123", "id").unwrap(),
            "001Abc123"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        let err = sanitize_path_segment("", "account_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        let err = sanitize_path_segment("   ", "account_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        let err = sanitize_path_segment("abc/def", "id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        let err = sanitize_path_segment("abc\\def", "id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        let err = sanitize_path_segment("abc..def", "id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        let err = sanitize_path_segment("abc%2fdef", "id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        let err = sanitize_path_segment("abc%5Cdef", "id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_allows_hyphens_and_underscores() {
        assert_eq!(
            sanitize_path_segment("abc-def_ghi", "id").unwrap(),
            "abc-def_ghi"
        );
    }

    // -- validate_soql_field(s) tests --

    #[test]
    fn validate_soql_field_accepts_identifier_and_relationship() {
        assert!(validate_soql_field("Name").is_ok());
        assert!(validate_soql_field("Account.Name").is_ok());
        assert!(validate_soql_field("Custom_Field__c").is_ok());
        assert!(validate_soql_field("Owner.Profile.Name").is_ok());
    }

    #[test]
    fn validate_soql_field_rejects_empty() {
        assert!(validate_soql_field("").is_err());
    }

    #[test]
    fn validate_soql_field_rejects_soql_injection() {
        // Breaking out of the column list / changing the queried object.
        assert!(validate_soql_field("Id FROM User WHERE Name != ''").is_err());
        assert!(validate_soql_field("Id), (SELECT Name FROM Contacts").is_err());
        assert!(validate_soql_field("Id,Secret").is_err());
        assert!(validate_soql_field("COUNT(Id)").is_err());
    }

    #[test]
    fn validate_soql_field_rejects_query_param_smuggling_and_whitespace() {
        // Interpolated into `?fields=` for get_account; must not carry `&`/`=`
        // or surrounding whitespace that would break the URL query.
        assert!(validate_soql_field("Name&admin=true").is_err());
        assert!(validate_soql_field(" Name ").is_err());
    }

    #[test]
    fn validate_soql_fields_none_is_ok() {
        assert!(validate_soql_fields(None).is_ok());
    }

    #[test]
    fn validate_soql_fields_rejects_when_any_entry_is_bad() {
        let good = vec!["Id".to_string(), "Name".to_string()];
        assert!(validate_soql_fields(Some(&good)).is_ok());
        let bad = vec!["Id".to_string(), "Name) FROM User--".to_string()];
        assert!(validate_soql_fields(Some(&bad)).is_err());
    }
}
