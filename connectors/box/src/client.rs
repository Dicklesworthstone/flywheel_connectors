//! `Box` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{
    Client, Response, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
};
use tracing::{debug, instrument};

use crate::{
    error::{BoxError, BoxResult},
    types::ApiErrorResponse,
};

/// Default `Box` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.box.com/2.0";

/// Default `Box` upload base URL.
pub const DEFAULT_UPLOAD_URL: &str = "https://upload.box.com/api/2.0";

const CREDENTIAL_ID_HEADER: HeaderName = HeaderName::from_static("x-fcp-credential-id");

/// Authentication mode for the `Box` API.
#[derive(Clone)]
pub enum BoxAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl BoxAuth {
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

impl fmt::Debug for BoxAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Box` API client.
pub struct BoxClient {
    client: Client,
    auth: BoxAuth,
    base_url: String,
    upload_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for BoxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("upload_url", &self.upload_url)
            .finish()
    }
}

impl BoxClient {
    /// Create a new `Box` client.
    pub fn new(auth: BoxAuth, base_url: Option<&str>, upload_url: Option<&str>) -> BoxResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-box/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            upload_url: upload_url
                .unwrap_or(DEFAULT_UPLOAD_URL)
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

    fn add_auth(&self, req: reqwest::RequestBuilder) -> BoxResult<reqwest::RequestBuilder> {
        let mut headers = HeaderMap::new();
        match &self.auth {
            BoxAuth::BearerToken(value) => {
                let bearer = format!("Bearer {value}");
                let header_value = HeaderValue::from_str(&bearer).map_err(|_| {
                    BoxError::InvalidInput("invalid bearer credential header".into())
                })?;
                headers.insert(AUTHORIZATION, header_value);
            }
            BoxAuth::CredentialId(id) => {
                let header_value = HeaderValue::from_str(&id.to_string())
                    .map_err(|_| BoxError::InvalidInput("invalid credential id header".into()))?;
                headers.insert(CREDENTIAL_ID_HEADER, header_value);
            }
        }
        Ok(req.headers(headers))
    }

    async fn handle_response(&self, resp: Response) -> BoxResult<serde_json::Value> {
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
    ) -> BoxResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let parsed = serde_json::from_str::<ApiErrorResponse>(&body).ok();
        let detail = parsed
            .as_ref()
            .and_then(|e| e.message.clone())
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(BoxError::Unauthorized),
            403 => Err(BoxError::Forbidden),
            404 => Err(BoxError::NotFound { resource: detail }),
            409 => Err(BoxError::Conflict { message: detail }),
            429 => Err(BoxError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(BoxError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, query), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self
            .add_auth(self.client.get(&url))?
            .header("Accept", "application/json");

        if let Some(q) = query {
            req = req.query(q);
        }

        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))?
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn post_upload(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.upload_url);
        debug!(url = %redact_url(&url), "POST upload request");
        let req = self.add_auth(self.client.post(&url))?.multipart(form);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> BoxResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))?
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Reject path-segment values that contain traversal characters.
    fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> BoxResult<&'a str> {
        if value.trim().is_empty() {
            return Err(BoxError::InvalidInput(format!("{field} must not be empty")));
        }
        let lower = value.to_ascii_lowercase();
        if value.contains('/')
            || value.contains('\\')
            || value.contains("..")
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(BoxError::InvalidInput(format!(
                "{field} contains path traversal characters"
            )));
        }
        Ok(value)
    }

    // -- Files --

    /// Get file metadata.
    pub async fn get_file(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        Self::sanitize_path_segment(file_id, "file_id")?;
        self.get(&format!("/files/{file_id}"), None).await
    }

    /// Upload a file (simplified -- sends JSON attributes, not real multipart binary).
    /// In production, the actual binary content would be sent via multipart form.
    /// For the connector protocol, we pass metadata and let the host handle content.
    pub async fn upload_file(
        &self,
        folder_id: &str,
        name: &str,
        content: Option<&str>,
    ) -> BoxResult<serde_json::Value> {
        Self::sanitize_path_segment(folder_id, "folder_id")?;
        let attributes = serde_json::json!({
            "name": name,
            "parent": {"id": folder_id}
        });

        let attrs_part = reqwest::multipart::Part::text(attributes.to_string())
            .mime_str("application/json")
            .unwrap();

        let file_content = content.unwrap_or("").to_string();
        let file_part = reqwest::multipart::Part::text(file_content)
            .file_name(name.to_string())
            .mime_str("application/octet-stream")
            .unwrap();

        let form = reqwest::multipart::Form::new()
            .part("attributes", attrs_part)
            .part("file", file_part);

        self.post_upload("/files/content", form).await
    }

    /// Delete a file.
    pub async fn delete_file(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        Self::sanitize_path_segment(file_id, "file_id")?;
        self.delete(&format!("/files/{file_id}")).await
    }

    // -- Folders --

    /// List folder items.
    pub async fn list_folder_items(
        &self,
        folder_id: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> BoxResult<serde_json::Value> {
        Self::sanitize_path_segment(folder_id, "folder_id")?;
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(o) = offset {
            query.push(("offset", o.to_string()));
        }
        self.get(
            &format!("/folders/{folder_id}/items"),
            if query.is_empty() { None } else { Some(&query) },
        )
        .await
    }

    // -- Sharing --

    /// List collaborations for a file.
    pub async fn list_file_collaborations(&self, file_id: &str) -> BoxResult<serde_json::Value> {
        Self::sanitize_path_segment(file_id, "file_id")?;
        self.get(&format!("/files/{file_id}/collaborations"), None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bearer_value() -> String {
        ["sample", "bearer"].join("-")
    }

    fn sample_bearer() -> BoxAuth {
        BoxAuth::BearerToken(sample_bearer_value())
    }

    #[test]
    fn auth_debug_redacts_token() {
        let sample = sample_bearer_value();
        let auth = BoxAuth::BearerToken(sample.clone());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains(&sample));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let auth = sample_bearer();
        assert!(!auth.is_secretless());
        let cred = BoxAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_bearer() {
        let auth = sample_bearer();
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = BoxAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = BoxAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.box.com/2.0");
    }

    #[test]
    fn default_upload_url_value() {
        assert_eq!(DEFAULT_UPLOAD_URL, "https://upload.box.com/api/2.0");
    }

    #[test]
    fn client_debug_format() {
        let sample = sample_bearer_value();
        let client = BoxClient::new(BoxAuth::BearerToken(sample.clone()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("BoxClient"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&sample));
    }

    #[test]
    fn client_custom_base_url() {
        let client =
            BoxClient::new(sample_bearer(), Some("https://custom.box.com/2.0/"), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.box.com"));
    }

    #[test]
    fn client_custom_upload_url() {
        let client = BoxClient::new(
            sample_bearer(),
            None,
            Some("https://upload.custom.box.com/api/2.0/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("upload.custom.box.com"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = BoxClient::new(
            sample_bearer(),
            Some("https://api.box.com/2.0/"),
            Some("https://upload.box.com/api/2.0/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        // Trailing slash should be stripped
        assert!(!dbg.contains("2.0/\""));
    }

    #[test]
    fn client_with_credential_id() {
        let client =
            BoxClient::new(BoxAuth::CredentialId(CredentialId::new()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = sample_bearer();
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = BoxAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https"));
    }

    #[test]
    fn default_upload_url_starts_with_https() {
        assert!(DEFAULT_UPLOAD_URL.starts_with("https"));
    }

    #[test]
    fn default_base_url_does_not_end_with_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn default_upload_url_does_not_end_with_slash() {
        assert!(!DEFAULT_UPLOAD_URL.ends_with('/'));
    }

    #[test]
    fn client_default_urls() {
        let client = BoxClient::new(sample_bearer(), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("api.box.com"));
        assert!(dbg.contains("upload.box.com"));
    }

    #[test]
    fn auth_credential_redacted_label_format() {
        let id = CredentialId::new();
        let expected = format!("credential_id:{id}");
        let auth = BoxAuth::CredentialId(id);
        assert_eq!(auth.redacted_label(), expected);
    }

    #[test]
    fn client_debug_does_not_leak_token() {
        let sample = sample_bearer_value();
        let client = BoxClient::new(BoxAuth::BearerToken(sample.clone()), None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains(&sample));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = sample_bearer();
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_clone() {
        let auth = BoxAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(BoxClient::sanitize_path_segment("../admin", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("foo/bar", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("foo\\bar", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("foo%2fbar", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("foo%5Cbar", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("", "file_id").is_err());
        assert!(BoxClient::sanitize_path_segment("  ", "file_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            BoxClient::sanitize_path_segment("12345678", "file_id").unwrap(),
            "12345678"
        );
        assert_eq!(
            BoxClient::sanitize_path_segment("folder-id-42", "folder_id").unwrap(),
            "folder-id-42"
        );
    }
}
