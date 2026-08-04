//! `Retool` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{RetoolError, RetoolResult},
    types::ApiErrorResponse,
};

/// Default `Retool` API base URL template.
pub const DEFAULT_BASE_URL_TEMPLATE: &str = "https://{subdomain}.retool.com/api/v1";

/// Validate a caller-supplied Retool subdomain before it is interpolated into
/// the request host (`https://{subdomain}.retool.com`).
///
/// The subdomain becomes part of the URL authority, so an unvalidated value can
/// change the effective host entirely — e.g. `evil.com/` parses as host
/// `evil.com` with the rest pushed into the path, and `@`/`:` can graft on
/// userinfo or a port. A DNS label is `[A-Za-z0-9-]` (no leading/trailing
/// hyphen), which keeps the host pinned under `*.retool.com` while rejecting
/// every authority-injection vector.
fn validate_subdomain(subdomain: &str) -> RetoolResult<&str> {
    let trimmed = subdomain.trim();
    if trimmed.is_empty() {
        return Err(RetoolError::InvalidInput(
            "subdomain must not be empty".into(),
        ));
    }
    if trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(RetoolError::InvalidInput(format!(
            "subdomain '{trimmed}' must be a DNS label (letters, digits, hyphens)"
        )));
    }
    Ok(trimmed)
}

/// `Retool` authentication credentials.
#[derive(Clone)]
pub struct RetoolAuth {
    pub api_token: String,
}

impl RetoolAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        "api_token:redacted".to_string()
    }
}

impl fmt::Debug for RetoolAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetoolAuth")
            .field("api_token", &"<redacted>")
            .finish()
    }
}

/// `Retool` API client.
pub struct RetoolClient {
    client: Client,
    auth: RetoolAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for RetoolClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetoolClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl RetoolClient {
    /// Create a new `Retool` client.
    pub fn new(
        auth: RetoolAuth,
        subdomain: Option<&str>,
        base_url: Option<&str>,
    ) -> RetoolResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-retool/0.1.0 (FCP connector)")
            .build()?;

        let url = if let Some(u) = base_url {
            u.trim_end_matches('/').to_string()
        } else {
            let sub = validate_subdomain(subdomain.unwrap_or("app"))?;
            format!("https://{sub}.retool.com/api/v1")
        };

        Ok(Self {
            client,
            auth,
            base_url: url,
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
        req.header("Authorization", format!("Bearer {}", self.auth.api_token))
    }

    async fn handle_response(&self, resp: Response) -> RetoolResult<serde_json::Value> {
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
    ) -> RetoolResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.detail())
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(RetoolError::Unauthorized),
            403 => Err(RetoolError::Forbidden),
            404 => Err(RetoolError::NotFound { resource: detail }),
            429 => Err(RetoolError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(RetoolError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> RetoolResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> RetoolResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Workflows --

    /// List all workflows.
    pub async fn list_workflows(&self) -> RetoolResult<serde_json::Value> {
        self.get("/workflows").await
    }

    /// Run a workflow by ID with optional body data.
    pub async fn run_workflow(
        &self,
        workflow_id: &str,
        body: Option<&serde_json::Value>,
    ) -> RetoolResult<serde_json::Value> {
        let default_body = serde_json::json!({});
        let payload = body.unwrap_or(&default_body);
        self.post(&format!("/workflows/{workflow_id}/run"), payload)
            .await
    }
}

fn decode_success_body(status: StatusCode, body: &str) -> RetoolResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(RetoolError::Api {
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
        let auth = RetoolAuth {
            api_token: "secret-token-value".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = RetoolAuth {
            api_token: "secret".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            RetoolError::Api {
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
            RetoolError::Api {
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
    fn client_new_with_custom_base_url() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client =
            RetoolClient::new(auth, None, Some("https://test.example.com/api/v1")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api/v1");
    }

    #[test]
    fn client_new_default_url_with_subdomain() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client = RetoolClient::new(auth, Some("myorg"), None).unwrap();
        assert_eq!(client.base_url, "https://myorg.retool.com/api/v1");
    }

    #[test]
    fn client_new_default_url_no_subdomain() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client = RetoolClient::new(auth, None, None).unwrap();
        assert_eq!(client.base_url, "https://app.retool.com/api/v1");
    }

    #[test]
    fn validate_subdomain_accepts_dns_labels() {
        assert_eq!(validate_subdomain("myorg").unwrap(), "myorg");
        assert_eq!(validate_subdomain("my-org-1").unwrap(), "my-org-1");
        assert_eq!(validate_subdomain("  myorg  ").unwrap(), "myorg");
    }

    #[test]
    fn validate_subdomain_rejects_authority_injection() {
        // host hijack via `/`, userinfo via `@`, port via `:`, extra labels
        // via `.`, query/fragment via `?`/`#`.
        assert!(validate_subdomain("evil.com/").is_err());
        assert!(validate_subdomain("app.evil.com").is_err());
        assert!(validate_subdomain("app@evil.com").is_err());
        assert!(validate_subdomain("app:8080").is_err());
        assert!(validate_subdomain("app#frag").is_err());
        assert!(validate_subdomain("").is_err());
        assert!(validate_subdomain("-app").is_err());
        assert!(validate_subdomain("app-").is_err());
    }

    #[test]
    fn client_new_rejects_malicious_subdomain() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        assert!(RetoolClient::new(auth, Some("evil.com/"), None).is_err());
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client =
            RetoolClient::new(auth, None, Some("https://test.example.com/api/v1/")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api/v1");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = RetoolAuth {
            api_token: "secret-api-key-value".into(),
        };
        let client = RetoolClient::new(auth, None, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
        assert!(!dbg.contains("secret-api-key-value"));
    }

    #[test]
    fn auth_clone() {
        let auth = RetoolAuth {
            api_token: "tok123".into(),
        };
        let cloned = RetoolAuth::clone(&auth);
        assert_eq!(cloned.api_token, "tok123");
    }

    #[test]
    fn client_new_base_url_overrides_subdomain() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client =
            RetoolClient::new(auth, Some("ignored"), Some("https://custom.example.com")).unwrap();
        assert_eq!(client.base_url, "https://custom.example.com");
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client = RetoolClient::new(auth, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("RetoolClient"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("RetoolAuth"));
    }

    #[test]
    fn default_base_url_template_contains_placeholder() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("{subdomain}"));
    }

    #[test]
    fn default_base_url_template_starts_with_https() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.starts_with("https://"));
    }

    #[test]
    fn auth_redacted_label_consistent() {
        let auth1 = RetoolAuth {
            api_token: "secret1".into(),
        };
        let auth2 = RetoolAuth {
            api_token: "secret2".into(),
        };
        assert_eq!(auth1.redacted_label(), auth2.redacted_label());
    }

    #[test]
    fn client_debug_does_not_contain_token() {
        let auth = RetoolAuth {
            api_token: "super-secret-token-value".into(),
        };
        let client = RetoolClient::new(auth, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-token-value"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client = RetoolClient::new(auth, None, Some("https://example.com/api/v1///")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_empty_custom_url() {
        let auth = RetoolAuth {
            api_token: "tok".into(),
        };
        let client = RetoolClient::new(auth, None, Some("")).unwrap();
        assert!(client.base_url.is_empty());
    }
}
