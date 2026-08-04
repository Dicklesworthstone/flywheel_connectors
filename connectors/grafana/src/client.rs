//! Grafana API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

/// Percent-encode a query parameter value.
fn encode_query_value(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Sanitize a path segment by percent-encoding special characters.
fn sanitize_path_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

use crate::{
    error::{GrafanaError, GrafanaResult},
    types::ApiErrorResponse,
};

/// Default Grafana Cloud API base URL.
pub const DEFAULT_BASE_URL: &str = "https://grafana.com/api";

/// Authentication mode for the Grafana API.
#[derive(Clone)]
pub enum GrafanaAuth {
    /// Bearer token (API key or service account token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl GrafanaAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for GrafanaAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Grafana API client.
pub struct GrafanaClient {
    client: Client,
    auth: GrafanaAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for GrafanaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrafanaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl GrafanaClient {
    /// Create a new Grafana client.
    pub fn new(auth: GrafanaAuth, base_url: Option<&str>) -> GrafanaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-grafana/0.1.0")
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

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: GrafanaAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            GrafanaAuth::BearerToken(token) => req.bearer_auth(token),
            GrafanaAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> GrafanaResult<serde_json::Value> {
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
    ) -> GrafanaResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(GrafanaError::Unauthorized),
            403 => Err(GrafanaError::Forbidden),
            404 => Err(GrafanaError::NotFound { resource: detail }),
            429 => Err(GrafanaError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(GrafanaError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Issue a request with retry.
    ///
    /// br-kxd3e: replay safety is derived from the verb, which is sound here
    /// because this client uses each one for its standard meaning — GET reads,
    /// PUT/PATCH set named fields to named values, DELETE converges, and only
    /// POST creates. A replay of a POST after a 5xx creates a second object or
    /// double-counts an ingested event.
    async fn request_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> GrafanaResult<serde_json::Value> {
        let replay_safe = http_method != "POST";
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "grafana request");

            let req = match http_method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "DELETE" => self.client.delete(url),
                _ => unreachable!(),
            };
            let req = if let Some(b) = body { req.json(b) } else { req };
            let req = self.add_auth(req);

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
                    let err = GrafanaError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body)).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("DELETE", &url, None).await
    }

    // -- Dashboards --

    /// Search/list dashboards.
    pub async fn search_dashboards(
        &self,
        query: Option<&str>,
        tag: Option<&[String]>,
        limit: Option<i64>,
    ) -> GrafanaResult<serde_json::Value> {
        let mut params = Vec::new();
        params.push("type=dash-db".to_string());
        if let Some(q) = query {
            params.push(format!("query={}", encode_query_value(q)));
        }
        if let Some(tags) = tag {
            for t in tags {
                params.push(format!("tag={}", encode_query_value(t)));
            }
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        let qs = params.join("&");
        self.get(&format!("/search?{qs}")).await
    }

    /// Get a dashboard by UID.
    pub async fn get_dashboard(&self, uid: &str) -> GrafanaResult<serde_json::Value> {
        let uid = sanitize_path_segment(uid);
        self.get(&format!("/dashboards/uid/{uid}")).await
    }

    /// Create or update a dashboard.
    pub async fn save_dashboard(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/dashboards/db", body).await
    }

    /// Delete a dashboard by UID.
    pub async fn delete_dashboard(&self, uid: &str) -> GrafanaResult<serde_json::Value> {
        let uid = sanitize_path_segment(uid);
        self.delete(&format!("/dashboards/uid/{uid}")).await
    }

    // -- Datasources --

    /// List all datasources.
    pub async fn list_datasources(&self) -> GrafanaResult<serde_json::Value> {
        self.get("/datasources").await
    }

    /// Query a datasource via the query API.
    pub async fn query_datasource(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/ds/query", body).await
    }

    // -- Alerts --

    /// List alert rules.
    pub async fn list_alert_rules(
        &self,
        state: Option<&str>,
        limit: Option<i64>,
    ) -> GrafanaResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(s) = state {
            params.push(format!("state={}", encode_query_value(s)));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/ruler/grafana/api/v1/rules{qs}")).await
    }

    /// Create an alert rule.
    pub async fn create_alert_rule(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/ruler/grafana/api/v1/rules", body).await
    }

    // -- Annotations --

    /// Create an annotation.
    pub async fn create_annotation(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/annotations", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_value_special_chars() {
        let encoded = encode_query_value("my dashboard&foo=bar");
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn encode_query_value_empty() {
        assert_eq!(encode_query_value(""), "");
    }

    #[test]
    fn encode_query_value_alphanumeric_preserved() {
        assert_eq!(encode_query_value("abc123"), "abc123");
    }

    #[test]
    fn sanitize_path_segment_rejects_slashes() {
        let sanitized = sanitize_path_segment("uid/../../etc");
        assert!(!sanitized.contains('/'));
    }

    #[test]
    fn sanitize_path_segment_normal() {
        assert_eq!(sanitize_path_segment("abc123"), "abc123");
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = GrafanaAuth::BearerToken("supersecret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let bearer = GrafanaAuth::BearerToken("tok".into());
        assert!(!bearer.is_secretless());

        let cred = GrafanaAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let bearer = GrafanaAuth::BearerToken("tok".into());
        assert_eq!(bearer.redacted_label(), "bearer_token:redacted");

        let cred = GrafanaAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone_bearer() {
        let bearer = GrafanaAuth::BearerToken("tok".into());
        let cloned = bearer.clone();
        // Use both to ensure neither is "dropped without use"
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
        assert_eq!(bearer.redacted_label(), "bearer_token:redacted");
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_clone_credential() {
        let cred = GrafanaAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        // Use both to prevent redundant_clone lint
        assert!(cloned.is_secretless());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_debug_credential_id_shows_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = GrafanaAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id_str));
    }

    #[test]
    fn client_new_default_url() {
        let client = GrafanaClient::new(GrafanaAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = GrafanaClient::new(
            GrafanaAuth::BearerToken("tok".into()),
            Some("http://localhost:3000/api"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("http://localhost:3000/api"));
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = GrafanaClient::new(
            GrafanaAuth::BearerToken("tok".into()),
            Some("http://localhost:3000/api/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("http://localhost:3000/api"));
        assert!(!dbg.contains("api/\""));
    }

    #[test]
    fn client_new_trims_multiple_trailing_slashes() {
        let client = GrafanaClient::new(
            GrafanaAuth::BearerToken("tok".into()),
            Some("http://localhost:3000/api///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        // trim_end_matches removes all trailing slashes
        assert!(!dbg.contains("api/\""));
    }

    #[test]
    fn client_debug_redacts_token() {
        let client =
            GrafanaClient::new(GrafanaAuth::BearerToken("supersecret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("GrafanaClient"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = GrafanaClient::new(
            GrafanaAuth::BearerToken("tok".into()),
            Some("https://my-grafana.example.com/api"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://my-grafana.example.com/api"));
    }

    #[test]
    fn client_with_client_trims_slash() {
        let http_client = Client::new();
        let client = GrafanaClient::with_client(
            http_client,
            GrafanaAuth::BearerToken("tok".into()),
            "https://example.com/api/",
        );
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("api/\""));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://grafana.com/api");
    }

    #[test]
    fn auth_bearer_not_secretless() {
        let auth = GrafanaAuth::BearerToken(String::new());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = GrafanaAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    // ── Additional client coverage tests ──────────────────────────

    #[test]
    fn auth_redacted_label_does_not_contain_token() {
        let auth = GrafanaAuth::BearerToken("glsa_super_secret_key_12345".into());
        let label = auth.redacted_label();
        assert!(!label.contains("glsa_super_secret_key_12345"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn auth_credential_label_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = GrafanaAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.contains(&id_str));
    }

    #[test]
    fn client_new_empty_string_url() {
        let client = GrafanaClient::new(GrafanaAuth::BearerToken("tok".into()), Some("")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GrafanaClient"));
    }
}
