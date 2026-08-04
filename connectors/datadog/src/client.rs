//! Datadog API client.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

/// Percent-encode a query parameter value.
fn encode_query_value(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

use crate::{
    error::{DatadogError, DatadogResult},
    types::ApiErrorResponse,
};

/// Datadog region configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatadogRegion {
    Us1,
    Us3,
    Us5,
    Eu1,
    Ap1,
}

impl DatadogRegion {
    /// Parse a region string.
    pub fn parse_region(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "us1" | "us" => Some(Self::Us1),
            "us3" => Some(Self::Us3),
            "us5" => Some(Self::Us5),
            "eu1" | "eu" => Some(Self::Eu1),
            "ap1" => Some(Self::Ap1),
            _ => None,
        }
    }

    /// Get the API base URL for this region.
    #[must_use]
    pub const fn api_base_url(&self) -> &str {
        match self {
            Self::Us1 => "https://api.datadoghq.com/api/v1",
            Self::Us3 => "https://api.us3.datadoghq.com/api/v1",
            Self::Us5 => "https://api.us5.datadoghq.com/api/v1",
            Self::Eu1 => "https://api.datadoghq.eu/api/v1",
            Self::Ap1 => "https://api.ap1.datadoghq.com/api/v1",
        }
    }
}

/// Default API base URL (US1).
pub const DEFAULT_BASE_URL: &str = "https://api.datadoghq.com/api/v1";

/// Authentication mode for the Datadog API.
#[derive(Clone)]
pub enum DatadogAuth {
    /// API key + Application key pair.
    ApiKeys { api_key: String, app_key: String },
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl DatadogAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKeys { .. } => "api_keys:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for DatadogAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKeys { .. } => f
                .debug_struct("ApiKeys")
                .field("api_key", &"<redacted>")
                .field("app_key", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Datadog API client.
pub struct DatadogClient {
    client: Client,
    auth: DatadogAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for DatadogClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatadogClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl DatadogClient {
    /// Create a new Datadog client.
    pub fn new(auth: DatadogAuth, base_url: Option<&str>) -> DatadogResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-datadog/0.1.0")
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

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: DatadogAuth, base_url: &str) -> Self {
        Self {
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
        }
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            DatadogAuth::ApiKeys { api_key, app_key } => req
                .header("DD-API-KEY", api_key)
                .header("DD-APPLICATION-KEY", app_key),
            DatadogAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> DatadogResult<serde_json::Value> {
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
    ) -> DatadogResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.errors.first().cloned())
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(DatadogError::Unauthorized),
            403 => Err(DatadogError::Forbidden),
            404 => Err(DatadogError::NotFound { resource: detail }),
            429 => Err(DatadogError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(DatadogError::Api {
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
    ) -> DatadogResult<serde_json::Value> {
        let replay_safe = http_method != "POST";
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "datadog request");

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
                    let err = DatadogError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> DatadogResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> DatadogResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("POST", &url, Some(body)).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> DatadogResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("DELETE", &url, None).await
    }

    // -- Events --

    /// Create an event.
    pub async fn create_event(&self, body: &serde_json::Value) -> DatadogResult<serde_json::Value> {
        self.post("/events", body).await
    }

    /// List events in a time range.
    pub async fn list_events(
        &self,
        start: i64,
        end: i64,
        priority: Option<&str>,
        sources: Option<&str>,
        tags: Option<&str>,
    ) -> DatadogResult<serde_json::Value> {
        let mut params = vec![format!("start={start}"), format!("end={end}")];
        if let Some(p) = priority {
            params.push(format!("priority={}", encode_query_value(p)));
        }
        if let Some(s) = sources {
            params.push(format!("sources={}", encode_query_value(s)));
        }
        if let Some(t) = tags {
            params.push(format!("tags={}", encode_query_value(t)));
        }
        let qs = params.join("&");
        self.get(&format!("/events?{qs}")).await
    }

    // -- Metrics --

    /// Query time-series metrics.
    pub async fn query_metrics(
        &self,
        query: &str,
        from_ts: i64,
        to_ts: i64,
    ) -> DatadogResult<serde_json::Value> {
        self.get(&format!(
            "/query?query={}&from={from_ts}&to={to_ts}",
            encode_query_value(query)
        ))
        .await
    }

    /// Submit custom metrics.
    pub async fn submit_metrics(
        &self,
        body: &serde_json::Value,
    ) -> DatadogResult<serde_json::Value> {
        self.post("/series", body).await
    }

    // -- Monitors --

    /// List monitors.
    pub async fn list_monitors(
        &self,
        tags: Option<&str>,
        monitor_tags: Option<&str>,
    ) -> DatadogResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(t) = tags {
            params.push(format!("tags={}", encode_query_value(t)));
        }
        if let Some(mt) = monitor_tags {
            params.push(format!("monitor_tags={}", encode_query_value(mt)));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/monitor{qs}")).await
    }

    /// Create a monitor.
    pub async fn create_monitor(
        &self,
        body: &serde_json::Value,
    ) -> DatadogResult<serde_json::Value> {
        self.post("/monitor", body).await
    }

    /// Delete a monitor.
    pub async fn delete_monitor(&self, monitor_id: i64) -> DatadogResult<serde_json::Value> {
        self.delete(&format!("/monitor/{monitor_id}")).await
    }

    // -- Logs --

    /// Search logs.
    pub async fn search_logs(&self, body: &serde_json::Value) -> DatadogResult<serde_json::Value> {
        self.post("/logs-queries/list", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_value_special_chars() {
        let encoded = encode_query_value(concat!("avg:system.cpu", "{host:web01}", "&extra=1"));
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('{'));
        assert!(!encoded.contains('}'));
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
    fn region_from_str() {
        assert_eq!(DatadogRegion::parse_region("us1"), Some(DatadogRegion::Us1));
        assert_eq!(DatadogRegion::parse_region("US"), Some(DatadogRegion::Us1));
        assert_eq!(DatadogRegion::parse_region("eu1"), Some(DatadogRegion::Eu1));
        assert_eq!(DatadogRegion::parse_region("EU"), Some(DatadogRegion::Eu1));
        assert_eq!(DatadogRegion::parse_region("us3"), Some(DatadogRegion::Us3));
        assert_eq!(DatadogRegion::parse_region("us5"), Some(DatadogRegion::Us5));
        assert_eq!(DatadogRegion::parse_region("ap1"), Some(DatadogRegion::Ap1));
        assert_eq!(DatadogRegion::parse_region("invalid"), None);
    }

    #[test]
    fn region_api_urls() {
        assert_eq!(
            DatadogRegion::Us1.api_base_url(),
            "https://api.datadoghq.com/api/v1"
        );
        assert_eq!(
            DatadogRegion::Eu1.api_base_url(),
            "https://api.datadoghq.eu/api/v1"
        );
        assert_eq!(
            DatadogRegion::Us3.api_base_url(),
            "https://api.us3.datadoghq.com/api/v1"
        );
        assert_eq!(
            DatadogRegion::Us5.api_base_url(),
            "https://api.us5.datadoghq.com/api/v1"
        );
        assert_eq!(
            DatadogRegion::Ap1.api_base_url(),
            "https://api.ap1.datadoghq.com/api/v1"
        );
    }

    #[test]
    fn auth_debug_redacts_keys() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "supersecret_api".into(),
            app_key: "supersecret_app".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("supersecret_api"));
        assert!(!dbg.contains("supersecret_app"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let keys = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        assert!(!keys.is_secretless());

        let cred = DatadogAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let keys = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        assert_eq!(keys.redacted_label(), "api_keys:redacted");

        let cred = DatadogAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    // ── Client construction ───────────────────────────────────────

    #[test]
    fn client_new_default_url() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let client = DatadogClient::new(auth, None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let client = DatadogClient::new(auth, Some("https://custom.example.com/api/v1")).unwrap();
        assert_eq!(client.base_url, "https://custom.example.com/api/v1");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let client = DatadogClient::new(auth, Some("https://example.com/api/")).unwrap();
        assert_eq!(client.base_url, "https://example.com/api");
    }

    #[test]
    fn client_debug_format_redacts_keys() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "supersecret_key".into(),
            app_key: "supersecret_app".into(),
        };
        let client = DatadogClient::new(auth, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecret_key"));
        assert!(!dbg.contains("supersecret_app"));
        assert!(dbg.contains("DatadogClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_with_client_trims_trailing_slash() {
        let inner = Client::new();
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let client = DatadogClient::with_client(inner, auth, "https://example.com/");
        assert_eq!(client.base_url, "https://example.com");
    }

    // ── Auth clone ────────────────────────────────────────────────

    #[test]
    fn auth_api_keys_clone() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "key1".into(),
            app_key: "app1".into(),
        };
        let cloned = auth.clone();
        // Use both original and clone to verify clone correctness
        assert_eq!(auth.redacted_label(), "api_keys:redacted");
        assert_eq!(cloned.redacted_label(), "api_keys:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let cred = DatadogAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        assert!(cred.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_debug_credential_id_contains_id() {
        let id = CredentialId::new();
        let id_str = id.to_string();
        let auth = DatadogAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains(&id_str));
        assert!(dbg.contains("CredentialId"));
    }

    // ── Region edge cases ─────────────────────────────────────────

    #[test]
    fn region_parse_case_insensitive() {
        assert_eq!(DatadogRegion::parse_region("US1"), Some(DatadogRegion::Us1));
        assert_eq!(DatadogRegion::parse_region("Us1"), Some(DatadogRegion::Us1));
        assert_eq!(DatadogRegion::parse_region("EU1"), Some(DatadogRegion::Eu1));
        assert_eq!(DatadogRegion::parse_region("Eu"), Some(DatadogRegion::Eu1));
        assert_eq!(DatadogRegion::parse_region("AP1"), Some(DatadogRegion::Ap1));
    }

    #[test]
    fn region_parse_empty_string() {
        assert_eq!(DatadogRegion::parse_region(""), None);
    }

    #[test]
    fn region_parse_whitespace() {
        assert_eq!(DatadogRegion::parse_region("  "), None);
    }

    #[test]
    fn region_eq_and_copy() {
        let r1 = DatadogRegion::Us1;
        let r2 = r1; // Copy
        assert_eq!(r1, r2);
        assert_ne!(r1, DatadogRegion::Eu1);
    }

    #[test]
    fn region_debug_format() {
        let dbg = format!("{:?}", DatadogRegion::Ap1);
        assert_eq!(dbg, "Ap1");
    }

    #[test]
    fn default_base_url_constant() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
        assert!(DEFAULT_BASE_URL.contains("datadoghq"));
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    // ── Additional region / auth / client tests ──────────────────

    #[test]
    fn region_clone() {
        let r = DatadogRegion::Us3;
        let cloned = r;
        assert_eq!(r, cloned);
    }

    #[test]
    fn region_all_variants_have_distinct_urls() {
        let urls: Vec<&str> = [
            DatadogRegion::Us1,
            DatadogRegion::Us3,
            DatadogRegion::Us5,
            DatadogRegion::Eu1,
            DatadogRegion::Ap1,
        ]
        .iter()
        .map(|r| r.api_base_url())
        .collect();
        let mut unique = urls.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(urls.len(), unique.len());
    }

    #[test]
    fn region_all_urls_start_with_https() {
        for r in &[
            DatadogRegion::Us1,
            DatadogRegion::Us3,
            DatadogRegion::Us5,
            DatadogRegion::Eu1,
            DatadogRegion::Ap1,
        ] {
            assert!(
                r.api_base_url().starts_with("https://"),
                "{r:?} url should start with https"
            );
        }
    }

    #[test]
    fn region_parse_mixed_case_us3() {
        assert_eq!(DatadogRegion::parse_region("Us3"), Some(DatadogRegion::Us3));
        assert_eq!(DatadogRegion::parse_region("US3"), Some(DatadogRegion::Us3));
    }

    #[test]
    fn region_parse_mixed_case_us5() {
        assert_eq!(DatadogRegion::parse_region("Us5"), Some(DatadogRegion::Us5));
        assert_eq!(DatadogRegion::parse_region("US5"), Some(DatadogRegion::Us5));
    }

    #[test]
    fn region_parse_mixed_case_ap1() {
        assert_eq!(DatadogRegion::parse_region("Ap1"), Some(DatadogRegion::Ap1));
        assert_eq!(DatadogRegion::parse_region("AP1"), Some(DatadogRegion::Ap1));
    }

    #[test]
    fn auth_debug_api_keys_contains_struct_name() {
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKeys"));
    }

    #[test]
    fn client_with_client_preserves_base_url() {
        let inner = Client::new();
        let auth = DatadogAuth::ApiKeys {
            api_key: "k".into(),
            app_key: "a".into(),
        };
        let client = DatadogClient::with_client(inner, auth, "https://test.example.com/api/v1");
        assert_eq!(client.base_url, "https://test.example.com/api/v1");
    }

    #[test]
    fn client_new_with_credential_id() {
        let auth = DatadogAuth::CredentialId(CredentialId::new());
        let client = DatadogClient::new(auth, None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }
}
