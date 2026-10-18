//! `Amplitude` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument};

use crate::{
    error::{AmplitudeError, AmplitudeResult},
    types::{ApiErrorResponse, ChartQueryResponse, CohortsListResponse, EventsExportResponse},
};

/// Default `Amplitude` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://amplitude.com/api/2";

/// `Amplitude` authentication credentials.
#[derive(Clone)]
pub struct AmplitudeAuth {
    pub api_key: String,
    pub secret_key: String,
}

impl AmplitudeAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        let prefix = if self.api_key.len() >= 4 {
            &self.api_key[..4]
        } else {
            &self.api_key
        };
        format!("api_key:{prefix}...,secret_key:redacted")
    }

    /// Build the Basic auth header value.
    #[must_use]
    pub fn basic_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.api_key, self.secret_key);
        format!("Basic {}", BASE64.encode(credentials.as_bytes()))
    }
}

impl fmt::Debug for AmplitudeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AmplitudeAuth")
            .field("api_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// `Amplitude` API client.
pub struct AmplitudeClient {
    client: Client,
    auth: AmplitudeAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for AmplitudeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AmplitudeClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AmplitudeClient {
    /// Create a new `Amplitude` client.
    pub fn new(auth: AmplitudeAuth, base_url: Option<&str>) -> AmplitudeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-amplitude/0.1.0 (FCP connector)")
            .build()?;

        let url = match base_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => DEFAULT_BASE_URL.to_string(),
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

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Authorization", self.auth.basic_auth_header())
    }

    /// Parse a successful JSON response into the caller-supplied typed shape.
    ///
    /// br-csgvd: previously the client returned `serde_json::Value` for every
    /// endpoint, which let an upstream that altered its response shape slip
    /// through the connector boundary unnoticed. Each caller now declares the
    /// exact type it expects, so a shape regression surfaces as a `Decode`
    /// error at the boundary instead of as silently wrong output downstream.
    async fn handle_response<T>(&self, resp: Response) -> AmplitudeResult<T>
    where
        T: DeserializeOwned + Default,
    {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error<T>(&self, status: StatusCode, resp: Response) -> AmplitudeResult<T> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error.or(e.message))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(AmplitudeError::Unauthorized),
            403 => Err(AmplitudeError::Forbidden),
            404 => Err(AmplitudeError::NotFound { resource: detail }),
            429 => Err(AmplitudeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(AmplitudeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Issue a request with retry.
    ///
    /// br-kxd3e / br-d018i: GET requests are always replay-safe. POST event
    /// ingestion (`/2/httpapi`, `/batch`) is replay-safe when every event in
    /// the request body carries a non-empty `insert_id` (Amplitude's documented
    /// 7-day sliding-window deduplication key).
    async fn request_with_retry<T>(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> AmplitudeResult<T>
    where
        T: DeserializeOwned + Default,
    {
        let replay_safe = http_method != "POST" || body_has_amplitude_insert_ids(body);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, url = %redact_url(url), "amplitude request");

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
                    let err = AmplitudeError::Http(err);
                    let replayable = replay_safe || err.replay_is_safe();
                    let retry_after = err.retry_after();
                    AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                }
            }
        })
        .await
    }

    #[instrument(skip(self), fields(url))]
    async fn get<T>(&self, path: &str) -> AmplitudeResult<T>
    where
        T: DeserializeOwned + Default,
    {
        let url = format!("{}{path}", self.base_url);
        self.request_with_retry("GET", &url, None).await
    }

    // -- Charts --

    /// Query a chart by ID.
    pub async fn query_chart(&self, chart_id: &str) -> AmplitudeResult<ChartQueryResponse> {
        let safe_id = sanitize_path_segment(chart_id, "chart_id")?;
        self.get(&format!("/charts/{safe_id}/query")).await
    }

    // -- Cohorts --

    /// List all cohorts.
    pub async fn list_cohorts(&self) -> AmplitudeResult<CohortsListResponse> {
        self.get("/cohorts").await
    }

    // -- Events --

    /// Export events for a date range.
    pub async fn export_events(
        &self,
        start: &str,
        end: &str,
    ) -> AmplitudeResult<EventsExportResponse> {
        let safe_start = encode_query_value(start, "start")?;
        let safe_end = encode_query_value(end, "end")?;
        self.get(&format!("/export?start={safe_start}&end={safe_end}"))
            .await
    }
}

fn event_obj_has_amplitude_insert_id(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("insert_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

fn ensure_amplitude_event_insert_id(obj: &mut serde_json::Map<String, serde_json::Value>) {
    if !event_obj_has_amplitude_insert_id(obj) {
        obj.insert(
            "insert_id".to_string(),
            serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
        );
    }
}

/// Ensure every Amplitude event in `body` carries a stable `insert_id`.
#[must_use]
pub fn ensure_amplitude_insert_ids(body: &serde_json::Value) -> serde_json::Value {
    let mut cloned = body.clone();
    if let Some(obj) = cloned.as_object_mut() {
        if let Some(events) = obj
            .get_mut("events")
            .and_then(serde_json::Value::as_array_mut)
        {
            for item in events {
                if let Some(item_obj) = item.as_object_mut() {
                    ensure_amplitude_event_insert_id(item_obj);
                }
            }
        } else {
            ensure_amplitude_event_insert_id(obj);
        }
    }
    cloned
}

fn body_has_amplitude_insert_ids(body: Option<&serde_json::Value>) -> bool {
    let Some(obj) = body.and_then(serde_json::Value::as_object) else {
        return false;
    };
    if event_obj_has_amplitude_insert_id(obj) {
        return true;
    }
    obj.get("events")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|events| {
            !events.is_empty()
                && events.iter().all(|item| {
                    item.as_object()
                        .is_some_and(event_obj_has_amplitude_insert_id)
                })
        })
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path traversal sequences, slashes,
/// and percent-encoded equivalents.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> AmplitudeResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AmplitudeError::InvalidInput(format!(
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
        return Err(AmplitudeError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

/// Percent-encode a value for safe inclusion in a URL query string.
///
/// Rejects empty values and encodes characters that could alter URL
/// structure (`&`, `=`, `#`, `?`, `/`, `\`, `%` unless already part of a
/// valid percent-encoded triplet is not assumed -- we encode `%`
/// unconditionally to prevent double-encoding attacks).
fn encode_query_value(value: &str, field: &str) -> AmplitudeResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AmplitudeError::InvalidInput(format!(
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

fn decode_success_body<T>(status: StatusCode, body: &str) -> AmplitudeResult<T>
where
    T: DeserializeOwned + Default,
{
    if status == StatusCode::NO_CONTENT {
        return Ok(T::default());
    }
    if body.trim().is_empty() {
        return Ok(T::default());
    }
    Ok(serde_json::from_str(body)?)
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_keys() {
        let auth = AmplitudeAuth {
            api_key: "my-api-key-123".into(),
            secret_key: "super-secret-key".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("my-api-key-123"));
        assert!(!dbg.contains("super-secret-key"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = AmplitudeAuth {
            api_key: "abcdef123456".into(),
            secret_key: "my_super_secret_value".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("abcd"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("my_super_secret_value"));
        assert!(!label.contains("abcdef123456"));
    }

    #[test]
    fn auth_redacted_label_short_key() {
        let auth = AmplitudeAuth {
            api_key: "ab".into(),
            secret_key: "sec".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("ab"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn auth_basic_auth_header() {
        let auth = AmplitudeAuth {
            api_key: "api_key".into(),
            secret_key: "secret_key".into(),
        };
        let header = auth.basic_auth_header();
        assert!(header.starts_with("Basic "));
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "api_key:secret_key");
    }

    #[test]
    fn auth_basic_auth_header_special_chars() {
        let auth = AmplitudeAuth {
            api_key: "key+with/special=chars".into(),
            secret_key: "sec:ret!@#".into(),
        };
        let header = auth.basic_auth_header();
        assert!(header.starts_with("Basic "));
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "key+with/special=chars:sec:ret!@#");
    }

    #[test]
    fn auth_basic_auth_header_empty_values() {
        let auth = AmplitudeAuth {
            api_key: String::new(),
            secret_key: String::new(),
        };
        let header = auth.basic_auth_header();
        let encoded = &header["Basic ".len()..];
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, ":");
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://test.example.com/api")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_new_default_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, None).unwrap();
        assert_eq!(client.base_url, "https://amplitude.com/api/2");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://test.example.com/api/")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
        assert!(!dbg.contains("KEY"));
        assert!(!dbg.contains("SECRET"));
    }

    #[test]
    fn auth_clone() {
        let auth = AmplitudeAuth {
            api_key: "KEY".into(),
            secret_key: "SECRET".into(),
        };
        let cloned = AmplitudeAuth::clone(&auth);
        assert_eq!(cloned.api_key, "KEY");
        assert_eq!(cloned.secret_key, "SECRET");
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://amplitude.com/api/2");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = AmplitudeAuth {
            api_key: "K".into(),
            secret_key: "S".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://example.com///")).unwrap();
        // trim_end_matches removes all trailing slashes
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn auth_basic_auth_header_consistency() {
        let auth = AmplitudeAuth {
            api_key: "test_key".into(),
            secret_key: "test_secret".into(),
        };
        // Calling twice should produce the same result
        let h1 = auth.basic_auth_header();
        let h2 = auth.basic_auth_header();
        assert_eq!(h1, h2);
    }

    #[test]
    fn auth_redacted_label_exactly_four_chars() {
        let auth = AmplitudeAuth {
            api_key: "abcd".into(),
            secret_key: "sec".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("abcd"));
        assert!(label.contains("redacted"));
    }

    #[test]
    fn auth_redacted_label_one_char_key() {
        let auth = AmplitudeAuth {
            api_key: "x".into(),
            secret_key: "sec".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("x..."));
    }

    #[test]
    fn auth_redacted_label_empty_key() {
        let auth = AmplitudeAuth {
            api_key: String::new(),
            secret_key: "sec".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("...,secret_key:redacted"));
    }

    #[test]
    fn auth_basic_auth_header_unicode() {
        let auth = AmplitudeAuth {
            api_key: "key\u{00e9}".into(),
            secret_key: "sec\u{00e9}".into(),
        };
        let header = auth.basic_auth_header();
        assert!(header.starts_with("Basic "));
    }

    #[test]
    fn client_debug_does_not_leak_keys() {
        let auth = AmplitudeAuth {
            api_key: "MY_SECRET_KEY".into(),
            secret_key: "MY_SECRET_SECRET".into(),
        };
        let client = AmplitudeClient::new(auth, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("MY_SECRET_KEY"));
        assert!(!dbg.contains("MY_SECRET_SECRET"));
        assert!(dbg.contains("AmplitudeClient"));
    }

    #[test]
    fn decode_success_body_accepts_empty_ok() {
        let parsed = decode_success_body::<serde_json::Value>(StatusCode::OK, "").unwrap();
        assert_eq!(parsed, serde_json::Value::Null);
    }

    #[test]
    fn decode_success_body_accepts_whitespace_ok() {
        let parsed = decode_success_body::<serde_json::Value>(StatusCode::OK, "  \n\t").unwrap();
        assert_eq!(parsed, serde_json::Value::Null);
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        let parsed = decode_success_body::<serde_json::Value>(StatusCode::NO_CONTENT, "").unwrap();
        assert_eq!(parsed, serde_json::Value::Null);
    }

    #[test]
    fn client_stores_base_url() {
        let auth = AmplitudeAuth {
            api_key: "K".into(),
            secret_key: "S".into(),
        };
        let client = AmplitudeClient::new(auth, Some("https://custom.api.com/v2")).unwrap();
        assert_eq!(client.base_url, "https://custom.api.com/v2");
    }

    #[test]
    fn auth_debug_struct_format() {
        let auth = AmplitudeAuth {
            api_key: "key".into(),
            secret_key: "sec".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("AmplitudeAuth"));
        assert!(dbg.contains("api_key"));
        assert!(dbg.contains("secret_key"));
    }

    #[test]
    fn encode_query_value_plain_date() {
        assert_eq!(encode_query_value("20260101", "start").unwrap(), "20260101");
    }

    #[test]
    fn encode_query_value_encodes_ampersand() {
        let encoded = encode_query_value("a&b=c", "start").unwrap();
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn encode_query_value_encodes_hash() {
        let encoded = encode_query_value("a#frag", "start").unwrap();
        assert!(!encoded.contains('#'));
        assert!(encoded.contains("%23"));
    }

    #[test]
    fn encode_query_value_encodes_slash() {
        let encoded = encode_query_value("2026/01/01", "start").unwrap();
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_query_value_encodes_percent() {
        let encoded = encode_query_value("100%done", "start").unwrap();
        assert!(encoded.contains("%25"));
    }

    #[test]
    fn encode_query_value_rejects_empty() {
        assert!(encode_query_value("", "start").is_err());
    }

    #[test]
    fn encode_query_value_rejects_whitespace_only() {
        assert!(encode_query_value("   ", "end").is_err());
    }

    #[test]
    fn encode_query_value_allows_dash_underscore_dot_tilde() {
        assert_eq!(
            encode_query_value("2026-01-01_v1.0~rc", "start").unwrap(),
            "2026-01-01_v1.0~rc"
        );
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("chart_abc123", "chart_id").unwrap(),
            "chart_abc123"
        );
    }

    #[test]
    fn sanitize_path_segment_trims_whitespace() {
        assert_eq!(sanitize_path_segment("  abc  ", "f").unwrap(), "abc");
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        assert!(sanitize_path_segment("   ", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        assert!(sanitize_path_segment("../etc/passwd", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        assert!(sanitize_path_segment("foo\\bar", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        assert!(sanitize_path_segment("foo..bar", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        assert!(sanitize_path_segment("foo%2fbar", "chart_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        assert!(sanitize_path_segment("foo%5Cbar", "chart_id").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn post_with_amplitude_insert_ids_retries_after_5xx_with_stable_key() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/httpapi"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/httpapi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 200,
                "events_ingested": 1
            })))
            .mount(&mock_server)
            .await;

        let mut client = AmplitudeClient::new(
            AmplitudeAuth {
                api_key: "k".into(),
                secret_key: "s".into(),
            },
            Some(&mock_server.uri()),
        )
        .unwrap();
        client.retry_config.initial_delay_ms = 1;
        client.retry_config.max_delay_ms = 5;

        let payload = ensure_amplitude_insert_ids(&serde_json::json!({
            "api_key": "k",
            "events": [
                {
                    "user_id": "u-1",
                    "event_type": "Checkout"
                }
            ]
        }));
        let url = format!("{}/httpapi", client.base_url);
        let resp: serde_json::Value = client
            .request_with_retry("POST", &url, Some(&payload))
            .await
            .expect("POST with insert_id on every event should retry 503 and succeed");
        assert_eq!(resp["code"], 200);

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let body_0: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let body_1: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        let id_0 = body_0["events"][0]["insert_id"].as_str().unwrap();
        let id_1 = body_1["events"][0]["insert_id"].as_str().unwrap();
        assert!(!id_0.is_empty());
        assert_eq!(id_0, id_1);
    }

    #[fcp_async_core::runtime::test]
    async fn post_without_insert_id_does_not_retry_after_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/httpapi"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let mut client = AmplitudeClient::new(
            AmplitudeAuth {
                api_key: "k".into(),
                secret_key: "s".into(),
            },
            Some(&mock_server.uri()),
        )
        .unwrap();
        client.retry_config.initial_delay_ms = 1;
        client.retry_config.max_delay_ms = 5;

        let payload = serde_json::json!({
            "api_key": "k",
            "events": [{ "user_id": "u-1", "event_type": "Unkeyed" }]
        });
        let url = format!("{}/httpapi", client.base_url);
        let err = client
            .request_with_retry::<serde_json::Value>("POST", &url, Some(&payload))
            .await
            .expect_err("POST without insert_id must fail closed on 503");
        assert!(matches!(err, AmplitudeError::Api { status_code: 503, .. }));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }
}
