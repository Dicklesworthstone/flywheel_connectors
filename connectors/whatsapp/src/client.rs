//! WhatsApp Business API client.

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::{Client, RequestBuilder, Url};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{WhatsAppError, WhatsAppResult};
use crate::types::{ApiErrorResponse, ProfileResponse, SendMessageResponse};

/// Validate a URL path segment to prevent path-traversal attacks.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> WhatsAppResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(WhatsAppError::InvalidInput(format!(
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
        return Err(WhatsAppError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(trimmed)
}

/// WhatsApp API client with retry and runtime integration.
pub struct WhatsAppClient {
    client: Client,
    base_url: String,
    phone_number_id: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for WhatsAppClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsAppClient")
            .field("base_url", &self.base_url)
            .field("phone_number_id", &self.phone_number_id)
            .field("access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl WhatsAppClient {
    /// Create a new WhatsApp client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        phone_number_id: &str,
        access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> WhatsAppResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(WhatsAppError::Http)?;

        Ok(Self {
            client,
            base_url: normalize_base_url(base_url)?,
            phone_number_id: phone_number_id.to_string(),
            access_token: access_token.to_string(),
            retry_config,
        })
    }

    /// Send a text message.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_text_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        text: &str,
        preview_url: bool,
    ) -> WhatsAppResult<SendMessageResponse> {
        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": {
                "body": text,
                "preview_url": preview_url,
            }
        });

        self.send_message(runtime, &body).await
    }

    /// Send a template message.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_template_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        template_name: &str,
        language_code: &str,
        components: &[serde_json::Value],
    ) -> WhatsAppResult<SendMessageResponse> {
        let mut body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "template",
            "template": {
                "name": template_name,
                "language": { "code": language_code }
            }
        });

        if !components.is_empty() {
            body["template"]["components"] = serde_json::Value::Array(components.to_vec());
        }

        self.send_message(runtime, &body).await
    }

    /// Send an arbitrary message payload with retry.
    ///
    /// br-kxd3e: every caller of this helper DELIVERS a message, and the
    /// WhatsApp Cloud API has no idempotency key, so a replay that reached
    /// Meta sends the message a second time. Only a connect-phase failure —
    /// the one class that proves no request bytes were written — is retried
    /// here. A 429 is refused WITHOUT the message being sent and stays
    /// retryable; it is handled before the gate below.
    async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        body: &serde_json::Value,
    ) -> WhatsAppResult<SendMessageResponse> {
        let safe_id = sanitize_path_segment(&self.phone_number_id, "phone_number_id")?;
        let url = format!("{}/{safe_id}/messages", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Sending WhatsApp message");
                let request = authenticate(client.post(&url), &token).json(&body);
                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let replayable = !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            WhatsAppError::Http(e),
                            None,
                            replayable,
                        );
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: WhatsAppError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(WhatsAppError::Unauthorized(
                        "Invalid access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    // Every remaining retryable class here is a 5xx, which
                    // means Meta RECEIVED the send and may already have
                    // delivered it.
                    if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
                        return AttemptOutcome::Terminal(WhatsAppError::Api {
                            code: api_err.error.code,
                            message: api_err.error.message,
                            error_type: api_err.error.error_type,
                            subcode: api_err.error.error_subcode,
                        });
                    }
                    return AttemptOutcome::Terminal(WhatsAppError::Api {
                        code: u32::from(status),
                        message: text,
                        error_type: "HttpError".into(),
                        subcode: None,
                    });
                }

                match resp.json::<SendMessageResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(WhatsAppError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get business profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_profile(&self, runtime: &ConnectorRuntime) -> WhatsAppResult<ProfileResponse> {
        let safe_id = sanitize_path_segment(&self.phone_number_id, "phone_number_id")?;
        let url = format!("{}/{safe_id}/whatsapp_business_profile", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, "Fetching WhatsApp business profile");
                let request = authenticate(client.get(&url), &token)
                    .query(&[("fields", "about,address,description,vertical")]);
                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: WhatsAppError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    if status == 429 {
                        let retry_after = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map(Duration::from_secs);
                        return AttemptOutcome::Retryable {
                            error: WhatsAppError::RateLimited {
                                retry_after_ms: retry_after
                                    .unwrap_or(Duration::from_secs(30))
                                    .as_millis()
                                    as u64,
                            },
                            retry_after,
                        };
                    }
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "WhatsApp profile request failed");
                    let decision = classify_http_status(status, None);
                    let err = WhatsAppError::Api {
                        code: u32::from(status),
                        message: text,
                        error_type: "HttpError".into(),
                        subcode: None,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<ProfileResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(WhatsAppError::Http(e)),
                }
            }
        })
        .await
    }

    /// Health check: validate API reachability with a lightweight GET.
    ///
    /// # Errors
    ///
    /// Returns an error if the API is unreachable.
    pub async fn health_check(&self) -> WhatsAppResult<()> {
        let safe_id = sanitize_path_segment(&self.phone_number_id, "phone_number_id")?;
        let url = format!("{}/{safe_id}", self.base_url);
        let resp = authenticate(self.client.get(&url), &self.access_token)
            .send()
            .await
            .map_err(WhatsAppError::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() || status == 400 {
            // 400 is acceptable for health check (means API is reachable)
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(WhatsAppError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(WhatsAppError::Unauthorized("Invalid access token".into()))
        } else {
            Err(WhatsAppError::Api {
                code: u32::from(status),
                message: format!("Health check failed with HTTP {status}"),
                error_type: "HealthCheckError".into(),
                subcode: None,
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode (credential injection).
    pub fn is_secretless(&self) -> bool {
        self.access_token.is_empty()
    }
}

fn normalize_base_url(base_url: &str) -> WhatsAppResult<String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(WhatsAppError::Config("base_url must not be empty".into()));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|error| WhatsAppError::Config(format!("invalid base_url: {error}")))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        // Previously only `http` was rejected, so a nonsense scheme like
        // `ftp://graph.facebook.com/` slipped past the allowlist check
        // and was only caught later by reqwest at request time. Fail
        // fast at config time.
        return Err(WhatsAppError::Config(
            "base_url must use http or https".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| WhatsAppError::Config("base_url must include a host".into()))?;
    let is_local_test_host = host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host == "127.0.0.1"
        || host == "::1";
    if parsed.scheme() == "http" && !is_local_test_host {
        return Err(WhatsAppError::Config(
            "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests".into(),
        ));
    }
    if !host.eq_ignore_ascii_case("graph.facebook.com") && !is_local_test_host {
        return Err(WhatsAppError::Config(
            "base_url host must be graph.facebook.com or a local test host".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        // WhatsAppClient builds every request URL via
        //   format!("{}/{safe_id}/messages", self.base_url)
        // (see send_message / update_profile / get_* above). Userinfo
        // embedded in base_url would survive `trim_end_matches('/')`
        // below and get baked into every downstream URL, silently
        // overriding the access_token the connector will try to send
        // via the Authorization header. Reject at config time.
        return Err(WhatsAppError::Config(
            "base_url must not include userinfo".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(WhatsAppError::Config(
            "base_url must not include a query string or fragment".into(),
        ));
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn authenticate(request: RequestBuilder, access_token: &str) -> RequestBuilder {
    if access_token.is_empty() {
        request
    } else {
        request.bearer_auth(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_base_url_accepts_graph_facebook_com() {
        let out = normalize_base_url("https://graph.facebook.com/v21.0").unwrap();
        assert_eq!(out, "https://graph.facebook.com/v21.0");
    }

    #[test]
    fn normalize_base_url_rejects_userinfo() {
        let err = normalize_base_url("https://attacker:pw@graph.facebook.com/v21.0").unwrap_err();
        match err {
            WhatsAppError::Config(msg) => assert!(msg.contains("userinfo"), "got: {msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn normalize_base_url_rejects_unknown_scheme() {
        // Previously only http was rejected; ftp://graph.facebook.com/...
        // slipped past and was only caught later by reqwest.
        let err = normalize_base_url("ftp://graph.facebook.com/v21.0").unwrap_err();
        match err {
            WhatsAppError::Config(msg) => assert!(msg.contains("http or https"), "got: {msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn normalize_base_url_rejects_query_and_fragment() {
        assert!(matches!(
            normalize_base_url("https://graph.facebook.com/v21.0?leak=x").unwrap_err(),
            WhatsAppError::Config(_)
        ));
        assert!(matches!(
            normalize_base_url("https://graph.facebook.com/v21.0#frag").unwrap_err(),
            WhatsAppError::Config(_)
        ));
    }

    #[test]
    fn normalize_base_url_still_pins_host() {
        assert!(matches!(
            normalize_base_url("https://evil.example.com/v21.0").unwrap_err(),
            WhatsAppError::Config(_)
        ));
    }

    #[test]
    fn client_creation() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0/",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn client_creation_rejects_non_meta_remote_host() {
        let err = WhatsAppClient::new(
            "https://evil.example.com/v21.0",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("graph.facebook.com"));
    }

    #[test]
    fn client_creation_rejects_remote_http_host() {
        let err = WhatsAppClient::new(
            "http://graph.facebook.com/v21.0",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("must use https"));
    }

    #[test]
    fn secretless_detection() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_access_token() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "super_secret_token_value",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_token_value"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for access_token"
        );
    }

    #[test]
    fn non_secretless() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    // ── sanitize_path_segment tests ─────────────────────────────────

    #[test]
    fn sanitize_path_segment_valid() {
        assert_eq!(
            sanitize_path_segment("123456", "phone_number_id").unwrap(),
            "123456"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        let err = sanitize_path_segment("", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        let err = sanitize_path_segment("   ", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        let err = sanitize_path_segment("123/456", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        let err = sanitize_path_segment("123\\456", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        let err = sanitize_path_segment("123..456", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        let err = sanitize_path_segment("123%2f456", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash() {
        let err = sanitize_path_segment("123%5Cdef", "phone_number_id").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_rejects_traversal_phone_number_id() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "../admin",
            "tok",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, WhatsAppError::InvalidInput(_)));
    }
}
