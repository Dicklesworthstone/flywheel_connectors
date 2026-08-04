//! Telnyx Call Control REST client.
//!
//! The connector uses Telnyx API v2 with bearer-token or FCP credential-id
//! authentication. Tests point the same client at deterministic loopback HTTP
//! servers, but production direct-token mode is constrained to api.telnyx.com by
//! connector configuration.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{
    Client, Response, StatusCode,
    header::{self, HeaderValue},
};
use serde::de::DeserializeOwned;

use crate::{
    error::{TelnyxError, TelnyxResult},
    types::{TelnyxApiErrorEnvelope, TelnyxCall, TelnyxCommand, TelnyxEnvelope},
};

/// Default Telnyx API v2 base URL.
pub const DEFAULT_API_BASE: &str = "https://api.telnyx.com/v2";

/// Telnyx authentication mode.
#[derive(Clone)]
pub enum TelnyxAuth {
    /// Direct API key.
    ApiKey { api_key: String },
    /// Secretless credential injection via egress proxy.
    CredentialId { credential_id: CredentialId },
}

impl std::fmt::Debug for TelnyxAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey { .. } => formatter
                .debug_struct("ApiKey")
                .field("api_key", &"[REDACTED]")
                .finish(),
            Self::CredentialId { credential_id } => formatter
                .debug_struct("CredentialId")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl TelnyxAuth {
    /// Human-readable auth label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether the connector holds no raw credential material.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }
}

/// Telnyx REST client.
pub struct TelnyxClient {
    http: Client,
    auth: TelnyxAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    pub(crate) retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for TelnyxClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelnyxClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl TelnyxClient {
    /// Create a Telnyx client with a direct API key.
    pub fn new(api_key: &str) -> TelnyxResult<Self> {
        Self::new_with_auth(TelnyxAuth::ApiKey {
            api_key: api_key.to_string(),
        })
    }

    /// Create a Telnyx client with the supplied auth mode.
    pub fn new_with_auth(auth: TelnyxAuth) -> TelnyxResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        match &auth {
            TelnyxAuth::ApiKey { api_key } => {
                let authorization =
                    HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|error| {
                        TelnyxError::Api {
                            message: format!("Invalid Telnyx authorization header: {error}"),
                            status_code: None,
                            retry_after: None,
                        }
                    })?;
                headers.insert(header::AUTHORIZATION, authorization);
            }
            TelnyxAuth::CredentialId { credential_id } => {
                let credential_id = credential_id.to_string();
                let credential_header =
                    HeaderValue::from_str(&credential_id).map_err(|error| TelnyxError::Api {
                        message: format!("Invalid Telnyx credential id header: {error}"),
                        status_code: None,
                        retry_after: None,
                    })?;
                headers.insert("X-FCP-Credential-ID", credential_header);
            }
        }

        let request_timeout = Duration::from_secs(30);
        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-telnyx/0.1.0")
            .timeout(request_timeout)
            .build()
            .map_err(TelnyxError::Http)?;

        Ok(Self {
            http,
            auth,
            base_url: DEFAULT_API_BASE.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Override API base URL for loopback tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim_end_matches('/').to_string();
        self
    }

    /// Set maximum retries for deterministic tests.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self.retry_config.initial_delay_ms = 1;
        self.retry_config.max_delay_ms = 1;
        self.retry_config.jitter_enabled = false;
        self
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Configured base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Auth mode label with secrets redacted.
    #[must_use]
    pub fn auth_mode(&self) -> &'static str {
        self.auth.redacted_label()
    }

    /// Initiate an outbound call.
    pub async fn initiate_call(
        &self,
        request: &InitiateCallRequest<'_>,
    ) -> TelnyxResult<TelnyxCall> {
        let path = "/calls";
        let payload = build_initiate_call_payload(request);
        self.post_data(path, &payload).await
    }

    /// Answer/continue a call.
    pub async fn continue_call(&self, call_control_id: &str) -> TelnyxResult<TelnyxCommand> {
        let call_control_id = sanitize_call_control_id(call_control_id, "call_control_id")?;
        self.post_data(
            &format!("/calls/{call_control_id}/actions/answer"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Speak text into a call.
    pub async fn speak_call(&self, request: &SpeakCallRequest<'_>) -> TelnyxResult<TelnyxCommand> {
        let call_control_id = sanitize_call_control_id(request.call_control_id, "call_control_id")?;
        self.post_data(
            &format!("/calls/{call_control_id}/actions/speak"),
            &build_speak_call_payload(request),
        )
        .await
    }

    /// End a call.
    pub async fn end_call(&self, call_control_id: &str) -> TelnyxResult<TelnyxCommand> {
        let call_control_id = sanitize_call_control_id(call_control_id, "call_control_id")?;
        self.post_data(
            &format!("/calls/{call_control_id}/actions/hangup"),
            &serde_json::json!({}),
        )
        .await
    }

    /// Fetch call status/details.
    pub async fn status_call(&self, call_control_id: &str) -> TelnyxResult<TelnyxCall> {
        let call_control_id = sanitize_call_control_id(call_control_id, "call_control_id")?;
        self.get_data(&format!("/calls/{call_control_id}")).await
    }

    /// Transfer a call.
    pub async fn transfer_call(
        &self,
        request: &TransferCallRequest<'_>,
    ) -> TelnyxResult<TelnyxCommand> {
        let call_control_id = sanitize_call_control_id(request.call_control_id, "call_control_id")?;
        self.post_data(
            &format!("/calls/{call_control_id}/actions/transfer"),
            &build_transfer_call_payload(request),
        )
        .await
    }

    /// Gather DTMF digits using spoken prompt text.
    pub async fn gather_using_speak(
        &self,
        request: &GatherUsingSpeakRequest<'_>,
    ) -> TelnyxResult<TelnyxCommand> {
        let call_control_id = sanitize_call_control_id(request.call_control_id, "call_control_id")?;
        self.post_data(
            &format!("/calls/{call_control_id}/actions/gather_using_speak"),
            &build_gather_using_speak_payload(request),
        )
        .await
    }

    async fn get_data<T: DeserializeOwned>(&self, path: &str) -> TelnyxResult<T> {
        let data = self
            // GET is idempotent.
            .execute(true, || self.http.get(format!("{}{}", self.base_url, path)))
            .await?;
        unwrap_data(data)
    }

    async fn post_data<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> TelnyxResult<T> {
        let url = format!("{}{}", self.base_url, path);
        // NOT replay-safe: these POSTs send messages and place calls, and
        // Telnyx offers no idempotency key for them.
        let data = self
            .execute(false, || self.http.post(&url).json(body))
            .await?;
        unwrap_data(data)
    }

    /// Run a request under the retry policy.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a side
    /// effect. Telnyx has no idempotency-key mechanism on the Messages or Calls
    /// APIs, so a replayed `POST /messages` sends and bills a second SMS. Only
    /// a pre-transmission failure may be retried for those.
    ///
    /// A 429 stays retryable regardless — Telnyx rejects a rate-limited request
    /// without performing it. See br-kxd3e.
    async fn execute(
        &self,
        replay_safe: bool,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> TelnyxResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| async {
            match build_request().send().await {
                Ok(response) => Self::response_outcome(response, replay_safe).await,
                // Only a connect-phase failure proves the request never left
                // the client; `is_timeout()` covers the TOTAL request timeout,
                // which fires after the body was fully sent.
                Err(error) => {
                    let replayable = replay_safe || !transport_error_reached_service(&error);
                    AttemptOutcome::retryable_if_replayable(
                        TelnyxError::Http(error),
                        None,
                        replayable,
                    )
                }
            }
        })
        .await
    }

    async fn response_outcome(
        response: Response,
        replay_safe: bool,
    ) -> AttemptOutcome<serde_json::Value, TelnyxError> {
        let status = response.status();
        let retry_after = retry_after_header(&response);

        if status == StatusCode::TOO_MANY_REQUESTS {
            return AttemptOutcome::Retryable {
                error: TelnyxError::RateLimited {
                    retry_after_ms: retry_after.map_or(60_000, duration_millis_saturating),
                },
                retry_after,
            };
        }
        if status.is_server_error()
            || matches!(status, StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY)
        {
            let body = response.text().await.unwrap_or_default();
            // All of these mean Telnyx RECEIVED the request. A 5xx can be
            // returned after the message was already queued, and a 408 can
            // follow a request the server read in full.
            return AttemptOutcome::retryable_if_replayable(
                TelnyxError::Api {
                    message: format!("HTTP {status}: {body}"),
                    status_code: Some(status.as_u16()),
                    retry_after,
                },
                retry_after,
                replay_safe,
            );
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return AttemptOutcome::Terminal(TelnyxError::Unauthorized);
        }
        if status == StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            return AttemptOutcome::Terminal(TelnyxError::NotFound { resource: body });
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let message = telnyx_error_message(status, &body);
            return AttemptOutcome::Terminal(TelnyxError::Api {
                message,
                status_code: Some(status.as_u16()),
                retry_after,
            });
        }

        match response.text().await {
            Ok(body) => match serde_json::from_str(&body) {
                Ok(data) => AttemptOutcome::Success(data),
                Err(error) => AttemptOutcome::Terminal(TelnyxError::Json(error)),
            },
            Err(error) => AttemptOutcome::Terminal(TelnyxError::Http(error)),
        }
    }
}

fn unwrap_data<T: DeserializeOwned>(value: serde_json::Value) -> TelnyxResult<T> {
    let envelope: TelnyxEnvelope<T> = serde_json::from_value(value)?;
    Ok(envelope.data)
}

/// Validate a Telnyx `call_control_id` before interpolating it into a request
/// path.
///
/// The identifier is a URL-safe base64 token (`[A-Za-z0-9_=-]` plus `:`), so
/// this rejects only the characters that would let a caller-supplied value
/// escape its segment: `/`, `\`, `..`, encoded slashes, and `?`/`#`. Without it,
/// a `call_control_id` of `REALID/actions/hangup#` turns an `answer` request
/// into a `hangup`, and a raw `/` reaches sibling `/v2/...` resources.
fn sanitize_call_control_id<'a>(value: &'a str, field: &str) -> TelnyxResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TelnyxError::InvalidInput(format!(
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
        return Err(TelnyxError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

fn retry_after_header(response: &Response) -> Option<Duration> {
    response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn telnyx_error_message(status: StatusCode, body: &str) -> String {
    serde_json::from_str::<TelnyxApiErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| {
            envelope.errors.first().map(|error| {
                error
                    .detail
                    .clone()
                    .or_else(|| error.title.clone())
                    .unwrap_or_else(|| format!("HTTP {status}"))
            })
        })
        .unwrap_or_else(|| format!("HTTP {status}: {body}"))
}

/// Request data for Telnyx outbound call creation.
#[derive(Debug, Clone, Copy)]
pub struct InitiateCallRequest<'a> {
    pub to: &'a str,
    pub from: &'a str,
    pub connection_id: &'a str,
    pub webhook_url: Option<&'a str>,
    pub client_state: Option<&'a str>,
    pub timeout_secs: Option<u32>,
    pub stream_url: Option<&'a str>,
    pub stream_auth_token: Option<&'a str>,
}

/// Build Telnyx outbound-call request JSON.
#[must_use]
pub fn build_initiate_call_payload(request: &InitiateCallRequest<'_>) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "to": request.to,
        "from": request.from,
        "connection_id": request.connection_id,
    });
    insert_optional(&mut payload, "webhook_url", request.webhook_url);
    insert_optional(&mut payload, "client_state", request.client_state);
    insert_optional_u32(&mut payload, "timeout_secs", request.timeout_secs);
    insert_optional(&mut payload, "stream_url", request.stream_url);
    insert_optional(&mut payload, "stream_auth_token", request.stream_auth_token);
    payload
}

/// Request data for Telnyx speak command.
#[derive(Debug, Clone, Copy)]
pub struct SpeakCallRequest<'a> {
    pub call_control_id: &'a str,
    pub payload: &'a str,
    pub voice: Option<&'a str>,
    pub language: Option<&'a str>,
    pub client_state: Option<&'a str>,
    pub command_id: Option<&'a str>,
}

/// Build Telnyx speak command JSON.
#[must_use]
pub fn build_speak_call_payload(request: &SpeakCallRequest<'_>) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "payload": request.payload,
        "payload_type": "text",
    });
    insert_optional(&mut payload, "voice", request.voice);
    insert_optional(&mut payload, "language", request.language);
    insert_optional(&mut payload, "client_state", request.client_state);
    insert_optional(&mut payload, "command_id", request.command_id);
    payload
}

/// Request data for Telnyx transfer command.
#[derive(Debug, Clone, Copy)]
pub struct TransferCallRequest<'a> {
    pub call_control_id: &'a str,
    pub to: &'a str,
    pub from: Option<&'a str>,
    pub timeout_secs: Option<u32>,
    pub client_state: Option<&'a str>,
}

/// Build Telnyx transfer command JSON.
#[must_use]
pub fn build_transfer_call_payload(request: &TransferCallRequest<'_>) -> serde_json::Value {
    let mut payload = serde_json::json!({ "to": request.to });
    insert_optional(&mut payload, "from", request.from);
    insert_optional_u32(&mut payload, "timeout_secs", request.timeout_secs);
    insert_optional(&mut payload, "client_state", request.client_state);
    payload
}

/// Request data for Telnyx gather-using-speak command.
#[derive(Debug, Clone, Copy)]
pub struct GatherUsingSpeakRequest<'a> {
    pub call_control_id: &'a str,
    pub payload: &'a str,
    pub voice: Option<&'a str>,
    pub language: Option<&'a str>,
    pub minimum_digits: Option<u32>,
    pub maximum_digits: Option<u32>,
    pub timeout_millis: Option<u32>,
    pub terminator: Option<&'a str>,
    pub client_state: Option<&'a str>,
}

/// Build Telnyx gather command JSON.
#[must_use]
pub fn build_gather_using_speak_payload(
    request: &GatherUsingSpeakRequest<'_>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "payload": request.payload,
        "payload_type": "text",
    });
    insert_optional(&mut payload, "voice", request.voice);
    insert_optional(&mut payload, "language", request.language);
    insert_optional_u32(&mut payload, "minimum_digits", request.minimum_digits);
    insert_optional_u32(&mut payload, "maximum_digits", request.maximum_digits);
    insert_optional_u32(&mut payload, "timeout_millis", request.timeout_millis);
    insert_optional(&mut payload, "terminator", request.terminator);
    insert_optional(&mut payload, "client_state", request.client_state);
    payload
}

/// Encode FCP callback/session binding data into Telnyx `client_state`.
pub fn encode_client_state(call_auth_token: &str) -> TelnyxResult<String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "fcp_call_auth_token": call_auth_token,
    }))?;
    Ok(STANDARD.encode(body))
}

/// Decode FCP callback/session binding data from Telnyx `client_state`.
pub fn decode_client_state_token(client_state: &str) -> TelnyxResult<String> {
    let bytes = STANDARD
        .decode(client_state)
        .map_err(|error| TelnyxError::Api {
            message: format!("client_state must be base64 encoded JSON: {error}"),
            status_code: None,
            retry_after: None,
        })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value
        .get("fcp_call_auth_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| TelnyxError::Api {
            message: "client_state missing fcp_call_auth_token".into(),
            status_code: None,
            retry_after: None,
        })
}

fn insert_optional(payload: &mut serde_json::Value, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        payload[key] = serde_json::Value::String(value.to_string());
    }
}

fn insert_optional_u32(payload: &mut serde_json::Value, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        payload[key] = serde_json::Value::Number(value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_create_payload_preserves_webhook_session_and_media_fields() {
        let payload = build_initiate_call_payload(&InitiateCallRequest {
            to: "+15551230000",
            from: "+15559870000",
            connection_id: "conn-123",
            webhook_url: Some("https://voice.example.com/telnyx"),
            client_state: Some("encoded-state"),
            timeout_secs: Some(20),
            stream_url: Some("wss://voice.example.com/media"),
            stream_auth_token: Some("AAAAAAAAAAAAAAAAAAAAAA"),
        });
        assert_eq!(payload["to"], "+15551230000");
        assert_eq!(payload["connection_id"], "conn-123");
        assert_eq!(payload["client_state"], "encoded-state");
        assert_eq!(payload["stream_auth_token"], "AAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn command_builders_cover_speak_transfer_and_gather() {
        let speak = build_speak_call_payload(&SpeakCallRequest {
            call_control_id: "call-1",
            payload: "hello",
            voice: Some("female"),
            language: Some("en-US"),
            client_state: Some("state"),
            command_id: Some("cmd-1"),
        });
        assert_eq!(speak["payload_type"], "text");
        assert_eq!(speak["voice"], "female");

        let transfer = build_transfer_call_payload(&TransferCallRequest {
            call_control_id: "call-1",
            to: "+15550000001",
            from: Some("+15550000002"),
            timeout_secs: Some(30),
            client_state: Some("state"),
        });
        assert_eq!(transfer["to"], "+15550000001");
        assert_eq!(transfer["timeout_secs"], 30);

        let gather = build_gather_using_speak_payload(&GatherUsingSpeakRequest {
            call_control_id: "call-1",
            payload: "press 1",
            voice: None,
            language: Some("en-US"),
            minimum_digits: Some(1),
            maximum_digits: Some(4),
            timeout_millis: Some(5_000),
            terminator: Some("#"),
            client_state: Some("state"),
        });
        assert_eq!(gather["maximum_digits"], 4);
        assert_eq!(gather["terminator"], "#");
    }

    #[test]
    fn client_state_roundtrips_without_exposing_plain_token_shape() {
        let encoded = encode_client_state("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_ne!(encoded, "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            decode_client_state_token(&encoded).unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAA"
        );
    }
}
