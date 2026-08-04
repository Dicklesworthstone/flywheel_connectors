//! Plivo Voice REST client.
//!
//! Plivo uses Basic auth (`auth_id:auth_secret`) against
//! `https://api.plivo.com/v1/Account/{auth_id}`. Tests point the same client at
//! deterministic loopback HTTP servers, while production direct-secret mode is
//! constrained by connector configuration to `api.plivo.com`.
#![allow(
    clippy::future_not_send,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc
)]

use std::{collections::BTreeMap, fmt::Write as _, time::Duration};

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
use url::{Url, form_urlencoded};

use crate::{
    error::{PlivoError, PlivoResult},
    types::{PlivoApiErrorEnvelope, PlivoCall, PlivoCommand},
};

/// Default Plivo API base URL prefix.
pub const DEFAULT_API_BASE_PREFIX: &str = "https://api.plivo.com/v1/Account";

/// Plivo authentication mode.
#[derive(Clone)]
pub enum PlivoAuth {
    /// Direct Basic auth.
    Direct {
        auth_id: String,
        auth_secret: String,
    },
    /// Secretless credential injection via egress proxy.
    CredentialId {
        auth_id: String,
        credential_id: CredentialId,
    },
}

impl std::fmt::Debug for PlivoAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { auth_id, .. } => formatter
                .debug_struct("Direct")
                .field("auth_id", auth_id)
                .field("auth_secret", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                auth_id,
                credential_id,
            } => formatter
                .debug_struct("CredentialId")
                .field("auth_id", auth_id)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl PlivoAuth {
    /// Human-readable auth label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "auth_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether the connector holds no raw API credential material.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Account auth id.
    #[must_use]
    pub fn auth_id(&self) -> &str {
        match self {
            Self::Direct { auth_id, .. } | Self::CredentialId { auth_id, .. } => auth_id,
        }
    }
}

/// Plivo REST client.
pub struct PlivoClient {
    http: Client,
    auth: PlivoAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    pub(crate) retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for PlivoClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlivoClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl PlivoClient {
    /// Create a Plivo client with direct credentials.
    pub fn new(auth_id: &str, auth_secret: &str) -> PlivoResult<Self> {
        Self::new_with_auth(PlivoAuth::Direct {
            auth_id: auth_id.to_string(),
            auth_secret: auth_secret.to_string(),
        })
    }

    /// Create a Plivo client with the supplied auth mode.
    pub fn new_with_auth(auth: PlivoAuth) -> PlivoResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        match &auth {
            PlivoAuth::Direct {
                auth_id,
                auth_secret,
            } => {
                let credentials = STANDARD.encode(format!("{auth_id}:{auth_secret}"));
                let authorization = HeaderValue::from_str(&format!("Basic {credentials}"))
                    .map_err(|error| PlivoError::Api {
                        message: format!("Invalid Plivo authorization header: {error}"),
                        status_code: None,
                        retry_after: None,
                    })?;
                headers.insert(header::AUTHORIZATION, authorization);
            }
            PlivoAuth::CredentialId { credential_id, .. } => {
                let credential_id = credential_id.to_string();
                let credential_header =
                    HeaderValue::from_str(&credential_id).map_err(|error| PlivoError::Api {
                        message: format!("Invalid Plivo credential id header: {error}"),
                        status_code: None,
                        retry_after: None,
                    })?;
                headers.insert("X-FCP-Credential-ID", credential_header);
            }
        }

        let request_timeout = Duration::from_secs(30);
        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-plivo/0.1.0")
            .timeout(request_timeout)
            .build()
            .map_err(PlivoError::Http)?;

        Ok(Self {
            http,
            base_url: format!("{DEFAULT_API_BASE_PREFIX}/{}", auth.auth_id()),
            auth,
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
    pub async fn initiate_call(&self, request: &InitiateCallRequest<'_>) -> PlivoResult<PlivoCall> {
        let payload = build_initiate_call_payload(request);
        self.post_form("/Call/", &payload).await
    }

    /// Continue a call by transferring one or both legs to a new XML URL.
    pub async fn continue_call(
        &self,
        request: &ContinueCallRequest<'_>,
    ) -> PlivoResult<PlivoCommand> {
        let call_uuid = sanitize_call_uuid(request.call_uuid, "call_uuid")?;
        let payload = build_continue_call_payload(request);
        self.post_form(&format!("/Call/{call_uuid}/"), &payload)
            .await
    }

    /// Speak text during an active call.
    pub async fn speak_call(&self, request: &SpeakCallRequest<'_>) -> PlivoResult<PlivoCommand> {
        let call_uuid = sanitize_call_uuid(request.call_uuid, "call_uuid")?;
        let payload = build_speak_call_payload(request);
        self.post_form(&format!("/Call/{call_uuid}/Speak/"), &payload)
            .await
    }

    /// End a call.
    pub async fn end_call(&self, call_uuid: &str) -> PlivoResult<PlivoCommand> {
        let call_uuid = sanitize_call_uuid(call_uuid, "call_uuid")?;
        self.delete(&format!("/Call/{call_uuid}/")).await
    }

    /// Fetch call status/details.
    pub async fn status_call(&self, call_uuid: &str) -> PlivoResult<PlivoCall> {
        let call_uuid = sanitize_call_uuid(call_uuid, "call_uuid")?;
        self.get(&format!("/Call/{call_uuid}/")).await
    }

    /// Transfer a call.
    pub async fn transfer_call(
        &self,
        request: &TransferCallRequest<'_>,
    ) -> PlivoResult<PlivoCommand> {
        let call_uuid = sanitize_call_uuid(request.call_uuid, "call_uuid")?;
        let payload = build_transfer_call_payload(request);
        self.post_form(&format!("/Call/{call_uuid}/"), &payload)
            .await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> PlivoResult<T> {
        // GET is idempotent.
        self.execute_json(true, || self.http.get(format!("{}{}", self.base_url, path)))
            .await
    }

    async fn delete(&self, path: &str) -> PlivoResult<PlivoCommand> {
        // DELETE is idempotent per HTTP semantics.
        self.execute_json(true, || {
            self.http.delete(format!("{}{}", self.base_url, path))
        })
        .await
    }

    async fn post_form<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &BTreeMap<String, String>,
    ) -> PlivoResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let encoded = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                body.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .finish();
        // NOT replay-safe: these POSTs send messages and place calls, and
        // Plivo offers no idempotency key for them.
        self.execute_json(false, || {
            self.http
                .post(&url)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(encoded.clone())
        })
        .await
    }

    /// Run a request under the retry policy.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a side
    /// effect. Plivo has no idempotency-key mechanism on the Message or Call
    /// APIs, so a replayed `POST /Message/` sends and bills a second SMS. Only
    /// a pre-transmission failure may be retried for those.
    ///
    /// A 429 stays retryable regardless — Plivo rejects a rate-limited request
    /// without performing it. See br-kxd3e.
    async fn execute_json<T: DeserializeOwned>(
        &self,
        replay_safe: bool,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> PlivoResult<T> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let data = RetryLoop::execute(&ctx, &policy, |_attempt| async {
            match build_request().send().await {
                Ok(response) => Self::response_outcome(response, replay_safe).await,
                // Only a connect-phase failure proves the request never left
                // the client; `is_timeout()` covers the TOTAL request timeout,
                // which fires after the body was fully sent.
                Err(error) => {
                    let replayable = replay_safe || !transport_error_reached_service(&error);
                    AttemptOutcome::retryable_if_replayable(
                        PlivoError::Http(error),
                        None,
                        replayable,
                    )
                }
            }
        })
        .await?;
        serde_json::from_value(data).map_err(PlivoError::Json)
    }

    async fn response_outcome(
        response: Response,
        replay_safe: bool,
    ) -> AttemptOutcome<serde_json::Value, PlivoError> {
        let status = response.status();
        let retry_after = retry_after_header(&response);

        if status == StatusCode::TOO_MANY_REQUESTS {
            return AttemptOutcome::Retryable {
                error: PlivoError::RateLimited {
                    retry_after_ms: retry_after.map_or(60_000, duration_millis_saturating),
                },
                retry_after,
            };
        }
        if status.is_server_error()
            || matches!(status, StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY)
        {
            let body = response.text().await.unwrap_or_default();
            // All of these mean Plivo RECEIVED the request. A 5xx can be
            // returned after the message was already queued, and a 408 can
            // follow a request the server read in full.
            return AttemptOutcome::retryable_if_replayable(
                PlivoError::Api {
                    message: format!("HTTP {status}: {body}"),
                    status_code: Some(status.as_u16()),
                    retry_after,
                },
                retry_after,
                replay_safe,
            );
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return AttemptOutcome::Terminal(PlivoError::Unauthorized);
        }
        if status == StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            return AttemptOutcome::Terminal(PlivoError::NotFound { resource: body });
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return AttemptOutcome::Terminal(PlivoError::Api {
                message: plivo_error_message(status, &body),
                status_code: Some(status.as_u16()),
                retry_after,
            });
        }

        let status_code = status.as_u16();
        match response.text().await {
            Ok(body) if body.trim().is_empty() => AttemptOutcome::Success(serde_json::json!({
                "message": "no content",
                "status_code": status_code
            })),
            Ok(body) => match serde_json::from_str(&body) {
                Ok(data) => AttemptOutcome::Success(data),
                Err(error) => AttemptOutcome::Terminal(PlivoError::Json(error)),
            },
            Err(error) => AttemptOutcome::Terminal(PlivoError::Http(error)),
        }
    }
}

fn retry_after_header(response: &Response) -> Option<Duration> {
    response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Validate a Plivo `call_uuid` before interpolating it into a request path.
///
/// The value is a UUID (`[0-9a-fA-F-]`), so this rejects only the characters
/// that would let a caller-supplied value escape its segment: `/`, `\`, `..`,
/// encoded slashes, and `?`/`#`. Without it, a `call_uuid` with an embedded
/// `/` or `..` pivots `end_call`/`status_call` to sibling endpoints under the
/// account (e.g. `DELETE /Call/../Endpoint/...`), or a `?` injects query params.
fn sanitize_call_uuid<'a>(value: &'a str, field: &str) -> PlivoResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlivoError::InvalidInput(format!(
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
        return Err(PlivoError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn plivo_error_message(status: StatusCode, body: &str) -> String {
    serde_json::from_str::<PlivoApiErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| envelope.error.or(envelope.message))
        .unwrap_or_else(|| format!("HTTP {status}: {body}"))
}

/// Request data for Plivo outbound call creation.
#[derive(Debug, Clone, Copy)]
pub struct InitiateCallRequest<'a> {
    pub to: &'a str,
    pub from: &'a str,
    pub answer_url: &'a str,
    pub answer_method: Option<&'a str>,
    pub hangup_url: Option<&'a str>,
    pub hangup_method: Option<&'a str>,
    pub ring_url: Option<&'a str>,
    pub ring_method: Option<&'a str>,
    pub fallback_url: Option<&'a str>,
    pub time_limit: Option<u32>,
}

/// Build Plivo outbound-call form data.
#[must_use]
pub fn build_initiate_call_payload(request: &InitiateCallRequest<'_>) -> BTreeMap<String, String> {
    let mut payload = BTreeMap::from([
        ("to".into(), request.to.into()),
        ("from".into(), request.from.into()),
        ("answer_url".into(), request.answer_url.into()),
    ]);
    insert_optional(&mut payload, "answer_method", request.answer_method);
    insert_optional(&mut payload, "hangup_url", request.hangup_url);
    insert_optional(&mut payload, "hangup_method", request.hangup_method);
    insert_optional(&mut payload, "ring_url", request.ring_url);
    insert_optional(&mut payload, "ring_method", request.ring_method);
    insert_optional(&mut payload, "fallback_url", request.fallback_url);
    insert_optional_u32(&mut payload, "time_limit", request.time_limit);
    payload
}

/// Request data for Plivo continue command.
#[derive(Debug, Clone, Copy)]
pub struct ContinueCallRequest<'a> {
    pub call_uuid: &'a str,
    pub xml_url: &'a str,
    pub legs: Option<&'a str>,
}

/// Build Plivo continue form data.
#[must_use]
pub fn build_continue_call_payload(request: &ContinueCallRequest<'_>) -> BTreeMap<String, String> {
    let legs = request.legs.unwrap_or("both");
    let mut payload = BTreeMap::from([("legs".into(), legs.into())]);
    match legs {
        "aleg" => {
            payload.insert("aleg_url".into(), request.xml_url.into());
            payload.insert("aleg_method".into(), "POST".into());
        }
        "bleg" => {
            payload.insert("bleg_url".into(), request.xml_url.into());
            payload.insert("bleg_method".into(), "POST".into());
        }
        _ => {
            payload.insert("aleg_url".into(), request.xml_url.into());
            payload.insert("aleg_method".into(), "POST".into());
            payload.insert("bleg_url".into(), request.xml_url.into());
            payload.insert("bleg_method".into(), "POST".into());
        }
    }
    payload
}

/// Request data for Plivo speak command.
#[derive(Debug, Clone, Copy)]
pub struct SpeakCallRequest<'a> {
    pub call_uuid: &'a str,
    pub text: &'a str,
    pub voice: Option<&'a str>,
    pub language: Option<&'a str>,
    pub legs: Option<&'a str>,
    pub loop_forever: Option<bool>,
    pub mix: Option<bool>,
}

/// Build Plivo speak command form data.
#[must_use]
pub fn build_speak_call_payload(request: &SpeakCallRequest<'_>) -> BTreeMap<String, String> {
    let mut payload = BTreeMap::from([("text".into(), request.text.into())]);
    insert_optional(&mut payload, "voice", request.voice);
    insert_optional(&mut payload, "language", request.language);
    insert_optional(&mut payload, "legs", request.legs);
    insert_optional_bool(&mut payload, "loop", request.loop_forever);
    insert_optional_bool(&mut payload, "mix", request.mix);
    payload
}

/// Request data for Plivo transfer command.
#[derive(Debug, Clone, Copy)]
pub struct TransferCallRequest<'a> {
    pub call_uuid: &'a str,
    pub legs: &'a str,
    pub aleg_url: Option<&'a str>,
    pub bleg_url: Option<&'a str>,
    pub aleg_method: Option<&'a str>,
    pub bleg_method: Option<&'a str>,
}

/// Build Plivo transfer command form data.
#[must_use]
pub fn build_transfer_call_payload(request: &TransferCallRequest<'_>) -> BTreeMap<String, String> {
    let mut payload = BTreeMap::from([("legs".into(), request.legs.into())]);
    insert_optional(&mut payload, "aleg_url", request.aleg_url);
    insert_optional(&mut payload, "bleg_url", request.bleg_url);
    insert_optional(&mut payload, "aleg_method", request.aleg_method);
    insert_optional(&mut payload, "bleg_method", request.bleg_method);
    payload
}

/// Request data for Plivo `GetDigits` XML generation.
#[derive(Debug, Clone, Copy)]
pub struct GatherDigitsRequest<'a> {
    pub prompt: &'a str,
    pub action_url: &'a str,
    pub method: Option<&'a str>,
    pub digit_timeout_secs: Option<u32>,
    pub finish_on_key: Option<&'a str>,
    pub num_digits: Option<u32>,
    pub retries: Option<u32>,
}

/// Build Plivo XML for DTMF collection.
#[must_use]
pub fn build_gather_digits_xml(request: &GatherDigitsRequest<'_>) -> String {
    let mut attrs = BTreeMap::from([("action".to_string(), xml_escape(request.action_url))]);
    attrs.insert(
        "method".into(),
        xml_escape(request.method.unwrap_or("POST")),
    );
    insert_optional_u32_attr(&mut attrs, "digitTimeout", request.digit_timeout_secs);
    if let Some(value) = request.finish_on_key {
        attrs.insert("finishOnKey".into(), xml_escape(value));
    }
    insert_optional_u32_attr(&mut attrs, "numDigits", request.num_digits);
    insert_optional_u32_attr(&mut attrs, "retries", request.retries);

    let attrs = attrs
        .into_iter()
        .fold(String::new(), |mut output, (key, value)| {
            let _ = write!(output, " {key}=\"{value}\"");
            output
        });
    format!(
        "<Response><GetDigits{attrs}><Speak>{}</Speak></GetDigits></Response>",
        xml_escape(request.prompt)
    )
}

/// Append FCP call-auth material to a Plivo callback URL.
pub fn append_call_auth_to_url(raw_url: &str, call_auth_value: &str) -> PlivoResult<String> {
    let mut url = Url::parse(raw_url).map_err(|error| PlivoError::Api {
        message: format!("invalid callback URL: {error}"),
        status_code: None,
        retry_after: None,
    })?;
    url.query_pairs_mut()
        .append_pair("fcp_call_auth_token", call_auth_value);
    Ok(url.to_string())
}

/// Extract FCP call-auth material from a Plivo callback URL.
#[must_use]
pub fn call_auth_from_url(raw_url: &str) -> Option<String> {
    Url::parse(raw_url).ok().and_then(|url| {
        url.query_pairs()
            .find(|(key, _)| key == "fcp_call_auth_token")
            .map(|(_, value)| value.into_owned())
    })
}

fn insert_optional(payload: &mut BTreeMap<String, String>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        payload.insert(key.into(), value.into());
    }
}

fn insert_optional_u32(payload: &mut BTreeMap<String, String>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        payload.insert(key.into(), value.to_string());
    }
}

fn insert_optional_bool(payload: &mut BTreeMap<String, String>, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        payload.insert(key.into(), value.to_string());
    }
}

fn insert_optional_u32_attr(attrs: &mut BTreeMap<String, String>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        attrs.insert(key.into(), value.to_string());
    }
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_create_payload_preserves_answer_url_and_status_callbacks() {
        let payload = build_initiate_call_payload(&InitiateCallRequest {
            to: "+15551230000",
            from: "+15559870000",
            answer_url: "https://voice.example.com/plivo",
            answer_method: Some("POST"),
            hangup_url: Some("https://voice.example.com/hangup"),
            hangup_method: Some("POST"),
            ring_url: Some("https://voice.example.com/ring"),
            ring_method: Some("POST"),
            fallback_url: Some("https://voice.example.com/fallback"),
            time_limit: Some(60),
        });
        assert_eq!(payload["to"], "+15551230000");
        assert_eq!(payload["answer_url"], "https://voice.example.com/plivo");
        assert_eq!(payload["time_limit"], "60");
    }

    #[test]
    fn command_builders_cover_continue_speak_transfer_and_gather_xml() {
        let continued = build_continue_call_payload(&ContinueCallRequest {
            call_uuid: "call-1",
            xml_url: "https://voice.example.com/continue",
            legs: Some("aleg"),
        });
        assert_eq!(continued["aleg_url"], "https://voice.example.com/continue");

        let speak = build_speak_call_payload(&SpeakCallRequest {
            call_uuid: "call-1",
            text: "hello",
            voice: Some("WOMAN"),
            language: Some("en-US"),
            legs: Some("both"),
            loop_forever: Some(false),
            mix: Some(true),
        });
        assert_eq!(speak["text"], "hello");
        assert_eq!(speak["mix"], "true");

        let transfer = build_transfer_call_payload(&TransferCallRequest {
            call_uuid: "call-1",
            legs: "both",
            aleg_url: Some("https://voice.example.com/a"),
            bleg_url: Some("https://voice.example.com/b"),
            aleg_method: None,
            bleg_method: Some("POST"),
        });
        assert_eq!(transfer["bleg_url"], "https://voice.example.com/b");

        let gather = build_gather_digits_xml(&GatherDigitsRequest {
            prompt: "Press <1>",
            action_url: "https://voice.example.com/gather?x=1&y=2",
            method: Some("POST"),
            digit_timeout_secs: Some(5),
            finish_on_key: Some("#"),
            num_digits: Some(1),
            retries: Some(2),
        });
        assert!(gather.contains("&lt;1&gt;"));
        assert!(gather.contains("finishOnKey=\"#\""));
        assert!(gather.contains("x=1&amp;y=2"));
    }

    #[test]
    fn callback_auth_is_url_query_bound() {
        let url = append_call_auth_to_url("https://voice.example.com/plivo?foo=bar", "abc123")
            .expect("append auth");
        assert!(url.contains("foo=bar"));
        assert_eq!(call_auth_from_url(&url).as_deref(), Some("abc123"));
    }
}
