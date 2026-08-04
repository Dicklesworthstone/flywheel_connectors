//! Twilio REST API client.
//!
//! Twilio uses Basic auth (account_sid:auth_token) and
//! `application/x-www-form-urlencoded` POST bodies (the REST API does not
//! parse JSON request bodies). Base URL:
//! `https://api.twilio.com/2010-04-01/Accounts/{account_sid}`

use std::fmt::Write;
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode, header};
// tracing macros handled by RetryLoop internals

use crate::{
    error::{TwilioError, TwilioResult},
    types::{
        ApiErrorResponse, CallListResponse, ConversationListResponse,
        ConversationMessageListResponse, ConversationParticipant, MediaListResponse,
        MessageListResponse, PhoneNumberListResponse, RecordingListResponse, TwilioAccount,
        TwilioCall, TwilioConversation, TwilioMediaResource, TwilioMessage, TwilioVerification,
        TwilioVideoRoom, TwimlTemplate, VerificationCheck, VideoParticipantListResponse,
        VideoRecordingListResponse, VideoRoomListResponse, WhatsAppMessage,
    },
};

/// Default Twilio API base URL prefix.
pub const DEFAULT_API_BASE: &str = "https://api.twilio.com/2010-04-01/Accounts";

/// Default Twilio Conversations API base URL.
pub const DEFAULT_CONVERSATIONS_BASE: &str = "https://conversations.twilio.com/v1";

/// Default Twilio Verify API base URL.
pub const DEFAULT_VERIFY_BASE: &str = "https://verify.twilio.com/v2";

/// Default Twilio Video API base URL.
pub const DEFAULT_VIDEO_BASE: &str = "https://video.twilio.com/v1";

/// Authentication mode for the Twilio client.
#[derive(Clone)]
pub enum TwilioAuth {
    /// Direct credentials: account SID + auth token (Basic auth).
    Token {
        account_sid: String,
        auth_token: String,
    },
    /// Secretless credential injection via egress proxy.
    CredentialId {
        account_sid: String,
        credential_id: CredentialId,
    },
}

impl std::fmt::Debug for TwilioAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { account_sid, .. } => f
                .debug_struct("Token")
                .field("account_sid", account_sid)
                .field("auth_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                account_sid,
                credential_id,
            } => f
                .debug_struct("CredentialId")
                .field("account_sid", account_sid)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl TwilioAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Get the account SID regardless of auth mode.
    #[must_use]
    pub fn account_sid(&self) -> &str {
        match self {
            Self::Token { account_sid, .. } | Self::CredentialId { account_sid, .. } => account_sid,
        }
    }
}

/// Twilio REST API client.
pub struct TwilioClient {
    http: Client,
    auth: TwilioAuth,
    base_url: String,
    conversations_base_url: String,
    verify_base_url: String,
    video_base_url: String,
    account_sid: String,
    max_retries: u32,
    runtime: ConnectorRuntime,
    pub(crate) retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for TwilioClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwilioClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("conversations_base_url", &self.conversations_base_url)
            .field("verify_base_url", &self.verify_base_url)
            .field("video_base_url", &self.video_base_url)
            .field("account_sid", &self.account_sid)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl TwilioClient {
    /// Create a new Twilio client with account SID and auth token.
    pub fn new(account_sid: &str, auth_token: &str) -> TwilioResult<Self> {
        Self::new_with_auth(TwilioAuth::Token {
            account_sid: account_sid.to_string(),
            auth_token: auth_token.to_string(),
        })
    }

    /// Create a new Twilio client with the specified auth mode.
    pub fn new_with_auth(auth: TwilioAuth) -> TwilioResult<Self> {
        // No default Content-Type: GET requests carry no body, and write
        // operations set `application/x-www-form-urlencoded` per request via
        // `RequestBuilder::form` (Twilio's REST API does not parse JSON bodies).
        let mut headers = header::HeaderMap::new();

        match &auth {
            TwilioAuth::Token {
                account_sid,
                auth_token,
            } => {
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{account_sid}:{auth_token}"));
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Basic {credentials}").parse().unwrap(),
                );
            }
            TwilioAuth::CredentialId { credential_id, .. } => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    credential_id.to_string().parse().unwrap(),
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-twilio/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(TwilioError::Http)?;

        let sid = auth.account_sid().to_string();
        let base_url = format!("{DEFAULT_API_BASE}/{sid}");
        let conversations_base_url = DEFAULT_CONVERSATIONS_BASE.to_string();
        let verify_base_url = DEFAULT_VERIFY_BASE.to_string();
        let video_base_url = DEFAULT_VIDEO_BASE.to_string();

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            http,
            auth,
            base_url,
            conversations_base_url,
            verify_base_url,
            video_base_url,
            account_sid: sid,
            max_retries: 2,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Lightweight connectivity probe for self-check.
    pub async fn health_check(&self) -> TwilioResult<TwilioAccount> {
        self.get_account().await
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set a custom Conversations API base URL (for testing).
    #[must_use]
    pub fn with_conversations_base_url(mut self, url: &str) -> Self {
        self.conversations_base_url = url.to_string();
        self
    }

    /// Set a custom Video API base URL (for testing).
    #[must_use]
    pub fn with_video_base_url(mut self, url: &str) -> Self {
        self.video_base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Get the account SID.
    #[must_use]
    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }

    // ── Messaging operations ─────────────────────────────────────

    /// Send an SMS or MMS message.
    pub async fn send_message(
        &self,
        to: &str,
        from: &str,
        body: &str,
        media_url: Option<&[String]>,
        status_callback: Option<&str>,
    ) -> TwilioResult<TwilioMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Body": body,
        });
        if let Some(urls) = media_url {
            payload["MediaUrl"] = serde_json::json!(urls);
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a message by SID.
    pub async fn get_message(&self, message_sid: &str) -> TwilioResult<TwilioMessage> {
        let message_sid = validate_sid(message_sid, "message_sid")?;
        let url = format!("{}/Messages/{message_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List messages with optional filters.
    pub async fn list_messages(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        date_sent: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MessageListResponse> {
        let base_url = format!("{}/Messages.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", v.to_string()));
        }
        if let Some(v) = from {
            params.push(("From", v.to_string()));
        }
        if let Some(v) = date_sent {
            params.push(("DateSent", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Voice operations ─────────────────────────────────────────

    /// Create (initiate) a voice call.
    pub async fn create_call(
        &self,
        to: &str,
        from: &str,
        url: &str,
        status_callback: Option<&str>,
        timeout: Option<u32>,
        record: Option<bool>,
    ) -> TwilioResult<TwilioCall> {
        let api_url = format!("{}/Calls.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Url": url,
        });
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        if let Some(t) = timeout {
            payload["Timeout"] = serde_json::Value::Number(t.into());
        }
        if let Some(r) = record {
            payload["Record"] = serde_json::Value::Bool(r);
        }
        let data = self.post_form(&api_url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a call by SID.
    pub async fn get_call(&self, call_sid: &str) -> TwilioResult<TwilioCall> {
        let call_sid = validate_sid(call_sid, "call_sid")?;
        let url = format!("{}/Calls/{call_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Hangup (end) a call by updating its status to "completed".
    pub async fn hangup_call(&self, call_sid: &str) -> TwilioResult<TwilioCall> {
        let call_sid = validate_sid(call_sid, "call_sid")?;
        let url = format!("{}/Calls/{call_sid}.json", self.base_url);
        let payload = serde_json::json!({ "Status": "completed" });
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List calls with optional filters.
    pub async fn list_calls(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        status: Option<&str>,
        start_time: Option<&str>,
        end_time: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<CallListResponse> {
        let base_url = format!("{}/Calls.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", v.to_string()));
        }
        if let Some(v) = from {
            params.push(("From", v.to_string()));
        }
        if let Some(v) = status {
            params.push(("Status", v.to_string()));
        }
        if let Some(v) = start_time {
            params.push(("StartTime", v.to_string()));
        }
        if let Some(v) = end_time {
            params.push(("EndTime", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Generate TwiML XML from a safe template.
    ///
    /// This is a local operation; no API call is made.
    #[must_use]
    pub fn generate_twiml(
        template: &TwimlTemplate,
        message: Option<&str>,
        url: Option<&str>,
        voice: Option<&str>,
        language: Option<&str>,
        digits: Option<&str>,
        number: Option<&str>,
        length: Option<u32>,
        reason: Option<&str>,
    ) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response>\n");

        match template {
            TwimlTemplate::Say => {
                let msg = Self::escape_xml(message.unwrap_or("Hello from FCP."));
                let v = voice.unwrap_or("alice");
                let lang = language.unwrap_or("en-US");
                let _ = writeln!(xml, "  <Say voice=\"{v}\" language=\"{lang}\">{msg}</Say>");
            }
            TwimlTemplate::Play => {
                let u = Self::escape_xml(url.unwrap_or(""));
                let _ = writeln!(xml, "  <Play>{u}</Play>");
            }
            TwimlTemplate::Gather => {
                let prompt = Self::escape_xml(message.unwrap_or("Please enter your selection."));
                let v = voice.unwrap_or("alice");
                let lang = language.unwrap_or("en-US");
                let num_digits = digits.unwrap_or("1");
                let _ = write!(
                    xml,
                    "  <Gather numDigits=\"{num_digits}\">\n    <Say voice=\"{v}\" language=\"{lang}\">{prompt}</Say>\n  </Gather>\n"
                );
            }
            TwimlTemplate::Dial => {
                let num = Self::escape_xml(number.unwrap_or(""));
                let _ = writeln!(xml, "  <Dial>{num}</Dial>");
            }
            TwimlTemplate::Pause => {
                let len = length.unwrap_or(1);
                let _ = writeln!(xml, "  <Pause length=\"{len}\"/>");
            }
            TwimlTemplate::Reject => {
                let r = reason.unwrap_or("rejected");
                let _ = writeln!(xml, "  <Reject reason=\"{r}\"/>");
            }
            TwimlTemplate::Hangup => {
                xml.push_str("  <Hangup/>\n");
            }
        }

        xml.push_str("</Response>");
        xml
    }

    /// Escape XML special characters.
    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    // ── Recording operations ─────────────────────────────────────

    /// List recordings with optional filters.
    pub async fn list_recordings(
        &self,
        call_sid: Option<&str>,
        date_created: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<RecordingListResponse> {
        let base_url = format!("{}/Recordings.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = call_sid {
            params.push(("CallSid", v.to_string()));
        }
        if let Some(v) = date_created {
            params.push(("DateCreated", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a recording, returning the base64-encoded audio data and content type.
    pub async fn download_recording(
        &self,
        recording_sid: &str,
        format: Option<&str>,
    ) -> TwilioResult<(String, String)> {
        let recording_sid = validate_sid(recording_sid, "recording_sid")?;
        // `ext` is interpolated into the request path; Twilio only serves mp3/wav
        // recordings, so an allowlist both matches the API and prevents an
        // attacker-supplied `format` (e.g. `mp3/../..`) from escaping the segment.
        let ext = format.unwrap_or("mp3");
        if !matches!(ext, "mp3" | "wav") {
            return Err(TwilioError::InvalidInput(
                "recording format must be `mp3` or `wav`".into(),
            ));
        }
        let url = format!("{}/Recordings/{recording_sid}.{ext}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let content_type = if ext == "wav" {
            "audio/wav"
        } else {
            "audio/mpeg"
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, content_type.to_string()))
    }

    /// Download media attached to a message, returning base64-encoded data and content type.
    pub async fn download_media(
        &self,
        message_sid: &str,
        media_sid: &str,
    ) -> TwilioResult<(String, String)> {
        let message_sid = validate_sid(message_sid, "message_sid")?;
        let media_sid = validate_sid(media_sid, "media_sid")?;
        let url = format!("{}/Messages/{message_sid}/Media/{media_sid}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, "application/octet-stream".to_string()))
    }

    // ── Media operations ─────────────────────────────────────────

    /// List media resources attached to a message.
    pub async fn list_media(
        &self,
        message_sid: &str,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MediaListResponse> {
        let message_sid = validate_sid(message_sid, "message_sid")?;
        let base_url = format!("{}/Messages/{message_sid}/Media.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific media resource by SID.
    pub async fn get_media(
        &self,
        message_sid: &str,
        media_sid: &str,
    ) -> TwilioResult<TwilioMediaResource> {
        let message_sid = validate_sid(message_sid, "message_sid")?;
        let media_sid = validate_sid(media_sid, "media_sid")?;
        let url = format!(
            "{}/Messages/{message_sid}/Media/{media_sid}.json",
            self.base_url
        );
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── WhatsApp operations ──────────────────────────────────────

    /// Send a freeform WhatsApp message.
    ///
    /// Uses the same Messages API as SMS but with `whatsapp:` prefix on numbers.
    pub async fn whatsapp_send(
        &self,
        to: &str,
        from: &str,
        body: &str,
        media_url: Option<&[String]>,
        status_callback: Option<&str>,
    ) -> TwilioResult<WhatsAppMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let wa_to = ensure_whatsapp_prefix(to);
        let wa_from = ensure_whatsapp_prefix(from);
        let mut payload = serde_json::json!({
            "To": wa_to,
            "From": wa_from,
            "Body": body,
        });
        if let Some(urls) = media_url {
            payload["MediaUrl"] = serde_json::json!(urls);
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Send a template-based WhatsApp message.
    ///
    /// Uses `ContentSid` to reference pre-approved templates with optional
    /// `ContentVariables` for variable substitution.
    pub async fn whatsapp_send_template(
        &self,
        to: &str,
        from: &str,
        content_sid: &str,
        content_variables: Option<&serde_json::Value>,
        status_callback: Option<&str>,
    ) -> TwilioResult<WhatsAppMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let wa_to = ensure_whatsapp_prefix(to);
        let wa_from = ensure_whatsapp_prefix(from);
        let mut payload = serde_json::json!({
            "To": wa_to,
            "From": wa_from,
            "ContentSid": content_sid,
        });
        if let Some(vars) = content_variables {
            payload["ContentVariables"] = serde_json::Value::String(vars.to_string());
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a WhatsApp message by SID.
    pub async fn whatsapp_get(&self, message_sid: &str) -> TwilioResult<WhatsAppMessage> {
        let message_sid = validate_sid(message_sid, "message_sid")?;
        let url = format!("{}/Messages/{message_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List WhatsApp messages by filtering on the `whatsapp:` prefix.
    pub async fn whatsapp_list(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        date_sent: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MessageListResponse> {
        let base_url = format!("{}/Messages.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", ensure_whatsapp_prefix(v)));
        }
        if let Some(v) = from {
            params.push(("From", ensure_whatsapp_prefix(v)));
        }
        if let Some(v) = date_sent {
            params.push(("DateSent", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Account operations ───────────────────────────────────────

    /// Get account details.
    pub async fn get_account(&self) -> TwilioResult<TwilioAccount> {
        let url = format!("{}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List phone numbers on the account.
    pub async fn list_phone_numbers(
        &self,
        phone_number: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<PhoneNumberListResponse> {
        let base_url = format!("{}/IncomingPhoneNumbers.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = phone_number {
            params.push(("PhoneNumber", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Conversations API ──────────────────────────────────────

    /// Create a new conversation.
    pub async fn create_conversation(
        &self,
        friendly_name: Option<&str>,
        unique_name: Option<&str>,
    ) -> TwilioResult<TwilioConversation> {
        let url = format!("{}/Conversations", self.conversations_base_url);
        let mut payload = serde_json::json!({});
        if let Some(name) = friendly_name {
            payload["FriendlyName"] = serde_json::Value::String(name.to_string());
        }
        if let Some(name) = unique_name {
            payload["UniqueName"] = serde_json::Value::String(name.to_string());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a conversation by SID.
    pub async fn get_conversation(
        &self,
        conversation_sid: &str,
    ) -> TwilioResult<TwilioConversation> {
        let url = format!(
            "{}/Conversations/{conversation_sid}",
            self.conversations_base_url
        );
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List conversations with optional pagination.
    pub async fn list_conversations(
        &self,
        page_size: Option<u32>,
    ) -> TwilioResult<ConversationListResponse> {
        let base_url = format!("{}/Conversations", self.conversations_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Add a participant to a conversation.
    pub async fn add_participant(
        &self,
        conversation_sid: &str,
        identity: Option<&str>,
        messaging_address: Option<&str>,
        messaging_proxy_address: Option<&str>,
    ) -> TwilioResult<ConversationParticipant> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Participants",
            self.conversations_base_url
        );
        let mut payload = serde_json::json!({});
        if let Some(id) = identity {
            payload["Identity"] = serde_json::Value::String(id.to_string());
        }
        if let Some(addr) = messaging_address {
            payload["MessagingBinding.Address"] = serde_json::Value::String(addr.to_string());
        }
        if let Some(proxy) = messaging_proxy_address {
            payload["MessagingBinding.ProxyAddress"] = serde_json::Value::String(proxy.to_string());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Remove a participant from a conversation.
    pub async fn remove_participant(
        &self,
        conversation_sid: &str,
        participant_sid: &str,
    ) -> TwilioResult<()> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Participants/{participant_sid}",
            self.conversations_base_url
        );
        self.delete(&url).await
    }

    /// Send a message into a conversation.
    pub async fn send_conversation_message(
        &self,
        conversation_sid: &str,
        author: Option<&str>,
        body: &str,
    ) -> TwilioResult<serde_json::Value> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Messages",
            self.conversations_base_url
        );
        let mut payload = serde_json::json!({
            "Body": body,
        });
        if let Some(a) = author {
            payload["Author"] = serde_json::Value::String(a.to_string());
        }
        self.post_form(&url, &payload).await
    }

    /// List messages in a conversation.
    pub async fn list_conversation_messages(
        &self,
        conversation_sid: &str,
        page_size: Option<u32>,
        order: Option<&str>,
    ) -> TwilioResult<ConversationMessageListResponse> {
        let base_url = format!(
            "{}/Conversations/{conversation_sid}/Messages",
            self.conversations_base_url
        );
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = order {
            params.push(("Order", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Verify API ─────────────────────────────────────────────

    /// Send a verification code (create a verification).
    pub async fn send_verification(
        &self,
        service_sid: &str,
        to: &str,
        channel: &str,
    ) -> TwilioResult<TwilioVerification> {
        let url = format!(
            "{}/Services/{service_sid}/Verifications",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "To": to,
            "Channel": channel,
        });
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Check a verification code.
    pub async fn check_verification(
        &self,
        service_sid: &str,
        to: &str,
        code: &str,
    ) -> TwilioResult<VerificationCheck> {
        let url = format!(
            "{}/Services/{service_sid}/VerificationCheck",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "To": to,
            "Code": code,
        });
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a pending verification.
    pub async fn cancel_verification(
        &self,
        service_sid: &str,
        verification_sid: &str,
    ) -> TwilioResult<TwilioVerification> {
        let url = format!(
            "{}/Services/{service_sid}/Verifications/{verification_sid}",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "Status": "canceled",
        });
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Video API ──────────────────────────────────────────────────

    /// Create a video room.
    pub async fn create_video_room(
        &self,
        unique_name: Option<&str>,
        room_type: Option<&str>,
        max_participants: Option<u32>,
    ) -> TwilioResult<TwilioVideoRoom> {
        let url = format!("{}/Rooms", self.video_base_url);
        let mut payload = serde_json::json!({});
        if let Some(name) = unique_name {
            payload["UniqueName"] = serde_json::Value::String(name.to_string());
        }
        if let Some(rt) = room_type {
            payload["Type"] = serde_json::Value::String(rt.to_string());
        }
        if let Some(mp) = max_participants {
            payload["MaxParticipants"] = serde_json::Value::Number(mp.into());
        }
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a video room by SID or unique name.
    pub async fn get_video_room(&self, room_sid: &str) -> TwilioResult<TwilioVideoRoom> {
        let room_sid = sanitize_path_segment(room_sid, "room_sid")?;
        let url = format!("{}/Rooms/{room_sid}", self.video_base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List video rooms.
    pub async fn list_video_rooms(
        &self,
        status: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<VideoRoomListResponse> {
        let base_url = format!("{}/Rooms", self.video_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = status {
            params.push(("Status", s.to_string()));
        }
        if let Some(ps) = page_size {
            params.push(("PageSize", ps.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// End a video room (set status to completed).
    pub async fn end_video_room(&self, room_sid: &str) -> TwilioResult<TwilioVideoRoom> {
        let room_sid = sanitize_path_segment(room_sid, "room_sid")?;
        let url = format!("{}/Rooms/{room_sid}", self.video_base_url);
        let payload = serde_json::json!({
            "Status": "completed",
        });
        let data = self.post_form(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List participants in a video room.
    pub async fn list_video_participants(
        &self,
        room_sid: &str,
        status: Option<&str>,
    ) -> TwilioResult<VideoParticipantListResponse> {
        let room_sid = sanitize_path_segment(room_sid, "room_sid")?;
        let base_url = format!("{}/Rooms/{room_sid}/Participants", self.video_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = status {
            params.push(("Status", s.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List recordings for a video room.
    pub async fn list_video_recordings(
        &self,
        room_sid: &str,
    ) -> TwilioResult<VideoRecordingListResponse> {
        let room_sid = sanitize_path_segment(room_sid, "room_sid")?;
        let url = format!("{}/Rooms/{room_sid}/Recordings", self.video_base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> TwilioResult<serde_json::Value> {
        // GET is idempotent.
        self.execute(true, || self.http.get(url)).await
    }

    async fn get_with_params(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> TwilioResult<serde_json::Value> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        // GET is idempotent.
        self.execute(true, || self.http.get(&url)).await
    }

    async fn get_bytes(&self, url: &str) -> TwilioResult<Vec<u8>> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| async {
            let result = self.http.get(url).send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        let retry_after = retry_result.or(Some(Duration::from_secs(1)));
                        return AttemptOutcome::Retryable {
                            error: TwilioError::RateLimited {
                                retry_after_ms: retry_after
                                    .map_or(60_000, |d| d.as_millis() as u64),
                            },
                            retry_after,
                        };
                    }

                    let status = response.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return AttemptOutcome::Terminal(TwilioError::Unauthorized);
                    }
                    if status == StatusCode::NOT_FOUND {
                        return AttemptOutcome::Terminal(TwilioError::NotFound {
                            resource: url.to_string(),
                        });
                    }
                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        return AttemptOutcome::Terminal(TwilioError::Api {
                            message: format!("HTTP {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_code: None,
                        });
                    }

                    match response.bytes().await {
                        Ok(bytes) => AttemptOutcome::Success(bytes.to_vec()),
                        Err(e) => AttemptOutcome::Terminal(TwilioError::Http(e)),
                    }
                }
                Err(e) => AttemptOutcome::Retryable {
                    retry_after: None,
                    error: TwilioError::Http(e),
                },
            }
        })
        .await
    }

    /// POST a Twilio write operation.
    ///
    /// The `body` is built by callers as a `serde_json::Value` map using
    /// Twilio's PascalCase field names, but Twilio's REST API only accepts
    /// `application/x-www-form-urlencoded` request bodies — so the map is
    /// flattened into form pairs here. Array-valued fields (e.g. `MediaUrl`)
    /// are emitted as repeated keys, matching Twilio's convention.
    async fn post_form(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> TwilioResult<serde_json::Value> {
        let encoded = encode_form_body(&json_to_form_pairs(body));
        // NOT replay-safe: these POSTs send messages and place calls, and
        // Twilio offers no idempotency key for them.
        self.execute(false, || {
            self.http
                .post(url)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(encoded.clone())
        })
        .await
    }

    async fn delete(&self, url: &str) -> TwilioResult<()> {
        // DELETE is idempotent per HTTP semantics.
        let resp = self.execute(true, || self.http.delete(url)).await;
        match resp {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Run a request under the retry policy.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a side
    /// effect. It must be `false` for anything that creates a resource: Twilio
    /// has no idempotency-key mechanism on the Messages or Calls APIs, so a
    /// replayed `POST /Messages` sends a second SMS and bills for it. Only a
    /// pre-transmission failure (a connect error) may be retried in that case.
    ///
    /// A 429 stays retryable regardless — Twilio rejects a rate-limited request
    /// without performing it, so replaying it cannot duplicate anything.
    ///
    /// See br-kxd3e.
    async fn execute(
        &self,
        replay_safe: bool,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> TwilioResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| async {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        let retry_after = retry_result.or(Some(Duration::from_secs(1)));
                        return AttemptOutcome::Retryable {
                            error: TwilioError::RateLimited {
                                retry_after_ms: retry_after
                                    .map_or(60_000, |d| d.as_millis() as u64),
                            },
                            retry_after,
                        };
                    }

                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return AttemptOutcome::Terminal(TwilioError::Unauthorized);
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return AttemptOutcome::Terminal(TwilioError::NotFound { resource: body });
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        // A 5xx means Twilio RECEIVED the request; the message
                        // may already have been queued for delivery.
                        return AttemptOutcome::retryable_if_replayable(
                            TwilioError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                                error_code: None,
                            },
                            None,
                            replay_safe,
                        );
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<ApiErrorResponse> = serde_json::from_str(&body).ok();
                        let (message, error_code) = api_err
                            .as_ref()
                            .map(|e| {
                                (
                                    e.message.clone().unwrap_or(format!("HTTP {status}")),
                                    e.code.map(|c| c.to_string()),
                                )
                            })
                            .unwrap_or((format!("HTTP {status}: {body}"), None));
                        return AttemptOutcome::Terminal(TwilioError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_code,
                        });
                    }

                    match response.text().await {
                        Ok(body) => match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(TwilioError::from(e)),
                        },
                        Err(e) => AttemptOutcome::Terminal(TwilioError::Http(e)),
                    }
                }
                // Only a connect-phase failure proves the request never left
                // the client; `is_timeout()` covers the TOTAL request timeout,
                // which fires after the body was fully sent.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(TwilioError::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }
}

/// Ensure a phone number has the `whatsapp:` prefix.
fn ensure_whatsapp_prefix(number: &str) -> String {
    if number.starts_with("whatsapp:") {
        number.to_string()
    } else {
        format!("whatsapp:{number}")
    }
}

/// Validate a Twilio resource SID before interpolating it into a request path.
///
/// Twilio SIDs are a 2-letter prefix followed by 32 hex characters — strictly
/// `[A-Za-z0-9]`. Callers reach these values through `require_str`, which does
/// no charset validation, so a `message_sid`/`call_sid`/`media_sid` such as
/// `../Calls/CAxxxx` (or `REALID/actions/hangup#`) would normalize to a
/// different resource or action than intended (e.g. a "get message" request
/// reading a call, or an "answer" turning into a "hangup"). Rejecting any
/// non-alphanumeric byte keeps every request pinned to the addressed resource.
fn validate_sid<'a>(value: &'a str, field: &str) -> TwilioResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TwilioError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if trimmed.len() > 64 || !trimmed.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(TwilioError::InvalidInput(format!(
            "{field} must be an alphanumeric Twilio SID"
        )));
    }
    Ok(trimmed)
}

/// Validate a value that may be a Twilio SID *or* a resource unique name (such
/// as a Video Room `UniqueName`), rejecting only the characters that would let
/// it escape its URL path segment. Unlike [`validate_sid`], this permits the
/// `-`/`_`/`.` that unique names may contain while still blocking traversal
/// (`/`, `\`, `..`, encoded slashes) and query/fragment injection (`?`, `#`).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> TwilioResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TwilioError::InvalidInput(format!(
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
        return Err(TwilioError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

/// Flatten a `serde_json::Value` map into `application/x-www-form-urlencoded`
/// key/value pairs for a Twilio POST body.
///
/// Twilio request payloads are always shallow maps of PascalCase field names to
/// scalar values (Twilio uses dotted keys such as `MessagingBinding.Address`
/// rather than nested objects, and passes structured data like
/// `ContentVariables` as a pre-serialized JSON string). Scalars render to their
/// natural string form; array values (e.g. `MediaUrl`) become repeated keys.
/// Null values are omitted.
fn json_to_form_pairs(body: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let Some(map) = body.as_object() else {
        return pairs;
    };
    for (key, value) in map {
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) => pairs.push((key.clone(), s.clone())),
            serde_json::Value::Bool(b) => pairs.push((key.clone(), b.to_string())),
            serde_json::Value::Number(n) => pairs.push((key.clone(), n.to_string())),
            serde_json::Value::Array(items) => {
                for item in items {
                    let rendered = match item {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    pairs.push((key.clone(), rendered));
                }
            }
            // Nested objects do not occur in Twilio payloads; fall back to the
            // compact JSON encoding rather than dropping the field silently.
            other @ serde_json::Value::Object(_) => {
                pairs.push((key.clone(), other.to_string()));
            }
        }
    }
    pairs
}

/// Serialize form pairs into an `application/x-www-form-urlencoded` body.
///
/// Values are percent-encoded with the same `NON_ALPHANUMERIC` set used for
/// query strings elsewhere in this client (spaces become `%20`, which Twilio
/// urldecodes identically to `+`). Keys are Twilio's fixed PascalCase /
/// dotted field names (e.g. `MessagingBinding.Address`) and are emitted
/// verbatim so the server sees the documented parameter names.
fn encode_form_body(pairs: &[(String, String)]) -> String {
    let mut body = String::new();
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            body.push('&');
        }
        let encoded =
            percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
        let _ = write!(body, "{key}={encoded}");
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    #[test]
    fn validate_sid_rejects_cross_resource_traversal() {
        for bad in [
            "",
            "   ",
            "../Calls/CAxxxxxxxx",
            "REALID/actions/hangup",
            "SID#frag",
            "SID?x=y",
            "a/b",
            "a\\b",
            "MM..2f..2f",
            &"M".repeat(65),
        ] {
            assert!(
                validate_sid(bad, "message_sid").is_err(),
                "expected `{bad}` to be rejected"
            );
        }
        // Real 34-character Twilio SIDs pass (trimmed).
        assert_eq!(
            validate_sid("MM0123456789abcdef0123456789abcdef", "message_sid").unwrap(),
            "MM0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            validate_sid(" CA0123456789abcdef0123456789abcdef ", "call_sid").unwrap(),
            "CA0123456789abcdef0123456789abcdef"
        );
    }

    enum TestHttpBody {
        Json(serde_json::Value),
        Text(&'static str),
        Empty,
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: TestHttpBody,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        #[must_use]
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Json(body),
            }
        }

        #[must_use]
        fn text(method: &'static str, path: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Text(body),
            }
        }

        #[must_use]
        const fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Empty,
            }
        }
    }

    impl TestHttpServer {
        #[must_use]
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        #[must_use]
        fn account_base_url(&self) -> String {
            format!("{}/2010-04-01/Accounts/ACtest123", self.url)
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn test_server(responses: Vec<TestHttpResponse>) -> (TestHttpServer, String) {
        let server = TestHttpServer::respond(responses);
        let base = server.account_base_url();
        (server, base)
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: TestHttpResponse) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap();
            }
        }

        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let (body, is_json_body) = match response.body {
            TestHttpBody::Json(body) => (body.to_string(), true),
            TestHttpBody::Text(body) => (body.to_string(), false),
            TestHttpBody::Empty => (String::new(), false),
        };
        let reason = match response.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        if is_json_body {
            write!(stream, "content-type: application/json\r\n").unwrap();
        }
        write!(stream, "\r\n{body}").unwrap();
        stream.flush().unwrap();
    }

    fn test_client(base_url: &str) -> TwilioClient {
        TwilioClient::new("ACtest123", "test_auth_token")
            .unwrap()
            .with_base_url(base_url)
            .with_retry_config(0)
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            201,
            serde_json::json!({
                "sid": "SMtest123",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Hello from FCP!",
                "date_created": "2026-03-01T00:00:00Z"
            }),
        )]);

        let client = test_client(&base);
        let msg = client
            .send_message(
                "+15551234567",
                "+15559876543",
                "Hello from FCP!",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMtest123");
        assert_eq!(msg.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_message() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMabc.json",
            200,
            serde_json::json!({
                "sid": "SMabc",
                "status": "delivered",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Test message",
                "date_created": "2026-03-01T00:00:00Z",
                "num_media": "0"
            }),
        )]);

        let client = test_client(&base);
        let msg = client.get_message("SMabc").await.unwrap();
        assert_eq!(msg.sid, "SMabc");
        assert_eq!(msg.status, "delivered");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            200,
            serde_json::json!({
                "messages": [
                    { "sid": "SM1", "status": "delivered", "to": "+1", "from": "+2" },
                    { "sid": "SM2", "status": "sent", "to": "+3", "from": "+4" }
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_messages(None, None, None, Some(20), None)
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Calls.json",
            201,
            serde_json::json!({
                "sid": "CAtest",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "date_created": "2026-03-01T00:00:00Z"
            }),
        )]);

        let client = test_client(&base);
        let call = client
            .create_call(
                "+15551234567",
                "+15559876543",
                "https://example.com/twiml",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(call.sid, "CAtest");
        assert_eq!(call.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_call() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Calls/CAxyz.json",
            200,
            serde_json::json!({
                "sid": "CAxyz",
                "status": "completed",
                "to": "+15551234567",
                "from": "+15559876543",
                "duration": "42",
                "date_created": "2026-03-01T00:00:00Z",
                "price": "-0.0100"
            }),
        )]);

        let client = test_client(&base);
        let call = client.get_call("CAxyz").await.unwrap();
        assert_eq!(call.sid, "CAxyz");
        assert_eq!(call.duration.as_deref(), Some("42"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_hangup_call() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Calls/CAactive.json",
            200,
            serde_json::json!({
                "sid": "CAactive",
                "status": "completed",
                "to": "+15551234567",
                "from": "+15559876543",
                "duration": "120",
                "date_created": "2026-03-01T00:00:00Z"
            }),
        )]);

        let client = test_client(&base);
        let call = client.hangup_call("CAactive").await.unwrap();
        assert_eq!(call.sid, "CAactive");
        assert_eq!(call.status, "completed");
        assert_eq!(call.duration.as_deref(), Some("120"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_calls() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Calls.json",
            200,
            serde_json::json!({
                "calls": [
                    { "sid": "CA1", "status": "completed", "to": "+1", "from": "+2", "duration": "30" },
                    { "sid": "CA2", "status": "in-progress", "to": "+3", "from": "+4" }
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_calls(None, None, None, None, None, Some(20), None)
            .await
            .unwrap();
        assert_eq!(result.calls.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_calls_with_filters() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Calls.json",
            200,
            serde_json::json!({
                "calls": [
                    { "sid": "CA1", "status": "completed", "to": "+15551234567", "from": "+2" }
                ],
                "next_page_uri": "/next"
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_calls(
                Some("+15551234567"),
                None,
                Some("completed"),
                None,
                None,
                Some(10),
                Some(0),
            )
            .await
            .unwrap();
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.next_page_uri.as_deref(), Some("/next"));
    }

    #[test]
    fn test_generate_twiml_say() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hello world"),
            None,
            Some("alice"),
            Some("en-US"),
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Response>"));
        assert!(xml.contains("</Response>"));
        assert!(xml.contains("<Say"));
        assert!(xml.contains("voice=\"alice\""));
        assert!(xml.contains("language=\"en-US\""));
        assert!(xml.contains("Hello world"));
    }

    #[test]
    fn test_generate_twiml_say_defaults() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("voice=\"alice\""));
        assert!(xml.contains("language=\"en-US\""));
        assert!(xml.contains("Hello from FCP."));
    }

    #[test]
    fn test_generate_twiml_play() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Play,
            None,
            Some("https://example.com/audio.mp3"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Play>https://example.com/audio.mp3</Play>"));
    }

    #[test]
    fn test_generate_twiml_gather() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Gather,
            Some("Press 1 for help"),
            None,
            None,
            None,
            Some("1"),
            None,
            None,
            None,
        );
        assert!(xml.contains("<Gather numDigits=\"1\">"));
        assert!(xml.contains("Press 1 for help"));
        assert!(xml.contains("</Gather>"));
    }

    #[test]
    fn test_generate_twiml_dial() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Dial,
            None,
            None,
            None,
            None,
            None,
            Some("+15551234567"),
            None,
            None,
        );
        assert!(xml.contains("<Dial>+15551234567</Dial>"));
    }

    #[test]
    fn test_generate_twiml_pause() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Pause,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(5),
            None,
        );
        assert!(xml.contains("<Pause length=\"5\"/>"));
    }

    #[test]
    fn test_generate_twiml_pause_default_length() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Pause,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Pause length=\"1\"/>"));
    }

    #[test]
    fn test_generate_twiml_reject() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Reject,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("busy"),
        );
        assert!(xml.contains("<Reject reason=\"busy\"/>"));
    }

    #[test]
    fn test_generate_twiml_reject_default_reason() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Reject,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Reject reason=\"rejected\"/>"));
    }

    #[test]
    fn test_generate_twiml_hangup() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Hangup,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Hangup/>"));
    }

    #[test]
    fn test_generate_twiml_xml_escaping() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hello <world> & \"friends\""),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("Hello &lt;world&gt; &amp; &quot;friends&quot;"));
        assert!(!xml.contains("<world>"));
    }

    #[test]
    fn test_generate_twiml_has_xml_declaration() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hi"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(TwilioClient::escape_xml("hello"), "hello");
        assert_eq!(TwilioClient::escape_xml("<>"), "&lt;&gt;");
        assert_eq!(TwilioClient::escape_xml("a&b"), "a&amp;b");
        assert_eq!(TwilioClient::escape_xml("\"x\""), "&quot;x&quot;");
        assert_eq!(TwilioClient::escape_xml("it's"), "it&apos;s");
        assert_eq!(
            TwilioClient::escape_xml("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_account() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123.json",
            200,
            serde_json::json!({
                "sid": "ACtest123",
                "friendly_name": "Test Account",
                "status": "active",
                "type": "Full"
            }),
        )]);

        let client = test_client(&base);
        let account = client.get_account().await.unwrap();
        assert_eq!(account.sid, "ACtest123");
        assert_eq!(account.friendly_name.as_deref(), Some("Test Account"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_phone_numbers() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/IncomingPhoneNumbers.json",
            200,
            serde_json::json!({
                "incoming_phone_numbers": [
                    { "sid": "PN1", "phone_number": "+15551234567", "friendly_name": "Main" }
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_phone_numbers(None, None).await.unwrap();
        assert_eq!(result.incoming_phone_numbers.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let (_server, base) = test_server(vec![TestHttpResponse::empty(
            "GET",
            "/2010-04-01/Accounts/ACtest123.json",
            401,
        )]);

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMmissing.json",
            404,
            serde_json::json!({
                "code": 20404,
                "message": "The requested resource was not found"
            }),
        )]);

        let client = test_client(&base);
        let result = client.get_message("SMmissing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let (_server, base) = test_server(vec![TestHttpResponse::empty(
            "GET",
            "/2010-04-01/Accounts/ACtest123.json",
            429,
        )]);

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TwilioError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = TwilioError::Unauthorized;
        assert!(!err.is_retryable());

        let err = TwilioError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());

        let err = TwilioError::NotFound {
            resource: "message".into(),
        };
        assert!(!err.is_retryable());
    }

    // ── TwilioAuth tests ────────────────────────────────────────────────

    #[test]
    fn auth_token_redacted_label() {
        let auth = TwilioAuth::Token {
            account_sid: "ACtest".into(),
            auth_token: "secret123".into(),
        };
        assert_eq!(auth.redacted_label(), "token");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACtest".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert_eq!(auth.redacted_label(), "credential_id");
    }

    #[test]
    fn auth_token_is_not_secretless() {
        let auth = TwilioAuth::Token {
            account_sid: "ACtest".into(),
            auth_token: "token".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACtest".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_account_sid_from_token() {
        let auth = TwilioAuth::Token {
            account_sid: "ACabc123".into(),
            auth_token: "tok".into(),
        };
        assert_eq!(auth.account_sid(), "ACabc123");
    }

    #[test]
    fn auth_account_sid_from_credential_id() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACxyz789".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert_eq!(auth.account_sid(), "ACxyz789");
    }

    #[test]
    fn auth_token_debug_redacts_auth_token() {
        let auth = TwilioAuth::Token {
            account_sid: "ACdebug".into(),
            auth_token: "super_secret_should_not_appear".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("ACdebug"), "debug: {debug}");
        assert!(debug.contains("[REDACTED]"), "debug: {debug}");
        assert!(
            !debug.contains("super_secret_should_not_appear"),
            "debug: {debug}"
        );
    }

    #[test]
    fn auth_credential_id_debug_shows_id() {
        let cid = uuid::Uuid::new_v4();
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACdebug2".into(),
            credential_id: CredentialId::parse(&cid.to_string()).unwrap(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("ACdebug2"), "debug: {debug}");
        assert!(debug.contains("CredentialId"), "debug: {debug}");
    }

    #[test]
    fn auth_clone_token() {
        let original = TwilioAuth::Token {
            account_sid: "ACclone".into(),
            auth_token: "tok_clone".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.account_sid(), "ACclone");
        assert_eq!(cloned.redacted_label(), "token");
    }

    #[test]
    fn auth_clone_credential_id() {
        let original = TwilioAuth::CredentialId {
            account_sid: "ACclone2".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.account_sid(), "ACclone2");
        assert!(cloned.is_secretless());
    }

    // ── TwilioClient construction tests ─────────────────────────────────

    #[test]
    fn client_new_builds_with_default_base_url() {
        let client = TwilioClient::new("ACtest123", "auth_tok").unwrap();
        assert_eq!(client.account_sid(), "ACtest123");
    }

    #[test]
    fn client_with_base_url_overrides() {
        let client = TwilioClient::new("ACtest123", "tok")
            .unwrap()
            .with_base_url("http://localhost:8888");
        assert_eq!(client.account_sid(), "ACtest123");
        let debug = format!("{client:?}");
        assert!(debug.contains("http://localhost:8888"), "debug: {debug}");
    }

    #[test]
    fn client_with_retry_config() {
        let client = TwilioClient::new("ACtest", "tok")
            .unwrap()
            .with_retry_config(5);
        assert_eq!(client.retry_config.max_retries, 5);
    }

    #[test]
    fn client_debug_format_contains_key_fields() {
        let client = TwilioClient::new("ACfmt", "tok")
            .unwrap()
            .with_base_url("http://test.local")
            .with_retry_config(3);
        let debug = format!("{client:?}");
        assert!(debug.contains("TwilioClient"), "debug: {debug}");
        assert!(debug.contains("ACfmt"), "debug: {debug}");
        assert!(debug.contains("http://test.local"), "debug: {debug}");
        assert_eq!(client.retry_config.max_retries, 3);
    }

    #[test]
    fn client_new_with_auth_token_mode() {
        let client = TwilioClient::new_with_auth(TwilioAuth::Token {
            account_sid: "ACnew".into(),
            auth_token: "tok_new".into(),
        })
        .unwrap();
        assert_eq!(client.account_sid(), "ACnew");
    }

    #[test]
    fn client_new_with_auth_credential_id_mode() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let client = TwilioClient::new_with_auth(TwilioAuth::CredentialId {
            account_sid: "ACcred".into(),
            credential_id: cid,
        })
        .unwrap();
        assert_eq!(client.account_sid(), "ACcred");
    }

    #[test]
    fn client_default_retry_is_two() {
        let client = TwilioClient::new("ACtest", "tok").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("max_retries: 2"), "debug: {debug}");
    }

    #[test]
    fn client_base_url_includes_account_sid() {
        let client = TwilioClient::new("ACurl123", "tok").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("ACurl123"), "debug: {debug}");
        // The base URL should contain the default API base + account SID
        let expected_url = format!("{DEFAULT_API_BASE}/ACurl123");
        assert!(debug.contains(&expected_url), "debug: {debug}");
    }

    // ── Form-encoding of POST bodies ────────────────────────────────────

    #[test]
    fn json_to_form_pairs_flattens_scalars() {
        let body = serde_json::json!({
            "To": "+15551234567",
            "Timeout": 30,
            "Record": true,
        });
        let pairs = json_to_form_pairs(&body);
        assert!(pairs.contains(&("To".to_string(), "+15551234567".to_string())));
        assert!(pairs.contains(&("Timeout".to_string(), "30".to_string())));
        assert!(pairs.contains(&("Record".to_string(), "true".to_string())));
    }

    #[test]
    fn json_to_form_pairs_emits_repeated_keys_for_arrays() {
        let body = serde_json::json!({
            "Body": "hi",
            "MediaUrl": ["https://a.example/1.png", "https://a.example/2.png"],
        });
        let pairs = json_to_form_pairs(&body);
        let media: Vec<&String> = pairs
            .iter()
            .filter(|(k, _)| k == "MediaUrl")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(media.len(), 2, "each MediaUrl should be a separate pair");
        assert_eq!(media[0], "https://a.example/1.png");
        assert_eq!(media[1], "https://a.example/2.png");
    }

    #[test]
    fn json_to_form_pairs_omits_null_and_handles_empty() {
        let body = serde_json::json!({ "A": serde_json::Value::Null, "B": "keep" });
        let pairs = json_to_form_pairs(&body);
        assert_eq!(pairs, vec![("B".to_string(), "keep".to_string())]);
        assert!(json_to_form_pairs(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn encode_form_body_percent_encodes_values() {
        let body = encode_form_body(&[
            ("To".to_string(), "+15551234567".to_string()),
            ("Body".to_string(), "hi there".to_string()),
        ]);
        // `+` and space must be percent-encoded so they survive form decoding.
        assert_eq!(body, "To=%2B15551234567&Body=hi%20there");
        assert_eq!(encode_form_body(&[]), "");
    }

    // ── Default API base constant ───────────────────────────────────────

    #[test]
    fn default_api_base_is_twilio() {
        assert!(DEFAULT_API_BASE.contains("api.twilio.com"));
        assert!(DEFAULT_API_BASE.contains("2010-04-01"));
        assert!(DEFAULT_API_BASE.contains("Accounts"));
    }

    // ── HTTP edge case tests ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_recordings() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Recordings.json",
            200,
            serde_json::json!({
                "recordings": [
                    {"sid": "RE1", "duration": "30"},
                    {"sid": "RE2", "duration": "60"}
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_recordings(None, None, None).await.unwrap();
        assert_eq!(result.recordings.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_forbidden_returns_unauthorized() {
        let (_server, base) = test_server(vec![TestHttpResponse::empty(
            "GET",
            "/2010-04-01/Accounts/ACtest123.json",
            403,
        )]);

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_api_error_with_error_body() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            400,
            serde_json::json!({
                "code": 21211,
                "message": "Invalid 'To' Phone Number"
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_messages(None, None, None, None, None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            &err,
            TwilioError::Api {
                message,
                status_code: Some(400),
                error_code: Some(error_code),
            } if message == "Invalid 'To' Phone Number" && error_code == "21211"
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_no_retry() {
        let (_server, base) = test_server(vec![TestHttpResponse::text(
            "GET",
            "/2010-04-01/Accounts/ACtest123.json",
            503,
            "Service Unavailable",
        )]);

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            &err,
            TwilioError::Api {
                status_code: Some(503),
                message,
                ..
            } if message.contains("503")
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_media_url() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            201,
            serde_json::json!({
                "sid": "SMmedia",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222",
                "body": "With media",
                "num_media": "1"
            }),
        )]);

        let client = test_client(&base);
        let media = vec!["https://example.com/image.png".to_string()];
        let msg = client
            .send_message(
                "+15551111111",
                "+15552222222",
                "With media",
                Some(&media),
                None,
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMmedia");
        assert_eq!(msg.num_media.as_deref(), Some("1"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_callback() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            201,
            serde_json::json!({
                "sid": "SMcb",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222",
                "body": "With callback"
            }),
        )]);

        let client = test_client(&base);
        let msg = client
            .send_message(
                "+15551111111",
                "+15552222222",
                "With callback",
                None,
                Some("https://example.com/callback"),
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMcb");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call_with_all_options() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "POST",
            "/2010-04-01/Accounts/ACtest123/Calls.json",
            201,
            serde_json::json!({
                "sid": "CAfull",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222"
            }),
        )]);

        let client = test_client(&base);
        let call = client
            .create_call(
                "+15551111111",
                "+15552222222",
                "https://example.com/twiml",
                Some("https://example.com/status"),
                Some(30),
                Some(true),
            )
            .await
            .unwrap();
        assert_eq!(call.sid, "CAfull");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages_with_filters() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages.json",
            200,
            serde_json::json!({
                "messages": [{"sid": "SMfiltered"}],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_messages(
                Some("+15551111111"),
                Some("+15552222222"),
                Some("2026-03-01"),
                Some(10),
                Some(0),
            )
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_phone_numbers_with_filter() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/IncomingPhoneNumbers.json",
            200,
            serde_json::json!({
                "incoming_phone_numbers": [
                    {"sid": "PNfiltered", "phone_number": "+15551234567"}
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_phone_numbers(Some("+15551234567"), Some(10))
            .await
            .unwrap();
        assert_eq!(result.incoming_phone_numbers.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_recordings_with_filters() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Recordings.json",
            200,
            serde_json::json!({
                "recordings": [{"sid": "REfiltered"}],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client
            .list_recordings(Some("CA123"), Some("2026-03-01"), Some(5))
            .await
            .unwrap();
        assert_eq!(result.recordings.len(), 1);
    }

    // ── Media operations tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_media() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json",
            200,
            serde_json::json!({
                "media_list": [
                    {
                        "sid": "ME001",
                        "account_sid": "ACtest123",
                        "parent_sid": "SMabc",
                        "content_type": "image/jpeg",
                        "date_created": "2026-03-01T00:00:00Z"
                    },
                    {
                        "sid": "ME002",
                        "account_sid": "ACtest123",
                        "parent_sid": "SMabc",
                        "content_type": "image/png",
                        "date_created": "2026-03-01T00:01:00Z"
                    }
                ],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_media("SMabc", None, None).await.unwrap();
        assert_eq!(result.media_list.len(), 2);
        assert!(result.next_page_uri.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_media_with_pagination() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json",
            200,
            serde_json::json!({
                "media_list": [
                    {"sid": "ME001", "content_type": "image/jpeg"}
                ],
                "next_page_uri": "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json?Page=1"
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_media("SMabc", Some(1), Some(0)).await.unwrap();
        assert_eq!(result.media_list.len(), 1);
        assert!(result.next_page_uri.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_media_empty() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMnomedia/Media.json",
            200,
            serde_json::json!({
                "media_list": [],
                "next_page_uri": null
            }),
        )]);

        let client = test_client(&base);
        let result = client.list_media("SMnomedia", None, None).await.unwrap();
        assert!(result.media_list.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_media() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/ME001.json",
            200,
            serde_json::json!({
                "sid": "ME001",
                "account_sid": "ACtest123",
                "parent_sid": "SMabc",
                "content_type": "image/jpeg",
                "date_created": "2026-03-01T00:00:00Z",
                "date_updated": "2026-03-01T00:00:01Z",
                "uri": "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/ME001.json"
            }),
        )]);

        let client = test_client(&base);
        let media = client.get_media("SMabc", "ME001").await.unwrap();
        assert_eq!(media.sid, "ME001");
        assert_eq!(media.content_type.as_deref(), Some("image/jpeg"));
        assert_eq!(media.parent_sid.as_deref(), Some("SMabc"));
        assert_eq!(media.account_sid.as_deref(), Some("ACtest123"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_media_not_found() {
        let (_server, base) = test_server(vec![TestHttpResponse::json(
            "GET",
            "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/MEmissing.json",
            404,
            serde_json::json!({
                "code": 20404,
                "message": "The requested resource was not found"
            }),
        )]);

        let client = test_client(&base);
        let result = client.get_media("SMabc", "MEmissing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::NotFound { .. }));
    }
}
