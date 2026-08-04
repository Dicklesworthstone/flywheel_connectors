//! Nextcloud Talk OCS client with retry-aware request helpers.

#![allow(clippy::missing_errors_doc)]

use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Client, Method, RequestBuilder};
use serde::de::DeserializeOwned;
use tracing::debug;
use url::form_urlencoded;

use crate::config::{NextcloudTalkAuth, NextcloudTalkConfig};
use crate::error::{NextcloudTalkError, NextcloudTalkResult};
use crate::types::{
    AddParticipantRequest, CallParticipant, ChatMessage, ChatMessagesPage, ChatMessagesQuery,
    Conversation, ConversationListQuery, ConversationToken, CreateConversationRequest,
    FileShareMetaData, FileShareResponse, MessageId, OcsEnvelope, Participant,
    ParticipantListQuery, Reaction, ReactionRequest, ReadMarkerRequest, RemoveParticipantRequest,
    SendChatMessageRequest, ServerCapabilitiesResponse, ShareFileRequest,
};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
const OCS_API_REQUEST_HEADER: &str = "OCS-APIRequest";
const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";

#[derive(Debug, Clone)]
struct RawResponse {
    status: u16,
    headers: HeaderMap,
    body: String,
}

/// Nextcloud Talk client with typed request helpers.
#[derive(Clone)]
pub struct NextcloudTalkClient {
    client: Client,
    server_url: String,
    auth: NextcloudTalkAuth,
    retry_config: HttpRetryConfig,
    force_language: Option<String>,
}

impl std::fmt::Debug for NextcloudTalkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextcloudTalkClient")
            .field("server_url", &self.server_url)
            .field("auth", &"[REDACTED]")
            .field("force_language", &self.force_language)
            .finish_non_exhaustive()
    }
}

impl NextcloudTalkClient {
    /// Construct a new Nextcloud Talk client from validated connector config.
    pub fn new(config: &NextcloudTalkConfig) -> NextcloudTalkResult<Self> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(OCS_API_REQUEST_HEADER, HeaderValue::from_static("true"));
        default_headers.insert(
            USER_AGENT,
            HeaderValue::from_static("fcp-nextcloud-talk/0.1.0"),
        );

        let client = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .default_headers(default_headers)
            .build()
            .map_err(NextcloudTalkError::Http)?;

        Ok(Self {
            client,
            server_url: config.normalized_server_url(),
            auth: config.auth.clone(),
            retry_config: config.retry.clone(),
            force_language: config.force_language.clone(),
        })
    }

    /// Return the configured server URL.
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Return the configured auth mode label for diagnostics.
    #[must_use]
    pub const fn auth_mode(&self) -> &'static str {
        self.auth.mode_label()
    }

    /// Fetch the Nextcloud server capabilities document.
    pub async fn get_capabilities(
        &self,
        runtime: &ConnectorRuntime,
    ) -> NextcloudTalkResult<ServerCapabilitiesResponse> {
        let raw = self
            .request_raw(
                runtime,
                Method::GET,
                "/ocs/v1.php/cloud/capabilities",
                Vec::new(),
                Vec::new(),
            )
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Probe Nextcloud and verify that Talk capabilities are present.
    pub async fn health_check(
        &self,
        runtime: &ConnectorRuntime,
    ) -> NextcloudTalkResult<ServerCapabilitiesResponse> {
        let capabilities = self.get_capabilities(runtime).await?;
        if capabilities.capabilities.spreed.is_none() {
            return Err(NextcloudTalkError::Config(
                "Nextcloud Talk capabilities are not exposed by the target server".into(),
            ));
        }
        Ok(capabilities)
    }

    /// List the current user's conversations.
    pub async fn get_conversations(
        &self,
        runtime: &ConnectorRuntime,
        query: &ConversationListQuery,
    ) -> NextcloudTalkResult<Vec<Conversation>> {
        let mut params = Vec::new();
        if query.include_status {
            params.push(("includeStatus".into(), "1".into()));
        }
        if let Some(modified_since) = query.modified_since {
            params.push(("modifiedSince".into(), modified_since.to_string()));
        }

        let raw = self
            .request_raw(
                runtime,
                Method::GET,
                "/ocs/v2.php/apps/spreed/api/v4/room",
                params,
                Vec::new(),
            )
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Create a new conversation.
    pub async fn create_conversation(
        &self,
        runtime: &ConnectorRuntime,
        request: &CreateConversationRequest,
    ) -> NextcloudTalkResult<Conversation> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let mut form = vec![("roomType".into(), u8::from(request.room_type).to_string())];
        push_optional(&mut form, "invite", request.invite.as_deref());
        push_optional(&mut form, "source", request.source.as_deref());
        push_optional(&mut form, "roomName", request.room_name.as_deref());
        push_optional(&mut form, "objectType", request.object_type.as_deref());
        push_optional(&mut form, "objectId", request.object_id.as_deref());
        push_optional(&mut form, "password", request.password.as_deref());

        let raw = self
            .request_raw(
                runtime,
                Method::POST,
                "/ocs/v2.php/apps/spreed/api/v4/room",
                Vec::new(),
                form,
            )
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Fetch a single conversation by token.
    pub async fn get_conversation(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
    ) -> NextcloudTalkResult<Conversation> {
        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v4/room/{}",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::GET, &path, Vec::new(), Vec::new())
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Fetch chat messages or perform a long-poll request.
    pub async fn get_messages(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        query: &ChatMessagesQuery,
    ) -> NextcloudTalkResult<ChatMessagesPage> {
        query.validate().map_err(NextcloudTalkError::InvalidInput)?;

        let mut params = vec![
            ("lookIntoFuture".into(), bool_flag(query.look_into_future)),
            ("setReadMarker".into(), bool_flag(query.set_read_marker)),
            (
                "includeLastKnown".into(),
                bool_flag(query.include_last_known),
            ),
            ("noStatusUpdate".into(), bool_flag(query.no_status_update)),
            (
                "markNotificationsAsRead".into(),
                bool_flag(query.mark_notifications_as_read),
            ),
        ];
        push_optional_u16(&mut params, "limit", query.limit);
        push_optional_message_id(
            &mut params,
            "lastKnownMessageId",
            query.last_known_message_id,
        );
        push_optional_message_id(&mut params, "lastCommonReadId", query.last_common_read_id);
        push_optional_u16(&mut params, "timeout", query.timeout_secs);

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/chat/{}",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::GET, &path, params, Vec::new())
            .await?;

        if raw.status == 304 {
            return Ok(ChatMessagesPage {
                messages: Vec::new(),
                last_given: extract_message_id_header(&raw.headers, "X-Chat-Last-Given"),
                last_common_read: extract_message_id_header(
                    &raw.headers,
                    "X-Chat-Last-Common-Read",
                ),
                not_modified: true,
            });
        }

        let messages: Vec<ChatMessage> = Self::decode_ocs(&raw)?;
        Ok(ChatMessagesPage {
            messages,
            last_given: extract_message_id_header(&raw.headers, "X-Chat-Last-Given"),
            last_common_read: extract_message_id_header(&raw.headers, "X-Chat-Last-Common-Read"),
            not_modified: false,
        })
    }

    /// Send a new message to a conversation.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        request: &SendChatMessageRequest,
    ) -> NextcloudTalkResult<ChatMessage> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let mut form = vec![("message".into(), request.message.clone())];
        push_optional(
            &mut form,
            "actorDisplayName",
            request.actor_display_name.as_deref(),
        );
        push_optional_message_id(&mut form, "replyTo", request.reply_to);
        if let Some(reference_id) = &request.reference_id {
            form.push(("referenceId".into(), reference_id.0.clone()));
        }
        if request.silent {
            form.push(("silent".into(), "1".into()));
        }

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/chat/{}",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::POST, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Delete a message from a conversation.
    pub async fn delete_message(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        message_id: MessageId,
    ) -> NextcloudTalkResult<ChatMessage> {
        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/chat/{}/{}",
            encode_segment(token.as_str()),
            message_id.get()
        );
        let raw = self
            .request_raw(runtime, Method::DELETE, &path, Vec::new(), Vec::new())
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Update the read marker for a conversation.
    pub async fn set_read_marker(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        request: &ReadMarkerRequest,
    ) -> NextcloudTalkResult<Conversation> {
        let mut form = Vec::new();
        push_optional_message_id(&mut form, "lastReadMessage", request.last_read_message);

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/chat/{}/read",
            encode_segment(token.as_str())
        );
        // The form names the marker's target value, so applying it twice
        // converges on the same read position.
        let raw = self
            .request_raw_replay_safe(runtime, Method::POST, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs(&raw)
    }

    /// List conversation participants.
    pub async fn list_participants(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        query: &ParticipantListQuery,
    ) -> NextcloudTalkResult<Vec<Participant>> {
        let mut params = Vec::new();
        if query.include_status {
            params.push(("includeStatus".into(), "1".into()));
        }

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v4/room/{}/participants",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::GET, &path, params, Vec::new())
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Add a participant to a conversation.
    pub async fn add_participant(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        request: &AddParticipantRequest,
    ) -> NextcloudTalkResult<serde_json::Value> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let mut form = vec![("newParticipant".into(), request.new_participant.clone())];
        push_optional(&mut form, "source", request.source.as_deref());

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v4/room/{}/participants",
            encode_segment(token.as_str())
        );
        // Room membership is a set: re-adding a participant who is already in
        // the room does not produce a second membership.
        let raw = self
            .request_raw_replay_safe(runtime, Method::POST, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Remove an attendee from a conversation.
    pub async fn remove_participant(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        request: &RemoveParticipantRequest,
    ) -> NextcloudTalkResult<()> {
        let form = vec![("attendeeId".into(), request.attendee_id.get().to_string())];
        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v4/room/{}/attendees",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::DELETE, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs::<serde_json::Value>(&raw).map(|_| ())
    }

    /// Fetch the list of connected participants for a call.
    pub async fn get_call_state(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
    ) -> NextcloudTalkResult<Vec<CallParticipant>> {
        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v4/call/{}",
            encode_segment(token.as_str())
        );
        let raw = self
            .request_raw(runtime, Method::GET, &path, Vec::new(), Vec::new())
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Add a reaction to a chat message.
    pub async fn add_reaction(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        message_id: MessageId,
        request: &ReactionRequest,
    ) -> NextcloudTalkResult<Vec<Reaction>> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/reaction/{}/{}",
            encode_segment(token.as_str()),
            message_id.get()
        );
        let form = vec![("reaction".into(), request.reaction.clone())];
        // Reactions are set membership too — the same reaction twice is one
        // reaction.
        let raw = self
            .request_raw_replay_safe(runtime, Method::POST, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Delete a reaction from a chat message.
    pub async fn delete_reaction(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        message_id: MessageId,
        request: &ReactionRequest,
    ) -> NextcloudTalkResult<Vec<Reaction>> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let path = format!(
            "/ocs/v2.php/apps/spreed/api/v1/reaction/{}/{}",
            encode_segment(token.as_str()),
            message_id.get()
        );
        let form = vec![("reaction".into(), request.reaction.clone())];
        let raw = self
            .request_raw(runtime, Method::DELETE, &path, Vec::new(), form)
            .await?;
        Self::decode_ocs(&raw)
    }

    /// Share a file into a conversation.
    pub async fn share_file(
        &self,
        runtime: &ConnectorRuntime,
        token: &ConversationToken,
        request: &ShareFileRequest,
    ) -> NextcloudTalkResult<FileShareResponse> {
        request
            .validate()
            .map_err(NextcloudTalkError::InvalidInput)?;

        let mut form = vec![
            ("shareType".into(), "10".into()),
            ("shareWith".into(), token.as_str().to_string()),
            ("path".into(), request.path.clone()),
        ];
        if let Some(reference_id) = &request.reference_id {
            form.push(("referenceId".into(), reference_id.0.clone()));
        }
        if let Some(meta) = &request.talk_meta_data {
            form.push(("talkMetaData".into(), serialize_share_meta(meta)?));
        }

        let raw = self
            .request_raw(
                runtime,
                Method::POST,
                "/ocs/v2.php/apps/files_sharing/api/v1/shares",
                Vec::new(),
                form,
            )
            .await?;
        Self::decode_ocs(&raw)
    }

    fn decode_ocs<T>(raw: &RawResponse) -> NextcloudTalkResult<T>
    where
        T: DeserializeOwned,
    {
        let envelope: OcsEnvelope<T> = serde_json::from_str(&raw.body)?;
        if envelope.ocs.meta.status.eq_ignore_ascii_case("ok") {
            Ok(envelope.ocs.data)
        } else {
            Err(NextcloudTalkError::Api {
                status_code: raw.status,
                ocs_status_code: Some(envelope.ocs.meta.statuscode),
                message: envelope.ocs.meta.message,
                request_id: extract_request_id(&raw.headers),
            })
        }
    }

    /// Issue a request, deriving replay safety from the HTTP method.
    ///
    /// br-kxd3e: GET, DELETE, PUT, and HEAD are idempotent per HTTP semantics,
    /// so replaying them is safe. POST is treated as NOT replay-safe, which
    /// fails closed — a POST added later gets the safe behaviour without its
    /// author having to know this exists. The POSTs that genuinely converge on
    /// the same state opt in via [`Self::request_raw_replay_safe`].
    async fn request_raw(
        &self,
        runtime: &ConnectorRuntime,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        form: Vec<(String, String)>,
    ) -> NextcloudTalkResult<RawResponse> {
        let replay_safe = method != Method::POST;
        self.request_raw_with_replay_safety(runtime, method, path, query, form, replay_safe)
            .await
    }

    /// Issue a POST whose replay cannot duplicate a side effect.
    async fn request_raw_replay_safe(
        &self,
        runtime: &ConnectorRuntime,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        form: Vec<(String, String)>,
    ) -> NextcloudTalkResult<RawResponse> {
        self.request_raw_with_replay_safety(runtime, method, path, query, form, true)
            .await
    }

    async fn request_raw_with_replay_safety(
        &self,
        runtime: &ConnectorRuntime,
        method: Method,
        path: &str,
        mut query: Vec<(String, String)>,
        form: Vec<(String, String)>,
        replay_safe: bool,
    ) -> NextcloudTalkResult<RawResponse> {
        query.push(("format".into(), "json".into()));
        if let Some(force_language) = &self.force_language {
            query.push(("forceLanguage".into(), force_language.clone()));
        }

        let url = format!("{}{}", self.server_url, path);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let method_for_log = method.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let client = self.client.clone();
            let auth = self.auth.clone();
            let url = url.clone();
            let method = method.clone();
            let query = query.clone();
            let form = form.clone();
            let method_for_log = method_for_log.clone();
            async move {
                debug!(attempt, method = %method_for_log, path = %redact_url(&url), "Nextcloud Talk request");

                let mut request = client.request(method, &url).query(&query);
                request = apply_auth(request, &auth);
                if !form.is_empty() {
                    request = request
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(serialize_form(&form));
                }

                let response = match request.send().await {
                    Ok(response) => response,
                    Err(error) => {
                        // Only a connect-phase failure proves the request never
                        // reached the server.
                        let replayable =
                            replay_safe || !transport_error_reached_service(&error);
                        return AttemptOutcome::retryable_if_replayable(
                            NextcloudTalkError::Http(error),
                            None,
                            replayable,
                        );
                    }
                };

                let status = response.status().as_u16();
                let headers = response.headers().clone();
                let retry_after = parse_retry_after_ms(&headers);
                let body = response.text().await.unwrap_or_default();
                let raw = RawResponse {
                    status,
                    headers: headers.clone(),
                    body,
                };

                if status == 304 {
                    return AttemptOutcome::Success(raw);
                }

                if !(200..300).contains(&status) {
                    let error = NextcloudTalkError::from_api_response(
                        status,
                        &raw.body,
                        extract_request_id(&headers),
                        retry_after,
                    );
                    let decision =
                        classify_http_status(status, retry_after.map(Duration::from_millis));
                    if error.is_retryable() && !matches!(decision, RetryDecision::Terminal) {
                        // A 429 was refused WITHOUT being performed, so it stays
                        // retryable even for a non-replay-safe POST. Every other
                        // retryable class here is a 5xx, which means the server
                        // received the request and may have acted on it.
                        let replayable = replay_safe || status == 429;
                        return AttemptOutcome::retryable_if_replayable(
                            error,
                            retry_after.map(Duration::from_millis),
                            replayable,
                        );
                    }
                    return AttemptOutcome::Terminal(error);
                }

                AttemptOutcome::Success(raw)
            }
        })
        .await
    }
}

fn apply_auth(builder: RequestBuilder, auth: &NextcloudTalkAuth) -> RequestBuilder {
    match auth {
        NextcloudTalkAuth::Basic { username, password } => {
            builder.basic_auth(username, Some(password))
        }
        NextcloudTalkAuth::AppPassword {
            username,
            app_password,
        } => builder.basic_auth(username, Some(app_password)),
        NextcloudTalkAuth::BearerToken { access_token } => builder.bearer_auth(access_token),
        NextcloudTalkAuth::CredentialId { credential_id } => {
            builder.header(CREDENTIAL_ID_HEADER, credential_id)
        }
    }
}

fn push_optional(form: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        form.push((key.into(), value.to_string()));
    }
}

fn push_optional_u16(form: &mut Vec<(String, String)>, key: &str, value: Option<u16>) {
    if let Some(value) = value {
        form.push((key.into(), value.to_string()));
    }
}

fn push_optional_message_id(form: &mut Vec<(String, String)>, key: &str, value: Option<MessageId>) {
    if let Some(value) = value {
        form.push((key.into(), value.get().to_string()));
    }
}

fn bool_flag(value: bool) -> String {
    if value { "1".into() } else { "0".into() }
}

fn encode_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn serialize_share_meta(meta: &FileShareMetaData) -> NextcloudTalkResult<String> {
    serde_json::to_string(meta).map_err(NextcloudTalkError::Json)
}

fn extract_request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("x-nextcloud-request-id"))
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn parse_retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
}

fn extract_message_id_header(headers: &HeaderMap, name: &str) -> Option<MessageId> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(MessageId)
}

fn serialize_form(form: &[(String, String)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(
        form.iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    serializer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NextcloudTalkConfig;

    fn base_config() -> NextcloudTalkConfig {
        NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com/subdir",
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "secret"
            }
        }))
        .expect("config")
    }

    #[test]
    fn client_normalizes_server_url() {
        let client = NextcloudTalkClient::new(&base_config()).expect("client");
        assert_eq!(client.server_url(), "https://cloud.example.com/subdir");
        assert_eq!(client.auth_mode(), "app_password");
    }

    #[test]
    fn encode_segments_preserves_token_structure() {
        assert_eq!(encode_segment("room/with space"), "room%2Fwith%20space");
    }

    #[test]
    fn parse_message_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Chat-Last-Given", HeaderValue::from_static("42"));
        headers.insert("X-Chat-Last-Common-Read", HeaderValue::from_static("41"));

        assert_eq!(
            extract_message_id_header(&headers, "X-Chat-Last-Given").map(MessageId::get),
            Some(42)
        );
        assert_eq!(
            extract_message_id_header(&headers, "X-Chat-Last-Common-Read").map(MessageId::get),
            Some(41)
        );
    }

    #[test]
    fn serialize_share_meta_uses_nextcloud_field_names() {
        let meta = FileShareMetaData {
            message_type: Some("voice-message".into()),
            caption: Some("Standup notes".into()),
            reply_to: Some(MessageId(42)),
        };

        let encoded = serialize_share_meta(&meta).expect("metadata should serialize");
        assert!(encoded.contains("\"messageType\":\"voice-message\""));
        assert!(encoded.contains("\"caption\":\"Standup notes\""));
        assert!(encoded.contains("\"replyTo\":42"));
        assert!(!encoded.contains("message_type"));
        assert!(!encoded.contains("reply_to"));
    }
}
