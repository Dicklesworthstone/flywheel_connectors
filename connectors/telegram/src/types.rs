//! Telegram API types.
//!
//! Types definitions for Telegram Bot API objects.

#![allow(dead_code)]

use std::{collections::HashSet, fmt};

use fcp_prelude::{CredentialId, FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, de};

pub const DEFAULT_TELEGRAM_BASE_URL: &str = "https://api.telegram.org";
pub const MIN_POLL_TIMEOUT_SECS: i32 = 1;
pub const MAX_POLL_TIMEOUT_SECS: i32 = 50;
pub const MIN_POLL_LEASE_TTL_SECS: u64 = 10;
pub const MIN_WEBHOOK_SECRET_TOKEN_CHARS: usize = 1;
pub const MAX_WEBHOOK_SECRET_TOKEN_CHARS: usize = 256;
pub const MAX_WEBHOOK_URL_CHARS: usize = 2048;
pub const MIN_WEBHOOK_MAX_CONNECTIONS: i64 = 1;
pub const MAX_WEBHOOK_MAX_CONNECTIONS: i64 = 100;
const MAX_REPLY_TO_MESSAGE_DEPTH: usize = 8;
pub const TELEGRAM_CHAT_ACTIONS: &[&str] = &[
    "typing",
    "upload_photo",
    "record_video",
    "upload_video",
    "record_voice",
    "upload_voice",
    "upload_document",
    "choose_sticker",
    "find_location",
    "record_video_note",
    "upload_video_note",
];
pub const DEFAULT_TELEGRAM_ALLOWED_UPDATES: &[&str] = &[
    "message",
    "edited_message",
    "channel_post",
    "edited_channel_post",
    "business_connection",
    "business_message",
    "edited_business_message",
    "deleted_business_messages",
    "message_reaction",
    "message_reaction_count",
    "inline_query",
    "chosen_inline_result",
    "callback_query",
    "shipping_query",
    "pre_checkout_query",
    "poll",
    "poll_answer",
    "my_chat_member",
    "chat_member",
    "chat_join_request",
];
pub const KNOWN_ALLOWED_UPDATES: &[&str] = DEFAULT_TELEGRAM_ALLOWED_UPDATES;
pub const TELEGRAM_POLLING_CURSOR_STATE_VERSION: u8 = 2;

/// Update object representing an incoming event.
/// Telegram API response wrapper.
#[derive(Debug, Deserialize)]
pub struct TelegramResponse<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub description: Option<String>,
    pub error_code: Option<i32>,
}

/// Telegram Update object.
#[derive(Debug, Clone)]
pub struct Update {
    pub update_id: i64,
    pub kind: UpdateKind,
}

impl<'de> Deserialize<'de> for Update {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| de::Error::custom("Telegram update must be a JSON object"))?;

        let update_id = object
            .remove("update_id")
            .ok_or_else(|| de::Error::missing_field("update_id"))
            .and_then(|value| i64::deserialize(value).map_err(de::Error::custom))?;

        let update_kind_count = KNOWN_ALLOWED_UPDATES
            .iter()
            .filter(|field| object.get(**field).is_some_and(|value| !value.is_null()))
            .count();
        if update_kind_count > 1 {
            return Err(de::Error::custom(
                "Telegram update includes multiple update payload kinds",
            ));
        }

        let kind = if let Some(value) = object.remove("message").filter(|value| !value.is_null()) {
            UpdateKind::Message(serde_json::from_value(value).map_err(de::Error::custom)?)
        } else if let Some(value) = object
            .remove("edited_message")
            .filter(|value| !value.is_null())
        {
            UpdateKind::EditedMessage(serde_json::from_value(value).map_err(de::Error::custom)?)
        } else if let Some(value) = object
            .remove("channel_post")
            .filter(|value| !value.is_null())
        {
            UpdateKind::ChannelPost(serde_json::from_value(value).map_err(de::Error::custom)?)
        } else if let Some(value) = object
            .remove("edited_channel_post")
            .filter(|value| !value.is_null())
        {
            UpdateKind::EditedChannelPost(serde_json::from_value(value).map_err(de::Error::custom)?)
        } else if let Some(value) = object
            .remove("callback_query")
            .filter(|value| !value.is_null())
        {
            UpdateKind::CallbackQuery(serde_json::from_value(value).map_err(de::Error::custom)?)
        } else {
            UpdateKind::Unknown
        };

        Ok(Self { update_id, kind })
    }
}

/// Different kinds of updates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Message(Message),
    EditedMessage(Message),
    ChannelPost(Message),
    EditedChannelPost(Message),
    CallbackQuery(CallbackQuery),
    #[serde(other)]
    Unknown,
}

/// Telegram Message object.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub from: Option<User>,
    pub chat: Chat,
    pub date: i64,
    pub text: Option<String>,
    pub caption: Option<String>,
    pub photo: Option<Vec<PhotoSize>>,
    pub document: Option<Document>,
    pub audio: Option<Audio>,
    pub video: Option<Video>,
    pub voice: Option<Voice>,
    #[serde(default, deserialize_with = "deserialize_reply_to_message")]
    pub reply_to_message: Option<Box<Message>>,
    pub message_thread_id: Option<i64>,
}

fn deserialize_reply_to_message<'de, D>(deserializer: D) -> Result<Option<Box<Message>>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };

    ensure_reply_to_message_depth(&value, 1).map_err(de::Error::custom)?;
    let message = Message::deserialize(value).map_err(de::Error::custom)?;
    Ok(Some(Box::new(message)))
}

fn ensure_reply_to_message_depth(
    value: &serde_json::Value,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > MAX_REPLY_TO_MESSAGE_DEPTH {
        return Err("reply_to_message nesting exceeds Telegram parser limit");
    }

    if let Some(reply) = value.get("reply_to_message") {
        if !reply.is_null() {
            ensure_reply_to_message_depth(reply, depth + 1)?;
        }
    }

    Ok(())
}

/// Telegram User object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: i64,
    pub is_bot: bool,
    pub first_name: String,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub language_code: Option<String>,
}

/// Telegram Chat object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub chat_type: String,
    pub title: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Photo size in a photo array.
#[derive(Debug, Clone, Deserialize)]
pub struct PhotoSize {
    pub file_id: String,
    pub file_unique_id: String,
    pub width: i32,
    pub height: i32,
    pub file_size: Option<i64>,
}

/// Document attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Document {
    pub file_id: String,
    pub file_unique_id: String,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Audio attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Audio {
    pub file_id: String,
    pub file_unique_id: String,
    pub duration: i32,
    pub title: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Video attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Video {
    pub file_id: String,
    pub file_unique_id: String,
    pub width: i32,
    pub height: i32,
    pub duration: i32,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Voice message.
#[derive(Debug, Clone, Deserialize)]
pub struct Voice {
    pub file_id: String,
    pub file_unique_id: String,
    pub duration: i32,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Callback query from inline keyboard.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    pub message: Option<Message>,
    pub chat_instance: String,
    pub data: Option<String>,
}

/// File info returned by getFile.
#[derive(Debug, Clone, Deserialize)]
pub struct File {
    pub file_id: String,
    pub file_unique_id: String,
    pub file_size: Option<i64>,
    pub file_path: Option<String>,
}

/// Bot info returned by getMe.
#[derive(Debug, Clone, Deserialize)]
pub struct BotInfo {
    pub id: i64,
    pub is_bot: bool,
    pub first_name: String,
    pub username: Option<String>,
    pub can_join_groups: Option<bool>,
    pub can_read_all_group_messages: Option<bool>,
    pub supports_inline_queries: Option<bool>,
}

/// Send message request parameters.
#[derive(Debug, Serialize)]
pub struct SendMessageRequest {
    pub chat_id: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
}

/// Send chat action request parameters.
#[derive(Debug, Serialize)]
pub struct SendChatActionRequest {
    pub chat_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_connection_id: Option<String>,
}

/// Telegram message reaction type for setMessageReaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReactionType {
    Emoji { emoji: String },
    CustomEmoji { custom_emoji_id: String },
}

/// Set message reaction request parameters.
#[derive(Debug, Serialize)]
pub struct SetMessageReactionRequest {
    pub chat_id: String,
    pub message_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reaction: Option<Vec<ReactionType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_big: Option<bool>,
}

/// setWebhook request parameters.
#[derive(Debug, Clone, Serialize)]
pub struct SetWebhookRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_updates: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_pending_updates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}

/// deleteWebhook request parameters.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteWebhookRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_pending_updates: Option<bool>,
}

/// Webhook status returned by getWebhookInfo.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookInfo {
    pub url: String,
    pub has_custom_certificate: bool,
    pub pending_update_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synchronization_error_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_updates: Option<Vec<String>>,
}

/// Get updates request parameters.
#[derive(Debug, Serialize)]
pub struct GetUpdatesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_updates: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramAuthConfig {
    BotToken,
    CredentialId(CredentialId),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelegramInboundPolicyMode {
    #[default]
    Deny,
    Open,
    Allowlist,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TelegramPolicyId(String);

impl TelegramPolicyId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TelegramPolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_TELEGRAM_ID]")
    }
}

impl<'de> Deserialize<'de> for TelegramPolicyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TelegramPolicyIdVisitor;

        impl de::Visitor<'_> for TelegramPolicyIdVisitor {
            type Value = TelegramPolicyId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Telegram numeric ID as a string or integer")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = value.trim();
                if value.is_empty() {
                    return Err(E::custom("Telegram policy IDs must not be empty"));
                }
                Ok(TelegramPolicyId(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TelegramPolicyId(value.to_string()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TelegramPolicyId(value.to_string()))
            }
        }

        deserializer.deserialize_any(TelegramPolicyIdVisitor)
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramInboundPolicy {
    pub mode: TelegramInboundPolicyMode,
    pub allowed_user_ids: Vec<TelegramPolicyId>,
    pub allowed_chat_ids: Vec<TelegramPolicyId>,
    pub allowed_topic_resource_uris: Vec<String>,
}

impl Default for TelegramInboundPolicy {
    fn default() -> Self {
        Self {
            mode: TelegramInboundPolicyMode::Deny,
            allowed_user_ids: Vec::new(),
            allowed_chat_ids: Vec::new(),
            allowed_topic_resource_uris: Vec::new(),
        }
    }
}

impl fmt::Debug for TelegramInboundPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramInboundPolicy")
            .field("mode", &self.mode)
            .field("allowed_user_ids", &self.allowed_user_ids.len())
            .field("allowed_chat_ids", &self.allowed_chat_ids.len())
            .field(
                "allowed_topic_resource_uris",
                &self.allowed_topic_resource_uris.len(),
            )
            .finish()
    }
}

impl TelegramInboundPolicy {
    #[must_use]
    pub fn has_allowlist_entries(&self) -> bool {
        !self.allowed_user_ids.is_empty()
            || !self.allowed_chat_ids.is_empty()
            || !self.allowed_topic_resource_uris.is_empty()
    }

    pub fn validate(&self) -> FcpResult<()> {
        validate_policy_ids("allowed_user_ids", &self.allowed_user_ids, false)?;
        validate_policy_ids("allowed_chat_ids", &self.allowed_chat_ids, true)?;
        validate_topic_resource_uris(&self.allowed_topic_resource_uris)?;

        if self.mode == TelegramInboundPolicyMode::Allowlist && !self.has_allowlist_entries() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "inbound_policy allowlist mode requires at least one allowed user, chat, or topic resource"
                        .into(),
            });
        }

        Ok(())
    }
}

fn validate_policy_ids(
    label: &str,
    ids: &[TelegramPolicyId],
    allow_negative: bool,
) -> FcpResult<()> {
    let mut seen = HashSet::new();
    for id in ids {
        let value = id.as_str();
        if !is_valid_policy_numeric_id(value, allow_negative) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{label} contains invalid Telegram ID: {value}"),
            });
        }
        if !seen.insert(value) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{label} contains duplicate Telegram ID: {value}"),
            });
        }
    }
    Ok(())
}

fn validate_topic_resource_uris(values: &[String]) -> FcpResult<()> {
    let mut seen = HashSet::new();
    for value in values {
        if value.trim() != value || value.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_topic_resource_uris entries must be non-empty canonical strings"
                    .into(),
            });
        }
        if !is_valid_topic_resource_uri(value) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "allowed_topic_resource_uris contains invalid Telegram topic resource URI: {value}"
                ),
            });
        }
        if !seen.insert(value.as_str()) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "allowed_topic_resource_uris contains duplicate Telegram topic resource URI: {value}"
                ),
            });
        }
    }
    Ok(())
}

fn is_valid_topic_resource_uri(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("telegram:chat:") else {
        return false;
    };
    let Some((chat_id, topic_id)) = rest.split_once(":topic:") else {
        return false;
    };
    is_valid_policy_numeric_id(chat_id, true) && is_valid_policy_numeric_id(topic_id, false)
}

fn is_valid_policy_numeric_id(value: &str, allow_negative: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    let digits = if allow_negative {
        value.strip_prefix('-').unwrap_or(value)
    } else {
        value
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Telegram connector configuration.
#[derive(Clone, Default, Deserialize)]
pub struct TelegramConfig {
    /// Bot credential (required)
    #[serde(default)]
    pub credential: Option<String>,

    /// Credential object reference for secretless setups.
    #[serde(default)]
    pub credential_id: Option<CredentialId>,

    /// Custom API base URL (optional)
    #[serde(default)]
    pub base_url: Option<String>,

    /// Polling timeout in seconds
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout: i32,

    /// Allowed updates filter
    #[serde(default)]
    pub allowed_updates: Vec<String>,

    /// External Telegram sender policy, enforced before EventEnvelope emission.
    #[serde(default)]
    pub inbound_policy: TelegramInboundPolicy,

    /// Telegram webhook secret token forwarded from
    /// X-Telegram-Bot-Api-Secret-Token for webhook mode.
    #[serde(default)]
    pub webhook_secret_token: Option<String>,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[REDACTED]"),
            )
            .field("credential_id", &self.credential_id)
            .field("base_url", &self.base_url)
            .field("poll_timeout", &self.poll_timeout)
            .field("allowed_updates", &self.allowed_updates)
            .field("inbound_policy", &self.inbound_policy)
            .field(
                "webhook_secret_token",
                &self.webhook_secret_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub(crate) fn default_poll_timeout() -> i32 {
    30
}

impl TelegramConfig {
    pub fn resolve_auth_mode(&self) -> FcpResult<TelegramAuthConfig> {
        let inline_credential = self
            .credential
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        match (inline_credential, self.credential_id) {
            (Some(_), None) => Ok(TelegramAuthConfig::BotToken),
            (None, Some(id)) => Ok(TelegramAuthConfig::CredentialId(id)),
            (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Provide exactly one of credential or credential_id".into(),
            }),
            (None, None) => Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required credential or credential_id in configuration".into(),
            }),
        }
    }

    pub fn normalize_base_url(&self) -> FcpResult<String> {
        let raw = self
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_TELEGRAM_BASE_URL)
            .trim();

        if raw.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url cannot be empty".into(),
            });
        }

        let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid base_url: {error}"),
        })?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must use http or https".into(),
            });
        }
        if parsed.host_str().is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must include a host".into(),
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must not include userinfo".into(),
            });
        }
        if parsed.path() != "/" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must not include a path".into(),
            });
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must not include query or fragment components".into(),
            });
        }
        let host = parsed.host_str().unwrap_or_default();
        let is_local_test_host = host.eq_ignore_ascii_case("localhost")
            || host.ends_with(".localhost")
            || host == "127.0.0.1"
            || host == "::1";
        if parsed.scheme() == "http" && !is_local_test_host {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                        .into(),
            });
        }
        if !host.eq_ignore_ascii_case("api.telegram.org") && !is_local_test_host {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url host must be api.telegram.org or a local test host".into(),
            });
        }

        Ok(raw.trim_end_matches('/').to_string())
    }

    pub fn validate_runtime_settings(&self) -> FcpResult<()> {
        if !(MIN_POLL_TIMEOUT_SECS..=MAX_POLL_TIMEOUT_SECS).contains(&self.poll_timeout) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "poll_timeout must be between {MIN_POLL_TIMEOUT_SECS} and {MAX_POLL_TIMEOUT_SECS} seconds"
                ),
            });
        }

        validate_allowed_updates(&self.allowed_updates)?;
        self.inbound_policy.validate()?;
        if let Some(token) = self.webhook_secret_token.as_deref() {
            validate_webhook_secret_token(token)?;
        }

        Ok(())
    }

    #[must_use]
    pub fn normalized_allowed_updates(&self) -> Vec<String> {
        if self.allowed_updates.is_empty() {
            return DEFAULT_TELEGRAM_ALLOWED_UPDATES
                .iter()
                .map(|update| (*update).to_string())
                .collect();
        }
        self.allowed_updates.clone()
    }

    #[must_use]
    pub fn auth_label(&self) -> &'static str {
        if self.credential_id.is_some() {
            "credential_id"
        } else {
            "bot_token"
        }
    }
}

pub(crate) fn validate_webhook_secret_token(token: &str) -> FcpResult<()> {
    if token.len() < MIN_WEBHOOK_SECRET_TOKEN_CHARS || token.len() > MAX_WEBHOOK_SECRET_TOKEN_CHARS
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "webhook_secret_token must be between {MIN_WEBHOOK_SECRET_TOKEN_CHARS} and {MAX_WEBHOOK_SECRET_TOKEN_CHARS} characters"
            ),
        });
    }
    if token.trim() != token || token.chars().any(char::is_control) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook_secret_token must not contain leading/trailing whitespace or control characters".into(),
        });
    }
    if !token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "webhook_secret_token must contain only ASCII letters, digits, underscore, or hyphen"
                    .into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_allowed_updates(updates: &[String]) -> FcpResult<()> {
    let mut seen = HashSet::new();
    for update in updates {
        if update.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_updates entries must not be empty".into(),
            });
        }
        if !seen.insert(update.as_str()) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("allowed_updates contains duplicate value: {update}"),
            });
        }
        if !KNOWN_ALLOWED_UPDATES.contains(&update.as_str()) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("allowed_updates contains unsupported type: {update}"),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_webhook_url(url: &str) -> FcpResult<()> {
    if url.is_empty() || url.trim() != url || url.len() > MAX_WEBHOOK_URL_CHARS {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "webhook url must be non-empty, trimmed, and at most {MAX_WEBHOOK_URL_CHARS} characters"
            ),
        });
    }

    let parsed = Url::parse(url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid webhook url: {error}"),
    })?;
    if parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook url must use https".into(),
        });
    }
    if parsed.host_str().is_none() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook url must include a host".into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook url must not include userinfo".into(),
        });
    }
    if parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook url must not include a fragment".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_webhook_max_connections(max_connections: i64) -> FcpResult<()> {
    if !(MIN_WEBHOOK_MAX_CONNECTIONS..=MAX_WEBHOOK_MAX_CONNECTIONS).contains(&max_connections) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "max_connections must be between {MIN_WEBHOOK_MAX_CONNECTIONS} and {MAX_WEBHOOK_MAX_CONNECTIONS}"
            ),
        });
    }
    Ok(())
}

pub(crate) fn validate_webhook_ip_address(ip_address: &str) -> FcpResult<()> {
    ip_address
        .parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("ip_address must be a valid IP address: {error}"),
        })
}

pub(crate) fn validate_set_webhook_request(request: &SetWebhookRequest) -> FcpResult<()> {
    validate_webhook_url(&request.url)?;
    if let Some(max_connections) = request.max_connections {
        validate_webhook_max_connections(max_connections)?;
    }
    if let Some(allowed_updates) = request.allowed_updates.as_ref() {
        validate_allowed_updates(allowed_updates)?;
    }
    if let Some(ip_address) = request.ip_address.as_deref() {
        validate_webhook_ip_address(ip_address)?;
    }
    if let Some(secret_token) = request.secret_token.as_deref() {
        validate_webhook_secret_token(secret_token)?;
    }
    Ok(())
}

pub(crate) fn validate_chat_action(action: &str) -> FcpResult<()> {
    if TELEGRAM_CHAT_ACTIONS.contains(&action) {
        return Ok(());
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!("unsupported Telegram chat action: {action}"),
    })
}

pub(crate) fn validate_reactions(reactions: &[ReactionType]) -> FcpResult<()> {
    if reactions.len() > 1 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Telegram bots can set at most one non-paid reaction per message".into(),
        });
    }
    for reaction in reactions {
        match reaction {
            ReactionType::Emoji { emoji } => validate_reaction_field("emoji", emoji)?,
            ReactionType::CustomEmoji { custom_emoji_id } => {
                validate_reaction_field("custom_emoji_id", custom_emoji_id)?;
            }
        }
    }
    Ok(())
}

fn validate_reaction_field(field: &str, value: &str) -> FcpResult<()> {
    if value.trim() != value || value.is_empty() || value.chars().any(char::is_control) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "{field} must be a non-empty value without surrounding whitespace or control characters"
            ),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResult {
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub critical: bool,
}

impl DoctorResult {
    #[must_use]
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self { status, checks }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramPollingCursorState {
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub bot_id: Option<String>,
    pub offset: Option<i64>,
    pub last_poll_count: usize,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramPollLeaseRecord {
    pub holder_instance_id: String,
    pub lease_seq: u64,
    pub updated_at: u64,
    pub expires_at: u64,
}

/// Options for sending messages.
#[derive(Debug, Default, Clone)]
pub struct SendMessageOptions {
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

#[allow(dead_code)] // Helper methods for future use
impl SendMessageOptions {
    /// Set parse mode to HTML.
    #[must_use]
    pub fn html(mut self) -> Self {
        self.parse_mode = Some("HTML".into());
        self
    }

    /// Set parse mode to MarkdownV2.
    #[must_use]
    pub fn markdown_v2(mut self) -> Self {
        self.parse_mode = Some("MarkdownV2".into());
        self
    }

    /// Set reply to a specific message.
    #[must_use]
    pub fn reply_to_message_id(mut self, id: i64) -> Self {
        self.reply_to_message_id = Some(id);
        self
    }
}

/// Options for sending media.
#[derive(Debug, Default, Clone)]
pub struct SendMediaOptions {
    pub caption: Option<String>,
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

/// Request body for send media methods.
///
/// Telegram expects the media field name to vary by type (photo, document, etc.).
/// We use a custom serializer to emit the correct field name.
#[derive(Debug)]
pub struct SendMediaRequest {
    pub chat_id: String,
    pub media_field: String,
    pub media_value: String,
    pub caption: Option<String>,
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

impl Serialize for SendMediaRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut count = 2;
        if self.caption.is_some() {
            count += 1;
        }
        if self.parse_mode.is_some() {
            count += 1;
        }
        if self.reply_to_message_id.is_some() {
            count += 1;
        }
        if self.message_thread_id.is_some() {
            count += 1;
        }

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("chat_id", &self.chat_id)?;
        map.serialize_entry(&self.media_field, &self.media_value)?;
        if let Some(caption) = &self.caption {
            map.serialize_entry("caption", caption)?;
        }
        if let Some(parse_mode) = &self.parse_mode {
            map.serialize_entry("parse_mode", parse_mode)?;
        }
        if let Some(reply_to_message_id) = self.reply_to_message_id {
            map.serialize_entry("reply_to_message_id", &reply_to_message_id)?;
        }
        if let Some(message_thread_id) = self.message_thread_id {
            map.serialize_entry("message_thread_id", &message_thread_id)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    // ---- TelegramResponse ----

    #[test]
    fn telegram_response_ok() {
        let json = r#"{"ok":true,"result":42}"#;
        let resp: TelegramResponse<i32> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.result, Some(42));
        assert!(resp.description.is_none());
    }

    #[test]
    fn telegram_response_error() {
        let json = r#"{"ok":false,"description":"Not Found","error_code":404}"#;
        let resp: TelegramResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error_code, Some(404));
        assert_eq!(resp.description.as_deref(), Some("Not Found"));
    }

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: 123,
            is_bot: true,
            first_name: "TestBot".to_string(),
            last_name: None,
            username: Some("test_bot".to_string()),
            language_code: Some("en".to_string()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 123);
        assert!(back.is_bot);
    }

    // ---- Chat ----

    #[test]
    fn chat_serde_roundtrip() {
        let chat = Chat {
            id: -100_123_456,
            chat_type: "supergroup".to_string(),
            title: Some("Test Group".to_string()),
            username: None,
            first_name: None,
            last_name: None,
        };
        let json = serde_json::to_string(&chat).unwrap();
        assert!(json.contains("\"type\":\"supergroup\""));
        let back: Chat = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, -100_123_456);
    }

    // ---- Message ----

    #[test]
    fn message_deserialize() {
        let json = json!({
            "message_id": 1,
            "chat": {"id": 123, "type": "private"},
            "date": 1_700_000_000,
            "text": "Hello!"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.text.as_deref(), Some("Hello!"));
        assert!(msg.from.is_none());
        assert!(msg.photo.is_none());
    }

    fn minimal_message_value(message_id: i64, reply_to_message: Option<Value>) -> Value {
        let mut message = json!({
            "message_id": message_id,
            "chat": {"id": 123, "type": "private"},
            "date": 1_700_000_000,
            "text": format!("message {message_id}")
        });

        if let Some(reply) = reply_to_message {
            if let Value::Object(fields) = &mut message {
                fields.insert("reply_to_message".into(), reply);
            }
        }

        message
    }

    fn reply_chain_value(depth: usize) -> Value {
        let mut reply = None;
        for idx in (0..depth).rev() {
            let message_id = i64::try_from(idx).unwrap_or(i64::MAX);
            reply = Some(minimal_message_value(message_id, reply));
        }
        match reply {
            Some(value) => value,
            None => minimal_message_value(0, None),
        }
    }

    #[test]
    fn message_deserialize_accepts_bounded_reply_chain() {
        let json = minimal_message_value(1, Some(reply_chain_value(MAX_REPLY_TO_MESSAGE_DEPTH)));
        let result = serde_json::from_value::<Message>(json);

        assert!(result.is_ok(), "bounded reply chain must parse: {result:?}");
        let has_reply = result.ok().and_then(|msg| msg.reply_to_message).is_some();
        assert!(has_reply);
    }

    #[test]
    fn message_deserialize_rejects_overdeep_reply_chain() {
        let json =
            minimal_message_value(1, Some(reply_chain_value(MAX_REPLY_TO_MESSAGE_DEPTH + 1)));
        let result = serde_json::from_value::<Message>(json);

        assert!(result.is_err(), "overdeep reply chain must be rejected");
        let error_message = result.err().map_or_else(String::new, |err| err.to_string());
        assert!(
            error_message.contains("reply_to_message nesting exceeds Telegram parser limit"),
            "unexpected error: {error_message}"
        );
    }

    // ---- PhotoSize ----

    #[test]
    fn photo_size_deserialize() {
        let json = json!({
            "file_id": "abc123",
            "file_unique_id": "unique1",
            "width": 320,
            "height": 240,
            "file_size": 15000
        });
        let photo: PhotoSize = serde_json::from_value(json).unwrap();
        assert_eq!(photo.width, 320);
        assert_eq!(photo.file_size, Some(15000));
    }

    // ---- Document ----

    #[test]
    fn document_deserialize() {
        let json = json!({
            "file_id": "doc1",
            "file_unique_id": "uniq1",
            "file_name": "report.pdf",
            "mime_type": "application/pdf"
        });
        let doc: Document = serde_json::from_value(json).unwrap();
        assert_eq!(doc.file_name.as_deref(), Some("report.pdf"));
    }

    // ---- BotInfo ----

    #[test]
    fn bot_info_deserialize() {
        let json = json!({
            "id": 123,
            "is_bot": true,
            "first_name": "MyBot",
            "username": "my_bot",
            "can_join_groups": true,
            "can_read_all_group_messages": false,
            "supports_inline_queries": false
        });
        let bot: BotInfo = serde_json::from_value(json).unwrap();
        assert!(bot.is_bot);
        assert_eq!(bot.can_join_groups, Some(true));
    }

    // ---- File ----

    #[test]
    fn file_deserialize() {
        let json = json!({
            "file_id": "f1",
            "file_unique_id": "fu1",
            "file_size": 1024,
            "file_path": "photos/file_0.jpg"
        });
        let file: File = serde_json::from_value(json).unwrap();
        assert_eq!(file.file_path.as_deref(), Some("photos/file_0.jpg"));
    }

    // ---- SendMessageRequest ----

    #[test]
    fn send_message_request_serialize() {
        let req = SendMessageRequest {
            chat_id: "123".to_string(),
            text: "Hello!".to_string(),
            parse_mode: Some("HTML".to_string()),
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"parse_mode\":\"HTML\""));
        assert!(!json.contains("reply_to_message_id"));
    }

    // ---- GetUpdatesRequest ----

    #[test]
    fn get_updates_request_serialize_minimal() {
        let req = GetUpdatesRequest {
            offset: None,
            limit: None,
            timeout: None,
            allowed_updates: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "{}");
    }

    // ---- UpdateKind ----

    #[test]
    fn update_with_message() {
        let json = json!({
            "update_id": 100,
            "message": {
                "message_id": 1,
                "chat": {"id": 123, "type": "private"},
                "date": 1_700_000_000,
                "text": "hi"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 100);
        assert!(matches!(update.kind, UpdateKind::Message(_)));
        if let UpdateKind::Message(msg) = &update.kind {
            assert_eq!(msg.text.as_deref(), Some("hi"));
        }
    }

    // ---- CallbackQuery ----

    #[test]
    fn callback_query_deserialize() {
        let json = json!({
            "id": "cb1",
            "from": {"id": 123, "is_bot": false, "first_name": "Alice"},
            "chat_instance": "inst1",
            "data": "button_clicked"
        });
        let cb: CallbackQuery = serde_json::from_value(json).unwrap();
        assert_eq!(cb.data.as_deref(), Some("button_clicked"));
        assert_eq!(cb.from.first_name, "Alice");
    }

    // ---- TelegramResponse additional ----

    #[test]
    fn telegram_response_ok_with_none_result() {
        let json = r#"{"ok":true}"#;
        let resp: TelegramResponse<i32> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.result.is_none());
        assert!(resp.description.is_none());
        assert!(resp.error_code.is_none());
    }

    // ---- User additional ----

    #[test]
    fn user_all_optional_fields_none() {
        let json = json!({
            "id": 999,
            "is_bot": false,
            "first_name": "Alice"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, 999);
        assert!(!user.is_bot);
        assert_eq!(user.first_name, "Alice");
        assert!(user.last_name.is_none());
        assert!(user.username.is_none());
        assert!(user.language_code.is_none());
    }

    #[test]
    fn user_clone() {
        let user = User {
            id: 1,
            is_bot: false,
            first_name: "Bob".into(),
            last_name: Some("Smith".into()),
            username: Some("bob_smith".into()),
            language_code: Some("de".into()),
        };
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.first_name, user.first_name);
        assert_eq!(cloned.last_name, user.last_name);
        assert_eq!(cloned.username, user.username);
        assert_eq!(cloned.language_code, user.language_code);
    }

    #[test]
    fn user_debug() {
        let user = User {
            id: 42,
            is_bot: true,
            first_name: "DebugBot".into(),
            last_name: None,
            username: None,
            language_code: None,
        };
        let debug = format!("{user:?}");
        assert!(debug.contains("User"));
        assert!(debug.contains("42"));
        assert!(debug.contains("DebugBot"));
    }

    // ---- Chat additional ----

    #[test]
    fn chat_private_type() {
        let json = json!({
            "id": 555,
            "type": "private",
            "first_name": "Carol"
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert_eq!(chat.id, 555);
        assert_eq!(chat.chat_type, "private");
        assert!(chat.title.is_none());
        assert_eq!(chat.first_name.as_deref(), Some("Carol"));
    }

    #[test]
    fn chat_clone() {
        let chat = Chat {
            id: -100_999,
            chat_type: "group".into(),
            title: Some("My Group".into()),
            username: None,
            first_name: None,
            last_name: None,
        };
        let cloned = chat.clone();
        assert_eq!(cloned.id, chat.id);
        assert_eq!(cloned.chat_type, chat.chat_type);
        assert_eq!(cloned.title, chat.title);
    }

    #[test]
    fn chat_debug() {
        let chat = Chat {
            id: 1,
            chat_type: "channel".into(),
            title: Some("Chan".into()),
            username: Some("chan_user".into()),
            first_name: None,
            last_name: None,
        };
        let debug = format!("{chat:?}");
        assert!(debug.contains("Chat"));
        assert!(debug.contains("channel"));
    }

    // ---- Message additional ----

    #[test]
    fn message_with_photo_array() {
        let json = json!({
            "message_id": 10,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "photo": [
                {
                    "file_id": "small",
                    "file_unique_id": "us",
                    "width": 90,
                    "height": 90,
                    "file_size": 1000
                },
                {
                    "file_id": "large",
                    "file_unique_id": "ul",
                    "width": 800,
                    "height": 600,
                    "file_size": 50000
                }
            ]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let photos = msg.photo.unwrap();
        assert_eq!(photos.len(), 2);
        assert_eq!(photos[0].file_id, "small");
        assert_eq!(photos[1].width, 800);
    }

    #[test]
    fn message_with_document() {
        let json = json!({
            "message_id": 11,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "document": {
                "file_id": "doc_id",
                "file_unique_id": "doc_uniq",
                "file_name": "notes.txt",
                "mime_type": "text/plain",
                "file_size": 256
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let doc = msg.document.unwrap();
        assert_eq!(doc.file_id, "doc_id");
        assert_eq!(doc.file_name.as_deref(), Some("notes.txt"));
    }

    #[test]
    fn message_with_audio() {
        let json = json!({
            "message_id": 12,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "audio": {
                "file_id": "audio_id",
                "file_unique_id": "audio_uniq",
                "duration": 180,
                "title": "Song Title",
                "mime_type": "audio/mpeg",
                "file_size": 3_000_000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let audio = msg.audio.unwrap();
        assert_eq!(audio.duration, 180);
        assert_eq!(audio.title.as_deref(), Some("Song Title"));
    }

    #[test]
    fn message_with_video() {
        let json = json!({
            "message_id": 13,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "video": {
                "file_id": "vid_id",
                "file_unique_id": "vid_uniq",
                "width": 1920,
                "height": 1080,
                "duration": 60,
                "mime_type": "video/mp4",
                "file_size": 10_000_000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let video = msg.video.unwrap();
        assert_eq!(video.width, 1920);
        assert_eq!(video.height, 1080);
        assert_eq!(video.duration, 60);
    }

    #[test]
    fn message_with_voice() {
        let json = json!({
            "message_id": 14,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "voice": {
                "file_id": "voice_id",
                "file_unique_id": "voice_uniq",
                "duration": 5,
                "mime_type": "audio/ogg",
                "file_size": 8000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let voice = msg.voice.unwrap();
        assert_eq!(voice.duration, 5);
        assert_eq!(voice.mime_type.as_deref(), Some("audio/ogg"));
    }

    #[test]
    fn message_with_reply_to_message() {
        let json = json!({
            "message_id": 20,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_001,
            "text": "This is a reply",
            "reply_to_message": {
                "message_id": 19,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "Original message"
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.text.as_deref(), Some("This is a reply"));
        let reply = msg.reply_to_message.unwrap();
        assert_eq!(reply.message_id, 19);
        assert_eq!(reply.text.as_deref(), Some("Original message"));
    }

    #[test]
    fn message_with_message_thread_id() {
        let json = json!({
            "message_id": 30,
            "chat": {"id": -100_555, "type": "supergroup", "title": "Forum"},
            "date": 1_700_000_000,
            "message_thread_id": 42,
            "text": "Topic reply"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.message_thread_id, Some(42));
        assert_eq!(msg.text.as_deref(), Some("Topic reply"));
    }

    #[test]
    fn message_with_caption_no_text() {
        let json = json!({
            "message_id": 31,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "caption": "Photo caption here",
            "photo": [{
                "file_id": "p1",
                "file_unique_id": "pu1",
                "width": 320,
                "height": 240
            }]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert!(msg.text.is_none());
        assert_eq!(msg.caption.as_deref(), Some("Photo caption here"));
        assert!(msg.photo.is_some());
    }

    // ---- PhotoSize additional ----

    #[test]
    fn photo_size_without_file_size() {
        let json = json!({
            "file_id": "ph1",
            "file_unique_id": "phu1",
            "width": 160,
            "height": 120
        });
        let photo: PhotoSize = serde_json::from_value(json).unwrap();
        assert_eq!(photo.width, 160);
        assert_eq!(photo.height, 120);
        assert!(photo.file_size.is_none());
    }

    #[test]
    fn photo_size_clone() {
        let photo = PhotoSize {
            file_id: "ph2".into(),
            file_unique_id: "phu2".into(),
            width: 640,
            height: 480,
            file_size: Some(25000),
        };
        let cloned = photo.clone();
        assert_eq!(cloned.file_id, photo.file_id);
        assert_eq!(cloned.width, photo.width);
        assert_eq!(cloned.file_size, photo.file_size);
    }

    // ---- Document additional ----

    #[test]
    fn document_minimal() {
        let json = json!({
            "file_id": "doc_min",
            "file_unique_id": "doc_min_u"
        });
        let doc: Document = serde_json::from_value(json).unwrap();
        assert_eq!(doc.file_id, "doc_min");
        assert!(doc.file_name.is_none());
        assert!(doc.mime_type.is_none());
        assert!(doc.file_size.is_none());
    }

    #[test]
    fn document_clone() {
        let doc = Document {
            file_id: "d1".into(),
            file_unique_id: "du1".into(),
            file_name: Some("data.csv".into()),
            mime_type: Some("text/csv".into()),
            file_size: Some(4096),
        };
        let cloned = doc.clone();
        assert_eq!(cloned.file_id, doc.file_id);
        assert_eq!(cloned.file_name, doc.file_name);
        assert_eq!(cloned.mime_type, doc.mime_type);
        assert_eq!(cloned.file_size, doc.file_size);
    }

    // ---- Audio additional ----

    #[test]
    fn audio_full_fields() {
        let json = json!({
            "file_id": "aud1",
            "file_unique_id": "audu1",
            "duration": 240,
            "title": "My Song",
            "mime_type": "audio/mpeg",
            "file_size": 5_000_000
        });
        let audio: Audio = serde_json::from_value(json).unwrap();
        assert_eq!(audio.file_id, "aud1");
        assert_eq!(audio.duration, 240);
        assert_eq!(audio.title.as_deref(), Some("My Song"));
        assert_eq!(audio.mime_type.as_deref(), Some("audio/mpeg"));
        assert_eq!(audio.file_size, Some(5_000_000));
    }

    #[test]
    fn audio_minimal() {
        let json = json!({
            "file_id": "aud2",
            "file_unique_id": "audu2",
            "duration": 10
        });
        let audio: Audio = serde_json::from_value(json).unwrap();
        assert_eq!(audio.duration, 10);
        assert!(audio.title.is_none());
        assert!(audio.mime_type.is_none());
        assert!(audio.file_size.is_none());
    }

    #[test]
    fn audio_clone() {
        let audio = Audio {
            file_id: "ac".into(),
            file_unique_id: "acu".into(),
            duration: 60,
            title: Some("Clone Test".into()),
            mime_type: Some("audio/ogg".into()),
            file_size: Some(100_000),
        };
        let cloned = audio.clone();
        assert_eq!(cloned.file_id, audio.file_id);
        assert_eq!(cloned.duration, audio.duration);
        assert_eq!(cloned.title, audio.title);
    }

    // ---- Video additional ----

    #[test]
    fn video_full_fields() {
        let json = json!({
            "file_id": "vid1",
            "file_unique_id": "vidu1",
            "width": 3840,
            "height": 2160,
            "duration": 300,
            "mime_type": "video/mp4",
            "file_size": 100_000_000
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert_eq!(video.width, 3840);
        assert_eq!(video.height, 2160);
        assert_eq!(video.duration, 300);
        assert_eq!(video.mime_type.as_deref(), Some("video/mp4"));
        assert_eq!(video.file_size, Some(100_000_000));
    }

    #[test]
    fn video_clone() {
        let video = Video {
            file_id: "vc".into(),
            file_unique_id: "vcu".into(),
            width: 1280,
            height: 720,
            duration: 30,
            mime_type: None,
            file_size: None,
        };
        let cloned = video.clone();
        assert_eq!(cloned.file_id, video.file_id);
        assert_eq!(cloned.width, video.width);
        assert_eq!(cloned.height, video.height);
    }

    // ---- Voice additional ----

    #[test]
    fn voice_full_fields() {
        let json = json!({
            "file_id": "v1",
            "file_unique_id": "vu1",
            "duration": 15,
            "mime_type": "audio/ogg",
            "file_size": 12000
        });
        let voice: Voice = serde_json::from_value(json).unwrap();
        assert_eq!(voice.duration, 15);
        assert_eq!(voice.mime_type.as_deref(), Some("audio/ogg"));
        assert_eq!(voice.file_size, Some(12000));
    }

    #[test]
    fn voice_minimal() {
        let json = json!({
            "file_id": "v2",
            "file_unique_id": "vu2",
            "duration": 1
        });
        let voice: Voice = serde_json::from_value(json).unwrap();
        assert_eq!(voice.duration, 1);
        assert!(voice.mime_type.is_none());
        assert!(voice.file_size.is_none());
    }

    #[test]
    fn voice_clone() {
        let voice = Voice {
            file_id: "vcl".into(),
            file_unique_id: "vclu".into(),
            duration: 7,
            mime_type: Some("audio/ogg".into()),
            file_size: Some(5000),
        };
        let cloned = voice.clone();
        assert_eq!(cloned.file_id, voice.file_id);
        assert_eq!(cloned.duration, voice.duration);
        assert_eq!(cloned.mime_type, voice.mime_type);
    }

    // ---- CallbackQuery additional ----

    #[test]
    fn callback_query_without_message_and_data() {
        let json = json!({
            "id": "cb_no_msg",
            "from": {"id": 555, "is_bot": false, "first_name": "Dave"},
            "chat_instance": "inst2"
        });
        let cb: CallbackQuery = serde_json::from_value(json).unwrap();
        assert_eq!(cb.id, "cb_no_msg");
        assert!(cb.message.is_none());
        assert!(cb.data.is_none());
    }

    #[test]
    fn callback_query_clone() {
        let cb = CallbackQuery {
            id: "cb_clone".into(),
            from: User {
                id: 1,
                is_bot: false,
                first_name: "Eve".into(),
                last_name: None,
                username: None,
                language_code: None,
            },
            message: None,
            chat_instance: "ci".into(),
            data: Some("action".into()),
        };
        let cloned = cb.clone();
        assert_eq!(cloned.id, cb.id);
        assert_eq!(cloned.from.first_name, cb.from.first_name);
        assert_eq!(cloned.data, cb.data);
    }

    // ---- File additional ----

    #[test]
    fn file_minimal() {
        let json = json!({
            "file_id": "f_min",
            "file_unique_id": "fu_min"
        });
        let file: File = serde_json::from_value(json).unwrap();
        assert_eq!(file.file_id, "f_min");
        assert!(file.file_size.is_none());
        assert!(file.file_path.is_none());
    }

    #[test]
    fn file_clone() {
        let file = File {
            file_id: "fc".into(),
            file_unique_id: "fcu".into(),
            file_size: Some(2048),
            file_path: Some("documents/file.pdf".into()),
        };
        let cloned = file.clone();
        assert_eq!(cloned.file_id, file.file_id);
        assert_eq!(cloned.file_size, file.file_size);
        assert_eq!(cloned.file_path, file.file_path);
    }

    // ---- BotInfo additional ----

    #[test]
    fn bot_info_minimal() {
        let json = json!({
            "id": 777,
            "is_bot": true,
            "first_name": "MinBot"
        });
        let bot: BotInfo = serde_json::from_value(json).unwrap();
        assert_eq!(bot.id, 777);
        assert!(bot.is_bot);
        assert_eq!(bot.first_name, "MinBot");
        assert!(bot.username.is_none());
        assert!(bot.can_join_groups.is_none());
        assert!(bot.can_read_all_group_messages.is_none());
        assert!(bot.supports_inline_queries.is_none());
    }

    #[test]
    fn bot_info_clone() {
        let bot = BotInfo {
            id: 888,
            is_bot: true,
            first_name: "CloneBot".into(),
            username: Some("clone_bot".into()),
            can_join_groups: Some(true),
            can_read_all_group_messages: Some(false),
            supports_inline_queries: Some(true),
        };
        let cloned = bot.clone();
        assert_eq!(cloned.id, bot.id);
        assert_eq!(cloned.first_name, bot.first_name);
        assert_eq!(cloned.username, bot.username);
        assert_eq!(cloned.can_join_groups, bot.can_join_groups);
        assert_eq!(cloned.supports_inline_queries, bot.supports_inline_queries);
    }

    // ---- SendMessageRequest additional ----

    #[test]
    fn send_message_request_with_all_fields() {
        let req = SendMessageRequest {
            chat_id: "12345".into(),
            text: "Hi!".into(),
            parse_mode: Some("MarkdownV2".into()),
            reply_to_message_id: Some(7),
            message_thread_id: Some(99),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"chat_id\":\"12345\""));
        assert!(json.contains("\"text\":\"Hi!\""));
        assert!(json.contains("\"parse_mode\":\"MarkdownV2\""));
        assert!(json.contains("\"reply_to_message_id\":7"));
        assert!(json.contains("\"message_thread_id\":99"));
    }

    #[test]
    fn send_message_request_skip_serializing_none_fields() {
        let req = SendMessageRequest {
            chat_id: "999".into(),
            text: "Minimal".into(),
            parse_mode: None,
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"chat_id\""));
        assert!(json.contains("\"text\""));
        assert!(!json.contains("parse_mode"));
        assert!(!json.contains("reply_to_message_id"));
        assert!(!json.contains("message_thread_id"));
    }

    // ---- GetUpdatesRequest additional ----

    #[test]
    fn get_updates_request_with_all_fields() {
        let req = GetUpdatesRequest {
            offset: Some(500),
            limit: Some(100),
            timeout: Some(30),
            allowed_updates: Some(vec!["message".into(), "callback_query".into()]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"offset\":500"));
        assert!(json.contains("\"limit\":100"));
        assert!(json.contains("\"timeout\":30"));
        assert!(json.contains("\"allowed_updates\""));
        assert!(json.contains("\"message\""));
        assert!(json.contains("\"callback_query\""));
    }

    #[test]
    fn get_updates_request_serialize_with_allowed_updates() {
        let req = GetUpdatesRequest {
            offset: None,
            limit: None,
            timeout: None,
            allowed_updates: Some(vec![
                "message".into(),
                "edited_message".into(),
                "channel_post".into(),
            ]),
        };
        let val: serde_json::Value = serde_json::to_value(&req).unwrap();
        let updates = val["allowed_updates"].as_array().unwrap();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0], "message");
        assert_eq!(updates[2], "channel_post");
    }

    #[test]
    fn telegram_config_rejects_base_url_userinfo() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "https://bot:secret@api.telegram.org"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn telegram_config_rejects_base_url_path_query_and_fragment() {
        for base_url in [
            "https://api.telegram.org/proxy",
            "https://api.telegram.org?proxy=1",
            "https://api.telegram.org#fragment",
            "http://localhost:8080/api",
        ] {
            let config: TelegramConfig =
                serde_json::from_value(json!({ "base_url": base_url })).unwrap();
            let err = config.normalize_base_url().unwrap_err();
            assert!(
                matches!(err, FcpError::InvalidRequest { .. }),
                "base_url should be rejected: {base_url}"
            );
        }
    }

    #[test]
    fn telegram_config_accepts_valid_webhook_secret_token() {
        let forwarded_header = ["telegram", "webhook", "fixture"].join("-");
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "123456:ABCDEFGHIJKLMNOPQRSTUVWXyz012345",
            "webhook_secret_token": forwarded_header
        }))
        .unwrap();

        assert!(config.validate_runtime_settings().is_ok());
        assert_eq!(
            config.webhook_secret_token.as_deref(),
            Some(forwarded_header.as_str())
        );
    }

    #[test]
    fn telegram_config_rejects_invalid_webhook_secret_tokens() {
        for secret in ["", " leading", "trailing ", "line\nbreak", "bad.token"] {
            let config: TelegramConfig = serde_json::from_value(json!({
                "credential": "123456:ABCDEFGHIJKLMNOPQRSTUVWXyz012345",
                "webhook_secret_token": secret
            }))
            .unwrap();
            assert!(
                config.validate_runtime_settings().is_err(),
                "webhook_secret_token should be rejected: {secret:?}"
            );
        }
    }

    #[test]
    fn set_webhook_request_validation_enforces_telegram_limits() {
        let valid = SetWebhookRequest {
            url: "https://example.com/fcp/telegram/webhook".into(),
            ip_address: Some("203.0.113.10".into()),
            max_connections: Some(40),
            allowed_updates: Some(vec!["message".into(), "callback_query".into()]),
            drop_pending_updates: Some(true),
            secret_token: Some("telegram-webhook-secret_1".into()),
        };
        assert!(validate_set_webhook_request(&valid).is_ok());

        for request in [
            SetWebhookRequest {
                url: "http://example.com/hook".into(),
                ..valid.clone()
            },
            SetWebhookRequest {
                max_connections: Some(101),
                ..valid.clone()
            },
            SetWebhookRequest {
                allowed_updates: Some(vec!["unknown_update".into()]),
                ..valid.clone()
            },
            SetWebhookRequest {
                ip_address: Some("not-an-ip".into()),
                ..valid
            },
        ] {
            assert!(validate_set_webhook_request(&request).is_err());
        }
    }

    // ---- UpdateKind additional ----

    #[test]
    fn update_kind_edited_message() {
        let json = json!({
            "update_id": 200,
            "edited_message": {
                "message_id": 5,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "edited text"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 200);
        assert!(matches!(update.kind, UpdateKind::EditedMessage(_)));
        if let UpdateKind::EditedMessage(msg) = &update.kind {
            assert_eq!(msg.message_id, 5);
            assert_eq!(msg.text.as_deref(), Some("edited text"));
        }
    }

    #[test]
    fn update_kind_channel_post() {
        let json = json!({
            "update_id": 201,
            "channel_post": {
                "message_id": 77,
                "chat": {"id": -100_222, "type": "channel", "title": "News"},
                "date": 1_700_000_000,
                "text": "Channel announcement"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert!(matches!(update.kind, UpdateKind::ChannelPost(_)));
        if let UpdateKind::ChannelPost(msg) = &update.kind {
            assert_eq!(msg.message_id, 77);
            assert_eq!(msg.chat.chat_type, "channel");
            assert_eq!(msg.text.as_deref(), Some("Channel announcement"));
        }
    }

    #[test]
    fn update_kind_callback_query_variant() {
        let json = json!({
            "update_id": 202,
            "callback_query": {
                "id": "cq_update",
                "from": {"id": 42, "is_bot": false, "first_name": "Frank"},
                "chat_instance": "ci_val",
                "data": "btn_press"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert!(matches!(update.kind, UpdateKind::CallbackQuery(_)));
        if let UpdateKind::CallbackQuery(cq) = &update.kind {
            assert_eq!(cq.id, "cq_update");
            assert_eq!(cq.data.as_deref(), Some("btn_press"));
        }
    }

    #[test]
    fn update_rejects_multiple_implemented_kinds() {
        let json = json!({
            "update_id": 203,
            "message": {
                "message_id": 1,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "primary"
            },
            "callback_query": {
                "id": "cq_update",
                "from": {"id": 42, "is_bot": false, "first_name": "Frank"},
                "chat_instance": "ci_val",
                "data": "btn_press"
            }
        });
        let result = serde_json::from_value::<Update>(json);

        assert!(result.is_err(), "ambiguous update must be rejected");
        let error_message = result.err().map_or_else(String::new, |err| err.to_string());
        assert!(
            error_message.contains("multiple update payload kinds"),
            "unexpected error: {error_message}"
        );
    }

    #[test]
    fn update_rejects_implemented_plus_unsupported_kind() {
        let json = json!({
            "update_id": 203,
            "message": {
                "message_id": 1,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "primary"
            },
            "poll": {
                "id": "poll1",
                "question": "ready?",
                "options": []
            }
        });
        let result = serde_json::from_value::<Update>(json);

        assert!(
            result.is_err(),
            "mixed known update payloads must be rejected"
        );
        let error_message = result.err().map_or_else(String::new, |err| err.to_string());
        assert!(
            error_message.contains("multiple update payload kinds"),
            "unexpected error: {error_message}"
        );
    }

    #[test]
    fn update_with_only_unsupported_kind_is_unknown() {
        let json = json!({
            "update_id": 203,
            "poll": {
                "id": "poll1",
                "question": "ready?",
                "options": []
            }
        });
        let result = serde_json::from_value::<Update>(json);

        assert!(
            matches!(
                result,
                Ok(Update {
                    update_id: 203,
                    kind: UpdateKind::Unknown
                })
            ),
            "unsupported-only update must parse as Unknown: {result:?}"
        );
    }

    #[test]
    fn update_kind_unknown_constructed_directly() {
        // #[serde(other)] with #[serde(flatten)] has limitations with
        // unrecognized keys in JSON. Test that the Unknown variant exists
        // and can be pattern-matched.
        let kind = UpdateKind::Unknown;
        assert!(matches!(kind, UpdateKind::Unknown));
        let debug = format!("{kind:?}");
        assert!(debug.contains("Unknown"));
    }

    #[test]
    fn update_kind_unknown_clone() {
        let kind = UpdateKind::Unknown;
        let cloned = kind.clone();
        assert!(matches!(kind, UpdateKind::Unknown));
        assert!(matches!(cloned, UpdateKind::Unknown));
    }

    #[test]
    fn update_kind_edited_channel_post() {
        let json = json!({
            "update_id": 204,
            "edited_channel_post": {
                "message_id": 88,
                "chat": {"id": -100_333, "type": "channel", "title": "EditedChan"},
                "date": 1_700_000_000,
                "text": "Corrected post"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert!(matches!(update.kind, UpdateKind::EditedChannelPost(_)));
        if let UpdateKind::EditedChannelPost(msg) = &update.kind {
            assert_eq!(msg.message_id, 88);
            assert_eq!(msg.text.as_deref(), Some("Corrected post"));
        }
    }
}
