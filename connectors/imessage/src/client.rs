//! `BlueBubbles` HTTP client.
//!
//! Communicates with the `BlueBubbles` REST API to bridge `iMessage`.
//! All requests require the server password as a query parameter.

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::{Client, Method, Url, multipart};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{BlueBubblesError, BlueBubblesResult};

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> BlueBubblesResult<&'a str> {
    if value.trim().is_empty() {
        return Err(BlueBubblesError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(BlueBubblesError::Validation(format!(
            "{field} contains invalid path characters"
        )));
    }
    Ok(value)
}

use crate::types::{
    BlueBubblesConfig, BlueBubblesMediaSendConfig, BlueBubblesSendTarget,
    BlueBubblesTargetResolution, BlueBubblesTargetService, Chat, Message, PaginatedResponse,
    QueryParams, SEND_METHOD_APPLE_SCRIPT, SEND_METHOD_PRIVATE_API, SendMediaOptions,
    SendMessageOptions, SendMessageRequest, SendMessageResponse, ServerInfo, WebhookRegistration,
    WebhookRegistrationRequest, normalize_bluebubbles_handle,
    normalize_bluebubbles_tapback_reaction,
};

const TARGET_RESOLUTION_PAGE_LIMIT: u64 = 500;
const TARGET_RESOLUTION_MAX_SCAN: u64 = 5_000;

fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn duration_to_ms(d: Duration) -> u64 {
    d.as_millis().try_into().unwrap_or(u64::MAX)
}

async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, BlueBubblesError> {
    resp.json::<T>().await.map_err(BlueBubblesError::Http)
}

async fn decode_server_info(resp: reqwest::Response) -> Result<ServerInfo, BlueBubblesError> {
    let value = resp
        .json::<serde_json::Value>()
        .await
        .map_err(BlueBubblesError::Http)?;
    let info = value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(&value);
    serde_json::from_value(info.clone()).map_err(BlueBubblesError::Json)
}

async fn decode_json_value(resp: reqwest::Response) -> Result<Value, BlueBubblesError> {
    resp.json::<Value>().await.map_err(BlueBubblesError::Http)
}

async fn decode_optional_json_value(resp: reqwest::Response) -> Result<Value, BlueBubblesError> {
    let bytes = resp.bytes().await.map_err(BlueBubblesError::Http)?;
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&bytes).map_err(BlueBubblesError::Json)
}

async fn decode_bounded_message(
    resp: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Message, BlueBubblesError> {
    if let Some(content_length) = resp.content_length() {
        let max_response_bytes = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
        if content_length > max_response_bytes {
            return Err(BlueBubblesError::Validation(format!(
                "message lookup response exceeds {max_response_bytes} bytes"
            )));
        }
    }

    let bytes = resp.bytes().await.map_err(BlueBubblesError::Http)?;
    if bytes.len() > max_response_bytes {
        return Err(BlueBubblesError::Validation(format!(
            "message lookup response exceeds {max_response_bytes} bytes"
        )));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(BlueBubblesError::Json)?;
    let message = value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(&value);
    serde_json::from_value(message.clone()).map_err(BlueBubblesError::Json)
}

fn parse_webhook_registrations(
    value: &Value,
) -> Result<Vec<WebhookRegistration>, BlueBubblesError> {
    let data = value
        .get("data")
        .filter(|value| value.is_array() || value.is_object())
        .unwrap_or(value);

    if let Some(webhooks) = data.as_array() {
        return webhooks
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(BlueBubblesError::Json);
    }

    if let Some(webhooks) = data
        .as_object()
        .and_then(|object| object.get("webhooks"))
        .and_then(Value::as_array)
    {
        return webhooks
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(BlueBubblesError::Json);
    }

    Err(BlueBubblesError::Json(serde_json::Error::io(
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "BlueBubbles webhook list response did not contain an array",
        ),
    )))
}

fn parse_macos_major_version(version: Option<&str>) -> Option<u64> {
    let version = version?.trim();
    let digits: String = version.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn extract_chat_identifier_from_guid(chat_guid: &str) -> Option<String> {
    let mut parts = chat_guid.split(';');
    let _service = parts.next()?;
    let _separator = parts.next()?;
    let identifier = parts.next()?.trim();
    if parts.next().is_some() || identifier.is_empty() {
        None
    } else {
        Some(identifier.to_string())
    }
}

fn extract_handle_from_chat_guid(chat_guid: &str) -> Option<String> {
    let mut parts = chat_guid.split(';');
    let _service = parts.next()?;
    let separator = parts.next()?;
    let handle = parts.next()?;
    if parts.next().is_some() || separator != "-" {
        None
    } else {
        normalize_bluebubbles_handle(handle)
    }
}

fn chat_matches_identifier(chat: &Chat, target: &str) -> bool {
    chat.guid == target
        || chat
            .chat_identifier
            .as_deref()
            .is_some_and(|identifier| identifier == target)
        || extract_chat_identifier_from_guid(&chat.guid).as_deref() == Some(target)
}

fn preferred_and_other_service(
    service: BlueBubblesTargetService,
) -> (&'static str, &'static str, Option<&'static str>) {
    let preferred = service.preferred_guid_service();
    let other = if preferred == "SMS" {
        "iMessage"
    } else {
        "SMS"
    };
    (preferred, other, Some(service.as_str()))
}

fn parse_chat_query_response(value: &Value) -> BlueBubblesResult<Vec<Chat>> {
    let data = value
        .get("data")
        .filter(|value| value.is_array() || value.is_object())
        .unwrap_or(value);

    if data.is_array() {
        return serde_json::from_value(data.clone()).map_err(BlueBubblesError::Json);
    }

    if let Some(chats) = data
        .as_object()
        .and_then(|object| object.get("chats"))
        .and_then(Value::as_array)
    {
        return serde_json::from_value(Value::Array(chats.clone())).map_err(BlueBubblesError::Json);
    }

    Err(BlueBubblesError::Json(serde_json::Error::io(
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "BlueBubbles chat query response did not contain an array",
        ),
    )))
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(|candidate| match candidate {
            Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
}

fn extract_bluebubbles_message_id(value: &Value) -> Option<String> {
    let data_array_first = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|array| array.first());
    let roots = [
        Some(value),
        value.get("data"),
        value.get("result"),
        value.get("payload"),
        value.get("message"),
        data_array_first,
    ];

    roots.into_iter().flatten().find_map(|root| {
        value_string(
            root,
            &[
                "message_id",
                "messageId",
                "messageGuid",
                "message_guid",
                "guid",
                "id",
                "uuid",
            ],
        )
    })
}

fn extract_created_chat_guid(value: &Value) -> Option<String> {
    let data = value.get("data").unwrap_or(value);
    value_string(data, &["chatGuid", "chat_guid", "guid"]).or_else(|| {
        let chats = data.get("chats").or_else(|| data.get("chat"))?;
        if let Some(array) = chats.as_array() {
            return array
                .first()
                .and_then(|chat| value_string(chat, &["guid", "chatGuid", "chat_guid"]));
        }
        value_string(chats, &["guid", "chatGuid", "chat_guid"])
    })
}

fn expand_home_path(value: &str) -> PathBuf {
    if value == "~" {
        return std::env::var_os("HOME").map_or_else(|| PathBuf::from(value), PathBuf::from);
    }
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(value)
}

fn local_path_from_input(value: &str, field: &str) -> BlueBubblesResult<PathBuf> {
    let value = value.trim();
    if value.is_empty() {
        return Err(BlueBubblesError::Validation(format!(
            "{field} must not be empty"
        )));
    }

    if value.contains("://") {
        let url = Url::parse(value).map_err(|error| {
            BlueBubblesError::Validation(format!("{field} URL is invalid: {error}"))
        })?;
        if url.scheme() != "file" {
            return Err(BlueBubblesError::Validation(format!(
                "{field} must be a local filesystem path or file:// URL"
            )));
        }
        return url.to_file_path().map_err(|()| {
            BlueBubblesError::Validation(format!("{field} file:// URL is not a local path"))
        });
    }

    let path = expand_home_path(value);
    if !path.is_absolute() {
        return Err(BlueBubblesError::Validation(format!(
            "{field} must be absolute or file://"
        )));
    }
    Ok(path)
}

fn sanitize_media_filename(raw: Option<&str>, source_path: &Path) -> BlueBubblesResult<String> {
    let source_name = source_path.file_name().and_then(|name| name.to_str());
    let raw = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(source_name)
        .unwrap_or("attachment");
    let raw = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    let filename: String = raw
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '"' | '\\' | '/' | '\r' | '\n') {
                '_'
            } else {
                ch
            }
        })
        .take(255)
        .collect();
    let filename = filename.trim();
    if filename.is_empty() || matches!(filename, "." | "..") {
        return Err(BlueBubblesError::Validation(
            "media filename must not be empty".into(),
        ));
    }
    Ok(filename.to_string())
}

fn sanitize_media_content_type(raw: &str) -> BlueBubblesResult<String> {
    let content_type = raw.trim().to_ascii_lowercase();
    if content_type.is_empty()
        || content_type.contains(';')
        || content_type.matches('/').count() != 1
        || content_type
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace() || matches!(ch, '"' | '\\'))
    {
        return Err(BlueBubblesError::Validation(
            "media content_type must be a plain MIME type".into(),
        ));
    }
    Ok(content_type)
}

fn infer_media_content_type(path: &Path) -> String {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("m4v") => "video/x-m4v",
        Some("mp3") => "audio/mpeg",
        Some("caf") => "audio/x-caf",
        Some("m4a") => "audio/mp4",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn media_content_type_allowed(config: &BlueBubblesMediaSendConfig, content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    config
        .allowed_mime_types
        .iter()
        .any(|allowed| allowed == &content_type)
        || config
            .allowed_mime_prefixes
            .iter()
            .any(|prefix| content_type.starts_with(prefix))
}

fn validate_voice_media(content_type: &str, path: &Path) -> BlueBubblesResult<()> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(
        (content_type, extension.as_deref()),
        ("audio/mpeg" | "audio/mp3" | "audio/x-caf" | "audio/caf", _) | (_, Some("mp3" | "caf"))
    ) {
        return Ok(());
    }
    Err(BlueBubblesError::Validation(
        "as_voice requires an mp3 or caf audio file".into(),
    ))
}

#[derive(Debug, Clone)]
struct PreparedMediaUpload {
    bytes: Vec<u8>,
    filename: String,
    content_type: String,
    byte_len: u64,
}

fn prepare_media_upload(
    config: &BlueBubblesMediaSendConfig,
    local_path: &str,
    options: &SendMediaOptions,
) -> BlueBubblesResult<PreparedMediaUpload> {
    if config.local_roots.is_empty() {
        return Err(BlueBubblesError::Config(
            "media_send.local_roots must be configured before sending local media".into(),
        ));
    }

    let requested_path = local_path_from_input(local_path, "local_path")?;
    let canonical_path = fs::canonicalize(&requested_path).map_err(|error| {
        BlueBubblesError::Validation(format!(
            "local_path must resolve to a readable file: {error}"
        ))
    })?;

    let mut inside_allowed_root = false;
    for root in &config.local_roots {
        let root_path = expand_home_path(root);
        let canonical_root = fs::canonicalize(&root_path).map_err(|error| {
            BlueBubblesError::Config(format!(
                "media_send.local_roots contains an unreadable root: {error}"
            ))
        })?;
        if canonical_path.starts_with(&canonical_root) && canonical_path != canonical_root {
            inside_allowed_root = true;
            break;
        }
    }
    if !inside_allowed_root {
        return Err(BlueBubblesError::Validation(
            "local_path is outside configured media_send.local_roots".into(),
        ));
    }

    let metadata = fs::metadata(&canonical_path).map_err(|error| {
        BlueBubblesError::Validation(format!("local_path metadata is unavailable: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(BlueBubblesError::Validation(
            "local_path must resolve to a regular file".into(),
        ));
    }
    if metadata.len() > config.max_bytes {
        return Err(BlueBubblesError::AttachmentTooLarge {
            size_bytes: metadata.len(),
            max_bytes: config.max_bytes,
        });
    }

    let filename = sanitize_media_filename(options.filename.as_deref(), &canonical_path)?;
    let content_type = options
        .content_type
        .as_deref()
        .map(sanitize_media_content_type)
        .transpose()?
        .unwrap_or_else(|| infer_media_content_type(&canonical_path));
    if options.as_voice {
        validate_voice_media(&content_type, &canonical_path)?;
    }
    if !media_content_type_allowed(config, &content_type) {
        return Err(BlueBubblesError::Validation(format!(
            "media content_type {content_type} is not allowed by media_send"
        )));
    }

    let bytes = fs::read(&canonical_path).map_err(|error| {
        BlueBubblesError::Validation(format!("local_path must be readable: {error}"))
    })?;
    let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if byte_len > config.max_bytes {
        return Err(BlueBubblesError::AttachmentTooLarge {
            size_bytes: byte_len,
            max_bytes: config.max_bytes,
        });
    }

    Ok(PreparedMediaUpload {
        bytes,
        filename,
        content_type,
        byte_len,
    })
}

/// Send-method decision used for `BlueBubbles` text sends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SendMethodDecision {
    /// Explicit `BlueBubbles` request method.
    pub method: String,
    /// Stable reason code for logs/tests/operator diagnostics.
    pub reason: &'static str,
    /// Whether `/server/info` was available before sending.
    pub server_info_available: bool,
    /// Reported Private API state when known.
    pub private_api: Option<bool>,
    /// Reported macOS version when known.
    pub os_version: Option<String>,
    /// Optional warning for degraded-but-preserved fallback sends.
    pub warning: Option<String>,
}

impl SendMethodDecision {
    fn for_options(info: &ServerInfo, options: &SendMessageOptions) -> BlueBubblesResult<Self> {
        if options.requires_private_api() {
            if !info.private_api {
                return Err(BlueBubblesError::PrivateApiRequired {
                    feature: options.private_api_feature_label(),
                });
            }
            return Ok(Self {
                method: SEND_METHOD_PRIVATE_API.to_string(),
                reason: "rich_send_private_api_available",
                server_info_available: true,
                private_api: Some(true),
                os_version: info.os_version.clone(),
                warning: None,
            });
        }

        let major = parse_macos_major_version(info.os_version.as_deref());
        if info.private_api && major.is_some_and(|major| major >= 26) {
            return Ok(Self {
                method: SEND_METHOD_PRIVATE_API.to_string(),
                reason: "macos26_private_api_available",
                server_info_available: true,
                private_api: Some(true),
                os_version: info.os_version.clone(),
                warning: None,
            });
        }

        let reason = match (info.private_api, major) {
            (true, Some(_)) => "plain_text_apple_script_supported",
            (true, None) => "private_api_available_macos_unknown",
            (false, Some(major)) if major >= 26 => {
                "macos26_private_api_disabled_apple_script_fallback"
            }
            (false, _) => "private_api_disabled_apple_script_fallback",
        };

        Ok(Self {
            method: SEND_METHOD_APPLE_SCRIPT.to_string(),
            reason,
            server_info_available: true,
            private_api: Some(info.private_api),
            os_version: info.os_version.clone(),
            warning: None,
        })
    }

    fn unavailable(error: &BlueBubblesError) -> Self {
        Self {
            method: SEND_METHOD_APPLE_SCRIPT.to_string(),
            reason: "server_info_unavailable_apple_script_fallback",
            server_info_available: false,
            private_api: None,
            os_version: None,
            warning: Some(format!(
                "BlueBubbles server info unavailable; using explicit apple-script fallback: {error}"
            )),
        }
    }

    fn unavailable_for_options(
        error: BlueBubblesError,
        options: &SendMessageOptions,
    ) -> BlueBubblesResult<Self> {
        if options.requires_private_api() {
            if matches!(
                &error,
                BlueBubblesError::Unauthorized { .. } | BlueBubblesError::RateLimited { .. }
            ) {
                return Err(error);
            }
            return Err(BlueBubblesError::PrivateApiRequired {
                feature: format!(
                    "{} (server info unavailable: {error})",
                    options.private_api_feature_label()
                ),
            });
        }
        Ok(Self::unavailable(&error))
    }
}

/// Multipart media-send decision derived from `BlueBubbles` server capabilities.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MediaSendDecision {
    /// Optional multipart `method` field sent to `BlueBubbles`.
    pub request_method: Option<String>,
    /// Stable reason code for logs/tests/operator diagnostics.
    pub reason: &'static str,
    /// Whether `/server/info` was available before sending.
    pub server_info_available: bool,
    /// Reported Private API state when known.
    pub private_api: Option<bool>,
    /// Reported macOS version when known.
    pub os_version: Option<String>,
    /// Optional warning for degraded-but-preserved fallback sends.
    pub warning: Option<String>,
}

impl MediaSendDecision {
    fn for_options(info: &ServerInfo, options: &SendMediaOptions) -> BlueBubblesResult<Self> {
        if options.requires_private_api() {
            if !info.private_api {
                return Err(BlueBubblesError::PrivateApiRequired {
                    feature: options.private_api_feature_label(),
                });
            }
            return Ok(Self {
                request_method: Some(SEND_METHOD_PRIVATE_API.to_string()),
                reason: "media_reply_private_api_available",
                server_info_available: true,
                private_api: Some(true),
                os_version: info.os_version.clone(),
                warning: None,
            });
        }

        if info.private_api {
            return Ok(Self {
                request_method: Some(SEND_METHOD_PRIVATE_API.to_string()),
                reason: "media_send_private_api_available",
                server_info_available: true,
                private_api: Some(true),
                os_version: info.os_version.clone(),
                warning: None,
            });
        }

        Ok(Self {
            request_method: None,
            reason: "media_send_default_api_private_api_disabled",
            server_info_available: true,
            private_api: Some(false),
            os_version: info.os_version.clone(),
            warning: None,
        })
    }

    fn unavailable(error: &BlueBubblesError) -> Self {
        Self {
            request_method: None,
            reason: "server_info_unavailable_media_default_api",
            server_info_available: false,
            private_api: None,
            os_version: None,
            warning: Some(format!(
                "BlueBubbles server info unavailable; using default media upload API: {error}"
            )),
        }
    }

    fn unavailable_for_options(
        error: BlueBubblesError,
        options: &SendMediaOptions,
    ) -> BlueBubblesResult<Self> {
        if options.requires_private_api() {
            if matches!(
                &error,
                BlueBubblesError::Unauthorized { .. } | BlueBubblesError::RateLimited { .. }
            ) {
                return Err(error);
            }
            return Err(BlueBubblesError::PrivateApiRequired {
                feature: format!(
                    "{} (server info unavailable: {error})",
                    options.private_api_feature_label()
                ),
            });
        }
        Ok(Self::unavailable(&error))
    }
}

/// Private-API action family used for deterministic availability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlueBubblesPrivateApiAction {
    Edit,
    Unsend,
    Reaction,
    Typing,
    MarkRead,
}

impl BlueBubblesPrivateApiAction {
    const fn key(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Unsend => "unsend",
            Self::Reaction => "reaction",
            Self::Typing => "typing",
            Self::MarkRead => "mark_read",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Edit => "message edit",
            Self::Unsend => "message unsend",
            Self::Reaction => "tapback reaction",
            Self::Typing => "typing indicator",
            Self::MarkRead => "read receipt",
        }
    }
}

/// Stable action availability status for one `BlueBubbles` action.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlueBubblesActionStatus {
    pub supported: bool,
    pub reason: &'static str,
    pub requires_private_api: bool,
}

impl BlueBubblesActionStatus {
    const fn supported(reason: &'static str) -> Self {
        Self {
            supported: true,
            reason,
            requires_private_api: true,
        }
    }

    const fn unsupported(reason: &'static str) -> Self {
        Self {
            supported: false,
            reason,
            requires_private_api: true,
        }
    }
}

/// Server-derived `BlueBubbles` action availability snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlueBubblesActionAvailability {
    pub server_info_available: bool,
    pub server_info_error: Option<String>,
    pub private_api: Option<bool>,
    pub helper_connected: Option<bool>,
    pub os_version: Option<String>,
    pub server_version: Option<String>,
    pub edit: BlueBubblesActionStatus,
    pub unsend: BlueBubblesActionStatus,
    pub reaction: BlueBubblesActionStatus,
    pub typing: BlueBubblesActionStatus,
    pub mark_read: BlueBubblesActionStatus,
}

impl BlueBubblesActionAvailability {
    fn from_info(info: &ServerInfo) -> Self {
        Self {
            server_info_available: true,
            server_info_error: None,
            private_api: Some(info.private_api),
            helper_connected: info.helper_connected,
            os_version: info.os_version.clone(),
            server_version: info.server_version.clone(),
            edit: action_status(BlueBubblesPrivateApiAction::Edit, info),
            unsend: action_status(BlueBubblesPrivateApiAction::Unsend, info),
            reaction: action_status(BlueBubblesPrivateApiAction::Reaction, info),
            typing: action_status(BlueBubblesPrivateApiAction::Typing, info),
            mark_read: action_status(BlueBubblesPrivateApiAction::MarkRead, info),
        }
    }

    fn unavailable(error: &BlueBubblesError) -> Self {
        Self {
            server_info_available: false,
            server_info_error: Some(error.to_string()),
            private_api: None,
            helper_connected: None,
            os_version: None,
            server_version: None,
            edit: BlueBubblesActionStatus::unsupported("server_info_unavailable"),
            unsend: BlueBubblesActionStatus::unsupported("server_info_unavailable"),
            reaction: BlueBubblesActionStatus::unsupported("server_info_unavailable"),
            typing: BlueBubblesActionStatus::unsupported("server_info_unavailable"),
            mark_read: BlueBubblesActionStatus::unsupported("server_info_unavailable"),
        }
    }
}

fn action_status(
    action: BlueBubblesPrivateApiAction,
    info: &ServerInfo,
) -> BlueBubblesActionStatus {
    if !info.private_api {
        return BlueBubblesActionStatus::unsupported("private_api_disabled");
    }
    if info.helper_connected == Some(false) {
        return BlueBubblesActionStatus::unsupported("helper_disconnected");
    }

    if action == BlueBubblesPrivateApiAction::Edit {
        let major = parse_macos_major_version(info.os_version.as_deref());
        return match major {
            Some(13..=25) => BlueBubblesActionStatus::supported("private_api_macos_supported"),
            Some(0..=12) => BlueBubblesActionStatus::unsupported("macos_version_too_old"),
            Some(_) => BlueBubblesActionStatus::unsupported("macos26_edit_unsupported"),
            None => BlueBubblesActionStatus::unsupported("os_version_unknown"),
        };
    }

    BlueBubblesActionStatus::supported("private_api_supported")
}

fn action_unavailable_error(
    action: BlueBubblesPrivateApiAction,
    status: &BlueBubblesActionStatus,
    source_error: Option<&BlueBubblesError>,
) -> BlueBubblesError {
    if status.reason == "private_api_disabled" {
        return BlueBubblesError::PrivateApiRequired {
            feature: action.label().to_string(),
        };
    }
    if status.reason == "server_info_unavailable" {
        let feature = source_error.map_or_else(
            || action.label().to_string(),
            |error| format!("{} (server info unavailable: {error})", action.label()),
        );
        return BlueBubblesError::PrivateApiRequired { feature };
    }

    BlueBubblesError::UnsupportedAction {
        action: action.label().to_string(),
        reason: status.reason.to_string(),
    }
}

/// Result of a `BlueBubbles` send plus the method decision that shaped the request.
#[derive(Debug, Clone)]
pub struct SendMessageOutcome {
    /// Raw `BlueBubbles` send response.
    pub response: SendMessageResponse,
    /// Send method decision used for the request body.
    pub decision: SendMethodDecision,
}

/// Result of a `BlueBubbles` media upload plus the decision that shaped multipart fields.
#[derive(Debug, Clone)]
pub struct SendMediaOutcome {
    /// Raw `BlueBubbles` response.
    pub response: Value,
    /// Multipart method decision used for the request.
    pub decision: MediaSendDecision,
    /// Message GUID extracted from the response when present.
    pub message_id: Option<String>,
    /// Sanitized uploaded filename.
    pub filename: String,
    /// Validated uploaded MIME type.
    pub content_type: String,
    /// Uploaded byte count.
    pub byte_len: u64,
}

/// Result of creating a new `BlueBubbles` DM chat.
#[derive(Debug, Clone)]
pub struct CreateChatOutcome {
    /// Raw `BlueBubbles` response.
    pub response: Value,
    /// Private API decision used before creating the chat.
    pub decision: SendMethodDecision,
    /// Chat GUID extracted from the response when present.
    pub chat_guid: Option<String>,
    /// Message GUID extracted from the response when present.
    pub message_id: Option<String>,
}

/// `BlueBubbles` API client.
pub struct BlueBubblesClient {
    client: Client,
    server_url: String,
    server_passcode: String,
    retry_config: HttpRetryConfig,
    request_timeout: Duration,
}

impl std::fmt::Debug for BlueBubblesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueBubblesClient")
            .field("client", &self.client)
            .field("server_url", &self.server_url)
            .field("server_passcode", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl BlueBubblesClient {
    /// Create a new `BlueBubbles` client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        server_url: &str,
        server_passcode: &str,
        retry_config: HttpRetryConfig,
    ) -> BlueBubblesResult<Self> {
        Self::build(
            server_url,
            server_passcode,
            retry_config,
            Duration::from_secs(30),
        )
    }

    /// Create a client from validated connector configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn from_config(config: &BlueBubblesConfig) -> BlueBubblesResult<Self> {
        Self::build(
            &config.server_url,
            &config.server_passcode,
            config.retry.clone(),
            Duration::from_millis(config.request_timeout_ms),
        )
    }

    fn build(
        server_url: &str,
        server_passcode: &str,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> BlueBubblesResult<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(BlueBubblesError::Http)?;

        Ok(Self {
            client,
            server_url: server_url.trim().trim_end_matches('/').to_string(),
            server_passcode: server_passcode.trim().to_string(),
            retry_config,
            request_timeout,
        })
    }

    /// Get the server base URL (for diagnostics).
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Get the configured request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Get server information.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn server_info(&self, runtime: &ConnectorRuntime) -> BlueBubblesResult<ServerInfo> {
        let url = format!("{}/api/v1/server/info", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles server info");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_server_info(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Compute a server-derived action availability snapshot.
    ///
    /// # Errors
    ///
    /// Returns authentication and rate-limit errors directly; other server-info failures become
    /// an unavailable snapshot so callers can inspect deterministic disabled reasons.
    pub async fn action_availability(
        &self,
        runtime: &ConnectorRuntime,
    ) -> BlueBubblesResult<BlueBubblesActionAvailability> {
        match self.server_info(runtime).await {
            Ok(info) => Ok(BlueBubblesActionAvailability::from_info(&info)),
            Err(error) => {
                if matches!(
                    &error,
                    BlueBubblesError::Unauthorized { .. } | BlueBubblesError::RateLimited { .. }
                ) {
                    Err(error)
                } else {
                    Ok(BlueBubblesActionAvailability::unavailable(&error))
                }
            }
        }
    }

    async fn require_action_available(
        &self,
        runtime: &ConnectorRuntime,
        action: BlueBubblesPrivateApiAction,
    ) -> BlueBubblesResult<ServerInfo> {
        match self.server_info(runtime).await {
            Ok(info) => {
                let status = action_status(action, &info);
                if status.supported {
                    Ok(info)
                } else {
                    Err(action_unavailable_error(action, &status, None))
                }
            }
            Err(error) => {
                if matches!(
                    &error,
                    BlueBubblesError::Unauthorized { .. } | BlueBubblesError::RateLimited { .. }
                ) {
                    Err(error)
                } else {
                    let status = BlueBubblesActionStatus::unsupported("server_info_unavailable");
                    Err(action_unavailable_error(action, &status, Some(&error)))
                }
            }
        }
    }

    async fn private_api_json_action(
        &self,
        runtime: &ConnectorRuntime,
        action: BlueBubblesPrivateApiAction,
        method: Method,
        path: String,
        body: Option<Value>,
    ) -> BlueBubblesResult<Value> {
        self.require_action_available(runtime, action).await?;

        let url = format!("{}{}", self.server_url, path);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            let method = method.clone();
            async move {
                debug!(
                    attempt,
                    action = action.key(),
                    "Calling BlueBubbles Private API action"
                );
                let mut request = client
                    .request(method, &url)
                    .query(&[("password", &server_passcode)]);
                if let Some(body) = &body {
                    request = request.json(body);
                }
                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_optional_json_value(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// List registered `BlueBubbles` webhook callbacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails or the response cannot be parsed.
    pub async fn list_webhooks(
        &self,
        runtime: &ConnectorRuntime,
    ) -> BlueBubblesResult<Vec<WebhookRegistration>> {
        let url = format!("{}/api/v1/webhook", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Listing BlueBubbles webhooks");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json_value(resp)
                    .await
                    .and_then(|value| parse_webhook_registrations(&value))
                {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Register a `BlueBubbles` webhook callback.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn register_webhook(
        &self,
        runtime: &ConnectorRuntime,
        webhook_url: &str,
        events: Vec<String>,
        skip_if_existing: bool,
    ) -> BlueBubblesResult<Value> {
        let webhook_url = webhook_url.trim();
        if webhook_url.is_empty() {
            return Err(BlueBubblesError::Validation(
                "webhook url must not be empty".into(),
            ));
        }
        reqwest::Url::parse(webhook_url).map_err(|error| {
            BlueBubblesError::Validation(format!("webhook url must be absolute: {error}"))
        })?;
        if events.is_empty() {
            return Err(BlueBubblesError::Validation(
                "webhook events must not be empty".into(),
            ));
        }

        if skip_if_existing {
            let webhooks = self.list_webhooks(runtime).await?;
            if let Some(existing) = webhooks
                .iter()
                .find(|webhook| webhook.url.as_deref() == Some(webhook_url))
            {
                return Ok(json!({
                    "registration_status": "existing",
                    "webhook": existing,
                }));
            }
        }

        let url = format!("{}/api/v1/webhook", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let body = WebhookRegistrationRequest {
            url: webhook_url.to_string(),
            events,
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Registering BlueBubbles webhook");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json_value(resp).await {
                    Ok(value) => AttemptOutcome::Success(json!({
                        "registration_status": "registered",
                        "response": value,
                    })),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Delete a registered `BlueBubbles` webhook callback by server ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn delete_webhook(
        &self,
        runtime: &ConnectorRuntime,
        webhook_id: &str,
    ) -> BlueBubblesResult<Value> {
        let webhook_id = sanitize_path_segment(webhook_id, "webhook_id")?;
        let url = format!("{}/api/v1/webhook/{webhook_id}", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Deleting BlueBubbles webhook");
                let resp = match client
                    .delete(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json_value(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Send a text message to a chat.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        text: &str,
        options: SendMessageOptions,
    ) -> BlueBubblesResult<SendMessageOutcome> {
        let url = format!("{}/api/v1/message/text", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let decision = match self.server_info(runtime).await {
            Ok(info) => SendMethodDecision::for_options(&info, &options)?,
            Err(error) => SendMethodDecision::unavailable_for_options(error, &options)?,
        };

        let body = SendMessageRequest {
            chat_guid: chat_guid.to_string(),
            message: text.to_string(),
            temp_guid: Some(uuid::Uuid::new_v4().to_string()),
            method: decision.method.clone(),
            selected_message_guid: options.reply_to_message_guid.clone(),
            part_index: options
                .reply_to_message_guid
                .as_ref()
                .map(|_| options.reply_to_part_index.unwrap_or(0)),
            effect_id: options.effect_id.clone(),
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            let decision = decision.clone();
            async move {
                debug!(
                    attempt,
                    send_method = %decision.method,
                    decision = decision.reason,
                    "Sending iMessage via BlueBubbles"
                );
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        // br-kxd3e: only a connect-phase failure proves the
                        // send never reached BlueBubbles. See the note on the
                        // 5xx arm below for why `tempGuid` does not license a
                        // post-transmission replay.
                        let replayable = !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            BlueBubblesError::from_transport_error(e),
                            None,
                            replayable,
                        );
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    // br-kxd3e: every remaining retryable class here is a 5xx,
                    // which means BlueBubbles received the send and may already
                    // have delivered the message.
                    //
                    // This request DOES carry a stable `tempGuid` across
                    // attempts, and an earlier pass through this sweep recorded
                    // that as making the retry safe. That was an assumption, not
                    // a verified fact: BlueBubbles documents `tempGuid` as a
                    // client-side correlation id so a client can match its own
                    // optimistic entry, NOT as a server-side deduplication key.
                    // Nothing in this repo or in the API establishes that a
                    // repeat of the same tempGuid is refused. Since the failure
                    // mode is a duplicate iMessage to a real person, this fails
                    // closed; the tempGuid is kept because it is still correct
                    // and costs nothing. 429 is handled above, before this gate.
                    return AttemptOutcome::Terminal(BlueBubblesError::from_api_response(
                        status, &text,
                    ));
                }

                match decode_json::<SendMessageResponse>(resp).await {
                    Ok(response) => {
                        AttemptOutcome::Success(SendMessageOutcome { response, decision })
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Send a local media file to a chat through the `BlueBubbles` multipart endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if local-root validation, file bounds, Private API gating, or upload fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_media(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        local_path: &str,
        media_config: &BlueBubblesMediaSendConfig,
        options: SendMediaOptions,
    ) -> BlueBubblesResult<SendMediaOutcome> {
        let prepared = prepare_media_upload(media_config, local_path, &options)?;
        let url = format!("{}/api/v1/message/attachment", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let decision = match self.server_info(runtime).await {
            Ok(info) => MediaSendDecision::for_options(&info, &options)?,
            Err(error) => MediaSendDecision::unavailable_for_options(error, &options)?,
        };
        let temp_guid = uuid::Uuid::new_v4().to_string();
        let upload_timeout = Duration::from_millis(media_config.upload_timeout_ms);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let chat_guid = chat_guid.to_string();
            let prepared = prepared.clone();
            let decision = decision.clone();
            let temp_guid = temp_guid.clone();
            let caption = options.caption.clone();
            let reply_to_message_guid = options.reply_to_message_guid.clone();
            let reply_to_part_index = options.reply_to_part_index.unwrap_or(0);
            let as_voice = options.as_voice;
            async move {
                debug!(
                    attempt,
                    upload_bytes = prepared.byte_len,
                    content_type = %prepared.content_type,
                    method = %decision.request_method.as_deref().unwrap_or("default"),
                    decision = decision.reason,
                    as_voice,
                    "Sending iMessage media via BlueBubbles"
                );

                let part = match multipart::Part::bytes(prepared.bytes.clone())
                    .file_name(prepared.filename.clone())
                    .mime_str(&prepared.content_type)
                {
                    Ok(part) => part,
                    Err(error) => {
                        return AttemptOutcome::Terminal(BlueBubblesError::Validation(format!(
                            "invalid media content_type: {error}"
                        )));
                    }
                };

                let mut form = multipart::Form::new()
                    .text("chatGuid", chat_guid)
                    .text("name", prepared.filename.clone())
                    .text("tempGuid", temp_guid)
                    .part("attachment", part);
                if let Some(method) = decision.request_method.clone() {
                    form = form.text("method", method);
                }
                if as_voice {
                    form = form.text("isAudioMessage", "true");
                }
                if let Some(reply_guid) = reply_to_message_guid {
                    form = form
                        .text("selectedMessageGuid", reply_guid)
                        .text("partIndex", reply_to_part_index.to_string());
                }
                if let Some(caption) = caption {
                    form = form
                        .text("message", caption.clone())
                        .text("text", caption.clone())
                        .text("caption", caption);
                }

                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .multipart(form)
                    .timeout(upload_timeout)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_optional_json_value(resp).await {
                    Ok(response) => {
                        let message_id = extract_bluebubbles_message_id(&response);
                        AttemptOutcome::Success(SendMediaOutcome {
                            response,
                            decision,
                            message_id,
                            filename: prepared.filename,
                            content_type: prepared.content_type,
                            byte_len: prepared.byte_len,
                        })
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    async fn query_chats_for_target_resolution(
        &self,
        runtime: &ConnectorRuntime,
        offset: u64,
        limit: u64,
    ) -> BlueBubblesResult<Vec<Chat>> {
        #[derive(Clone, Debug, serde::Serialize)]
        struct ChatQueryRequest {
            limit: u64,
            offset: u64,
            #[serde(rename = "with")]
            include: Vec<&'static str>,
        }

        let url = format!("{}/api/v1/chat/query", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let body = ChatQueryRequest {
            limit,
            offset,
            include: vec!["participants"],
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            async move {
                debug!(
                    attempt,
                    offset, limit, "Querying BlueBubbles chats for send-target resolution"
                );
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json_value(resp)
                    .await
                    .and_then(|value| parse_chat_query_response(&value))
                {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Resolve an explicit send target into a chat GUID without sending a message.
    ///
    /// # Errors
    ///
    /// Returns an error if the `BlueBubbles` chat query API fails.
    #[allow(clippy::too_many_lines)]
    pub async fn resolve_send_target(
        &self,
        runtime: &ConnectorRuntime,
        target: &BlueBubblesSendTarget,
        max_scan_chats: u64,
    ) -> BlueBubblesResult<BlueBubblesTargetResolution> {
        if let BlueBubblesSendTarget::ChatGuid(chat_guid) = target {
            return Ok(BlueBubblesTargetResolution::direct(chat_guid.clone()));
        }

        let max_scan_chats = max_scan_chats.clamp(1, TARGET_RESOLUTION_MAX_SCAN);
        let mut offset = 0;
        let mut scanned_chats = 0;
        let mut scanned_pages = 0;

        let mut direct_other_service_match: Option<String> = None;
        let mut direct_unknown_service_match: Option<String> = None;
        let mut participant_preferred_match: Option<String> = None;
        let mut participant_other_service_match: Option<String> = None;
        let mut participant_unknown_service_match: Option<String> = None;

        let (preferred_service, other_service, service_preference) = match target {
            BlueBubblesSendTarget::Handle { service, .. } => preferred_and_other_service(*service),
            _ => ("iMessage", "SMS", None),
        };
        let preferred_prefix = format!("{preferred_service};-;");
        let other_prefix = format!("{other_service};-;");
        let normalized_handle = match target {
            BlueBubblesSendTarget::Handle { address, .. } => {
                Some(normalize_bluebubbles_handle(address).ok_or_else(|| {
                    BlueBubblesError::Validation("handle target must not be empty".into())
                })?)
            }
            _ => None,
        };

        while offset < max_scan_chats {
            let remaining = max_scan_chats - offset;
            let limit = TARGET_RESOLUTION_PAGE_LIMIT.min(remaining);
            let chats = self
                .query_chats_for_target_resolution(runtime, offset, limit)
                .await?;
            scanned_pages += 1;
            scanned_chats += chats.len();

            if chats.is_empty() {
                return Ok(BlueBubblesTargetResolution::not_found(
                    target.kind(),
                    service_preference,
                    scanned_chats,
                    scanned_pages,
                    false,
                ));
            }

            for chat in &chats {
                match target {
                    BlueBubblesSendTarget::ChatId(chat_id) => {
                        if chat.id == Some(*chat_id) {
                            return Ok(BlueBubblesTargetResolution {
                                chat_guid: Some(chat.guid.clone()),
                                target_kind: target.kind(),
                                match_kind: "chat_id",
                                service_preference: None,
                                scanned_chats,
                                scanned_pages,
                                exhausted: false,
                            });
                        }
                    }
                    BlueBubblesSendTarget::ChatIdentifier(identifier) => {
                        if chat_matches_identifier(chat, identifier) {
                            return Ok(BlueBubblesTargetResolution {
                                chat_guid: Some(chat.guid.clone()),
                                target_kind: target.kind(),
                                match_kind: "chat_identifier",
                                service_preference: None,
                                scanned_chats,
                                scanned_pages,
                                exhausted: false,
                            });
                        }
                    }
                    BlueBubblesSendTarget::Handle { .. } => {
                        let Some(normalized_handle) = normalized_handle.as_deref() else {
                            continue;
                        };
                        if let Some(direct_handle) = extract_handle_from_chat_guid(&chat.guid) {
                            if direct_handle == normalized_handle {
                                if chat.guid.starts_with(&preferred_prefix) {
                                    return Ok(BlueBubblesTargetResolution {
                                        chat_guid: Some(chat.guid.clone()),
                                        target_kind: target.kind(),
                                        match_kind: "direct_preferred_service",
                                        service_preference,
                                        scanned_chats,
                                        scanned_pages,
                                        exhausted: false,
                                    });
                                }
                                if chat.guid.starts_with(&other_prefix) {
                                    direct_other_service_match
                                        .get_or_insert_with(|| chat.guid.clone());
                                } else {
                                    direct_unknown_service_match
                                        .get_or_insert_with(|| chat.guid.clone());
                                }
                            }
                        }

                        if chat.guid.contains(";-;")
                            && chat.participants.iter().any(|participant| {
                                normalize_bluebubbles_handle(&participant.address).as_deref()
                                    == Some(normalized_handle)
                            })
                        {
                            if chat.guid.starts_with(&preferred_prefix) {
                                participant_preferred_match
                                    .get_or_insert_with(|| chat.guid.clone());
                            } else if chat.guid.starts_with(&other_prefix) {
                                participant_other_service_match
                                    .get_or_insert_with(|| chat.guid.clone());
                            } else {
                                participant_unknown_service_match
                                    .get_or_insert_with(|| chat.guid.clone());
                            }
                        }
                    }
                    BlueBubblesSendTarget::ChatGuid(_) => {}
                }
            }

            offset += limit;
            if chats.len() < usize::try_from(limit).unwrap_or(usize::MAX) {
                break;
            }
        }

        let exhausted = offset >= max_scan_chats;
        let matched = participant_preferred_match
            .map(|chat_guid| (chat_guid, "participant_preferred_service"))
            .or_else(|| {
                direct_other_service_match.map(|chat_guid| (chat_guid, "direct_other_service"))
            })
            .or_else(|| {
                participant_other_service_match
                    .map(|chat_guid| (chat_guid, "participant_other_service"))
            })
            .or_else(|| {
                direct_unknown_service_match.map(|chat_guid| (chat_guid, "direct_unknown_service"))
            })
            .or_else(|| {
                participant_unknown_service_match
                    .map(|chat_guid| (chat_guid, "participant_unknown_service"))
            });

        if let Some((chat_guid, match_kind)) = matched {
            Ok(BlueBubblesTargetResolution {
                chat_guid: Some(chat_guid),
                target_kind: target.kind(),
                match_kind,
                service_preference,
                scanned_chats,
                scanned_pages,
                exhausted,
            })
        } else {
            Ok(BlueBubblesTargetResolution::not_found(
                target.kind(),
                service_preference,
                scanned_chats,
                scanned_pages,
                exhausted,
            ))
        }
    }

    /// Create a new direct-message chat through the `BlueBubbles` Private API.
    ///
    /// # Errors
    ///
    /// Returns an error if Private API support is unavailable or the API call fails.
    #[allow(clippy::too_many_lines)]
    pub async fn create_chat(
        &self,
        runtime: &ConnectorRuntime,
        address: &str,
        message: &str,
    ) -> BlueBubblesResult<CreateChatOutcome> {
        #[derive(Clone, Debug, serde::Serialize)]
        struct CreateChatRequest {
            addresses: Vec<String>,
            message: String,
            #[serde(rename = "tempGuid")]
            temp_guid: String,
        }

        let address = address.trim();
        if address.is_empty() {
            return Err(BlueBubblesError::Validation(
                "create_chat address must not be empty".into(),
            ));
        }
        if message.trim().is_empty() {
            return Err(BlueBubblesError::Validation(
                "create_chat message must not be empty".into(),
            ));
        }

        let info = match self.server_info(runtime).await {
            Ok(info) => info,
            Err(error) => {
                if matches!(
                    &error,
                    BlueBubblesError::Unauthorized { .. } | BlueBubblesError::RateLimited { .. }
                ) {
                    return Err(error);
                }
                return Err(BlueBubblesError::PrivateApiRequired {
                    feature: format!("new chat creation (server info unavailable: {error})"),
                });
            }
        };
        if !info.private_api {
            return Err(BlueBubblesError::PrivateApiRequired {
                feature: "new chat creation".into(),
            });
        }
        let decision = SendMethodDecision {
            method: SEND_METHOD_PRIVATE_API.to_string(),
            reason: "new_chat_private_api_available",
            server_info_available: true,
            private_api: Some(true),
            os_version: info.os_version.clone(),
            warning: None,
        };

        let url = format!("{}/api/v1/chat/new", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let body = CreateChatRequest {
            addresses: vec![address.to_string()],
            message: message.to_string(),
            temp_guid: uuid::Uuid::new_v4().to_string(),
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            let decision = decision.clone();
            async move {
                debug!(attempt, "Creating BlueBubbles DM chat");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json_value(resp).await {
                    Ok(response) => AttemptOutcome::Success(CreateChatOutcome {
                        chat_guid: extract_created_chat_guid(&response),
                        message_id: extract_bluebubbles_message_id(&response),
                        response,
                        decision,
                    }),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Edit a sent message through the `BlueBubbles` Private API.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is unsupported or the API call fails.
    pub async fn edit_message(
        &self,
        runtime: &ConnectorRuntime,
        message_guid: &str,
        new_text: &str,
        part_index: u64,
        backwards_compatibility_message: Option<&str>,
    ) -> BlueBubblesResult<Value> {
        let message_guid = sanitize_path_segment(message_guid, "message_guid")?;
        let new_text = new_text.trim();
        if new_text.is_empty() {
            return Err(BlueBubblesError::Validation(
                "edit_message new_text must not be empty".into(),
            ));
        }
        let fallback = format!("Edited to: {new_text}");
        let backwards_compatibility_message = backwards_compatibility_message
            .and_then(|message| {
                let message = message.trim();
                (!message.is_empty()).then_some(message)
            })
            .unwrap_or(&fallback);
        let body = json!({
            "editedMessage": new_text,
            "backwardsCompatibilityMessage": backwards_compatibility_message,
            "partIndex": part_index,
        });
        self.private_api_json_action(
            runtime,
            BlueBubblesPrivateApiAction::Edit,
            Method::POST,
            format!("/api/v1/message/{message_guid}/edit"),
            Some(body),
        )
        .await
    }

    /// Unsend a sent message through the `BlueBubbles` Private API.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is unsupported or the API call fails.
    pub async fn unsend_message(
        &self,
        runtime: &ConnectorRuntime,
        message_guid: &str,
        part_index: u64,
    ) -> BlueBubblesResult<Value> {
        let message_guid = sanitize_path_segment(message_guid, "message_guid")?;
        self.private_api_json_action(
            runtime,
            BlueBubblesPrivateApiAction::Unsend,
            Method::POST,
            format!("/api/v1/message/{message_guid}/unsend"),
            Some(json!({ "partIndex": part_index })),
        )
        .await
    }

    /// Send or remove an iMessage tapback reaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is unsupported, the reaction is invalid, or the API call
    /// fails.
    pub async fn send_reaction(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        message_guid: &str,
        reaction: &str,
        remove: bool,
        part_index: u64,
    ) -> BlueBubblesResult<Value> {
        let chat_guid = chat_guid.trim();
        if chat_guid.is_empty() {
            return Err(BlueBubblesError::Validation(
                "send_reaction chat_guid must not be empty".into(),
            ));
        }
        let message_guid = message_guid.trim();
        if message_guid.is_empty() {
            return Err(BlueBubblesError::Validation(
                "send_reaction message_guid must not be empty".into(),
            ));
        }
        let reaction =
            normalize_bluebubbles_tapback_reaction(reaction, remove).ok_or_else(|| {
                BlueBubblesError::Validation(
                    "reaction must be one of love, like, dislike, laugh, emphasize, or question"
                        .into(),
                )
            })?;
        self.private_api_json_action(
            runtime,
            BlueBubblesPrivateApiAction::Reaction,
            Method::POST,
            "/api/v1/message/react".to_string(),
            Some(json!({
                "chatGuid": chat_guid,
                "selectedMessageGuid": message_guid,
                "reaction": reaction,
                "partIndex": part_index,
            })),
        )
        .await
    }

    /// Start or stop a `BlueBubbles` typing indicator.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is unsupported or the API call fails.
    pub async fn set_typing(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        typing: bool,
    ) -> BlueBubblesResult<Value> {
        let chat_guid = sanitize_path_segment(chat_guid, "chat_guid")?;
        self.private_api_json_action(
            runtime,
            BlueBubblesPrivateApiAction::Typing,
            if typing { Method::POST } else { Method::DELETE },
            format!("/api/v1/chat/{chat_guid}/typing"),
            None,
        )
        .await
    }

    /// Get a paginated list of chats.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_chats(
        &self,
        runtime: &ConnectorRuntime,
        params: &QueryParams,
    ) -> BlueBubblesResult<PaginatedResponse<Chat>> {
        let url = format!("{}/api/v1/chat", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chats");
                let mut query: Vec<(&str, String)> = vec![("password", server_passcode)];
                if let Some(offset) = params.offset {
                    query.push(("offset", offset.to_string()));
                }
                if let Some(limit) = params.limit {
                    query.push(("limit", limit.to_string()));
                }
                if let Some(sort) = &params.sort {
                    query.push(("sort", sort.clone()));
                }

                let resp = match client.get(&url).query(&query).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json::<PaginatedResponse<Chat>>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Get a single chat by GUID.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_chat(
        &self,
        runtime: &ConnectorRuntime,
        guid: &str,
    ) -> BlueBubblesResult<Chat> {
        let guid = sanitize_path_segment(guid, "chat_guid")?;
        let url = format!("{}/api/v1/chat/{guid}", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let guid = guid.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let guid = guid.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chat");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::ChatNotFound { guid });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json::<Chat>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Get messages for a chat.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_messages(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        params: &QueryParams,
    ) -> BlueBubblesResult<PaginatedResponse<Message>> {
        let chat_guid = sanitize_path_segment(chat_guid, "chat_guid")?;
        let url = format!("{}/api/v1/chat/{chat_guid}/message", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let chat_guid = chat_guid.to_string();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let chat_guid = chat_guid.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles messages");
                let mut query: Vec<(&str, String)> = vec![("password", server_passcode)];
                if let Some(offset) = params.offset {
                    query.push(("offset", offset.to_string()));
                }
                if let Some(limit) = params.limit {
                    query.push(("limit", limit.to_string()));
                }
                if let Some(after) = params.after {
                    query.push(("after", after.to_string()));
                }
                if let Some(before) = params.before {
                    query.push(("before", before.to_string()));
                }
                if let Some(sort) = &params.sort {
                    query.push(("sort", sort.clone()));
                }

                let resp = match client.get(&url).query(&query).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::ChatNotFound {
                        guid: chat_guid,
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "BlueBubbles get_messages failed");
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_json::<PaginatedResponse<Message>>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Get a single message by GUID.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails or the bounded response cannot be decoded.
    pub async fn get_message_by_guid(
        &self,
        runtime: &ConnectorRuntime,
        message_guid: &str,
        max_response_bytes: usize,
    ) -> BlueBubblesResult<Message> {
        let message_guid = sanitize_path_segment(message_guid, "message_guid")?;
        let url = format!("{}/api/v1/message/{message_guid}", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let message_guid = message_guid.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let message_guid = message_guid.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles reply context");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: format!("Message not found: {message_guid}"),
                    });
                }

                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match decode_bounded_message(resp, max_response_bytes).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Download an attachment by GUID.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails.
    pub async fn download_attachment(
        &self,
        runtime: &ConnectorRuntime,
        guid: &str,
    ) -> BlueBubblesResult<Vec<u8>> {
        let guid = sanitize_path_segment(guid, "attachment_guid")?;
        let url = format!("{}/api/v1/attachment/{guid}/download", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Downloading BlueBubbles attachment");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.bytes().await {
                    Ok(bytes) => AttemptOutcome::Success(bytes.to_vec()),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Mark a chat as read.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn mark_read(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
    ) -> BlueBubblesResult<()> {
        let chat_guid = sanitize_path_segment(chat_guid, "chat_guid")?;
        self.require_action_available(runtime, BlueBubblesPrivateApiAction::MarkRead)
            .await?;
        let url = format!("{}/api/v1/chat/{chat_guid}/read", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Marking BlueBubbles chat as read");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                AttemptOutcome::Success(())
            }
        })
        .await
    }

    /// Lightweight health check: verify server is reachable.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is unreachable.
    pub async fn health_check(&self) -> BlueBubblesResult<()> {
        let url = format!("{}/api/v1/server/info", self.server_url);
        let resp = self
            .client
            .get(&url)
            .query(&[("password", &self.server_passcode)])
            .send()
            .await
            .map_err(BlueBubblesError::from_transport_error)?;

        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after =
                retry_after_from_headers(resp.headers()).unwrap_or(Duration::from_secs(30));
            return Err(BlueBubblesError::RateLimited {
                retry_after_ms: duration_to_ms(retry_after),
            });
        }

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(BlueBubblesError::from_api_response(status, &text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_info(private_api: bool, os_version: Option<&str>) -> ServerInfo {
        ServerInfo {
            os_version: os_version.map(str::to_string),
            server_version: Some("1.9.0".into()),
            private_api,
            helper_connected: None,
            proxy_service: None,
        }
    }

    fn plain_send_decision(info: &ServerInfo) -> SendMethodDecision {
        SendMethodDecision::for_options(info, &SendMessageOptions::default())
            .expect("plain text send does not require Private API")
    }

    #[test]
    fn send_method_uses_private_api_for_macos26_when_available() {
        let decision = plain_send_decision(&server_info(true, Some("26.0.1")));
        assert_eq!(decision.method, SEND_METHOD_PRIVATE_API);
        assert_eq!(decision.reason, "macos26_private_api_available");
        assert_eq!(decision.private_api, Some(true));
    }

    #[test]
    fn send_method_keeps_apple_script_for_older_macos_plain_text() {
        let decision = plain_send_decision(&server_info(true, Some("15.5")));
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(decision.reason, "plain_text_apple_script_supported");
    }

    #[test]
    fn send_method_requires_private_api_for_reply_or_effects() {
        let options = SendMessageOptions {
            reply_to_message_guid: Some("reply-guid-123".into()),
            reply_to_part_index: Some(0),
            effect_id: Some("com.apple.messages.effect.CKConfettiEffect".into()),
        };
        let decision =
            SendMethodDecision::for_options(&server_info(true, Some("15.5")), &options).unwrap();
        assert_eq!(decision.method, SEND_METHOD_PRIVATE_API);
        assert_eq!(decision.reason, "rich_send_private_api_available");

        let err = SendMethodDecision::for_options(&server_info(false, Some("26.0")), &options)
            .unwrap_err();
        assert!(matches!(err, BlueBubblesError::PrivateApiRequired { .. }));
    }

    #[test]
    fn send_method_falls_back_when_private_api_disabled_on_macos26() {
        let decision = plain_send_decision(&server_info(false, Some("26.0")));
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(
            decision.reason,
            "macos26_private_api_disabled_apple_script_fallback"
        );
        assert_eq!(decision.private_api, Some(false));
    }

    #[test]
    fn send_method_falls_back_when_server_info_is_unavailable() {
        let error = BlueBubblesError::ServerUnreachable;
        let decision = SendMethodDecision::unavailable(&error);
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(
            decision.reason,
            "server_info_unavailable_apple_script_fallback"
        );
        assert!(!decision.server_info_available);
        assert!(decision.warning.is_some());
    }

    #[test]
    fn macos_major_version_parser_handles_known_shapes() {
        assert_eq!(parse_macos_major_version(Some("26.0.1")), Some(26));
        assert_eq!(parse_macos_major_version(Some(" 15.7 ")), Some(15));
        assert_eq!(parse_macos_major_version(Some("Tahoe")), None);
        assert_eq!(parse_macos_major_version(None), None);
    }

    #[test]
    fn action_availability_requires_private_api_and_known_edit_support() {
        let mut info = server_info(true, Some("15.7"));
        info.helper_connected = Some(true);
        let availability = BlueBubblesActionAvailability::from_info(&info);
        assert!(availability.edit.supported);
        assert_eq!(availability.edit.reason, "private_api_macos_supported");
        assert!(availability.unsend.supported);
        assert!(availability.reaction.supported);
        assert!(availability.typing.supported);
        assert!(availability.mark_read.supported);

        let disabled = BlueBubblesActionAvailability::from_info(&server_info(false, Some("15.7")));
        assert!(!disabled.unsend.supported);
        assert_eq!(disabled.unsend.reason, "private_api_disabled");

        let macos26 = BlueBubblesActionAvailability::from_info(&server_info(true, Some("26.0")));
        assert!(!macos26.edit.supported);
        assert_eq!(macos26.edit.reason, "macos26_edit_unsupported");
        assert!(macos26.unsend.supported);

        let unknown = BlueBubblesActionAvailability::from_info(&server_info(true, None));
        assert!(!unknown.edit.supported);
        assert_eq!(unknown.edit.reason, "os_version_unknown");
    }

    #[test]
    fn action_availability_treats_disconnected_helper_as_unsupported() {
        let mut info = server_info(true, Some("15.7"));
        info.helper_connected = Some(false);
        let availability = BlueBubblesActionAvailability::from_info(&info);
        assert_eq!(availability.helper_connected, Some(false));
        assert!(!availability.edit.supported);
        assert_eq!(availability.edit.reason, "helper_disconnected");
        assert!(!availability.typing.supported);
        assert_eq!(availability.typing.reason, "helper_disconnected");
    }
}
