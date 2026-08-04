//! Telegram Bot API client.
//!
//! Implements the core Telegram Bot API methods using reqwest.
//! Based on patterns from clawdbot's Telegram integration.

use std::time::Duration;

use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use tracing::instrument;

use crate::error::TelegramError;
use crate::types::*;

/// Telegram Bot API client.
#[derive(Clone)]
pub struct TelegramClient {
    credential: String,
    client: Client,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for TelegramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramClient")
            .field("credential", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl TelegramClient {
    /// Create a new Telegram client.
    ///
    /// # Errors
    /// Returns an error if the HTTP client fails to build.
    pub fn new(credential: impl Into<String>) -> Result<Self, TelegramError> {
        let bot_credential = credential.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(TelegramError::Http)?;

        Ok(Self {
            credential: bot_credential,
            client,
            base_url: "https://api.telegram.org".into(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(60)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Set a custom base URL.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Build the API URL for a method.
    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.credential, method)
    }

    /// Execute a request with retries.
    async fn request<T, B>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        timeout: Option<Duration>,
    ) -> Result<T, TelegramError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.api_url(endpoint);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        // Telegram's Bot API has no idempotency key, so a replayed `sendMessage`
        // posts a second message to the chat. The HTTP verb is NOT a usable
        // proxy here: `getUpdates` is a POST but a long-poll read, and several
        // `set*` endpoints are POSTs that are idempotent by content. So this is
        // an explicit allowlist of the endpoints whose replay cannot duplicate
        // anything.
        //
        // FAILS CLOSED on purpose: an endpoint added later and not listed here
        // is treated as creating something, which costs a retry rather than
        // risking a duplicate message. See br-kxd3e.
        let replay_safe = matches!(
            endpoint,
            // Reads.
            "getMe" | "getUpdates" | "getWebhookInfo"
            // Idempotent by content — repeating them re-asserts the same state.
            | "setWebhook" | "deleteWebhook" | "setMessageReaction"
            // Ephemeral and self-expiring; repeating is invisible.
            | "sendChatAction"
            // Answering the same callback query twice is refused by Telegram,
            // not duplicated.
            | "answerCallbackQuery"
        );

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let url = &url;
            let ctx = ctx.clone();
            async move {
                match ctx
                    .run(async move {
                        let mut req = match method {
                            "POST" => self.client.post(url.as_str()),
                            _ => self.client.get(url.as_str()),
                        };

                        if let Some(b) = body {
                            req = req.json(b);
                        }

                        if let Some(t) = timeout {
                            req = req.timeout(t);
                        }

                        let result = req.send().await;

                        match result {
                            Ok(response) => {
                                let status = response.status();

                                if status == StatusCode::TOO_MANY_REQUESTS {
                                    // Try HTTP header first
                                    let header_val = response
                                        .headers()
                                        .get("retry-after")
                                        .and_then(|v| v.to_str().ok())
                                        .and_then(|v| v.parse::<u64>().ok());

                                    // If no header, parse the JSON body for
                                    // parameters.retry_after (Telegram's native format)
                                    let retry_after_secs = if let Some(s) = header_val {
                                        s
                                    } else {
                                        let body_val = response
                                            .json::<serde_json::Value>()
                                            .await
                                            .ok()
                                            .and_then(|v| {
                                                v.get("parameters")?.get("retry_after")?.as_u64()
                                            });
                                        body_val.unwrap_or(5)
                                    };

                                    return AttemptOutcome::Retryable {
                                        error: TelegramError::Api {
                                            code: 429,
                                            description: "Too Many Requests".into(),
                                        },
                                        retry_after: Some(Duration::from_secs(retry_after_secs)),
                                    };
                                }

                                if status.is_server_error() {
                                    // A 5xx means Telegram RECEIVED the request;
                                    // the message may already have been posted.
                                    return AttemptOutcome::retryable_if_replayable(
                                        TelegramError::Api {
                                            code: i32::from(status.as_u16()),
                                            description: format!("Server error: {status}"),
                                        },
                                        None,
                                        replay_safe,
                                    );
                                }

                                // Parse the Telegram response wrapper
                                let tg_response: TelegramResponse<T> = match response.json().await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        return AttemptOutcome::Terminal(TelegramError::Http(e));
                                    }
                                };

                                if tg_response.ok {
                                    return match tg_response.result {
                                        Some(data) => AttemptOutcome::Success(data),
                                        None => AttemptOutcome::Terminal(TelegramError::Api {
                                            code: 0,
                                            description: "Empty result".into(),
                                        }),
                                    };
                                }

                                // Handle logical API errors
                                let err = TelegramError::Api {
                                    code: tg_response.error_code.unwrap_or(0),
                                    description: tg_response
                                        .description
                                        .clone()
                                        .unwrap_or_default(),
                                };

                                if err.is_retryable() {
                                    AttemptOutcome::Retryable {
                                        retry_after: err.retry_after(),
                                        error: err,
                                    }
                                } else {
                                    AttemptOutcome::Terminal(err)
                                }
                            }
                            // `is_timeout()` covers the TOTAL request timeout,
                            // which fires after the body was fully sent — only
                            // a connect-phase failure proves the request never
                            // left the client.
                            Err(e) if e.is_timeout() || e.is_connect() => {
                                let replayable =
                                    replay_safe || !transport_error_reached_service(&e);
                                AttemptOutcome::retryable_if_replayable(
                                    TelegramError::Http(e),
                                    None,
                                    replayable,
                                )
                            }
                            Err(e) => AttemptOutcome::Terminal(TelegramError::Http(e)),
                        }
                    })
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(async_err) => {
                        AttemptOutcome::Terminal(TelegramError::from_async_error(async_err))
                    }
                }
            }
        })
        .await
    }

    /// Get bot information.
    #[instrument(skip(self))]
    pub async fn get_me(&self) -> Result<BotInfo, TelegramError> {
        self.request("GET", "getMe", None::<&()>, None).await
    }

    /// Get updates using long polling.
    #[instrument(skip(self))]
    pub async fn get_updates(
        &self,
        request: GetUpdatesRequest,
    ) -> Result<Vec<Update>, TelegramError> {
        let timeout =
            Duration::from_secs(u64::try_from(request.timeout.unwrap_or(30)).unwrap_or(30) + 10);
        // Default to empty vec if result is missing but ok is true (though request handles that)
        self.request("POST", "getUpdates", Some(&request), Some(timeout))
            .await
            .map(|opt: Vec<Update>| opt)
    }

    /// Send a text message.
    #[instrument(skip_all)]
    pub async fn send_message(
        &self,
        chat_id: impl Into<String>,
        text: impl Into<String>,
        options: SendMessageOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMessageRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            text: text.into(),
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };

        self.request("POST", "sendMessage", Some(&request), None)
            .await
    }

    /// Broadcast a typing/upload/etc. chat action.
    #[instrument(skip_all)]
    pub async fn send_chat_action(
        &self,
        chat_id: impl Into<String>,
        action: impl Into<String>,
        message_thread_id: Option<i64>,
        business_connection_id: Option<String>,
    ) -> Result<bool, TelegramError> {
        let action = action.into();
        validate_chat_action(&action).map_err(|error| TelegramError::from_fcp(&error))?;
        let request = SendChatActionRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            action,
            message_thread_id,
            business_connection_id,
        };

        self.request("POST", "sendChatAction", Some(&request), None)
            .await
    }

    /// Set or clear the bot's chosen reaction on a message.
    #[instrument(skip_all)]
    pub async fn set_message_reaction(
        &self,
        chat_id: impl Into<String>,
        message_id: i64,
        reaction: Option<Vec<ReactionType>>,
        is_big: Option<bool>,
    ) -> Result<bool, TelegramError> {
        if let Some(reactions) = reaction.as_ref() {
            validate_reactions(reactions).map_err(|error| TelegramError::from_fcp(&error))?;
        }
        let request = SetMessageReactionRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            message_id,
            reaction,
            is_big,
        };

        self.request("POST", "setMessageReaction", Some(&request), None)
            .await
    }

    /// Register the bot webhook with Telegram.
    #[instrument(skip_all)]
    pub async fn set_webhook(&self, request: SetWebhookRequest) -> Result<bool, TelegramError> {
        validate_set_webhook_request(&request).map_err(|error| TelegramError::from_fcp(&error))?;
        self.request("POST", "setWebhook", Some(&request), None)
            .await
    }

    /// Delete the bot webhook registration.
    #[instrument(skip_all)]
    pub async fn delete_webhook(
        &self,
        drop_pending_updates: Option<bool>,
    ) -> Result<bool, TelegramError> {
        let request = DeleteWebhookRequest {
            drop_pending_updates,
        };
        self.request("POST", "deleteWebhook", Some(&request), None)
            .await
    }

    /// Fetch the current Telegram webhook registration status.
    #[instrument(skip_all)]
    pub async fn get_webhook_info(&self) -> Result<WebhookInfo, TelegramError> {
        self.request("GET", "getWebhookInfo", None::<&()>, None)
            .await
    }

    /// Get file information for downloading.
    #[instrument(skip_all)]
    pub async fn get_file(&self, file_id: impl Into<String>) -> Result<File, TelegramError> {
        let file_id = file_id.into();
        // getFile uses query params, but our request helper expects JSON body for POST or no body for GET.
        // reqwest GET with body is technically allowed but getFile supports query params.
        // We can just construct the URL with query params.
        // Or cleaner: make request() support query params?
        // Simpler: Just manual impl for get_file or change request() to take an enum for body/query.
        // Let's manually invoke client for get_file to keep request() simple for JSON-RPC style calls.
        let url = self.api_url("getFile");
        let response: TelegramResponse<File> = self
            .client
            .get(&url)
            .query(&[("file_id", &file_id)])
            .send()
            .await?
            .json()
            .await?;

        if response.ok {
            response.result.ok_or_else(|| TelegramError::Api {
                code: 0,
                description: "Empty result".into(),
            })
        } else {
            Err(TelegramError::Api {
                code: response.error_code.unwrap_or(0),
                description: response.description.unwrap_or_default(),
            })
        }
    }

    /// Download a file by its path.
    ///
    /// The `file_path` is percent-encoded to prevent path injection from
    /// potentially user-controlled values returned in Telegram API responses.
    pub fn file_download_url(&self, file_path: &str) -> Result<String, TelegramError> {
        use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

        // Encode everything except unreserved chars and forward slash (path separator).
        const PATH_SEGMENT: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'#')
            .add(b'<')
            .add(b'>')
            .add(b'?')
            .add(b'`')
            .add(b'{')
            .add(b'}')
            .add(b'%')
            .add(b'\\');

        if file_path.is_empty() {
            return Err(TelegramError::InvalidFilePath(
                "path must not be empty".into(),
            ));
        }
        if file_path.starts_with('/') {
            return Err(TelegramError::InvalidFilePath(
                "absolute paths are not allowed".into(),
            ));
        }
        if file_path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(TelegramError::InvalidFilePath(
                "path traversal segments are not allowed".into(),
            ));
        }

        let encoded_path = utf8_percent_encode(file_path, PATH_SEGMENT).to_string();
        Ok(format!(
            "{}/file/bot{}/{}",
            self.base_url, self.credential, encoded_path
        ))
    }

    /// Send a photo to a chat.
    #[instrument(skip_all)]
    pub async fn send_photo(
        &self,
        chat_id: impl Into<String>,
        photo: impl Into<String>,
        options: SendMediaOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMediaRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            media_field: "photo".into(),
            media_value: photo.into(),
            caption: options.caption,
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };
        self.request("POST", "sendPhoto", Some(&request), None)
            .await
    }

    /// Send a document to a chat.
    #[instrument(skip_all)]
    pub async fn send_document(
        &self,
        chat_id: impl Into<String>,
        document: impl Into<String>,
        options: SendMediaOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMediaRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            media_field: "document".into(),
            media_value: document.into(),
            caption: options.caption,
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };
        self.request("POST", "sendDocument", Some(&request), None)
            .await
    }

    /// Send an audio file to a chat.
    #[instrument(skip_all)]
    pub async fn send_audio(
        &self,
        chat_id: impl Into<String>,
        audio: impl Into<String>,
        options: SendMediaOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMediaRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            media_field: "audio".into(),
            media_value: audio.into(),
            caption: options.caption,
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };
        self.request("POST", "sendAudio", Some(&request), None)
            .await
    }

    /// Send a video to a chat.
    #[instrument(skip_all)]
    pub async fn send_video(
        &self,
        chat_id: impl Into<String>,
        video: impl Into<String>,
        options: SendMediaOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMediaRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            media_field: "video".into(),
            media_value: video.into(),
            caption: options.caption,
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };
        self.request("POST", "sendVideo", Some(&request), None)
            .await
    }

    /// Send a voice message to a chat.
    #[instrument(skip_all)]
    pub async fn send_voice(
        &self,
        chat_id: impl Into<String>,
        voice: impl Into<String>,
        options: SendMediaOptions,
    ) -> Result<Message, TelegramError> {
        let request = SendMediaRequest {
            chat_id: normalize_chat_id(&chat_id.into())?,
            media_field: "voice".into(),
            media_value: voice.into(),
            caption: options.caption,
            parse_mode: options.parse_mode,
            reply_to_message_id: options.reply_to_message_id,
            message_thread_id: options.message_thread_id,
        };
        self.request("POST", "sendVoice", Some(&request), None)
            .await
    }

    /// Answer a callback query (acknowledge button press).
    #[instrument(skip_all)]
    pub async fn answer_callback_query(
        &self,
        callback_query_id: impl Into<String>,
        text: Option<&str>,
    ) -> Result<bool, TelegramError> {
        // answerCallbackQuery is POST with JSON (or form)
        #[derive(Serialize)]
        struct AnswerCallbackQueryRequest<'a> {
            callback_query_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            text: Option<&'a str>,
        }

        let request = AnswerCallbackQueryRequest {
            callback_query_id: callback_query_id.into(),
            text,
        };

        self.request("POST", "answerCallbackQuery", Some(&request), None)
            .await
    }
}

/// Normalize chat ID, handling various formats.
fn normalize_chat_id(id: &str) -> Result<String, TelegramError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(TelegramError::InvalidChatId("Empty chat ID".into()));
    }

    // Strip common prefixes
    let normalized = trimmed
        .strip_prefix("telegram:")
        .or_else(|| trimmed.strip_prefix("tg:"))
        .unwrap_or(trimmed);

    // Strip group: prefix
    let normalized = normalized.strip_prefix("group:").unwrap_or(normalized);

    // Handle t.me links
    if let Some(username) = normalized
        .strip_prefix("https://t.me/")
        .or_else(|| normalized.strip_prefix("http://t.me/"))
        .or_else(|| normalized.strip_prefix("t.me/"))
    {
        // Skip invite links (start with +)
        if username.starts_with('+') {
            return Err(TelegramError::InvalidChatId(
                "Cannot use invite links as chat ID".into(),
            ));
        }
        return Ok(format!("@{username}"));
    }

    // If it starts with @, it's a username
    if normalized.starts_with('@') {
        return Ok(normalized.to_string());
    }

    // If it's numeric (with optional leading - for groups), use as-is
    // Valid: "123456", "-100123456" (group IDs start with -)
    let is_valid_numeric = if let Some(rest) = normalized.strip_prefix('-') {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        !normalized.is_empty() && normalized.chars().all(|c| c.is_ascii_digit())
    };
    if is_valid_numeric {
        return Ok(normalized.to_string());
    }

    // Assume it's a username without @
    if normalized.len() >= 5 && normalized.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(format!("@{normalized}"));
    }

    Err(TelegramError::InvalidChatId(format!(
        "Cannot parse chat ID: {trimmed}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::FcpError;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn test_normalize_chat_id() {
        // Valid numeric IDs
        assert_eq!(normalize_chat_id("123456").unwrap(), "123456");
        assert_eq!(normalize_chat_id("-100123456").unwrap(), "-100123456");

        // Username formats
        assert_eq!(normalize_chat_id("@username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("myusername").unwrap(), "@myusername");

        // Prefixed formats
        assert_eq!(normalize_chat_id("telegram:123456").unwrap(), "123456");
        assert_eq!(
            normalize_chat_id("tg:group:-100123456").unwrap(),
            "-100123456"
        );

        // t.me links
        assert_eq!(normalize_chat_id("t.me/username").unwrap(), "@username");
        assert_eq!(normalize_chat_id("https://t.me/mybot").unwrap(), "@mybot");

        // Invalid inputs
        assert!(normalize_chat_id("").is_err());
        assert!(normalize_chat_id("t.me/+abc123").is_err()); // Invite links not allowed
        assert!(normalize_chat_id("---").is_err()); // Invalid numeric
        assert!(normalize_chat_id("1-2-3").is_err()); // Invalid numeric
        assert!(normalize_chat_id("-").is_err()); // Just a dash
    }

    #[derive(Clone, Debug)]
    struct StructuredHttpRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct StructuredHttpResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl StructuredHttpResponse {
        fn json(status: u16, body: &serde_json::Value) -> Self {
            Self {
                status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: body.to_string().into_bytes(),
            }
        }
    }

    struct StructuredTestHttpServer {
        base_url: String,
        _requests: Arc<Mutex<Vec<StructuredHttpRequest>>>,
        _join: thread::JoinHandle<()>,
    }

    impl StructuredTestHttpServer {
        fn spawn<F>(expected_requests: usize, responder: F) -> Self
        where
            F: Fn(usize, &StructuredHttpRequest) -> StructuredHttpResponse + Send + Sync + 'static,
        {
            let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test http server");
            let addr = listener.local_addr().expect("test http server addr");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let responder = Arc::new(responder);

            let join = thread::spawn(move || {
                for idx in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("accept test http connection");
                    let request = read_structured_http_request(&mut stream);
                    let response = responder(idx, &request);
                    requests_for_thread
                        .lock()
                        .expect("lock test http requests")
                        .push(request);
                    write_structured_http_response(&mut stream, response);
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                _requests: requests,
                _join: join,
            }
        }

        fn uri(&self) -> String {
            self.base_url.clone()
        }
    }

    fn test_client(server: &StructuredTestHttpServer) -> TelegramClient {
        TelegramClient::new("test_token_12345")
            .unwrap()
            .with_base_url(server.uri())
    }

    fn read_structured_http_request(stream: &mut std::net::TcpStream) -> StructuredHttpRequest {
        let mut buffer = Vec::new();
        let mut temp = [0u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut temp).expect("read test http request");
            assert!(read > 0, "unexpected EOF while reading test http request");
            buffer.extend_from_slice(&temp[..read]);
            if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let header_text = std::str::from_utf8(&buffer[..header_end]).expect("request headers utf8");
        let mut lines = header_text.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut request_line_parts = request_line.split_whitespace();
        let method = request_line_parts
            .next()
            .expect("request method")
            .to_string();
        let path = request_line_parts.next().expect("request path").to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').expect("header separator");
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut temp).expect("read test http body");
            assert!(read > 0, "unexpected EOF while reading test http body");
            body.extend_from_slice(&temp[..read]);
        }
        body.truncate(content_length);

        StructuredHttpRequest {
            method,
            path,
            headers,
            body,
        }
    }

    fn write_structured_http_response(
        stream: &mut std::net::TcpStream,
        response: StructuredHttpResponse,
    ) {
        use std::fmt::Write as _;

        let reason = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "OK",
        };
        let mut raw = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            reason,
            response.body.len()
        );
        for (name, value) in response.headers {
            write!(&mut raw, "{name}: {value}\r\n").expect("write response header to string");
        }
        raw.push_str("\r\n");
        stream
            .write_all(raw.as_bytes())
            .expect("write test http response headers");
        stream
            .write_all(&response.body)
            .expect("write test http response body");
    }

    fn request_json(request: &StructuredHttpRequest) -> serde_json::Value {
        serde_json::from_slice(&request.body).expect("request body should be JSON")
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_me_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/bottest_token_12345/getMe");
            assert!(
                !request.headers.contains_key("content-type"),
                "GET getMe should not send a content-type header"
            );
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                    "ok": true,
                    "result": {
                        "id": 123456789,
                        "is_bot": true,
                        "first_name": "Test Bot",
                        "username": "test_bot"
                    }
                }),
            )
        });
        let client = test_client(&server);

        let bot_info = client.get_me().await.unwrap();
        assert_eq!(bot_info.id, 123456789);
        assert!(bot_info.is_bot);
        assert_eq!(bot_info.first_name, "Test Bot");
        assert_eq!(bot_info.username.as_deref(), Some("test_bot"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_me_unauthorized() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/bottest_token_12345/getMe");
            StructuredHttpResponse::json(
                401,
                &serde_json::json!({
                    "ok": false,
                    "error_code": 401,
                    "description": "Unauthorized"
                }),
            )
        });
        let client = test_client(&server);

        let result = client.get_me().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TelegramError::Api { .. }));
        if let TelegramError::Api { code, description } = err {
            assert_eq!(code, 401);
            assert_eq!(description, "Unauthorized");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendMessage");
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("telegram send body json");
            assert_eq!(body["chat_id"], "123456");
            assert_eq!(body["text"], "Hello, World!");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 42,
                        "chat": {
                            "id": 123456,
                            "type": "private",
                            "first_name": "Test"
                        },
                        "date": 1234567890,
                        "text": "Hello, World!"
                    }
                }),
            )
        });
        let client = test_client(&server);

        let message = client
            .send_message("123456", "Hello, World!", SendMessageOptions::default())
            .await
            .unwrap();

        assert_eq!(message.message_id, 42);
        assert_eq!(message.chat.id, 123456);
        assert_eq!(message.text.as_deref(), Some("Hello, World!"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_html_parse_mode() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendMessage");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 43,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Bold text"
                }
                }),
            )
        });
        let client = test_client(&server);

        let options = SendMessageOptions::default().html();
        let message = client
            .send_message("123456", "<b>Bold text</b>", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 43);
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_reply_and_thread() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendMessage");
            assert_eq!(
                request_json(request),
                serde_json::json!({
                "chat_id": "123456",
                "text": "*Hello*",
                "parse_mode": "MarkdownV2",
                "reply_to_message_id": 7,
                "message_thread_id": 9
                })
            );
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 44,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "text": "Hello"
                }
                }),
            )
        });
        let client = test_client(&server);

        let mut options = SendMessageOptions::default()
            .markdown_v2()
            .reply_to_message_id(7);
        options.message_thread_id = Some(9);

        let message = client
            .send_message("123456", "*Hello*", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 44);
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_rate_limited() {
        let server = StructuredTestHttpServer::spawn(3, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendMessage");
            let mut response = StructuredHttpResponse::json(
                429,
                &serde_json::json!({
                        "ok": false,
                        "error_code": 429,
                        "description": "Too Many Requests: retry after 0",
                        "parameters": {"retry_after": 0}
                }),
            );
            response.headers.push(("retry-after".into(), "0".into()));
            response
        });
        let client = test_client(&server);

        let result = client
            .send_message("123456", "Test", SendMessageOptions::default())
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
        assert!(matches!(err, TelegramError::Api { .. }));
        if let TelegramError::Api { code, .. } = err {
            assert_eq!(code, 429);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_updates_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/getUpdates");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": [
                    {
                        "update_id": 100,
                        "message": {
                            "message_id": 1,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567890,
                            "text": "Hello"
                        }
                    },
                    {
                        "update_id": 101,
                        "message": {
                            "message_id": 2,
                            "chat": {
                                "id": 12345,
                                "type": "private",
                                "first_name": "User"
                            },
                            "date": 1234567891,
                            "text": "World"
                        }
                    }
                ]
                }),
            )
        });
        let client = test_client(&server);

        let request = GetUpdatesRequest {
            offset: None,
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].update_id, 100);
        assert_eq!(updates[1].update_id, 101);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_updates_empty() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/getUpdates");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": []
                }),
            )
        });
        let client = test_client(&server);

        let request = GetUpdatesRequest {
            offset: Some(100),
            limit: Some(10),
            timeout: Some(5),
            allowed_updates: None,
        };

        let updates = client.get_updates(request).await.unwrap();
        assert!(updates.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_webhook_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/setWebhook");
            assert_eq!(
                request_json(request),
                serde_json::json!({
                "url": "https://example.com/fcp/telegram/webhook",
                "ip_address": "203.0.113.10",
                "max_connections": 40,
                "allowed_updates": ["message", "callback_query"],
                "drop_pending_updates": true,
                "secret_token": "telegram_webhook_secret-1"
                })
            );
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": true
                }),
            )
        });
        let client = test_client(&server);

        let success = client
            .set_webhook(SetWebhookRequest {
                url: "https://example.com/fcp/telegram/webhook".into(),
                ip_address: Some("203.0.113.10".into()),
                max_connections: Some(40),
                allowed_updates: Some(vec!["message".into(), "callback_query".into()]),
                drop_pending_updates: Some(true),
                secret_token: Some("telegram_webhook_secret-1".into()),
            })
            .await
            .unwrap();

        assert!(success);
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_webhook_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/deleteWebhook");
            assert_eq!(
                request_json(request),
                serde_json::json!({
                "drop_pending_updates": true
                })
            );
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": true
                }),
            )
        });
        let client = test_client(&server);

        assert!(client.delete_webhook(Some(true)).await.unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_webhook_info_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/bottest_token_12345/getWebhookInfo");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "url": "https://example.com/fcp/telegram/webhook",
                    "has_custom_certificate": false,
                    "pending_update_count": 3,
                    "ip_address": "203.0.113.10",
                    "last_error_date": 1_700_000_000,
                    "last_error_message": "temporary upstream error",
                    "max_connections": 40,
                    "allowed_updates": ["message", "callback_query"]
                }
                }),
            )
        });
        let client = test_client(&server);

        let info = client.get_webhook_info().await.unwrap();
        assert_eq!(info.url, "https://example.com/fcp/telegram/webhook");
        assert!(!info.has_custom_certificate);
        assert_eq!(info.pending_update_count, 3);
        assert_eq!(info.ip_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(info.max_connections, Some(40));
        assert_eq!(
            info.allowed_updates,
            Some(vec!["message".into(), "callback_query".into()])
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_file_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "GET");
            assert!(request.path.starts_with("/bottest_token_12345/getFile?"));
            assert!(request.path.contains("file_id=AgACAgIAAxkBAAI"));
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "file_id": "AgACAgIAAxkBAAI",
                    "file_unique_id": "AQADAgATqRkyGw",
                    "file_size": 12345,
                    "file_path": "photos/file_0.jpg"
                }
                }),
            )
        });
        let client = test_client(&server);

        let file = client.get_file("AgACAgIAAxkBAAI").await.unwrap();
        assert_eq!(file.file_id, "AgACAgIAAxkBAAI");
        assert_eq!(file.file_unique_id, "AQADAgATqRkyGw");
        assert_eq!(file.file_size, Some(12345));
        assert_eq!(file.file_path.as_deref(), Some("photos/file_0.jpg"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_file_download_url() {
        let client = TelegramClient::new("my_bot_token").unwrap();
        let url = client.file_download_url("photos/file_0.jpg").unwrap();
        assert_eq!(
            url,
            "https://api.telegram.org/file/botmy_bot_token/photos/file_0.jpg"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_telegram_error_is_retryable() {
        // Rate limited errors should be retryable
        let rate_limited = TelegramError::Api {
            code: 429,
            description: "Too Many Requests".into(),
        };
        assert!(rate_limited.is_retryable());

        // Server errors should be retryable
        let server_error = TelegramError::Api {
            code: 500,
            description: "Internal Server Error".into(),
        };
        assert!(server_error.is_retryable());

        // Client errors should not be retryable
        let bad_request = TelegramError::Api {
            code: 400,
            description: "Bad Request".into(),
        };
        assert!(!bad_request.is_retryable());

        // Invalid chat ID should not be retryable
        let invalid_chat = TelegramError::InvalidChatId("bad".into());
        assert!(!invalid_chat.is_retryable());
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_photo_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendPhoto");
            assert_eq!(
                request_json(request),
                serde_json::json!({
                "chat_id": "123456",
                "photo": "AgACAgIAAxk",
                "caption": "Test photo",
                "message_thread_id": 42
                })
            );
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 50,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "photo": [{
                        "file_id": "AgACAgIAAxk",
                        "file_unique_id": "AQADAgAT",
                        "width": 320,
                        "height": 240,
                        "file_size": 12345
                    }]
                }
                }),
            )
        });
        let client = test_client(&server);

        let options = SendMediaOptions {
            caption: Some("Test photo".into()),
            message_thread_id: Some(42),
            ..Default::default()
        };
        let message = client
            .send_photo("123456", "AgACAgIAAxk", options)
            .await
            .unwrap();

        assert_eq!(message.message_id, 50);
        assert_eq!(message.chat.id, 123456);
        assert!(message.photo.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_document_success() {
        let server = StructuredTestHttpServer::spawn(1, |_idx, request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/bottest_token_12345/sendDocument");
            StructuredHttpResponse::json(
                200,
                &serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 51,
                    "chat": {
                        "id": 123456,
                        "type": "private",
                        "first_name": "Test"
                    },
                    "date": 1234567890,
                    "document": {
                        "file_id": "BQACAgIAAxk",
                        "file_unique_id": "AgADAgAT",
                        "file_name": "report.pdf",
                        "mime_type": "application/pdf",
                        "file_size": 98765
                    }
                }
                }),
            )
        });
        let client = test_client(&server);

        let message = client
            .send_document("123456", "BQACAgIAAxk", SendMediaOptions::default())
            .await
            .unwrap();

        assert_eq!(message.message_id, 51);
        assert!(message.document.is_some());
    }

    // ---- TelegramError Display / Debug / Error trait tests ----

    #[test]
    fn test_api_error_display() {
        let err = TelegramError::Api {
            code: 403,
            description: "Forbidden: bot was blocked".into(),
        };
        let display = format!("{err}");
        assert_eq!(
            display,
            "Telegram API error (403): Forbidden: bot was blocked"
        );
    }

    #[test]
    fn test_invalid_chat_id_display() {
        let err = TelegramError::InvalidChatId("bad-id".into());
        let display = format!("{err}");
        assert_eq!(display, "Invalid chat ID: bad-id");
    }

    #[test]
    fn test_api_error_debug() {
        let err = TelegramError::Api {
            code: 400,
            description: "Bad Request".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Api"));
        assert!(debug.contains("400"));
        assert!(debug.contains("Bad Request"));
    }

    #[test]
    fn test_invalid_chat_id_debug() {
        let err = TelegramError::InvalidChatId("xyz".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidChatId"));
        assert!(debug.contains("xyz"));
    }

    #[test]
    fn test_telegram_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TelegramError::Api {
            code: 500,
            description: "Internal".into(),
        });
        // source() should be None for Api variant
        assert!(err.source().is_none());

        let err2: Box<dyn std::error::Error> =
            Box::new(TelegramError::InvalidChatId("test".into()));
        assert!(err2.source().is_none());
    }

    // ---- is_retryable comprehensive tests ----

    #[test]
    fn test_api_429_is_retryable() {
        let err = TelegramError::Api {
            code: 429,
            description: "Too Many Requests".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_api_500_is_retryable() {
        let err = TelegramError::Api {
            code: 500,
            description: "Internal Server Error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_api_503_is_retryable() {
        let err = TelegramError::Api {
            code: 503,
            description: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_api_502_is_retryable() {
        let err = TelegramError::Api {
            code: 502,
            description: "Bad Gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_api_400_not_retryable() {
        let err = TelegramError::Api {
            code: 400,
            description: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_api_401_not_retryable() {
        let err = TelegramError::Api {
            code: 401,
            description: "Unauthorized".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_api_403_not_retryable() {
        let err = TelegramError::Api {
            code: 403,
            description: "Forbidden".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_api_404_not_retryable() {
        let err = TelegramError::Api {
            code: 404,
            description: "Not Found".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_api_499_not_retryable() {
        // 499 is < 500 and != 429
        let err = TelegramError::Api {
            code: 499,
            description: "Client Closed".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_invalid_chat_id_not_retryable() {
        let err = TelegramError::InvalidChatId("bad".into());
        assert!(!err.is_retryable());
    }

    // ---- normalize_chat_id comprehensive tests ----

    #[test]
    fn test_normalize_empty_string() {
        let result = normalize_chat_id("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, TelegramError::InvalidChatId(_)),
            "expected InvalidChatId, got {err:?}"
        );
        let TelegramError::InvalidChatId(msg) = err else {
            return;
        };
        assert!(msg.contains("Empty"));
    }

    #[test]
    fn test_normalize_whitespace_only() {
        let result = normalize_chat_id("   ");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, TelegramError::InvalidChatId(_)),
            "expected InvalidChatId, got {err:?}"
        );
        let TelegramError::InvalidChatId(msg) = err else {
            return;
        };
        assert!(msg.contains("Empty"));
    }

    #[test]
    fn test_normalize_tab_whitespace() {
        let result = normalize_chat_id("\t\n ");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_valid_positive_numeric() {
        assert_eq!(normalize_chat_id("123456").unwrap(), "123456");
    }

    #[test]
    fn test_normalize_valid_negative_numeric() {
        assert_eq!(normalize_chat_id("-100123456").unwrap(), "-100123456");
    }

    #[test]
    fn test_normalize_numeric_with_whitespace_trim() {
        assert_eq!(normalize_chat_id("  123456  ").unwrap(), "123456");
    }

    #[test]
    fn test_normalize_at_username() {
        assert_eq!(normalize_chat_id("@mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_bare_username_long_enough() {
        // >= 5 chars alphanumeric/underscore gets @ prepended
        assert_eq!(normalize_chat_id("mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_bare_username_with_underscore() {
        assert_eq!(normalize_chat_id("my_bot_name").unwrap(), "@my_bot_name");
    }

    #[test]
    fn test_normalize_bare_username_too_short() {
        // < 5 chars, not numeric, not @ => error
        let result = normalize_chat_id("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_bare_username_exactly_5() {
        assert_eq!(normalize_chat_id("abcde").unwrap(), "@abcde");
    }

    #[test]
    fn test_normalize_bare_username_4_chars_fails() {
        let result = normalize_chat_id("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_telegram_prefix() {
        assert_eq!(normalize_chat_id("telegram:123456").unwrap(), "123456");
    }

    #[test]
    fn test_normalize_tg_prefix() {
        assert_eq!(normalize_chat_id("tg:123456").unwrap(), "123456");
    }

    #[test]
    fn test_normalize_group_prefix() {
        assert_eq!(normalize_chat_id("group:-100123456").unwrap(), "-100123456");
    }

    #[test]
    fn test_normalize_tg_group_prefix_combined() {
        assert_eq!(
            normalize_chat_id("tg:group:-100123456").unwrap(),
            "-100123456"
        );
    }

    #[test]
    fn test_normalize_telegram_group_prefix_combined() {
        assert_eq!(
            normalize_chat_id("telegram:group:-100123456").unwrap(),
            "-100123456"
        );
    }

    #[test]
    fn test_normalize_https_tme_link() {
        assert_eq!(normalize_chat_id("https://t.me/mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_http_tme_link() {
        assert_eq!(normalize_chat_id("http://t.me/mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_bare_tme_link() {
        assert_eq!(normalize_chat_id("t.me/mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_tme_invite_link_rejected() {
        let result = normalize_chat_id("https://t.me/+abc123");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, TelegramError::InvalidChatId(_)),
            "expected InvalidChatId about invite links, got {err:?}"
        );
        let TelegramError::InvalidChatId(msg) = err else {
            return;
        };
        assert!(msg.contains("invite"));
    }

    #[test]
    fn test_normalize_bare_tme_invite_link_rejected() {
        let result = normalize_chat_id("t.me/+secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_just_dash_fails() {
        let result = normalize_chat_id("-");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_multiple_dashes_fails() {
        let result = normalize_chat_id("---");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_mixed_numeric_dashes_fails() {
        let result = normalize_chat_id("1-2-3");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_special_chars_fails() {
        let result = normalize_chat_id("!@#$");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_username_with_special_chars_fails() {
        // Has a dot which is not alphanumeric or underscore
        let result = normalize_chat_id("my.bot");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_telegram_prefix_with_username() {
        assert_eq!(normalize_chat_id("telegram:@mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_tg_prefix_with_username() {
        assert_eq!(normalize_chat_id("tg:@mybot").unwrap(), "@mybot");
    }

    #[test]
    fn test_normalize_single_digit() {
        assert_eq!(normalize_chat_id("0").unwrap(), "0");
    }

    #[test]
    fn test_normalize_large_numeric() {
        assert_eq!(normalize_chat_id("9999999999999").unwrap(), "9999999999999");
    }

    // ─── TelegramClient construction tests ──────────────────────────

    #[test]
    fn test_client_new_success() {
        let client = TelegramClient::new("123456:ABCtest");
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_debug_format() {
        let client = TelegramClient::new("123456:SECRET").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("TelegramClient"));
        // Credential must be redacted to prevent log exposure
        assert!(!debug.contains("123456:SECRET"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_client_clone() {
        let original = TelegramClient::new("test_token").unwrap();
        let cloned = original.clone();
        drop(original);
        // Cloned client is independent
        let debug = format!("{cloned:?}");
        assert!(debug.contains("TelegramClient"));
    }

    #[test]
    fn test_client_with_base_url() {
        let client = TelegramClient::new("test_token")
            .unwrap()
            .with_base_url("http://localhost:9090");
        let debug = format!("{client:?}");
        assert!(debug.contains("localhost:9090"));
    }

    #[test]
    fn test_client_api_url_format() {
        let client = TelegramClient::new("my_token").unwrap();
        let url = client.api_url("sendMessage");
        assert_eq!(url, "https://api.telegram.org/botmy_token/sendMessage");
    }

    #[test]
    fn test_client_api_url_custom_base() {
        let client = TelegramClient::new("my_token")
            .unwrap()
            .with_base_url("http://localhost:8080");
        let url = client.api_url("getMe");
        assert_eq!(url, "http://localhost:8080/botmy_token/getMe");
    }

    #[test]
    fn test_file_download_url_default_base() {
        let client = TelegramClient::new("bot_token_123").unwrap();
        let url = client.file_download_url("documents/file.pdf").unwrap();
        assert_eq!(
            url,
            "https://api.telegram.org/file/botbot_token_123/documents/file.pdf"
        );
    }

    #[test]
    fn test_file_download_url_custom_base() {
        let client = TelegramClient::new("tok")
            .unwrap()
            .with_base_url("http://localhost:9999");
        let url = client.file_download_url("pics/photo.jpg").unwrap();
        assert_eq!(url, "http://localhost:9999/file/bottok/pics/photo.jpg");
    }

    #[test]
    fn test_file_download_url_rejects_path_traversal() {
        let client = TelegramClient::new("tok").unwrap();
        let err = client
            .file_download_url("../../../etc/passwd?foo=bar")
            .unwrap_err();
        assert!(matches!(err, TelegramError::InvalidFilePath(_)));
    }

    #[test]
    fn test_file_download_url_encodes_spaces_and_hashes() {
        let client = TelegramClient::new("tok").unwrap();
        let url = client.file_download_url("photos/my file#2.jpg").unwrap();
        assert!(url.contains("%20"), "space should be encoded: {url}");
        assert!(url.contains("%23"), "hash should be encoded: {url}");
    }

    #[test]
    fn test_file_download_url_rejects_absolute_paths() {
        let client = TelegramClient::new("tok").unwrap();
        let err = client.file_download_url("/etc/passwd").unwrap_err();
        assert!(matches!(err, TelegramError::InvalidFilePath(_)));
    }

    // ─── SendMessageOptions tests ───────────────────────────────────

    #[test]
    fn test_send_message_options_default() {
        let opts = SendMessageOptions::default();
        assert!(opts.parse_mode.is_none());
        assert!(opts.reply_to_message_id.is_none());
        assert!(opts.message_thread_id.is_none());
    }

    #[test]
    fn test_send_message_options_html_builder() {
        let opts = SendMessageOptions::default().html();
        assert_eq!(opts.parse_mode.as_deref(), Some("HTML"));
    }

    #[test]
    fn test_send_message_options_markdown_v2_builder() {
        let opts = SendMessageOptions::default().markdown_v2();
        assert_eq!(opts.parse_mode.as_deref(), Some("MarkdownV2"));
    }

    #[test]
    fn test_send_message_options_reply_to_builder() {
        let opts = SendMessageOptions::default().reply_to_message_id(42);
        assert_eq!(opts.reply_to_message_id, Some(42));
    }

    #[test]
    fn test_send_message_options_chaining() {
        let opts = SendMessageOptions::default().html().reply_to_message_id(7);
        assert_eq!(opts.parse_mode.as_deref(), Some("HTML"));
        assert_eq!(opts.reply_to_message_id, Some(7));
    }

    // ─── SendMediaOptions tests ─────────────────────────────────────

    #[test]
    fn test_send_media_options_default() {
        let opts = SendMediaOptions::default();
        assert!(opts.caption.is_none());
        assert!(opts.parse_mode.is_none());
        assert!(opts.reply_to_message_id.is_none());
        assert!(opts.message_thread_id.is_none());
    }

    // ─── TelegramError is_retryable additional tests ─────────────────

    #[test]
    fn test_http_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TelegramError::Api {
            code: 500,
            description: "test".into(),
        });
        // Api variant should not have source
        assert!(err.source().is_none());
    }

    #[test]
    fn test_api_504_is_retryable() {
        let err = TelegramError::Api {
            code: 504,
            description: "Gateway Timeout".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_api_501_is_retryable() {
        let err = TelegramError::Api {
            code: 501,
            description: "Not Implemented".into(),
        };
        assert!(err.is_retryable()); // 501 >= 500
    }

    #[test]
    fn test_api_negative_code_not_retryable() {
        let err = TelegramError::Api {
            code: -1,
            description: "Unknown".into(),
        };
        assert!(!err.is_retryable());
    }

    // ─── SendMediaRequest custom serialize tests ─────────────────────

    #[test]
    fn test_send_media_request_serialize_photo() {
        let req = SendMediaRequest {
            chat_id: "123".into(),
            media_field: "photo".into(),
            media_value: "AgACAgIAAxk".into(),
            caption: Some("Test caption".into()),
            parse_mode: Some("HTML".into()),
            reply_to_message_id: Some(7),
            message_thread_id: Some(42),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["chat_id"], "123");
        assert_eq!(json["photo"], "AgACAgIAAxk");
        assert_eq!(json["caption"], "Test caption");
        assert_eq!(json["parse_mode"], "HTML");
        assert_eq!(json["reply_to_message_id"], 7);
        assert_eq!(json["message_thread_id"], 42);
    }

    #[test]
    fn test_send_media_request_serialize_document_minimal() {
        let req = SendMediaRequest {
            chat_id: "456".into(),
            media_field: "document".into(),
            media_value: "BQACAgIAAxk".into(),
            caption: None,
            parse_mode: None,
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["chat_id"], "456");
        assert_eq!(json["document"], "BQACAgIAAxk");
        assert!(json.get("caption").is_none());
        assert!(json.get("parse_mode").is_none());
        assert!(json.get("reply_to_message_id").is_none());
        assert!(json.get("message_thread_id").is_none());
    }

    #[test]
    fn test_send_media_request_serialize_video_with_caption() {
        let req = SendMediaRequest {
            chat_id: "789".into(),
            media_field: "video".into(),
            media_value: "CQACAgIAAxk".into(),
            caption: Some("Watch this".into()),
            parse_mode: None,
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["video"], "CQACAgIAAxk");
        assert_eq!(json["caption"], "Watch this");
        assert!(json.get("parse_mode").is_none());
    }

    // ─── TelegramError Display comprehensive tests ────────────────

    #[test]
    fn test_api_error_display_includes_code_and_desc() {
        let err = TelegramError::Api {
            code: 504,
            description: "Gateway Timeout".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("504"));
        assert!(msg.contains("Gateway Timeout"));
    }

    #[test]
    fn test_invalid_chat_id_display_includes_id() {
        let err = TelegramError::InvalidChatId("weird://value".into());
        let msg = format!("{err}");
        assert!(msg.contains("weird://value"));
    }

    #[test]
    fn test_api_error_debug_format_contains_variant() {
        let err = TelegramError::Api {
            code: 200,
            description: "Unusual".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("200"));
    }

    // ─── SendMediaOptions clone test ─────────────────────────────────

    #[test]
    fn test_send_media_options_clone() {
        let original = SendMediaOptions {
            caption: Some("test caption".into()),
            parse_mode: Some("HTML".into()),
            reply_to_message_id: Some(42),
            message_thread_id: Some(77),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.caption.as_deref(), Some("test caption"));
        assert_eq!(cloned.parse_mode.as_deref(), Some("HTML"));
        assert_eq!(cloned.reply_to_message_id, Some(42));
        assert_eq!(cloned.message_thread_id, Some(77));
    }

    #[test]
    fn test_send_message_options_clone() {
        let original = SendMessageOptions::default().html().reply_to_message_id(99);
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.parse_mode.as_deref(), Some("HTML"));
        assert_eq!(cloned.reply_to_message_id, Some(99));
    }

    #[test]
    fn test_send_message_options_debug() {
        let opts = SendMessageOptions::default().markdown_v2();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("SendMessageOptions"));
        assert!(dbg.contains("MarkdownV2"));
    }

    #[test]
    fn test_send_media_options_debug() {
        let opts = SendMediaOptions {
            caption: Some("debug test".into()),
            parse_mode: None,
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("SendMediaOptions"));
        assert!(dbg.contains("debug test"));
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn to_fcp_error_api_429() {
        let err = TelegramError::Api {
            code: 429,
            description: "rate limited".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                ..
            }
        ));
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = TelegramError::Api {
            code: 401,
            description: "bad token".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::Unauthorized { code: 2001, .. }
        ));
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = TelegramError::Api {
            code: 403,
            description: "blocked".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::CapabilityDenied { .. }
        ));
    }

    #[test]
    fn to_fcp_error_api_500() {
        let err = TelegramError::Api {
            code: 500,
            description: "internal error".into(),
        };
        let fcp_error = err.to_fcp_error();
        assert!(
            matches!(fcp_error, FcpError::External { .. }),
            "expected External, got {fcp_error:?}"
        );
        let FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } = fcp_error
        else {
            return;
        };
        assert_eq!(service, "telegram");
        assert!(retryable);
        assert_eq!(status_code, Some(500));
    }

    #[test]
    fn to_fcp_error_invalid_chat_id() {
        let err = TelegramError::InvalidChatId("bad".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, .. }
        ));
    }

    #[test]
    fn retry_after_429() {
        let err = TelegramError::Api {
            code: 429,
            description: "too many requests".into(),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_non_429_is_none() {
        let err = TelegramError::Api {
            code: 500,
            description: "error".into(),
        };
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn retry_after_invalid_chat_id_is_none() {
        assert!(
            TelegramError::InvalidChatId("x".into())
                .retry_after()
                .is_none()
        );
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, TelegramError::Api { code: 408, .. }));
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TelegramError::Api { code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_channel_full() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::from_async_error(AsyncError::ChannelFull);
        assert!(matches!(err, TelegramError::Api { code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::InvalidChatId("bad".into());
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::Api {
            code: 429,
            description: "rate limited".into(),
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = TelegramError::Api {
            code: 429,
            description: "rate limited".into(),
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(30))
        );
    }
}
