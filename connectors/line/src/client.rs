//! LINE Messaging API client.

use fcp_prelude::log_redaction::redact_url;
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
use uuid::Uuid;

/// LINE's request-deduplication header.
///
/// LINE stores the key for 24h and answers a repeat with 409 instead of
/// sending the message again. The value must be a UUID — LINE rejects any
/// other shape — so this cannot carry an `fcp2:`-prefixed key the way
/// Stripe's `Idempotency-Key` does.
const LINE_RETRY_KEY_HEADER: &str = "X-Line-Retry-Key";

/// Why replaying a LINE messaging POST cannot deliver the message twice.
///
/// Retrying a send after a 5xx or a timeout is only acceptable with one of
/// these in hand: both failures can be reported after LINE already delivered
/// the message (br-kxd3e).
#[derive(Debug, Clone)]
enum MessageReplaySafety {
    /// LINE deduplicates on [`LINE_RETRY_KEY_HEADER`]. Supported by the push,
    /// multicast, narrowcast, and broadcast endpoints.
    RetryKey(String),
    /// The reply endpoint takes no retry key and needs none: a reply token is
    /// single-use, so LINE rejects a second send with the same token rather
    /// than delivering a duplicate.
    SingleUseReplyToken,
}

impl MessageReplaySafety {
    /// Mint a fresh dedup key for one logical send.
    fn retry_key() -> Self {
        Self::RetryKey(Uuid::new_v4().to_string())
    }

    /// The header value to attach, if this endpoint takes one.
    fn retry_key_header(&self) -> Option<String> {
        match self {
            Self::RetryKey(key) => Some(key.clone()),
            Self::SingleUseReplyToken => None,
        }
    }
}

fn truncate_error_body(body: String) -> String {
    if body.len() > 500 {
        format!("{}...[truncated]", &body[..500])
    } else {
        body
    }
}

use crate::error::{LineError, LineResult};
use crate::types::{
    GroupMembersResponse, GroupSummary, Message, RichMenu, RichMenuCreateResponse,
    RichMenuListResponse, SentMessageResponse, UserProfile,
};

/// LINE API client with retry and runtime integration.
pub struct LineClient {
    client: Client,
    base_url: String,
    channel_access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for LineClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineClient")
            .field("base_url", &self.base_url)
            .field("channel_access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl LineClient {
    /// Create a new LINE client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        channel_access_token: &str,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> LineResult<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(LineError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            channel_access_token: channel_access_token.to_string(),
            retry_config,
        })
    }

    fn authenticate(&self, request: RequestBuilder) -> RequestBuilder {
        if self.channel_access_token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.channel_access_token)
        }
    }

    fn build_url(&self, path_segments: &[&str]) -> LineResult<Url> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|err| LineError::Config(format!("invalid LINE base_url: {err}")))?;
        let mut segments = url.path_segments_mut().map_err(|()| {
            LineError::Config("LINE base_url cannot be used as a hierarchical URL base".into())
        })?;
        segments.pop_if_empty();
        for segment in path_segments {
            segments.push(segment);
        }
        drop(segments);
        Ok(url)
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> LineResult<&str> {
        let trimmed = segment.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty()
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains("..")
            || trimmed.contains('\0')
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(LineError::InvalidInput(
                "Invalid path segment: contains forbidden characters".to_string(),
            ));
        }
        Ok(trimmed)
    }

    /// Push a message to a user.
    pub async fn push_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = self.build_url(&["v2", "bot", "message", "push"])?;
        let body = json!({ "to": to, "messages": messages });
        self.post_message(runtime, url, &body, MessageReplaySafety::retry_key())
            .await
    }

    /// Reply to a message using a reply token.
    pub async fn reply_message(
        &self,
        runtime: &ConnectorRuntime,
        reply_token: &str,
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = self.build_url(&["v2", "bot", "message", "reply"])?;
        let body = json!({ "replyToken": reply_token, "messages": messages });
        self.post_message(
            runtime,
            url,
            &body,
            MessageReplaySafety::SingleUseReplyToken,
        )
        .await
    }

    /// Multicast a message to multiple users.
    pub async fn multicast(
        &self,
        runtime: &ConnectorRuntime,
        to: &[String],
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = self.build_url(&["v2", "bot", "message", "multicast"])?;
        let body = json!({ "to": to, "messages": messages });
        self.post_message(runtime, url, &body, MessageReplaySafety::retry_key())
            .await
    }

    /// Common POST for messaging endpoints with retry.
    ///
    /// `replay_safety` states WHY replaying this request cannot deliver the
    /// message twice — see [`MessageReplaySafety`]. Every caller must supply
    /// one, so a messaging endpoint added later cannot inherit a retry loop
    /// without its author deciding the question (br-kxd3e).
    async fn post_message(
        &self,
        runtime: &ConnectorRuntime,
        url: Url,
        body: &serde_json::Value,
        replay_safety: MessageReplaySafety,
    ) -> LineResult<SentMessageResponse> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.clone();
        let body_clone = body.clone();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();
        // Resolved ONCE, outside the retry closure, so every attempt of this
        // call presents the same key. A per-attempt key would be worse than
        // none: it would look like protection while providing exactly zero.
        let retry_key = replay_safety.retry_key_header();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            let body = body_clone.clone();
            let retry_key = retry_key.clone();
            async move {
                debug!(attempt, "Sending LINE message");
                let mut request = if token.is_empty() {
                    client.post(url.clone())
                } else {
                    client.post(url.clone()).bearer_auth(&token)
                }
                .json(&body);
                if let Some(key) = retry_key.as_deref() {
                    request = request.header(LINE_RETRY_KEY_HEADER, key);
                }

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                // With a retry key attached, 409 is LINE reporting that it
                // already accepted an identical request and did NOT send the
                // message again. That is a success for the caller: surfacing an
                // error here would invite an invoke-level retry, which mints a
                // FRESH key and would genuinely duplicate the message.
                if status == 409 && retry_key.is_some() {
                    debug!("LINE deduplicated a retried message via X-Line-Retry-Key");
                    return AttemptOutcome::Success(SentMessageResponse::default());
                }
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: LineError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = truncate_error_body(resp.text().await.unwrap_or_default());
                    warn!(status, "LINE API request failed");
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                // LINE messaging endpoints return 200 with optional body
                let text = resp.text().await.unwrap_or_default();
                if text.is_empty() {
                    return AttemptOutcome::Success(SentMessageResponse::default());
                }
                match serde_json::from_str::<SentMessageResponse>(&text) {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Json(e)),
                }
            }
        })
        .await
    }

    /// Get a user's profile.
    pub async fn get_profile(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
    ) -> LineResult<UserProfile> {
        let user_id = Self::sanitize_path_segment(user_id)?;
        let url = self.build_url(&["v2", "bot", "profile", user_id])?;
        self.get_json(runtime, &url).await
    }

    /// Get a group's summary (profile).
    pub async fn get_group_summary(
        &self,
        runtime: &ConnectorRuntime,
        group_id: &str,
    ) -> LineResult<GroupSummary> {
        let group_id = Self::sanitize_path_segment(group_id)?;
        let url = self.build_url(&["v2", "bot", "group", group_id, "summary"])?;
        self.get_json(runtime, &url).await
    }

    /// Get group member IDs.
    pub async fn get_group_members(
        &self,
        runtime: &ConnectorRuntime,
        group_id: &str,
        start: Option<&str>,
    ) -> LineResult<GroupMembersResponse> {
        let group_id = Self::sanitize_path_segment(group_id)?;
        let mut url = self.build_url(&["v2", "bot", "group", group_id, "members", "ids"])?;
        if let Some(token) = start {
            url.query_pairs_mut().append_pair("start", token);
        }
        self.get_json(runtime, &url).await
    }

    /// List rich menus.
    pub async fn list_rich_menus(
        &self,
        runtime: &ConnectorRuntime,
    ) -> LineResult<RichMenuListResponse> {
        let url = self.build_url(&["v2", "bot", "richmenu", "list"])?;
        self.get_json(runtime, &url).await
    }

    /// Create a rich menu.
    pub async fn create_rich_menu(
        &self,
        runtime: &ConnectorRuntime,
        menu: &RichMenu,
    ) -> LineResult<RichMenuCreateResponse> {
        let url = self.build_url(&["v2", "bot", "richmenu"])?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(menu).map_err(LineError::Json)?;
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Creating LINE rich menu");
                let request = if token.is_empty() {
                    client.post(url.clone())
                } else {
                    client.post(url.clone()).bearer_auth(&token)
                }
                .json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        // br-kxd3e: unlike the messaging endpoints, LINE offers
                        // no dedup key for rich-menu creation, so a replay that
                        // reached LINE creates a SECOND menu. Only a
                        // connect-phase failure proves it did not.
                        let replayable = !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            LineError::Http(e),
                            None,
                            replayable,
                        );
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = truncate_error_body(resp.text().await.unwrap_or_default());
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    // A 429 was refused WITHOUT creating anything, so it stays
                    // retryable. Every other retryable class here (5xx) means
                    // LINE received the request and may have created the menu.
                    if status == 429 && !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<RichMenuCreateResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Http(e)),
                }
            }
        })
        .await
    }

    /// Delete a rich menu.
    pub async fn delete_rich_menu(
        &self,
        runtime: &ConnectorRuntime,
        rich_menu_id: &str,
    ) -> LineResult<()> {
        let rich_menu_id = Self::sanitize_path_segment(rich_menu_id)?;
        let url = self.build_url(&["v2", "bot", "richmenu", rich_menu_id])?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "Deleting LINE rich menu");
                let request = if token.is_empty() {
                    client.delete(url.clone())
                } else {
                    client.delete(url.clone()).bearer_auth(&token)
                };

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = truncate_error_body(resp.text().await.unwrap_or_default());
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
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

    /// Health check: verify the LINE API is reachable.
    pub async fn health_check(&self) -> LineResult<()> {
        let url = self.build_url(&["v2", "bot", "info"])?;
        let resp = self
            .authenticate(self.client.get(url))
            .send()
            .await
            .map_err(LineError::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() || status == 400 {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            Err(LineError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(LineError::Unauthorized(
                "Invalid channel access token".into(),
            ))
        } else {
            Err(LineError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.channel_access_token.is_empty()
    }

    /// Generic GET → JSON deserialization with retry.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &Url,
    ) -> LineResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.clone();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %redact_url(url.as_str()), "LINE API GET");
                let request = if token.is_empty() {
                    client.get(url.clone())
                } else {
                    client.get(url.clone()).bearer_auth(&token)
                };

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
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
                        error: LineError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = truncate_error_body(resp.text().await.unwrap_or_default());
                    warn!(status, "LINE API request failed");
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Http(e)),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = LineClient::new(
            "https://api.line.me",
            "test_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = LineClient::new(
            "https://api.line.me/",
            "test_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = LineClient::new(
            "https://api.line.me",
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn non_secretless() {
        let client = LineClient::new(
            "https://api.line.me",
            "real_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn debug_redacts_token() {
        let client = LineClient::new(
            "https://api.line.me",
            "super_secret_channel_token",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_channel_token"),
            "Debug output must not contain the raw token"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(LineClient::sanitize_path_segment("../etc/passwd").is_err());
        assert!(LineClient::sanitize_path_segment("foo/bar").is_err());
        assert!(LineClient::sanitize_path_segment("").is_err());
        assert!(LineClient::sanitize_path_segment("foo\0bar").is_err());
        assert!(LineClient::sanitize_path_segment("foo%2fbar").is_err());
        assert!(LineClient::sanitize_path_segment("foo%5Cbar").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(LineClient::sanitize_path_segment("U1234567890abcdef").is_ok());
        assert!(LineClient::sanitize_path_segment("richmenu-abc123").is_ok());
        assert_eq!(
            LineClient::sanitize_path_segment("  U1234567890abcdef  ").unwrap(),
            "U1234567890abcdef"
        );
    }
}
