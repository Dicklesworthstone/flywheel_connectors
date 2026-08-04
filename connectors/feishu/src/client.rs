//! Feishu/Lark API client.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{debug, warn};
use uuid::Uuid;

/// Body field Feishu deduplicates messaging requests on.
///
/// Unlike Stripe's or Mastodon's header-based keys, Feishu takes the dedup
/// value as a request-body field. Requests carrying the same value succeed at
/// most once within an hour.
const FEISHU_DEDUP_FIELD: &str = "uuid";

/// Why replaying a Feishu POST cannot duplicate a side effect.
///
/// A 5xx or a timeout can both be reported after Feishu already acted, so
/// retrying a POST needs one of these to hold (br-kxd3e).
#[derive(Debug, Clone)]
enum PostReplaySafety {
    /// Feishu deduplicates on [`FEISHU_DEDUP_FIELD`]. Honoured by the message
    /// send and reply endpoints.
    DedupUuid(String),
    /// Nothing to duplicate: either a read-only POST (Feishu models several
    /// queries as `*_batch_query` POSTs) or an operation that converges on the
    /// same state.
    NothingToDuplicate,
    /// No dedup mechanism, and a replay creates a second object.
    NotSafe,
}

impl PostReplaySafety {
    /// Mint a fresh dedup value for one logical send.
    fn dedup_uuid() -> Self {
        Self::DedupUuid(Uuid::new_v4().to_string())
    }

    /// Stamp the dedup value into the request body, if this endpoint takes one.
    fn apply_to_body(&self, mut body: serde_json::Value) -> serde_json::Value {
        if let Self::DedupUuid(value) = self
            && let Some(object) = body.as_object_mut()
        {
            object.insert(
                FEISHU_DEDUP_FIELD.to_owned(),
                serde_json::Value::String(value.clone()),
            );
        }
        body
    }

    /// Whether a request that reached Feishu may be sent again.
    const fn is_replay_safe(&self) -> bool {
        matches!(self, Self::DedupUuid(_) | Self::NothingToDuplicate)
    }
}

use crate::error::{FeishuError, FeishuResult};
use crate::types::{
    ApiResponse, CalendarEventsResponse, ChatInfo, ChatListResponse, DocumentContent,
    DriveCommentBatchQueryResponse, DriveCommentRepliesResponse, DriveDocumentMeta,
    DriveMetaBatchQueryResponse, MessageResponse, ReplyMessageRequest, SendMessageRequest,
    SpreadsheetInfo, TenantAccessTokenResponse, UserInfo,
};

/// Feishu API client with retry and runtime integration.
pub struct FeishuClient {
    client: Client,
    base_url: String,
    app_id: String,
    app_secret: String,
    tenant_access_token: Arc<Mutex<Option<String>>>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for FeishuClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuClient")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field(
                "tenant_access_token",
                &self
                    .tenant_access_token
                    .lock()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|_| "[REDACTED]")),
            )
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl FeishuClient {
    /// Create a new Feishu client.
    pub fn new(
        base_url: &str,
        app_id: &str,
        app_secret: &str,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> FeishuResult<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(FeishuError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            app_id: app_id.to_string(),
            app_secret: app_secret.to_string(),
            tenant_access_token: Arc::new(Mutex::new(None)),
            retry_config,
        })
    }

    /// Set the tenant access token (obtained via auth flow).
    pub fn set_tenant_access_token(&self, token: String) {
        if let Ok(mut guard) = self.tenant_access_token.lock() {
            *guard = Some(token);
        }
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> FeishuResult<&str> {
        let trimmed = segment.trim();
        let lower = trimmed.to_ascii_lowercase();
        if segment.trim().is_empty()
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains("..")
            || segment.contains('\0')
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(FeishuError::InvalidInput(
                "Invalid path segment: contains forbidden characters".into(),
            ));
        }
        Ok(trimmed)
    }

    fn auth_header(&self) -> FeishuResult<String> {
        let token = self
            .tenant_access_token
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| FeishuError::Unauthorized("No tenant access token".into()))?;
        Ok(format!("Bearer {token}"))
    }

    fn build_url(&self, path_segments: &[&str]) -> FeishuResult<Url> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|err| FeishuError::Config(format!("invalid Feishu base_url: {err}")))?;
        let mut segments = url.path_segments_mut().map_err(|()| {
            FeishuError::Config("Feishu base_url cannot be used as a hierarchical URL base".into())
        })?;
        segments.pop_if_empty();
        for segment in path_segments {
            segments.push(segment);
        }
        drop(segments);
        Ok(url)
    }

    async fn request_tenant_access_token(&self) -> FeishuResult<String> {
        let url =
            self.build_url(&["open-apis", "auth", "v3", "tenant_access_token", "internal"])?;
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });

        let resp = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(FeishuError::Http)?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            return Err(FeishuError::HttpStatus {
                status,
                message: format!("Token request failed with HTTP {status}"),
            });
        }

        let token_resp: TenantAccessTokenResponse = resp.json().await.map_err(FeishuError::Http)?;

        if token_resp.code != 0 {
            return Err(FeishuError::Api {
                code: token_resp.code,
                message: token_resp.msg,
            });
        }

        let token = token_resp
            .tenant_access_token
            .ok_or_else(|| FeishuError::Api {
                code: -1,
                message: "No token in response".into(),
            })?;

        self.set_tenant_access_token(token.clone());
        Ok(token)
    }

    /// Obtain a tenant access token from Feishu.
    pub async fn obtain_tenant_access_token(&self) -> FeishuResult<String> {
        self.request_tenant_access_token().await
    }

    async fn ensure_tenant_access_token(&self) -> FeishuResult<String> {
        match self.auth_header() {
            Ok(header) => Ok(header.trim_start_matches("Bearer ").to_string()),
            Err(_) => self.obtain_tenant_access_token().await,
        }
    }

    /// Send a message.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        receive_id_type: &str,
        req: &SendMessageRequest,
    ) -> FeishuResult<MessageResponse> {
        let mut url = self.build_url(&["open-apis", "im", "v1", "messages"])?;
        url.query_pairs_mut()
            .append_pair("receive_id_type", receive_id_type);
        let body = serde_json::to_value(req).map_err(FeishuError::Json)?;
        self.post_api(runtime, &url, &body, PostReplaySafety::dedup_uuid())
            .await
    }

    /// Reply to a message.
    pub async fn reply_message(
        &self,
        runtime: &ConnectorRuntime,
        message_id: &str,
        req: &ReplyMessageRequest,
    ) -> FeishuResult<MessageResponse> {
        let message_id = Self::sanitize_path_segment(message_id)?;
        let url = self.build_url(&["open-apis", "im", "v1", "messages", message_id, "reply"])?;
        let body = serde_json::to_value(req).map_err(FeishuError::Json)?;
        self.post_api(runtime, &url, &body, PostReplaySafety::dedup_uuid())
            .await
    }

    /// Get a message by ID.
    pub async fn get_message(
        &self,
        runtime: &ConnectorRuntime,
        message_id: &str,
    ) -> FeishuResult<MessageResponse> {
        let message_id = Self::sanitize_path_segment(message_id)?;
        let url = self.build_url(&["open-apis", "im", "v1", "messages", message_id])?;
        self.get_api(runtime, &url).await
    }

    /// List chats.
    pub async fn list_chats(
        &self,
        runtime: &ConnectorRuntime,
        page_token: Option<&str>,
        page_size: Option<u32>,
    ) -> FeishuResult<ChatListResponse> {
        let mut url = self.build_url(&["open-apis", "im", "v1", "chats"])?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(token) = page_token {
                query.append_pair("page_token", token);
            }
            if let Some(size) = page_size {
                query.append_pair("page_size", &size.to_string());
            }
        }
        self.get_api(runtime, &url).await
    }

    /// Get chat details.
    pub async fn get_chat(
        &self,
        runtime: &ConnectorRuntime,
        chat_id: &str,
    ) -> FeishuResult<ChatInfo> {
        let chat_id = Self::sanitize_path_segment(chat_id)?;
        let url = self.build_url(&["open-apis", "im", "v1", "chats", chat_id])?;
        self.get_api(runtime, &url).await
    }

    /// Get user info.
    pub async fn get_user(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        user_id_type: &str,
    ) -> FeishuResult<UserInfo> {
        let user_id = Self::sanitize_path_segment(user_id)?;
        let mut url = self.build_url(&["open-apis", "contact", "v3", "users", user_id])?;
        url.query_pairs_mut()
            .append_pair("user_id_type", user_id_type);
        self.get_api(runtime, &url).await
    }

    /// Get document content.
    pub async fn get_document(
        &self,
        runtime: &ConnectorRuntime,
        document_id: &str,
    ) -> FeishuResult<DocumentContent> {
        let document_id = Self::sanitize_path_segment(document_id)?;
        let url = self.build_url(&[
            "open-apis",
            "docx",
            "v1",
            "documents",
            document_id,
            "raw_content",
        ])?;
        self.get_api(runtime, &url).await
    }

    /// Get spreadsheet info.
    pub async fn get_spreadsheet(
        &self,
        runtime: &ConnectorRuntime,
        spreadsheet_token: &str,
    ) -> FeishuResult<SpreadsheetInfo> {
        let spreadsheet_token = Self::sanitize_path_segment(spreadsheet_token)?;
        let url = self.build_url(&[
            "open-apis",
            "sheets",
            "v3",
            "spreadsheets",
            spreadsheet_token,
        ])?;
        self.get_api(runtime, &url).await
    }

    /// List calendar events.
    pub async fn list_calendar_events(
        &self,
        runtime: &ConnectorRuntime,
        calendar_id: &str,
        page_token: Option<&str>,
    ) -> FeishuResult<CalendarEventsResponse> {
        let calendar_id = Self::sanitize_path_segment(calendar_id)?;
        let mut url = self.build_url(&[
            "open-apis",
            "calendar",
            "v4",
            "calendars",
            calendar_id,
            "events",
        ])?;
        if let Some(token) = page_token {
            url.query_pairs_mut().append_pair("page_token", token);
        }
        self.get_api(runtime, &url).await
    }

    /// Build a redaction-safe document-comment turn context.
    pub async fn get_comment_context(
        &self,
        runtime: &ConnectorRuntime,
        file_token: &str,
        file_type: &str,
        comment_id: &str,
        reply_id: Option<&str>,
    ) -> FeishuResult<serde_json::Value> {
        let file_token = Self::sanitize_path_segment(file_token)?;
        let comment_id = Self::sanitize_path_segment(comment_id)?;
        let meta_url = self.build_url(&["open-apis", "drive", "v1", "metas", "batch_query"])?;
        let meta_body = serde_json::json!({
            "request_docs": [{
                "doc_token": file_token,
                "doc_type": file_type,
            }],
            "with_url": true,
        });
        // Feishu models this lookup as a POST, but it only reads.
        let meta: DriveMetaBatchQueryResponse = self
            .post_api(
                runtime,
                &meta_url,
                &meta_body,
                PostReplaySafety::NothingToDuplicate,
            )
            .await?;
        let document = meta.metas.first().cloned().unwrap_or(DriveDocumentMeta {
            doc_token: Some(file_token.to_owned()),
            doc_type: Some(file_type.to_owned()),
            title: None,
            url: None,
        });

        let mut comment_url = self.build_url(&[
            "open-apis",
            "drive",
            "v1",
            "files",
            file_token,
            "comments",
            "batch_query",
        ])?;
        {
            let mut query = comment_url.query_pairs_mut();
            query.append_pair("file_type", file_type);
            query.append_pair("user_id_type", "open_id");
        }
        // Also a read-only POST.
        let comment_batch: DriveCommentBatchQueryResponse = self
            .post_api(
                runtime,
                &comment_url,
                &serde_json::json!({ "comment_ids": [comment_id] }),
                PostReplaySafety::NothingToDuplicate,
            )
            .await?;
        let comment = comment_batch.items.first().cloned();

        let mut replies_url = self.build_url(&[
            "open-apis",
            "drive",
            "v1",
            "files",
            file_token,
            "comments",
            comment_id,
            "replies",
        ])?;
        {
            let mut query = replies_url.query_pairs_mut();
            query.append_pair("file_type", file_type);
            query.append_pair("page_size", "100");
            query.append_pair("user_id_type", "open_id");
        }
        let replies: DriveCommentRepliesResponse = self.get_api(runtime, &replies_url).await?;
        let target_reply = reply_id.and_then(|target| {
            replies
                .items
                .iter()
                .find(|reply| reply.reply_id.as_deref() == Some(target))
        });
        let root_reply = comment
            .as_ref()
            .and_then(|comment| comment.reply_list.as_ref())
            .and_then(|list| list.replies.first());

        Ok(serde_json::json!({
            "file_token": file_token,
            "file_type": file_type,
            "comment_id": comment_id,
            "reply_id": reply_id,
            "document": document,
            "comment": comment,
            "is_whole_comment": comment.as_ref().and_then(|comment| comment.is_whole).unwrap_or(false),
            "quote_text": comment.as_ref().and_then(|comment| comment.quote.as_deref()),
            "root_comment_text": root_reply.map(Self::extract_comment_reply_text).unwrap_or_default(),
            "target_reply_text": target_reply.map(Self::extract_comment_reply_text).unwrap_or_default(),
            "replies": replies.items,
            "has_more_replies": replies.has_more,
            "raw_payload_included": false,
        }))
    }

    /// Reply to an existing Feishu Drive comment thread.
    pub async fn reply_to_comment(
        &self,
        runtime: &ConnectorRuntime,
        file_token: &str,
        file_type: &str,
        comment_id: &str,
        text: &str,
    ) -> FeishuResult<serde_json::Value> {
        let file_token = Self::sanitize_path_segment(file_token)?;
        let comment_id = Self::sanitize_path_segment(comment_id)?;
        let mut url = self.build_url(&[
            "open-apis",
            "drive",
            "v1",
            "files",
            file_token,
            "comments",
            comment_id,
            "replies",
        ])?;
        url.query_pairs_mut().append_pair("file_type", file_type);
        let body = serde_json::json!({
            "content": {
                "elements": [{
                    "type": "text_run",
                    "text_run": { "text": Self::escape_comment_text(text) },
                }],
            },
        });
        // Drive comments take no dedup key, so a replay posts a second reply.
        self.post_api(runtime, &url, &body, PostReplaySafety::NotSafe)
            .await
    }

    /// Add a whole-document Feishu Drive comment.
    pub async fn add_whole_comment(
        &self,
        runtime: &ConnectorRuntime,
        file_token: &str,
        file_type: &str,
        text: &str,
    ) -> FeishuResult<serde_json::Value> {
        let file_token = Self::sanitize_path_segment(file_token)?;
        let url = self.build_url(&[
            "open-apis",
            "drive",
            "v1",
            "files",
            file_token,
            "new_comments",
        ])?;
        let body = serde_json::json!({
            "file_type": file_type,
            "reply_elements": [{
                "type": "text",
                "text": Self::escape_comment_text(text),
            }],
        });
        // Same: a replay creates a SECOND comment on the document.
        self.post_api(runtime, &url, &body, PostReplaySafety::NotSafe)
            .await
    }

    /// Add or delete a Feishu Drive comment reaction.
    pub async fn update_comment_reaction(
        &self,
        runtime: &ConnectorRuntime,
        file_token: &str,
        file_type: &str,
        reply_id: &str,
        action: &str,
        reaction_type: &str,
    ) -> FeishuResult<serde_json::Value> {
        let file_token = Self::sanitize_path_segment(file_token)?;
        let reply_id = Self::sanitize_path_segment(reply_id)?;
        let mut url = self.build_url(&[
            "open-apis",
            "drive",
            "v2",
            "files",
            file_token,
            "comments",
            "reaction",
        ])?;
        url.query_pairs_mut().append_pair("file_type", file_type);
        let body = serde_json::json!({
            "action": action,
            "reply_id": reply_id,
            "reaction_type": reaction_type,
        });
        // The body names the target state (`action` is add or delete), so
        // applying it twice converges rather than stacking.
        self.post_api(runtime, &url, &body, PostReplaySafety::NothingToDuplicate)
            .await
    }

    /// Health check: verify the Feishu API is reachable via token request.
    pub async fn health_check(&self) -> FeishuResult<()> {
        // Use the auth endpoint as health check (it's always available)
        let url =
            self.build_url(&["open-apis", "auth", "v3", "tenant_access_token", "internal"])?;
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });
        let resp = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(FeishuError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            Err(FeishuError::RateLimited { retry_after_ms })
        } else {
            Err(FeishuError::HttpStatus {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if credentials are configured.
    pub fn has_credentials(&self) -> bool {
        !self.app_id.trim().is_empty() && !self.app_secret.trim().is_empty()
    }

    fn escape_comment_text(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn extract_comment_reply_text(reply: &crate::types::DriveCommentReply) -> String {
        let Some(content) = &reply.content else {
            return String::new();
        };
        let elements = content
            .get("elements")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut parts = Vec::new();
        for element in elements {
            match element.get("type").and_then(serde_json::Value::as_str) {
                Some("text_run") => {
                    if let Some(text) = element
                        .pointer("/text_run/text")
                        .and_then(serde_json::Value::as_str)
                    {
                        parts.push(text.to_owned());
                    }
                }
                Some("text") => {
                    if let Some(text) = element.get("text").and_then(serde_json::Value::as_str) {
                        parts.push(text.to_owned());
                    }
                }
                Some("docs_link") => {
                    if let Some(url) = element
                        .pointer("/docs_link/url")
                        .and_then(serde_json::Value::as_str)
                    {
                        parts.push(url.to_owned());
                    }
                }
                Some("person") => {
                    if let Some(name) = element
                        .pointer("/person/name")
                        .and_then(serde_json::Value::as_str)
                    {
                        parts.push(name.to_owned());
                    }
                }
                _ => {}
            }
        }
        parts.join("")
    }

    /// Generic POST with API response extraction and retry.
    ///
    /// `replay_safety` states WHY replaying this POST cannot duplicate a side
    /// effect — see [`PostReplaySafety`]. Every caller must supply one, so a
    /// POST added later cannot inherit this retry loop without its author
    /// deciding the question (br-kxd3e).
    async fn post_api<T: DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &Url,
        body: &serde_json::Value,
        replay_safety: PostReplaySafety,
    ) -> FeishuResult<T> {
        let auth = format!("Bearer {}", self.ensure_tenant_access_token().await?);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        // The dedup key is stamped into the body ONCE, before the retry loop,
        // so every attempt sends the same value. A per-attempt uuid would look
        // like protection while providing exactly zero.
        let body_clone = replay_safety.apply_to_body(body.clone());
        let replay_safe = replay_safety.is_replay_safe();
        let client = self.client.clone();
        let token_cache = Arc::clone(&self.tenant_access_token);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let auth = auth.clone();
            let body = body_clone.clone();
            let token_cache = Arc::clone(&token_cache);
            async move {
                debug!(attempt, url = %redact_url(&url), "Feishu API POST");
                let request = client.post(&url).header("Authorization", &auth).json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        // Only a connect-phase failure proves the request never
                        // reached Feishu.
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            FeishuError::Http(e),
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
                        error: FeishuError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    if let Ok(mut guard) = token_cache.lock() {
                        *guard = None;
                    }
                    return AttemptOutcome::Terminal(FeishuError::Unauthorized(
                        "Tenant access token invalid or expired".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Feishu API request failed");
                    let decision = classify_http_status(status, None);
                    let err = FeishuError::HttpStatus {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        // A 5xx means Feishu RECEIVED the request and may have
                        // acted on it. 429 is handled above, before this gate,
                        // because it was refused without being performed.
                        return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
                    }
                    return AttemptOutcome::Terminal(err);
                }

                let api_resp: ApiResponse<T> = match resp.json().await {
                    Ok(r) => r,
                    Err(e) => return AttemptOutcome::Terminal(FeishuError::Http(e)),
                };

                if api_resp.code != 0 {
                    let err = FeishuError::Api {
                        code: api_resp.code,
                        message: api_resp.msg,
                    };
                    if err.is_retryable() {
                        // Feishu's own retryable application codes are returned
                        // with HTTP 200, so the request definitely arrived.
                        return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match api_resp.data {
                    Some(data) => AttemptOutcome::Success(data),
                    None => AttemptOutcome::Terminal(FeishuError::Api {
                        code: -1,
                        message: "No data in response".into(),
                    }),
                }
            }
        })
        .await
    }

    /// Generic GET with API response extraction and retry.
    async fn get_api<T: DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &Url,
    ) -> FeishuResult<T> {
        let auth = format!("Bearer {}", self.ensure_tenant_access_token().await?);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let client = self.client.clone();
        let token_cache = Arc::clone(&self.tenant_access_token);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let auth = auth.clone();
            let token_cache = Arc::clone(&token_cache);
            async move {
                debug!(attempt, url = %redact_url(&url), "Feishu API GET");
                let request = client.get(&url).header("Authorization", &auth);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: FeishuError::Http(e),
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
                        error: FeishuError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    if let Ok(mut guard) = token_cache.lock() {
                        *guard = None;
                    }
                    return AttemptOutcome::Terminal(FeishuError::Unauthorized(
                        "Tenant access token invalid or expired".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Feishu API request failed");
                    let decision = classify_http_status(status, None);
                    let err = FeishuError::HttpStatus {
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

                let api_resp: ApiResponse<T> = match resp.json().await {
                    Ok(r) => r,
                    Err(e) => return AttemptOutcome::Terminal(FeishuError::Http(e)),
                };

                if api_resp.code != 0 {
                    let err = FeishuError::Api {
                        code: api_resp.code,
                        message: api_resp.msg,
                    };
                    if err.is_retryable() {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match api_resp.data {
                    Some(data) => AttemptOutcome::Success(data),
                    None => AttemptOutcome::Terminal(FeishuError::Api {
                        code: -1,
                        message: "No data in response".into(),
                    }),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_sdk::ConnectorRuntimeConfig;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Option<serde_json::Value>,
    }

    impl TestHttpResponse {
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
                body: Some(body),
            }
        }

        fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: None,
            }
        }
    }

    struct TestApiServer {
        uri: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestApiServer {
        fn start(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().unwrap();
                    serve_response(stream, response);
                }
            });
            Self {
                uri: format!("http://{addr}"),
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.uri
        }

        fn finish(mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test API server thread finished");
            }
        }
    }

    fn serve_response(mut stream: TcpStream, response: TestHttpResponse) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        assert_eq!(method, response.method);
        assert_eq!(target.split('?').next().unwrap_or(target), response.path);

        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let trimmed = header.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some(value) = trimmed.strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap();
            } else if let Some(value) = trimmed.strip_prefix("Content-Length:") {
                content_length = value.trim().parse().unwrap();
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
        }

        let body = response
            .body
            .map(|body| body.to_string())
            .unwrap_or_default();
        let reason = match response.status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "Test Status",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            reason,
            body.len(),
            body
        )
        .unwrap();
    }

    #[test]
    fn client_creation() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = FeishuClient::new(
            "https://open.feishu.cn/",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn has_credentials() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.has_credentials());
    }

    #[test]
    fn missing_credentials() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "",
            "",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.has_credentials());
    }

    #[test]
    fn debug_redacts_secrets() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "super_secret_value",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_value"),
            "Debug must not contain raw secret"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(FeishuClient::sanitize_path_segment("../etc").is_err());
        assert!(FeishuClient::sanitize_path_segment("foo/bar").is_err());
        assert!(FeishuClient::sanitize_path_segment("").is_err());
        assert!(FeishuClient::sanitize_path_segment("a\0b").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(FeishuClient::sanitize_path_segment("om_abc123").is_ok());
        assert!(FeishuClient::sanitize_path_segment("oc_def456").is_ok());
    }

    #[test]
    fn auth_header_without_token() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.auth_header().is_err());
    }

    #[test]
    fn auth_header_with_token() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        client.set_tenant_access_token("t-abc123".into());
        let header = client.auth_header().unwrap();
        assert_eq!(header, "Bearer t-abc123");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/open-apis/auth/v3/tenant_access_token/internal",
            200,
            serde_json::json!({
                "code": 0,
                "msg": "ok",
                "tenant_access_token": "t-test",
                "expire": 7200
            }),
        )]);

        let client = FeishuClient::new(
            server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn obtain_tenant_token() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/open-apis/auth/v3/tenant_access_token/internal",
            200,
            serde_json::json!({
                "code": 0,
                "msg": "ok",
                "tenant_access_token": "t-obtained",
                "expire": 7200
            }),
        )]);

        let client = FeishuClient::new(
            server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        let token = client.obtain_tenant_access_token().await.unwrap();
        assert_eq!(token, "t-obtained");
        assert!(client.auth_header().is_ok());
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_server_error() {
        let server = TestApiServer::start(vec![TestHttpResponse::empty(
            "POST",
            "/open-apis/auth/v3/tenant_access_token/internal",
            500,
        )]);

        let client = FeishuClient::new(
            server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.health_check().await.is_err());
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn list_chats_bootstraps_token_on_first_request() {
        let server = TestApiServer::start(vec![
            TestHttpResponse::json(
                "POST",
                "/open-apis/auth/v3/tenant_access_token/internal",
                200,
                serde_json::json!({
                "code": 0,
                "msg": "ok",
                "tenant_access_token": "t-lazy",
                "expire": 7200
                }),
            ),
            TestHttpResponse::json(
                "GET",
                "/open-apis/im/v1/chats",
                200,
                serde_json::json!({
                "code": 0,
                "msg": "ok",
                "data": {
                    "items": [{ "chat_id": "oc_123", "name": "General" }],
                    "page_token": null,
                    "has_more": false
                }
                }),
            ),
        ]);

        let client = FeishuClient::new(
            server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());

        let response = client.list_chats(&runtime, None, Some(20)).await.unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].chat_id, "oc_123");
        assert_eq!(client.auth_header().unwrap(), "Bearer t-lazy");
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn debug_redacts_token_after_set() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        client.set_tenant_access_token("t-super-secret-token".into());
        let debug_output = format!("{client:?}");
        assert!(!debug_output.contains("t-super-secret-token"));
    }
}
