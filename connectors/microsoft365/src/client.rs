//! Microsoft Graph REST API client.
//!
//! Uses Bearer token auth and JSON bodies for POST/PUT/PATCH.
//! Handles OData pagination via `@odata.nextLink`.

use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, header};
use tracing::warn;

use crate::{
    error::{M365Error, M365Result},
    onenote::PageContentCommand,
    types::GraphListResponse,
};

pub const DEFAULT_API_URL: &str = "https://graph.microsoft.com/v1.0";

/// Authentication mode for Microsoft Graph access.
#[derive(Clone)]
pub enum M365Auth {
    /// Direct bearer access token.
    AccessToken(String),
    /// Secretless credential reference for egress proxy injection.
    CredentialId(CredentialId),
}

impl M365Auth {
    /// Render a redacted auth label for diagnostics/logging.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => {
                let id_str = id.to_string();
                let prefix = id_str.chars().take(8).collect::<String>();
                format!("credential_id:{prefix}…")
            }
        }
    }

    /// True when auth depends on credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for M365Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Microsoft Graph REST API client.
pub struct M365Client {
    http: Client,
    auth: M365Auth,
    api_url: String,
    max_retries: u32,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl M365Client {
    /// Create a new Graph API client with a Bearer access token.
    pub fn new(access_token: &str) -> M365Result<Self> {
        Self::new_with_auth(M365Auth::AccessToken(access_token.to_string()))
    }

    /// Create a new Graph API client with explicit auth mode.
    pub fn new_with_auth(auth: M365Auth) -> M365Result<Self> {
        let http = Client::builder()
            .user_agent("fcp-microsoft365/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(M365Error::Http)?;

        Ok(Self {
            http,
            auth,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
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

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    fn build_api_url(&self, relative_path: &str) -> M365Result<String> {
        let base = format!("{}/", self.api_url.trim_end_matches('/'));
        let base_url = reqwest::Url::parse(&base)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph base URL: {e}")))?;
        let url = base_url
            .join(relative_path.trim_start_matches('/'))
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph request path: {e}")))?;
        Ok(url.to_string())
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            M365Auth::AccessToken(token) => {
                request.header(header::AUTHORIZATION, format!("Bearer {token}"))
            }
            M365Auth::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }

    /// Perform a lightweight credential/readiness check against Graph.
    ///
    /// This first probes `/me` (delegated flows) and falls back to `/organization`
    /// for application-permission tokens that do not expose `/me`.
    pub async fn health_check(&self) -> M365Result<serde_json::Value> {
        let me_url = format!("{}/me?$select=id,userPrincipalName", self.api_url);
        match self.get(&me_url).await {
            Ok(payload) => Ok(payload),
            Err(primary_err) => {
                let can_fallback = matches!(
                    primary_err,
                    M365Error::Api {
                        status_code: Some(401 | 403),
                        ..
                    }
                );
                if !can_fallback {
                    return Err(primary_err);
                }

                let org_url = format!("{}/organization?$select=id,displayName", self.api_url);
                match self.get(&org_url).await {
                    Ok(payload) => Ok(payload),
                    Err(_) => Err(primary_err),
                }
            }
        }
    }

    // ── Mail operations ──────────────────────────────────────────

    /// List messages in a user's mailbox.
    pub async fn list_messages(
        &self,
        user_id: &str,
        folder_id: Option<&str>,
        top: Option<u32>,
        skip: Option<u32>,
        filter: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let folder_part = match folder_id {
            Some(f) => {
                sanitize_path_segment(f, "folder_id")?;
                format!("/mailFolders/{f}")
            }
            None => String::new(),
        };
        let base = self.build_api_url(&format!(
            "{}{folder_part}/messages",
            user_scope_path(user_id)?
        ))?;
        let mut url = reqwest::Url::parse(&base)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph base URL: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(t) = top {
                pairs.append_pair("$top", &t.to_string());
            }
            if let Some(s) = skip {
                pairs.append_pair("$skip", &s.to_string());
            }
            if let Some(f) = filter {
                pairs.append_pair("$filter", f);
            }
        }
        let data = self.get(url.as_str()).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific message.
    pub async fn get_message(
        &self,
        user_id: &str,
        message_id: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Send a mail message.
    pub async fn send_message(&self, user_id: &str, message: &serde_json::Value) -> M365Result<()> {
        let url = self.build_api_url(&format!("{}/sendMail", user_scope_path(user_id)?))?;
        let body = serde_json::json!({ "message": message });
        self.post_json_no_content(&url, &body).await
    }

    /// Create a draft message.
    pub async fn create_draft(
        &self,
        user_id: &str,
        message: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = self.build_api_url(&format!("{}/messages", user_scope_path(user_id)?))?;
        self.post_json(&url, message).await
    }

    /// Search messages in a mailbox using Microsoft Graph `$search`.
    pub async fn search_messages(
        &self,
        user_id: &str,
        query: &str,
        top: Option<u32>,
        skip: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let base = self.build_api_url(&format!("{}/messages", user_scope_path(user_id)?))?;
        let mut url = reqwest::Url::parse(&base)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph base URL: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("$search", &format!("\"{query}\""));
            if let Some(t) = top {
                pairs.append_pair("$top", &t.to_string());
            }
            if let Some(s) = skip {
                pairs.append_pair("$skip", &s.to_string());
            }
        }

        let data = self
            .execute(
                || {
                    self.apply_auth(
                        self.http
                            .get(url.as_str())
                            .header("ConsistencyLevel", "eventual"),
                    )
                },
                true,
            )
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Reply to an existing message.
    pub async fn reply_message(
        &self,
        user_id: &str,
        message_id: &str,
        comment: Option<&str>,
        message: Option<&serde_json::Value>,
    ) -> M365Result<()> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/reply",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::Map::new();
        if let Some(comment) = comment {
            body.insert(
                "comment".into(),
                serde_json::Value::String(comment.to_string()),
            );
        }
        if let Some(message) = message {
            body.insert("message".into(), message.clone());
        }
        self.post_json_no_content(&url, &serde_json::Value::Object(body))
            .await
    }

    /// Forward an existing message.
    pub async fn forward_message(
        &self,
        user_id: &str,
        message_id: &str,
        comment: Option<&str>,
        to_recipients: &[serde_json::Value],
    ) -> M365Result<()> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/forward",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::Map::new();
        body.insert(
            "toRecipients".into(),
            serde_json::Value::Array(to_recipients.to_vec()),
        );
        if let Some(comment) = comment {
            body.insert(
                "comment".into(),
                serde_json::Value::String(comment.to_string()),
            );
        }
        self.post_json_no_content(&url, &serde_json::Value::Object(body))
            .await
    }

    /// List message attachments.
    pub async fn list_attachments(
        &self,
        user_id: &str,
        message_id: &str,
        top: Option<u32>,
        skip: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        sanitize_path_segment(message_id, "message_id")?;
        let mut url = self.build_api_url(&format!(
            "{}/messages/{message_id}/attachments",
            user_scope_path(user_id)?
        ))?;
        let mut params = Vec::new();
        if let Some(t) = top {
            params.push(format!("$top={t}"));
        }
        if let Some(s) = skip {
            params.push(format!("$skip={s}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Add an attachment to an existing message.
    pub async fn add_attachment(
        &self,
        user_id: &str,
        message_id: &str,
        attachment: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/attachments",
            user_scope_path(user_id)?
        ))?;
        self.post_json(&url, attachment).await
    }

    // ── Files operations ─────────────────────────────────────────

    /// List files and folders in OneDrive.
    pub async fn list_items(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let url = match path {
            Some(p) if !p.is_empty() => {
                let normalized_path = p.trim_matches('/');
                if normalized_path.is_empty() {
                    self.build_api_url(&format!("{user_scope}/drive/root/children"))?
                } else {
                    self.build_api_url(&format!(
                        "{user_scope}/drive/root:/{normalized_path}:/children"
                    ))?
                }
            }
            _ => self.build_api_url(&format!("{user_scope}/drive/root/children"))?,
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a file from OneDrive. Returns base64-encoded content.
    pub async fn download_file(
        &self,
        user_id: &str,
        item_id: &str,
    ) -> M365Result<(String, serde_json::Value)> {
        let (bytes, metadata) = self.download_file_raw(user_id, item_id).await?;
        let content = BASE64.encode(&bytes);
        Ok((content, metadata))
    }

    /// Download a file from OneDrive and return the raw bytes plus metadata.
    pub async fn download_file_raw(
        &self,
        user_id: &str,
        item_id: &str,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        self.download_drive_item_bytes(user_id, item_id, None).await
    }

    /// Download a drive item converted into another format (for example PDF).
    pub async fn download_file_as(
        &self,
        user_id: &str,
        item_id: &str,
        format: &str,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        self.download_drive_item_bytes(user_id, item_id, Some(format))
            .await
    }

    /// Upload a file to OneDrive (simple upload, up to 4 MB).
    pub async fn upload_file(
        &self,
        user_id: &str,
        path: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        let normalized_path = normalize_drive_root_path(path)?;
        let url = self.build_api_url(&format!(
            "{}/drive/root:/{normalized_path}:/content",
            user_scope_path(user_id)?
        ))?;
        self.put_bytes(&url, content).await
    }

    /// Delete a drive item.
    pub async fn delete_item(&self, user_id: &str, item_id: &str) -> M365Result<()> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}",
            user_scope_path(user_id)?
        ))?;
        self.delete_no_content(&url).await
    }

    /// Get metadata for a single drive item by ID.
    pub async fn get_item(&self, user_id: &str, item_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Search for files and folders in OneDrive.
    pub async fn search_files(&self, user_id: &str, query: &str) -> M365Result<GraphListResponse> {
        let encoded =
            percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC);
        let url = self.build_api_url(&format!(
            "{}/drive/root/search(q='{encoded}')",
            user_scope_path(user_id)?
        ))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a sharing link for a drive item.
    pub async fn create_share_link(
        &self,
        user_id: &str,
        item_id: &str,
        link_type: &str,
        scope: Option<&str>,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}/createLink",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::json!({ "type": link_type });
        if let Some(s) = scope {
            body["scope"] = serde_json::Value::String(s.to_string());
        }
        self.post_json(&url, &body).await
    }

    /// Replace the contents of an existing drive item.
    pub async fn update_item_content(
        &self,
        user_id: &str,
        item_id: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}/content",
            user_scope_path(user_id)?
        ))?;
        self.put_bytes(&url, content).await
    }

    // ── Calendar operations ──────────────────────────────────────

    /// List calendar events within a time range.
    pub async fn list_events(
        &self,
        user_id: &str,
        start_datetime: Option<&str>,
        end_datetime: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let url = match (start_datetime, end_datetime) {
            (Some(start), Some(end)) => {
                let mut url = reqwest::Url::parse(
                    &self.build_api_url(&format!("{user_scope}/calendarView"))?,
                )
                .map_err(|e| M365Error::InvalidConfig(format!("Invalid calendarView URL: {e}")))?;
                {
                    let mut pairs = url.query_pairs_mut();
                    pairs.append_pair("startDateTime", start);
                    pairs.append_pair("endDateTime", end);
                }
                url.to_string()
            }
            _ => self.build_api_url(&format!("{user_scope}/events"))?,
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a calendar event.
    pub async fn create_event(
        &self,
        user_id: &str,
        event: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = self.build_api_url(&format!("{}/events", user_scope_path(user_id)?))?;
        self.post_json(&url, event).await
    }

    /// Delete a calendar event.
    pub async fn delete_event(&self, user_id: &str, event_id: &str) -> M365Result<()> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.delete_no_content(&url).await
    }

    /// Get a single calendar event by ID.
    pub async fn get_event(&self, user_id: &str, event_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.get(&url).await
    }

    /// Update an existing calendar event (PATCH).
    pub async fn update_event(
        &self,
        user_id: &str,
        event_id: &str,
        updates: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.patch_json(&url, updates).await
    }

    /// Get free/busy schedule for users.
    pub async fn get_freebusy(
        &self,
        schedules: &[String],
        start_time: &serde_json::Value,
        end_time: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/me/calendar/getSchedule", self.api_url);
        let body = serde_json::json!({
            "schedules": schedules,
            "startTime": start_time,
            "endTime": end_time,
        });
        // Read-only POST: getSchedule queries availability and creates nothing.
        self.post_json_replay_safe(&url, &body).await
    }

    // ── Tasks operations ─────────────────────────────────────────

    /// List all To Do task lists.
    pub async fn list_task_lists(&self, user_id: &str) -> M365Result<GraphListResponse> {
        let url = self.build_api_url(&format!("{}/todo/lists", user_scope_path(user_id)?))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List tasks in a To Do list.
    pub async fn list_tasks(&self, user_id: &str, list_id: &str) -> M365Result<GraphListResponse> {
        sanitize_path_segment(list_id, "list_id")?;
        let url = self.build_api_url(&format!(
            "{}/todo/lists/{list_id}/tasks",
            user_scope_path(user_id)?
        ))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a task in a To Do list.
    pub async fn create_task(
        &self,
        user_id: &str,
        list_id: &str,
        task: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(list_id, "list_id")?;
        let url = self.build_api_url(&format!(
            "{}/todo/lists/{list_id}/tasks",
            user_scope_path(user_id)?
        ))?;
        self.post_json(&url, task).await
    }

    // ── OneNote operations ───────────────────────────────────────

    /// List OneNote notebooks for a user.
    pub async fn list_notebooks(
        &self,
        user_id: &str,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let mut url =
            self.build_api_url(&format!("{}/onenote/notebooks", user_scope_path(user_id)?))?;
        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List OneNote sections for a user, optionally scoped to a notebook or section group.
    pub async fn list_sections(
        &self,
        user_id: &str,
        notebook_id: Option<&str>,
        section_group_id: Option<&str>,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let mut url = if let Some(notebook_id) = notebook_id {
            sanitize_path_segment(notebook_id, "notebook_id")?;
            self.build_api_url(&format!(
                "{user_scope}/onenote/notebooks/{notebook_id}/sections"
            ))?
        } else if let Some(section_group_id) = section_group_id {
            sanitize_path_segment(section_group_id, "section_group_id")?;
            self.build_api_url(&format!(
                "{user_scope}/onenote/sectionGroups/{section_group_id}/sections"
            ))?
        } else {
            self.build_api_url(&format!("{user_scope}/onenote/sections"))?
        };

        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }

        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List OneNote pages in a section.
    pub async fn list_pages(
        &self,
        user_id: &str,
        section_id: &str,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        sanitize_path_segment(section_id, "section_id")?;
        let mut url = self.build_api_url(&format!(
            "{}/onenote/sections/{section_id}/pages",
            user_scope_path(user_id)?
        ))?;
        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get OneNote page metadata by page ID.
    pub async fn get_page(&self, user_id: &str, page_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(page_id, "page_id")?;
        let url = self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Fetch raw HTML content for a OneNote page.
    pub async fn get_page_content(
        &self,
        user_id: &str,
        page_id: &str,
        include_ids: bool,
    ) -> M365Result<String> {
        sanitize_path_segment(page_id, "page_id")?;
        let mut url = reqwest::Url::parse(&self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}/content",
            user_scope_path(user_id)?
        ))?)
        .map_err(|error| {
            M365Error::InvalidConfig(format!("Invalid OneNote content URL: {error}"))
        })?;
        if include_ids {
            url.query_pairs_mut().append_pair("includeIDs", "true");
        }
        self.get_text(url.as_str()).await
    }

    /// Create a OneNote page from HTML content.
    pub async fn create_page(
        &self,
        user_id: &str,
        section_id: &str,
        html: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(section_id, "section_id")?;
        let url = self.build_api_url(&format!(
            "{}/onenote/sections/{section_id}/pages",
            user_scope_path(user_id)?
        ))?;
        self.post_html(&url, html).await
    }

    /// Update a OneNote page using Graph content commands.
    pub async fn update_page(
        &self,
        user_id: &str,
        page_id: &str,
        commands: &[PageContentCommand],
    ) -> M365Result<()> {
        sanitize_path_segment(page_id, "page_id")?;
        let body = serde_json::to_value(commands)?;
        let url = self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}/content",
            user_scope_path(user_id)?
        ))?;
        self.patch_json_no_content(&url, &body).await
    }

    // ── Subscription operations ──────────────────────────────────

    /// Create a webhook subscription.
    pub async fn create_subscription(
        &self,
        subscription: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/subscriptions", self.api_url);
        self.post_json(&url, subscription).await
    }

    /// Renew a webhook subscription.
    pub async fn renew_subscription(
        &self,
        subscription_id: &str,
        expiration_datetime: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(subscription_id, "subscription_id")?;
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        let body = serde_json::json!({
            "expirationDateTime": expiration_datetime,
        });
        self.patch_json(&url, &body).await
    }

    /// Delete a webhook subscription.
    pub async fn delete_subscription(&self, subscription_id: &str) -> M365Result<()> {
        sanitize_path_segment(subscription_id, "subscription_id")?;
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        self.delete_no_content(&url).await
    }

    // ── Delta operations ─────────────────────────────────────────

    /// Perform a delta query for incremental sync.
    pub async fn delta_sync(
        &self,
        resource: &str,
        delta_token: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let delta_path = format!("{}/delta", resource.trim_end_matches('/'));
        let mut url = reqwest::Url::parse(&self.build_api_url(&delta_path)?)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid delta URL: {e}")))?;
        if let Some(token) = delta_token {
            url.query_pairs_mut().append_pair("$deltatoken", token);
        }

        // Follow all pages to collect all changes
        let mut all_values = Vec::new();
        let mut current_url = url.to_string();
        let mut final_delta_link;

        loop {
            let data = self.get(&current_url).await?;
            let page: GraphListResponse = serde_json::from_value(data)?;
            all_values.extend(page.value);
            final_delta_link = page.delta_link.clone();

            if let Some(next) = page.next_link {
                current_url = next;
            } else {
                break;
            }
        }

        Ok(GraphListResponse {
            value: all_values,
            next_link: None,
            delta_link: final_delta_link,
        })
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.get(url)), true)
            .await
    }

    async fn get_bytes(&self, url: &str) -> M365Result<Vec<u8>> {
        self.execute_bytes(|| self.apply_auth(self.http.get(url)), true)
            .await
    }

    async fn download_drive_item_bytes(
        &self,
        user_id: &str,
        item_id: &str,
        format: Option<&str>,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        sanitize_path_segment(item_id, "item_id")?;
        let user_scope = user_scope_path(user_id)?;
        let meta_url = self.build_api_url(&format!("{user_scope}/drive/items/{item_id}"))?;
        let metadata = self.get(&meta_url).await?;

        let content_url = match format {
            Some(format) => self.build_api_url(&format!(
                "{user_scope}/drive/items/{item_id}/content?format={format}"
            ))?,
            None => self.build_api_url(&format!("{user_scope}/drive/items/{item_id}/content"))?,
        };
        let bytes = self.get_bytes(&content_url).await?;
        Ok((bytes, metadata))
    }

    async fn get_text(&self, url: &str) -> M365Result<String> {
        self.execute_text(|| self.apply_auth(self.http.get(url)), true)
            .await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: fail-closed. The Graph POSTs behind this helper send mail
    /// (`sendMail`, `reply`, `forward`) or create items, so a replay is
    /// externally visible and irreversible. Read-only POSTs use
    /// [`Self::post_json_replay_safe`].
    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.post(url).json(body)), false)
            .await
    }

    /// POST whose replay cannot duplicate a side effect.
    ///
    /// Graph exposes some queries as POSTs because the request carries a body
    /// (`calendar/getSchedule`); those create nothing.
    async fn post_json_replay_safe(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.post(url).json(body)), true)
            .await
    }

    async fn post_json_no_content(&self, url: &str, body: &serde_json::Value) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.post(url).json(body)), false)
            .await
    }

    async fn post_html(&self, url: &str, html: &str) -> M365Result<serde_json::Value> {
        let html = html.to_string();
        // NOT replay-safe: creates a OneNote page.
        self.execute(
            || {
                self.apply_auth(
                    self.http
                        .post(url)
                        .header(header::ACCEPT, "application/json")
                        .header(header::CONTENT_TYPE, "text/html")
                        .body(html.clone()),
                )
            },
            false,
        )
        .await
    }

    async fn patch_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.patch(url).json(body)), true)
            .await
    }

    async fn patch_json_no_content(&self, url: &str, body: &serde_json::Value) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.patch(url).json(body)), true)
            .await
    }

    async fn put_bytes(&self, url: &str, content: &[u8]) -> M365Result<serde_json::Value> {
        let content = content.to_vec();
        // PUT of file content is idempotent: the same bytes to the same URL.
        self.execute(
            || {
                self.apply_auth(
                    self.http
                        .put(url)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .body(content.clone()),
                )
            },
            true,
        )
        .await
    }

    async fn delete_no_content(&self, url: &str) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.delete(url)), true)
            .await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> M365Result<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            // 429 stays retryable — Graph throttled it WITHOUT
                            // performing the work. A 5xx did reach Graph.
                            let replayable = replay_safe || err.replay_is_safe();
                            let retry_after = err.retry_after();
                            return AttemptOutcome::retryable_if_replayable(
                                err,
                                retry_after,
                                replayable,
                            );
                        }
                        ErrorAction::Success => {}
                    }

                    match response.text().await {
                        Ok(body) => match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(M365Error::from(e)),
                        },
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                // Only a connect-phase failure proves the request never
                // reached Graph.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(M365Error::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    async fn execute_bytes(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> M365Result<Vec<u8>> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            // 429 stays retryable — Graph throttled it WITHOUT
                            // performing the work. A 5xx did reach Graph.
                            let replayable = replay_safe || err.replay_is_safe();
                            let retry_after = err.retry_after();
                            return AttemptOutcome::retryable_if_replayable(
                                err,
                                retry_after,
                                replayable,
                            );
                        }
                        ErrorAction::Success => {}
                    }

                    match response.bytes().await {
                        Ok(bytes) => AttemptOutcome::Success(bytes.to_vec()),
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                // Only a connect-phase failure proves the request never
                // reached Graph.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(M365Error::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    async fn execute_text(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> M365Result<String> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            // 429 stays retryable — Graph throttled it WITHOUT
                            // performing the work. A 5xx did reach Graph.
                            let replayable = replay_safe || err.replay_is_safe();
                            let retry_after = err.retry_after();
                            return AttemptOutcome::retryable_if_replayable(
                                err,
                                retry_after,
                                replayable,
                            );
                        }
                        ErrorAction::Success => {}
                    }

                    match response.text().await {
                        Ok(body) => AttemptOutcome::Success(body),
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                // Only a connect-phase failure proves the request never
                // reached Graph.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(M365Error::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    async fn execute_no_content(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> M365Result<()> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            let replayable = replay_safe || err.replay_is_safe();
                            let retry_after = err.retry_after();
                            AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                        }
                        ErrorAction::Success => AttemptOutcome::Success(()),
                    }
                }
                // Only a connect-phase failure proves the request never
                // reached Graph.
                Err(e) => {
                    let replayable = replay_safe || !transport_error_reached_service(&e);
                    AttemptOutcome::retryable_if_replayable(M365Error::Http(e), None, replayable)
                }
            }
        })
        .await
    }

    async fn handle_error_status(
        &self,
        status: StatusCode,
        response: &reqwest::Response,
        attempt: u32,
    ) -> ErrorAction {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Authentication failed: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        if status == StatusCode::NOT_FOUND {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Resource not found: HTTP {status}"),
                status_code: Some(404),
                error_code: Some("NotFound".into()),
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(60_000, |s| s * 1000);

            let err = M365Error::RateLimit {
                retry_after_ms: retry_after,
            };
            if attempt < self.retry_config.max_retries {
                warn!(attempt, "rate limited, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if status.is_server_error() {
            let err = M365Error::Api {
                message: format!("Server error: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            };
            if attempt < self.retry_config.max_retries {
                warn!(attempt, status = %status, "server error, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if !status.is_success() && status != StatusCode::NO_CONTENT {
            return ErrorAction::Return(M365Error::Api {
                message: format!("HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        ErrorAction::Success
    }
}

fn normalize_drive_root_path(path: &str) -> M365Result<&str> {
    let normalized = path.trim_matches('/');
    if normalized.is_empty() {
        return Err(M365Error::InvalidConfig(
            "path must not be empty or root-only".into(),
        ));
    }
    Ok(normalized)
}

/// Reject path-segment values that contain traversal characters.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> M365Result<&'a str> {
    if value.trim().is_empty() {
        return Err(M365Error::InvalidConfig(format!(
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
        return Err(M365Error::InvalidConfig(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

fn user_scope_path(user_id: &str) -> M365Result<String> {
    if user_id.eq_ignore_ascii_case("me") {
        Ok("me".to_string())
    } else {
        // user_id can be an email address (alice@contoso.com) which is safe,
        // but must not contain path traversal characters.
        sanitize_path_segment(user_id, "user_id")?;
        Ok(format!("users/{user_id}"))
    }
}

enum ErrorAction {
    Return(M365Error),
    Retry(M365Error),
    Success,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_retryable() {
        let err = M365Error::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = M365Error::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = M365Error::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "user_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "user_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "user_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "user_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "user_id").is_err());
        assert!(sanitize_path_segment("", "user_id").is_err());
        assert!(sanitize_path_segment("  ", "user_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("msg_123", "message_id").unwrap(),
            "msg_123"
        );
        assert_eq!(
            sanitize_path_segment("alice@contoso.com", "user_id").unwrap(),
            "alice@contoso.com"
        );
    }

    #[test]
    fn user_scope_path_me_shortcut() {
        assert_eq!(user_scope_path("me").unwrap(), "me");
        assert_eq!(user_scope_path("ME").unwrap(), "me");
        assert_eq!(user_scope_path("Me").unwrap(), "me");
    }

    #[test]
    fn user_scope_path_rejects_traversal() {
        assert!(user_scope_path("../admin").is_err());
        assert!(user_scope_path("user/evil").is_err());
    }
}
