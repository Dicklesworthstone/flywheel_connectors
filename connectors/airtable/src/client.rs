//! Airtable REST API client.

use std::fmt;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode, Url, header, redirect::Policy};
use tracing::instrument;

use crate::{
    error::{AirtableError, AirtableResult},
    types::{
        AirtableApiError, AttachmentDownload, BaseSchemaResponse, CreateRecordsResponse,
        CreateWebhookResponse, DeleteRecordResponse, DeleteRecordsResponse, ListBasesResponse,
        ListRecordsResponse, ListWebhookPayloadsResponse, ListWebhooksResponse, Record,
        RefreshWebhookResponse, SortSpec, UpsertRecordsResponse,
    },
};

/// Default Airtable API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.airtable.com/v0";
const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(30);
const ATTACHMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ATTACHMENT_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ATTACHMENT_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;
const MAX_ATTACHMENT_REDIRECTS: usize = 5;

/// Authentication mode for the Airtable API.
#[derive(Clone)]
pub enum AirtableAuth {
    /// Direct `OAuth2` / personal access token (bearer auth).
    Token(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl AirtableAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::Token(_) => "token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for AirtableAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Airtable REST API client with retry logic and rate limit awareness.
pub struct AirtableClient {
    client: Client,
    auth: AirtableAuth,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    pub(crate) retry_config: HttpRetryConfig,
}

impl fmt::Debug for AirtableClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AirtableClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl AirtableClient {
    /// Create a new Airtable client with a personal access token.
    pub fn new(token: impl Into<String>) -> AirtableResult<Self> {
        Self::new_with_auth(AirtableAuth::Token(token.into()))
    }

    /// Create a new Airtable client with explicit auth mode.
    pub fn new_with_auth(auth: AirtableAuth) -> AirtableResult<Self> {
        let client = Client::builder()
            .timeout(DEFAULT_API_TIMEOUT)
            .user_agent("fcp-airtable/0.1.0")
            .build()
            .map_err(AirtableError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            jitter_enabled: self.retry_config.jitter_enabled,
        };
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Apply authentication to an outgoing request.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            AirtableAuth::Token(token) => builder.bearer_auth(token),
            AirtableAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Reject path-segment values that contain traversal characters.
    fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> AirtableResult<&'a str> {
        if value.trim().is_empty() {
            return Err(AirtableError::Api {
                error_type: "INVALID_REQUEST".into(),
                message: format!("{field} must not be empty"),
                status_code: Some(400),
            });
        }
        let lower = value.to_ascii_lowercase();
        if value.contains('/')
            || value.contains('\\')
            || value.contains("..")
            || value.contains('?')
            || value.contains('#')
            || value.contains('&')
            || value.contains('=')
            || value.contains('%')
            || value.chars().any(char::is_control)
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(AirtableError::Api {
                error_type: "INVALID_REQUEST".into(),
                message: format!("{field} contains path traversal characters"),
                status_code: Some(400),
            });
        }
        Ok(value)
    }

    /// Lightweight connectivity probe (list bases with no offset).
    pub async fn health_check(&self) -> AirtableResult<()> {
        let _: ListBasesResponse = self.get_with_params("/meta/bases", &[]).await?;
        Ok(())
    }

    // ── Base operations ─────────────────────────────────────────────

    /// List all accessible bases.
    #[instrument(skip(self))]
    pub async fn list_bases(&self, offset: Option<&str>) -> AirtableResult<ListBasesResponse> {
        let mut params: Vec<(&str, String)> = vec![];
        if let Some(o) = offset {
            params.push(("offset", o.to_string()));
        }
        self.get_with_params("/meta/bases", &params).await
    }

    /// Get the schema of a base.
    #[instrument(skip(self))]
    pub async fn get_base_schema(&self, base_id: &str) -> AirtableResult<BaseSchemaResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        let path = format!("/meta/bases/{base_id}/tables");
        self.get_with_params(&path, &[]).await
    }

    // ── Webhook operations ──────────────────────────────────────────

    /// List webhooks configured for a base.
    #[instrument(skip(self))]
    pub async fn list_webhooks(&self, base_id: &str) -> AirtableResult<ListWebhooksResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        let path = format!("/bases/{base_id}/webhooks");
        self.get_with_params(&path, &[]).await
    }

    /// Create a webhook for a base.
    #[instrument(skip(self, specification))]
    pub async fn create_webhook(
        &self,
        base_id: &str,
        notification_url: Option<&str>,
        specification: &serde_json::Value,
    ) -> AirtableResult<CreateWebhookResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        let path = format!("/bases/{base_id}/webhooks");
        let mut body = serde_json::json!({
            "specification": specification,
        });
        if let Some(url) = notification_url {
            body["notificationUrl"] = serde_json::Value::String(url.to_string());
        }
        self.post_json(&path, &body).await
    }

    /// Delete a webhook.
    #[instrument(skip(self))]
    pub async fn delete_webhook(
        &self,
        base_id: &str,
        webhook_id: &str,
    ) -> AirtableResult<serde_json::Value> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(webhook_id, "webhook_id")?;
        let path = format!("/bases/{base_id}/webhooks/{webhook_id}");
        self.delete(&path).await
    }

    /// Refresh a webhook before it expires.
    #[instrument(skip(self))]
    pub async fn refresh_webhook(
        &self,
        base_id: &str,
        webhook_id: &str,
    ) -> AirtableResult<RefreshWebhookResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(webhook_id, "webhook_id")?;
        let path = format!("/bases/{base_id}/webhooks/{webhook_id}/refresh");
        self.post_json(&path, &serde_json::json!({})).await
    }

    /// Enable or disable webhook notifications.
    #[instrument(skip(self))]
    pub async fn set_webhook_notifications(
        &self,
        base_id: &str,
        webhook_id: &str,
        enable: bool,
    ) -> AirtableResult<serde_json::Value> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(webhook_id, "webhook_id")?;
        let path = format!("/bases/{base_id}/webhooks/{webhook_id}/enableNotifications");
        self.post_json(&path, &serde_json::json!({ "enable": enable }))
            .await
    }

    /// List webhook payload history starting from a cursor.
    #[instrument(skip(self))]
    pub async fn list_webhook_payloads(
        &self,
        base_id: &str,
        webhook_id: &str,
        cursor: Option<u64>,
        limit: Option<u32>,
    ) -> AirtableResult<ListWebhookPayloadsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(webhook_id, "webhook_id")?;
        let path = format!("/bases/{base_id}/webhooks/{webhook_id}/payloads");
        let mut params = Vec::new();
        if let Some(cursor) = cursor {
            params.push(("cursor", cursor.to_string()));
        }
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }
        self.get_with_params(&path, &params).await
    }

    // ── Record operations ───────────────────────────────────────────

    /// List records from a table.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_records(
        &self,
        base_id: &str,
        table_id: &str,
        fields: Option<&[String]>,
        filter_by_formula: Option<&str>,
        max_records: Option<u32>,
        page_size: Option<u32>,
        sort: Option<&[SortSpec]>,
        view: Option<&str>,
        offset: Option<&str>,
    ) -> AirtableResult<ListRecordsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");

        // Build URL manually since sort params need dynamic keys
        let mut url = format!("{}{path}", self.base_url);
        let mut first = true;

        let mut append_param = |url: &mut String, key: &str, value: &str| {
            if first {
                url.push('?');
                first = false;
            } else {
                url.push('&');
            }
            let encoded =
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{key}={encoded}");
        };

        if let Some(fields) = fields {
            for f in fields {
                append_param(&mut url, "fields[]", f);
            }
        }
        if let Some(formula) = filter_by_formula {
            append_param(&mut url, "filterByFormula", formula);
        }
        if let Some(max) = max_records {
            append_param(&mut url, "maxRecords", &max.to_string());
        }
        if let Some(ps) = page_size {
            append_param(&mut url, "pageSize", &ps.to_string());
        }
        if let Some(sort) = sort {
            for (i, s) in sort.iter().enumerate() {
                let field_key = format!("sort[{i}][field]");
                let dir_key = format!("sort[{i}][direction]");
                append_param(&mut url, &field_key, &s.field);
                append_param(&mut url, &dir_key, &s.direction);
            }
        }
        if let Some(v) = view {
            append_param(&mut url, "view", v);
        }
        if let Some(o) = offset {
            append_param(&mut url, "offset", o);
        }

        self.get_raw_url(&url).await
    }

    /// Get a single record by ID.
    #[instrument(skip(self))]
    pub async fn get_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
    ) -> AirtableResult<Record> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        Self::sanitize_path_segment(record_id, "record_id")?;
        let path = format!("/{base_id}/{table_id}/{record_id}");
        self.get_with_params(&path, &[]).await
    }

    /// Create a single record.
    #[instrument(skip(self, fields))]
    pub async fn create_record(
        &self,
        base_id: &str,
        table_id: &str,
        fields: &serde_json::Value,
        typecast: Option<bool>,
    ) -> AirtableResult<Record> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.post_json(&path, &body).await
    }

    /// Create multiple records (batch, max 10).
    #[instrument(skip(self, records))]
    pub async fn create_records(
        &self,
        base_id: &str,
        table_id: &str,
        records: &[serde_json::Value],
        typecast: Option<bool>,
    ) -> AirtableResult<CreateRecordsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({ "records": records });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.post_json(&path, &body).await
    }

    /// Update multiple records (batch PATCH, max 10).
    #[instrument(skip(self, records))]
    pub async fn update_records(
        &self,
        base_id: &str,
        table_id: &str,
        records: &[serde_json::Value],
        typecast: Option<bool>,
    ) -> AirtableResult<CreateRecordsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({ "records": records });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.patch_json(&path, &body).await
    }

    /// Upsert multiple records using merge fields (batch PATCH, max 10).
    #[instrument(skip(self, records, fields_to_merge_on))]
    pub async fn upsert_records(
        &self,
        base_id: &str,
        table_id: &str,
        records: &[serde_json::Value],
        fields_to_merge_on: &[String],
        typecast: Option<bool>,
    ) -> AirtableResult<UpsertRecordsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({
            "records": records,
            "performUpsert": {
                "fieldsToMergeOn": fields_to_merge_on,
            },
        });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.patch_json(&path, &body).await
    }

    /// Update a record (PATCH - partial update).
    #[instrument(skip(self, fields))]
    pub async fn update_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
        fields: &serde_json::Value,
        typecast: Option<bool>,
    ) -> AirtableResult<Record> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        Self::sanitize_path_segment(record_id, "record_id")?;
        let path = format!("/{base_id}/{table_id}/{record_id}");
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.patch_json(&path, &body).await
    }

    /// Replace a record (PUT - full replacement).
    #[instrument(skip(self, fields))]
    pub async fn replace_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
        fields: &serde_json::Value,
    ) -> AirtableResult<Record> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        Self::sanitize_path_segment(record_id, "record_id")?;
        let path = format!("/{base_id}/{table_id}/{record_id}");
        let body = serde_json::json!({ "fields": fields });
        self.put_json(&path, &body).await
    }

    /// Delete a record.
    #[instrument(skip(self))]
    pub async fn delete_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
    ) -> AirtableResult<DeleteRecordResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        Self::sanitize_path_segment(record_id, "record_id")?;
        let path = format!("/{base_id}/{table_id}/{record_id}");
        self.delete(&path).await
    }

    /// Delete multiple records (batch DELETE, max 10).
    #[instrument(skip(self, record_ids))]
    pub async fn delete_records(
        &self,
        base_id: &str,
        table_id: &str,
        record_ids: &[String],
    ) -> AirtableResult<DeleteRecordsResponse> {
        Self::sanitize_path_segment(base_id, "base_id")?;
        Self::sanitize_path_segment(table_id, "table_id")?;
        let path = format!("/{base_id}/{table_id}");
        let params: Vec<(&str, String)> = record_ids
            .iter()
            .map(|record_id| ("records[]", record_id.clone()))
            .collect();
        self.delete_with_params(&path, &params).await
    }

    // ── Attachment operations ───────────────────────────────────────

    /// Download an attachment from a URL.
    #[instrument(skip(self, url))]
    pub async fn download_attachment(&self, url: &str) -> AirtableResult<AttachmentDownload> {
        let allow_local_test_hosts = self.allows_local_attachment_hosts();
        let attachment_client = Self::build_attachment_download_client()?;
        let mut current_url = Self::validate_attachment_url(url, allow_local_test_hosts)?;

        for redirect_count in 0..=MAX_ATTACHMENT_REDIRECTS {
            self.total_requests.fetch_add(1, Ordering::Relaxed);

            let mut response = attachment_client
                .get(current_url.clone())
                .send()
                .await
                .map_err(AirtableError::Http)?;

            if response.status().is_redirection() {
                if redirect_count == MAX_ATTACHMENT_REDIRECTS {
                    return Err(AirtableError::InvalidAttachmentUrl {
                        message: format!(
                            "Attachment URL exceeded redirect limit of {MAX_ATTACHMENT_REDIRECTS}"
                        ),
                    });
                }

                current_url = Self::resolve_attachment_redirect(
                    &current_url,
                    response.headers().get(header::LOCATION),
                    allow_local_test_hosts,
                )?;
                continue;
            }

            let status = response.status();
            if !status.is_success() {
                return Err(AirtableError::Api {
                    error_type: "DOWNLOAD_ERROR".into(),
                    message: format!("Attachment download failed with status {status}"),
                    status_code: Some(status.as_u16()),
                });
            }

            let declared_length = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .or_else(|| response.content_length());
            if declared_length.is_some_and(|len| len > MAX_ATTACHMENT_DOWNLOAD_BYTES) {
                return Err(AirtableError::AttachmentTooLarge {
                    max_bytes: MAX_ATTACHMENT_DOWNLOAD_BYTES,
                });
            }

            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            // Try to extract filename from content-disposition header.
            let filename = response
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.split("filename=")
                        .nth(1)
                        .map(|f| f.trim_matches('"').to_string())
                });

            let mut bytes = Vec::new();
            let mut total_bytes = 0_u64;
            while let Some(chunk) = response.chunk().await.map_err(AirtableError::Http)? {
                total_bytes =
                    total_bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                if total_bytes > MAX_ATTACHMENT_DOWNLOAD_BYTES {
                    return Err(AirtableError::AttachmentTooLarge {
                        max_bytes: MAX_ATTACHMENT_DOWNLOAD_BYTES,
                    });
                }
                bytes.extend_from_slice(&chunk);
            }

            let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
            return Ok(AttachmentDownload {
                data,
                content_type,
                filename,
            });
        }

        Err(AirtableError::InvalidAttachmentUrl {
            message: "Attachment URL exceeded redirect limit".into(),
        })
    }

    // ── Internal HTTP helpers ────────────────────────────────────────

    async fn get_raw_url<T: serde::de::DeserializeOwned>(&self, url: &str) -> AirtableResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.get(url));
            async move { Self::execute_once(req, true).await }
        })
        .await
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> AirtableResult<T> {
        let mut url = format!("{}{path}", self.base_url);
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
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.get(&url));
            async move { Self::execute_once(req, false).await }
        })
        .await
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::POST, path, body)
            .await
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::PATCH, path, body)
            .await
    }

    async fn put_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::PUT, path, body)
            .await
    }

    async fn delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> AirtableResult<T> {
        self.delete_with_url(path, &format!("{}{path}", self.base_url))
            .await
    }

    async fn delete_with_params<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> AirtableResult<T> {
        let mut url = format!("{}{path}", self.base_url);
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
        self.delete_with_url(path, &url).await
    }

    async fn delete_with_url<T: serde::de::DeserializeOwned>(
        &self,
        _path: &str,
        url: &str,
    ) -> AirtableResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self.apply_auth(self.client.delete(url));
            async move { Self::execute_once(req, true).await }
        })
        .await
    }

    async fn request_with_body<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        // br-kxd3e: PATCH and PUT address records by id and set fields to
        // values, so they converge; only POST creates records, and a replay
        // creates a SECOND set. Note this client already treats every
        // non-success status as terminal, so the transport arm in
        // `execute_once` is the only place a replay could happen.
        let replay_safe = method != reqwest::Method::POST;
        let url = format!("{}{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = self
                .apply_auth(self.client.request(method.clone(), &url))
                .json(body);
            async move { Self::execute_once(req, replay_safe).await }
        })
        .await
    }

    async fn execute_once<T: serde::de::DeserializeOwned>(
        req: reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> AttemptOutcome<T, AirtableError> {
        match req.send().await {
            Ok(resp) => {
                if let Some(retry_result) = Self::check_rate_limit(&resp) {
                    let err = AirtableError::RateLimited {
                        retry_after_secs: retry_result.map_or(30, |d| d.as_secs()),
                    };
                    return AttemptOutcome::Retryable {
                        retry_after: retry_result,
                        error: err,
                    };
                }
                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return AttemptOutcome::Terminal(AirtableError::Unauthorized);
                }
                if !status.is_success() {
                    return AttemptOutcome::Terminal(Self::parse_error_response(resp).await);
                }
                match resp.json::<T>().await {
                    Ok(data) => AttemptOutcome::Success(data),
                    Err(e) => AttemptOutcome::Terminal(e.into()),
                }
            }
            Err(e) => {
                // Only a connect-phase failure proves the create never reached
                // Airtable.
                let replayable = replay_safe || !transport_error_reached_service(&e);
                AttemptOutcome::retryable_if_replayable(e.into(), None, replayable)
            }
        }
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

    fn build_attachment_download_client() -> AirtableResult<Client> {
        Client::builder()
            .connect_timeout(ATTACHMENT_CONNECT_TIMEOUT)
            .timeout(ATTACHMENT_TOTAL_TIMEOUT)
            .redirect(Policy::none())
            .user_agent("fcp-airtable/0.1.0")
            .build()
            .map_err(AirtableError::Http)
    }

    fn allows_local_attachment_hosts(&self) -> bool {
        Url::parse(&self.base_url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
            .is_some_and(|host| is_local_test_host(&host))
    }

    fn validate_attachment_url(raw_url: &str, allow_local_test_hosts: bool) -> AirtableResult<Url> {
        let trimmed = raw_url.trim();
        if trimmed.is_empty() {
            return Err(AirtableError::InvalidAttachmentUrl {
                message: "Attachment URL cannot be empty".into(),
            });
        }

        let parsed = Url::parse(trimmed).map_err(|e| AirtableError::InvalidAttachmentUrl {
            message: format!("Attachment URL is invalid: {e}"),
        })?;

        let host = parsed
            .host_str()
            .ok_or_else(|| AirtableError::InvalidAttachmentUrl {
                message: "Attachment URL must include a host".into(),
            })?;
        let host_lower = host.to_ascii_lowercase();
        let local_test_host = allow_local_test_hosts && is_local_test_host(&host_lower);

        if parsed.scheme() != "https" && !local_test_host {
            return Err(AirtableError::InvalidAttachmentUrl {
                message: "Attachment URL must use https".into(),
            });
        }

        if host_lower.parse::<IpAddr>().is_ok() && !local_test_host {
            return Err(AirtableError::InvalidAttachmentUrl {
                message: "Attachment URL must not use an IP literal".into(),
            });
        }

        if !local_test_host && parsed.port_or_known_default() != Some(443) {
            return Err(AirtableError::InvalidAttachmentUrl {
                message: "Attachment URL must use port 443".into(),
            });
        }

        if attachment_host_allowed(&host_lower) || local_test_host {
            Ok(parsed)
        } else {
            Err(AirtableError::InvalidAttachmentUrl {
                message: format!(
                    "Attachment URL host '{host}' is not allowed by connector NetworkConstraints"
                ),
            })
        }
    }

    fn resolve_attachment_redirect(
        current_url: &Url,
        location: Option<&header::HeaderValue>,
        allow_local_test_hosts: bool,
    ) -> AirtableResult<Url> {
        let location = location
            .ok_or_else(|| AirtableError::InvalidAttachmentUrl {
                message: "Attachment redirect response is missing a Location header".into(),
            })?
            .to_str()
            .map_err(|_| AirtableError::InvalidAttachmentUrl {
                message: "Attachment redirect Location header is invalid".into(),
            })?;

        let resolved = current_url
            .join(location)
            .or_else(|_| Url::parse(location))
            .map_err(|e| AirtableError::InvalidAttachmentUrl {
                message: format!("Attachment redirect target is invalid: {e}"),
            })?;

        Self::validate_attachment_url(resolved.as_str(), allow_local_test_hosts)
    }

    async fn parse_error_response(resp: Response) -> AirtableError {
        let status_code = resp.status().as_u16();
        match resp.json::<AirtableApiError>().await {
            Ok(api_err) => {
                let error_type = api_err
                    .error
                    .as_ref()
                    .and_then(|e| e.error_type.clone())
                    .unwrap_or_else(|| "UNKNOWN_ERROR".into());
                let message = api_err
                    .error
                    .as_ref()
                    .and_then(|e| e.message.clone())
                    .unwrap_or_else(|| format!("HTTP {status_code}"));
                AirtableError::Api {
                    error_type,
                    message,
                    status_code: Some(status_code),
                }
            }
            Err(_) => AirtableError::Api {
                error_type: "UNKNOWN_ERROR".into(),
                message: format!("HTTP {status_code}"),
                status_code: Some(status_code),
            },
        }
    }
}

fn attachment_host_allowed(host: &str) -> bool {
    host == "dl.airtable.com"
        || host.ends_with(".dl.airtable.com")
        || host == "v5.airtableusercontent.com"
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Auth unit tests ──────────────────────────────────────────

    #[test]
    fn auth_token_debug_redacts() {
        let auth = AirtableAuth::Token("super-secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_credential_id_debug_shows_id() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id.to_string()));
    }

    #[test]
    fn auth_token_redacted_label() {
        let auth = AirtableAuth::Token("my-token".into());
        assert_eq!(auth.redacted_label(), "token:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains(&id.to_string()));
    }

    #[test]
    fn auth_token_is_not_secretless() {
        let auth = AirtableAuth::Token("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = AirtableAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_clone() {
        let auth = AirtableAuth::Token("test".into());
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert_eq!(auth2.redacted_label(), "token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert!(auth2.is_secretless());
        assert_eq!(auth2.redacted_label(), auth.redacted_label());
    }

    // ── Client construction tests ────────────────────────────────

    #[test]
    fn client_new_creates_with_defaults() {
        let client = AirtableClient::new("test_token").unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
        assert_eq!(client.max_retries, 3);
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn client_with_base_url() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://custom.example.com");
        assert_eq!(client.base_url, "https://custom.example.com");
    }

    #[test]
    fn client_with_retry_config() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(5, 2000, 120_000);
        assert_eq!(client.retry_config.max_retries, 5);
        assert_eq!(client.retry_config.initial_delay_ms, 2000);
        assert_eq!(client.retry_config.max_delay_ms, 120_000);
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = AirtableClient::new("my-secret-api-token").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret-api-token"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("AirtableClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://test.example.com");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://test.example.com"));
    }

    #[test]
    fn client_debug_shows_max_retries() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(7, 500, 30_000);
        assert_eq!(client.retry_config.max_retries, 7);
    }

    #[test]
    fn client_new_with_auth_token() {
        let client = AirtableClient::new_with_auth(AirtableAuth::Token("tok".into())).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_with_auth_credential_id() {
        let client =
            AirtableClient::new_with_auth(AirtableAuth::CredentialId(CredentialId::new())).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_total_requests_starts_at_zero() {
        let client = AirtableClient::new("tok").unwrap();
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.airtable.com/v0");
    }

    #[test]
    fn client_chained_builders() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://example.com")
            .with_retry_config(1, 100, 500);
        assert_eq!(client.base_url, "https://example.com");
        assert_eq!(client.retry_config.max_retries, 1);
        assert_eq!(client.retry_config.initial_delay_ms, 100);
        assert_eq!(client.retry_config.max_delay_ms, 500);
    }

    #[test]
    fn client_retry_config_zero_retries() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(0, 0, 0);
        assert_eq!(client.retry_config.max_retries, 0);
        assert_eq!(client.retry_config.initial_delay_ms, 0);
        assert_eq!(client.retry_config.max_delay_ms, 0);
    }

    #[test]
    fn client_new_empty_token() {
        let client = AirtableClient::new("").unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_retry_config_large_values() {
        let client =
            AirtableClient::new("tok")
                .unwrap()
                .with_retry_config(u32::MAX, u64::MAX, u64::MAX);
        assert_eq!(client.retry_config.max_retries, u32::MAX);
        assert_eq!(client.retry_config.initial_delay_ms, u64::MAX);
        assert_eq!(client.retry_config.max_delay_ms, u64::MAX);
    }

    #[test]
    fn auth_token_clone_preserves_secretless() {
        let auth = AirtableAuth::Token("secret".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(!cloned.is_secretless());
    }

    #[test]
    fn auth_credential_id_clone_preserves_secretless() {
        let auth = AirtableAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_contains_airtable() {
        assert!(DEFAULT_BASE_URL.contains("airtable"));
    }

    #[test]
    fn client_with_base_url_empty_string() {
        let client = AirtableClient::new("tok").unwrap().with_base_url("");
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn auth_debug_token_contains_redacted() {
        let auth = AirtableAuth::Token("my-long-secret-token-value".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-long-secret-token-value"));
    }

    #[test]
    fn attachment_host_allowlist_matches_manifest() {
        assert!(attachment_host_allowed("dl.airtable.com"));
        assert!(attachment_host_allowed("cdn.dl.airtable.com"));
        assert!(attachment_host_allowed("v5.airtableusercontent.com"));
        assert!(!attachment_host_allowed("example.com"));
    }

    #[test]
    fn validate_attachment_url_rejects_non_airtable_host_without_leaking_query() {
        let err = AirtableClient::validate_attachment_url(
            "https://evil.example.com/file.txt?sig=super-secret-token",
            false,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("evil.example.com"));
        assert!(!rendered.contains("super-secret-token"));
        assert!(!rendered.contains("file.txt?"));
    }

    #[test]
    fn validate_attachment_url_accepts_airtable_download_hosts() {
        assert!(
            AirtableClient::validate_attachment_url(
                "https://dl.airtable.com/.attachments/file.bin",
                false
            )
            .is_ok()
        );
        assert!(
            AirtableClient::validate_attachment_url("https://foo.dl.airtable.com/file.bin", false)
                .is_ok()
        );
        assert!(
            AirtableClient::validate_attachment_url(
                "https://v5.airtableusercontent.com/v3/file.bin",
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(AirtableClient::sanitize_path_segment("../admin", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("foo/bar", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("foo\\bar", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("foo%2fbar", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("foo%5Cbar", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("  ", "base_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_url_active_characters() {
        assert!(AirtableClient::sanitize_path_segment("app?123", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("app#123", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("app&123", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("app=123", "base_id").is_err());
        assert!(AirtableClient::sanitize_path_segment("app%23123", "base_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            AirtableClient::sanitize_path_segment("appABC123", "base_id").unwrap(),
            "appABC123"
        );
        assert_eq!(
            AirtableClient::sanitize_path_segment("tblXYZ", "table_id").unwrap(),
            "tblXYZ"
        );
        assert_eq!(
            AirtableClient::sanitize_path_segment("recDEF456", "record_id").unwrap(),
            "recDEF456"
        );
    }
}
