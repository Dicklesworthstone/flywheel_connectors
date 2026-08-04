//! Coda API client.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, RequestBuilder};
use std::fmt::Write as _;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{CodaError, CodaResult};
use crate::types::{
    ApiErrorResponse, Column, Control, DeleteRowsResponse, Doc, Formula, MutationStatus, Page,
    PaginatedResponse, Row, Table, UpsertRowsResponse, UserInfo,
};

/// Coda API client with retry and runtime integration.
pub struct CodaClient {
    client: Client,
    base_url: String,
    api_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for CodaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodaClient")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

const CODA_PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'\\');

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> CodaResult<&str> {
    let lower = segment.to_ascii_lowercase();
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(CodaError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

fn encode_path_segment(segment: &str) -> CodaResult<String> {
    Ok(utf8_percent_encode(
        sanitize_path_segment(segment)?,
        CODA_PATH_SEGMENT_ENCODE_SET,
    )
    .to_string())
}

fn push_query_param(url: &mut String, key: &str, value: &str, first: &mut bool) {
    let separator = if *first { '?' } else { '&' };
    *first = false;
    let _ = write!(
        url,
        "{separator}{key}={}",
        utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
    );
}

impl CodaClient {
    /// Create a new Coda client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        api_token: &str,
        request_timeout_ms: u64,
        retry_config: HttpRetryConfig,
    ) -> CodaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(CodaError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
            retry_config,
        })
    }

    /// Get authenticated user info and workspace binding.
    pub async fn whoami(&self, runtime: &ConnectorRuntime) -> CodaResult<UserInfo> {
        let url = format!("{}/whoami", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// List documents.
    pub async fn list_docs(
        &self,
        runtime: &ConnectorRuntime,
        workspace_id: Option<&str>,
        limit: Option<u32>,
        page_token: Option<&str>,
        query: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Doc>> {
        let mut url = format!("{}/docs", self.base_url);
        let mut first = true;
        if let Some(workspace_id) = workspace_id {
            push_query_param(&mut url, "workspaceId", workspace_id, &mut first);
        }
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        if let Some(q) = query {
            push_query_param(&mut url, "query", q, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single document.
    pub async fn get_doc(&self, runtime: &ConnectorRuntime, doc_id: &str) -> CodaResult<Doc> {
        let id = encode_path_segment(doc_id)?;
        let url = format!("{}/docs/{}", self.base_url, id);
        self.get_json(runtime, &url).await
    }

    /// List pages in a document.
    pub async fn list_pages(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Page>> {
        let id = encode_path_segment(doc_id)?;
        let mut url = format!("{}/docs/{}/pages", self.base_url, id);
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single page.
    pub async fn get_page(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        page_id_or_name: &str,
    ) -> CodaResult<Page> {
        let doc_id = encode_path_segment(doc_id)?;
        let page_id_or_name = encode_path_segment(page_id_or_name)?;
        let url = format!("{}/docs/{doc_id}/pages/{page_id_or_name}", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// List tables in a document.
    pub async fn list_tables(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Table>> {
        let id = encode_path_segment(doc_id)?;
        let mut url = format!("{}/docs/{}/tables", self.base_url, id);
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single table or view.
    pub async fn get_table(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id_or_name: &str,
    ) -> CodaResult<Table> {
        let doc_id = encode_path_segment(doc_id)?;
        let table_id_or_name = encode_path_segment(table_id_or_name)?;
        let url = format!("{}/docs/{doc_id}/tables/{table_id_or_name}", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// List columns in a table.
    pub async fn list_columns(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id_or_name: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Column>> {
        let doc_id = encode_path_segment(doc_id)?;
        let table_id_or_name = encode_path_segment(table_id_or_name)?;
        let mut url = format!(
            "{}/docs/{doc_id}/tables/{table_id_or_name}/columns",
            self.base_url
        );
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// List rows in a table.
    pub async fn list_rows(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
        query: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Row>> {
        let did = encode_path_segment(doc_id)?;
        let tid = encode_path_segment(table_id)?;
        let mut url = format!("{}/docs/{}/tables/{}/rows", self.base_url, did, tid);
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        if let Some(q) = query {
            push_query_param(&mut url, "query", q, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single row.
    pub async fn get_row(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id_or_name: &str,
        row_id_or_name: &str,
    ) -> CodaResult<Row> {
        let doc_id = encode_path_segment(doc_id)?;
        let table_id_or_name = encode_path_segment(table_id_or_name)?;
        let row_id_or_name = encode_path_segment(row_id_or_name)?;
        let url = format!(
            "{}/docs/{doc_id}/tables/{table_id_or_name}/rows/{row_id_or_name}",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    /// Upsert rows into a table.
    pub async fn upsert_rows(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id: &str,
        body: &serde_json::Value,
    ) -> CodaResult<UpsertRowsResponse> {
        let did = encode_path_segment(doc_id)?;
        let tid = encode_path_segment(table_id)?;
        let url = format!("{}/docs/{}/tables/{}/rows", self.base_url, did, tid);
        self.post_json(runtime, &url, body).await
    }

    /// Delete rows from a table.
    pub async fn delete_rows(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        table_id: &str,
        row_ids: &[String],
    ) -> CodaResult<DeleteRowsResponse> {
        let did = encode_path_segment(doc_id)?;
        let tid = encode_path_segment(table_id)?;
        let url = format!("{}/docs/{}/tables/{}/rows", self.base_url, did, tid);
        let body = serde_json::json!({ "rowIds": row_ids });
        self.delete_json(runtime, &url, &body).await
    }

    /// List formulas in a document.
    pub async fn list_formulas(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Formula>> {
        let id = encode_path_segment(doc_id)?;
        let mut url = format!("{}/docs/{}/formulas", self.base_url, id);
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single formula.
    pub async fn get_formula(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        formula_id_or_name: &str,
    ) -> CodaResult<Formula> {
        let doc_id = encode_path_segment(doc_id)?;
        let formula_id_or_name = encode_path_segment(formula_id_or_name)?;
        let url = format!(
            "{}/docs/{doc_id}/formulas/{formula_id_or_name}",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    /// List controls in a document.
    pub async fn list_controls(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        limit: Option<u32>,
        page_token: Option<&str>,
    ) -> CodaResult<PaginatedResponse<Control>> {
        let doc_id = encode_path_segment(doc_id)?;
        let mut url = format!("{}/docs/{doc_id}/controls", self.base_url);
        let mut first = true;
        if let Some(l) = limit {
            push_query_param(&mut url, "limit", &l.to_string(), &mut first);
        }
        if let Some(pt) = page_token {
            push_query_param(&mut url, "pageToken", pt, &mut first);
        }
        self.get_json(runtime, &url).await
    }

    /// Get a single control.
    pub async fn get_control(
        &self,
        runtime: &ConnectorRuntime,
        doc_id: &str,
        control_id_or_name: &str,
    ) -> CodaResult<Control> {
        let doc_id = encode_path_segment(doc_id)?;
        let control_id_or_name = encode_path_segment(control_id_or_name)?;
        let url = format!(
            "{}/docs/{doc_id}/controls/{control_id_or_name}",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    /// Get mutation status for an asynchronous write.
    pub async fn get_mutation_status(
        &self,
        runtime: &ConnectorRuntime,
        request_id: &str,
    ) -> CodaResult<MutationStatus> {
        let request_id = encode_path_segment(request_id)?;
        let url = format!("{}/mutationStatus/{request_id}", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// Health check: validate API reachability with GET /whoami.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> CodaResult<UserInfo> {
        self.whoami(runtime).await
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.api_token.is_empty()
    }

    /// Generic GET with retry + JSON deserialization.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CodaResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Coda GET");
                let request = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };

                match send_request(request, "GET").await {
                    Ok(text) => match serde_json::from_str::<T>(&text) {
                        Ok(v) => AttemptOutcome::Success(v),
                        Err(e) => AttemptOutcome::Terminal(CodaError::Json(e)),
                    },
                    Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: e.retry_after(),
                        error: e,
                    },
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }

    /// Generic POST with retry + JSON deserialization.
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CodaResult<T> {
        // br-kxd3e: READ THE REQUEST'S OWN SIGNAL, the same shape supabase
        // uses. Coda's row endpoint inserts by default, but becomes an UPSERT
        // when the body carries non-empty `keyColumns` — Coda then resolves on
        // those columns server-side, so a replay converges instead of adding
        // duplicate rows. Deriving it from the body keeps this correct as
        // operations change, rather than freezing a per-call-site guess.
        let replay_safe = body
            .get("keyColumns")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|columns| !columns.is_empty());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Coda POST");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                }
                .json(&body);

                match send_request(request, "POST").await {
                    Ok(text) => match serde_json::from_str::<T>(&text) {
                        Ok(v) => AttemptOutcome::Success(v),
                        Err(e) => AttemptOutcome::Terminal(CodaError::Json(e)),
                    },
                    Err(e) if e.is_retryable() => {
                        // 429 stays retryable — refused WITHOUT performing the
                        // work. A 5xx means the request arrived.
                        let replayable = replay_safe || matches!(e, CodaError::RateLimited { .. });
                        let retry_after = e.retry_after();
                        AttemptOutcome::retryable_if_replayable(e, retry_after, replayable)
                    }
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }

    /// Generic DELETE with JSON body + retry + JSON deserialization.
    async fn delete_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CodaResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.api_token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Coda DELETE");
                let request = if token.is_empty() {
                    client.delete(&url)
                } else {
                    client.delete(&url).bearer_auth(&token)
                }
                .json(&body);

                match send_request(request, "DELETE").await {
                    Ok(text) => match serde_json::from_str::<T>(&text) {
                        Ok(v) => AttemptOutcome::Success(v),
                        Err(e) => AttemptOutcome::Terminal(CodaError::Json(e)),
                    },
                    Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: e.retry_after(),
                        error: e,
                    },
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }
}

/// Send a request and handle common error statuses.
async fn send_request(request: RequestBuilder, label: &str) -> CodaResult<String> {
    let resp = request.send().await.map_err(CodaError::Http)?;
    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after_ms = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|s| s * 1000)
            .unwrap_or(30_000);
        return Err(CodaError::RateLimited { retry_after_ms });
    }

    if status == 401 {
        return Err(CodaError::Unauthorized("Invalid API token".into()));
    }

    if status == 404 {
        return Err(CodaError::NotFound("Resource not found".into()));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let message = if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
            api_err
                .message
                .unwrap_or_else(|| api_err.status_message.unwrap_or_else(|| text.clone()))
        } else {
            text
        };
        warn!(status, label, "Coda API error");
        return Err(CodaError::Api { status, message });
    }

    resp.text().await.map_err(CodaError::Http)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = CodaClient::new(
            "https://coda.io/apis/v1",
            "test_token",
            30_000,
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = CodaClient::new(
            "https://coda.io/apis/v1/",
            "test_token",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = CodaClient::new(
            "https://coda.io/apis/v1",
            "",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_api_token() {
        let client = CodaClient::new(
            "https://coda.io/apis/v1",
            "super_secret_token_value",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_token_value"),
            "Debug output must not contain the raw api_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for api_token"
        );
    }

    #[test]
    fn non_secretless() {
        let client = CodaClient::new(
            "https://coda.io/apis/v1",
            "real_token",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn sanitize_path_segment_valid() {
        assert!(sanitize_path_segment("doc123").is_ok());
        assert!(sanitize_path_segment("tbl-abc-456").is_ok());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../etc/passwd").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
    }
}
