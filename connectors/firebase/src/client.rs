//! Firebase Firestore and Realtime Database REST client.

use std::fmt;
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// RFC 3986 unreserved characters preserved in path segments.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    error::{FirebaseError, FirebaseResult},
    types::{
        FirestoreBatchWriteRequest, FirestoreCreateRequest, FirestoreDeleteRequest,
        FirestoreDocumentView, FirestoreDocumentWire, FirestoreGetRequest, FirestoreListRequest,
        FirestoreListResponse, FirestoreQueryRequest, FirestoreQueryResponse,
        FirestoreRunQueryResultWire, FirestoreUpdateRequest, RealtimeDeleteRequest,
        RealtimeGetRequest, RealtimeSetRequest, firestore_document_to_view,
        json_to_firestore_document,
    },
};

/// Default Firestore REST base URL.
pub const DEFAULT_FIRESTORE_BASE_URL: &str = "https://firestore.googleapis.com/v1";

/// Render a redacted auth label suitable for logs and diagnostics.
#[must_use]
pub(crate) fn firebase_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    match auth {
        GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
        GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
            format!("credential_id:{credential_id}")
        }
    }
}

/// Whether the provided auth mode relies on secretless credential injection.
#[must_use]
pub(crate) const fn firebase_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

/// Firebase REST client.
pub struct FirebaseClient {
    http: Client,
    auth: GoogleMaterializedAuth,
    project_id: String,
    database_id: String,
    firestore_base_url: String,
    realtime_database_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for FirebaseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirebaseClient")
            .field("auth", &firebase_auth_redacted_label(&self.auth))
            .field("project_id", &self.project_id)
            .field("database_id", &self.database_id)
            .field("firestore_base_url", &self.firestore_base_url)
            .field("realtime_database_url", &self.realtime_database_url)
            .finish_non_exhaustive()
    }
}

impl FirebaseClient {
    /// Create a new Firebase client.
    pub fn new(
        auth: GoogleMaterializedAuth,
        project_id: &str,
        database_id: &str,
        firestore_base_url: &str,
        realtime_database_url: &str,
        request_timeout_ms: u64,
    ) -> FirebaseResult<Self> {
        if project_id.trim().is_empty() {
            return Err(FirebaseError::InvalidInput(
                "project_id must not be empty".into(),
            ));
        }
        if database_id.trim().is_empty() {
            return Err(FirebaseError::InvalidInput(
                "database_id must not be empty".into(),
            ));
        }
        let firestore_base_url = firestore_base_url.trim_end_matches('/').to_string();
        let realtime_database_url = realtime_database_url.trim_end_matches('/').to_string();

        Url::parse(&firestore_base_url).map_err(|error| {
            FirebaseError::InvalidInput(format!("invalid firestore_base_url: {error}"))
        })?;
        Url::parse(&realtime_database_url).map_err(|error| {
            FirebaseError::InvalidInput(format!("invalid realtime_database_url: {error}"))
        })?;

        let http = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .user_agent("fcp-firebase/0.1.0")
            .build()
            .map_err(FirebaseError::Http)?;

        Ok(Self {
            http,
            auth,
            project_id: project_id.trim().to_string(),
            database_id: database_id.trim().to_string(),
            firestore_base_url,
            realtime_database_url,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default()
                    .with_request_timeout(Duration::from_millis(request_timeout_ms)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down request contexts for the client.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Fetch database metadata as a health probe.
    pub async fn health(&self) -> FirebaseResult<Value> {
        let url = format!("{}/{}", self.firestore_base_url, self.database_resource());
        self.execute_with_retry(Method::GET, url, Vec::new(), None)
            .await
    }

    /// Read one Firestore document.
    pub async fn firestore_get(
        &self,
        request: &FirestoreGetRequest,
    ) -> FirebaseResult<FirestoreDocumentView> {
        let url = format!(
            "{}/{}",
            self.firestore_base_url,
            self.document_resource(&request.document_path)?
        );
        let response = self
            .execute_with_retry(
                Method::GET,
                url,
                repeated_query("mask.fieldPaths", &request.mask),
                None,
            )
            .await?;
        let document: FirestoreDocumentWire = serde_json::from_value(response)?;
        Ok(firestore_document_to_view(document))
    }

    /// List Firestore documents under a collection.
    pub async fn firestore_list(
        &self,
        request: &FirestoreListRequest,
    ) -> FirebaseResult<FirestoreListResponse> {
        let (parent, collection_id) = self.collection_parent_and_id(&request.collection_path)?;
        let url = format!("{}/{parent}/{collection_id}", self.firestore_base_url);

        let mut query = repeated_query("mask.fieldPaths", &request.mask);
        if let Some(page_size) = request.page_size {
            query.push(("pageSize".into(), page_size.to_string()));
        }
        if let Some(page_token) = &request.page_token {
            query.push(("pageToken".into(), page_token.clone()));
        }
        if let Some(order_by) = &request.order_by {
            query.push(("orderBy".into(), order_by.clone()));
        }
        if request.show_missing {
            query.push(("showMissing".into(), "true".into()));
        }

        let response = self
            .execute_with_retry(Method::GET, url, query, None)
            .await?;
        let wire: FirestoreListWire = serde_json::from_value(response)?;
        Ok(FirestoreListResponse {
            documents: wire
                .documents
                .into_iter()
                .map(firestore_document_to_view)
                .collect(),
            next_page_token: wire.next_page_token,
        })
    }

    /// Create a Firestore document.
    pub async fn firestore_create(
        &self,
        request: &FirestoreCreateRequest,
    ) -> FirebaseResult<FirestoreDocumentView> {
        let (parent, collection_id) = self.collection_parent_and_id(&request.collection_path)?;
        let url = format!("{}/{parent}/{collection_id}", self.firestore_base_url);
        let mut query = repeated_query("mask.fieldPaths", &request.mask);
        if let Some(document_id) = &request.document_id {
            query.push(("documentId".into(), document_id.clone()));
        }
        let body = serde_json::to_value(
            json_to_firestore_document(&request.document).map_err(FirebaseError::InvalidInput)?,
        )?;
        let response = self
            .execute_with_retry(Method::POST, url, query, Some(body))
            .await?;
        let document: FirestoreDocumentWire = serde_json::from_value(response)?;
        Ok(firestore_document_to_view(document))
    }

    /// Update a Firestore document.
    pub async fn firestore_update(
        &self,
        request: &FirestoreUpdateRequest,
    ) -> FirebaseResult<FirestoreDocumentView> {
        let url = format!(
            "{}/{}",
            self.firestore_base_url,
            self.document_resource(&request.document_path)?
        );
        let body = serde_json::to_value(
            json_to_firestore_document(&request.document).map_err(FirebaseError::InvalidInput)?,
        )?;

        let update_mask = if request.update_mask.is_empty() {
            top_level_field_paths(&request.document)?
        } else {
            request.update_mask.clone()
        };
        let mut query = repeated_query("updateMask.fieldPaths", &update_mask);
        query.extend(repeated_query("mask.fieldPaths", &request.mask));
        if let Some(current_exists) = request.current_exists {
            query.push(("currentDocument.exists".into(), current_exists.to_string()));
        }
        if let Some(current_update_time) = &request.current_update_time {
            query.push((
                "currentDocument.updateTime".into(),
                current_update_time.clone(),
            ));
        }

        let response = self
            .execute_with_retry(Method::PATCH, url, query, Some(body))
            .await?;
        let document: FirestoreDocumentWire = serde_json::from_value(response)?;
        Ok(firestore_document_to_view(document))
    }

    /// Delete a Firestore document.
    pub async fn firestore_delete(
        &self,
        request: &FirestoreDeleteRequest,
    ) -> FirebaseResult<Value> {
        let url = format!(
            "{}/{}",
            self.firestore_base_url,
            self.document_resource(&request.document_path)?
        );
        let mut query = Vec::new();
        if let Some(current_exists) = request.current_exists {
            query.push(("currentDocument.exists".into(), current_exists.to_string()));
        }
        if let Some(current_update_time) = &request.current_update_time {
            query.push((
                "currentDocument.updateTime".into(),
                current_update_time.clone(),
            ));
        }

        self.execute_with_retry(Method::DELETE, url, query, None)
            .await
    }

    /// Run a Firestore structured query.
    pub async fn firestore_query(
        &self,
        request: &FirestoreQueryRequest,
    ) -> FirebaseResult<FirestoreQueryResponse> {
        let parent = self.parent_resource(request.parent_path.as_deref())?;
        let url = format!("{}/{parent}:runQuery", self.firestore_base_url);
        let response = self
            .execute_with_retry(
                Method::POST,
                url,
                Vec::new(),
                Some(json!({ "structuredQuery": request.structured_query })),
            )
            .await?;
        let rows: Vec<FirestoreRunQueryResultWire> = serde_json::from_value(response)?;

        let mut documents = Vec::new();
        let mut skipped_results = 0_u64;
        let mut read_time = None;
        let mut transaction = None;

        for row in rows {
            if let Some(document) = row.document {
                documents.push(firestore_document_to_view(document));
            }
            skipped_results = skipped_results.saturating_add(row.skipped_results.unwrap_or(0));
            if let Some(value) = row.read_time {
                read_time = Some(value);
            }
            if let Some(value) = row.transaction {
                transaction = Some(value);
            }
        }

        Ok(FirestoreQueryResponse {
            documents,
            skipped_results,
            read_time,
            transaction,
        })
    }

    /// Execute a Firestore batch write.
    pub async fn firestore_batch_write(
        &self,
        request: &FirestoreBatchWriteRequest,
    ) -> FirebaseResult<Value> {
        if request.writes.is_empty() {
            return Err(FirebaseError::InvalidInput(
                "writes must not be empty".into(),
            ));
        }
        let url = format!(
            "{}/{}/documents:batchWrite",
            self.firestore_base_url,
            self.database_resource()
        );
        self.execute_with_retry(
            Method::POST,
            url,
            Vec::new(),
            Some(json!({
                "writes": request.writes,
                "labels": request.labels,
            })),
        )
        .await
    }

    /// Read from Realtime Database.
    pub async fn rtdb_get(&self, request: &RealtimeGetRequest) -> FirebaseResult<Value> {
        let url = self.rtdb_resource_url(&request.path)?;
        let mut query = Vec::new();
        if let Some(order_by) = &request.order_by {
            query.push((
                "orderBy".into(),
                serde_json::to_string(order_by).map_err(FirebaseError::Json)?,
            ));
        }
        if let Some(start_at) = &request.start_at {
            query.push((
                "startAt".into(),
                serde_json::to_string(start_at).map_err(FirebaseError::Json)?,
            ));
        }
        if let Some(end_at) = &request.end_at {
            query.push((
                "endAt".into(),
                serde_json::to_string(end_at).map_err(FirebaseError::Json)?,
            ));
        }
        if let Some(equal_to) = &request.equal_to {
            query.push((
                "equalTo".into(),
                serde_json::to_string(equal_to).map_err(FirebaseError::Json)?,
            ));
        }
        if let Some(limit_to_first) = request.limit_to_first {
            query.push(("limitToFirst".into(), limit_to_first.to_string()));
        }
        if let Some(limit_to_last) = request.limit_to_last {
            query.push(("limitToLast".into(), limit_to_last.to_string()));
        }
        if request.shallow {
            query.push(("shallow".into(), "true".into()));
        }

        self.execute_with_retry(Method::GET, url, query, None).await
    }

    /// Write a value into Realtime Database.
    pub async fn rtdb_set(&self, request: &RealtimeSetRequest) -> FirebaseResult<Value> {
        let url = self.rtdb_resource_url(&request.path)?;
        let mut query = Vec::new();
        if request.silent {
            query.push(("print".into(), "silent".into()));
        }
        self.execute_with_retry(Method::PUT, url, query, Some(request.value.clone()))
            .await
    }

    /// Delete a value from Realtime Database.
    pub async fn rtdb_delete(&self, request: &RealtimeDeleteRequest) -> FirebaseResult<Value> {
        let url = self.rtdb_resource_url(&request.path)?;
        let mut query = Vec::new();
        if request.silent {
            query.push(("print".into(), "silent".into()));
        }
        self.execute_with_retry(Method::DELETE, url, query, None)
            .await
    }

    async fn execute_with_retry(
        &self,
        method: Method,
        url: String,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> FirebaseResult<Value> {
        // br-kxd3e: derived from the verb, which is sound here because this
        // client uses each one for its standard meaning. GET reads; PATCH and
        // PUT write a document at a caller-chosen path, so they converge;
        // DELETE converges. Only POST creates a document with a SERVER-chosen
        // auto-id, so a replay makes a second document.
        let replay_safe = method != Method::POST;
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let method = method.clone();
            let url = url.clone();
            let query = query.clone();
            let body = body.clone();
            async move {
                debug!(
                    url = %redact_url(&url),
                    method = %method,
                    attempt,
                    "firebase request"
                );
                match self.execute_once(method, &url, &query, body.as_ref()).await {
                    Ok(response) => AttemptOutcome::Success(response),
                    Err(error) if error.is_retryable() => {
                        // 429 stays retryable; a 5xx reached Firestore.
                        let replayable = replay_safe || error.replay_is_safe();
                        let retry_after = error.retry_after();
                        AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        method: Method,
        url: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> FirebaseResult<Value> {
        let mut builder = self.http.request(method, url);
        builder = builder.header("accept", "application/json");

        let mut headers = Vec::new();
        self.auth.apply_headers(&mut headers);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if !query.is_empty() {
            builder = builder.query(query);
        }
        if let Some(body) = body {
            builder = builder.json(body);
        }

        let response = builder.send().await?;
        let status_code = response.status().as_u16();
        let text = response.text().await?;
        if !(200..300).contains(&status_code) {
            return Err(FirebaseError::from_http_response(status_code, &text));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }

        serde_json::from_str(&text).map_err(FirebaseError::Json)
    }

    fn database_resource(&self) -> String {
        format!(
            "projects/{}/databases/{}",
            encode_path_segment(&self.project_id),
            encode_path_segment(&self.database_id)
        )
    }

    fn documents_root_resource(&self) -> String {
        format!("{}/documents", self.database_resource())
    }

    fn document_resource(&self, document_path: &str) -> FirebaseResult<String> {
        let segments = parse_document_path(document_path)?;
        Ok(format!(
            "{}/{}",
            self.documents_root_resource(),
            encode_segments(&segments)
        ))
    }

    fn collection_parent_and_id(&self, collection_path: &str) -> FirebaseResult<(String, String)> {
        let segments = parse_collection_path(collection_path)?;
        let collection_id = segments.last().cloned().ok_or_else(|| {
            FirebaseError::InvalidInput("collection_path must not be empty".into())
        })?;
        let parent = if segments.len() == 1 {
            self.documents_root_resource()
        } else {
            format!(
                "{}/{}",
                self.documents_root_resource(),
                encode_segments(&segments[..segments.len() - 1])
            )
        };
        Ok((parent, encode_path_segment(&collection_id)))
    }

    fn parent_resource(&self, parent_path: Option<&str>) -> FirebaseResult<String> {
        let Some(parent_path) = parent_path.map(str::trim) else {
            return Ok(self.documents_root_resource());
        };
        if parent_path.is_empty() {
            return Ok(self.documents_root_resource());
        }

        let segments = parse_parent_path(parent_path)?;
        Ok(format!(
            "{}/{}",
            self.documents_root_resource(),
            encode_segments(&segments)
        ))
    }

    fn rtdb_resource_url(&self, path: &str) -> FirebaseResult<String> {
        let segments = parse_resource_path(path, "path")?;
        let encoded = encode_segments(&segments);
        if encoded.is_empty() {
            Ok(format!("{}/.json", self.realtime_database_url))
        } else {
            Ok(format!("{}/{encoded}.json", self.realtime_database_url))
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirestoreListWire {
    #[serde(default)]
    documents: Vec<FirestoreDocumentWire>,
    #[serde(default)]
    next_page_token: Option<String>,
}

fn parse_resource_path(path: &str, field: &str) -> FirebaseResult<Vec<String>> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        let segment = segment.trim();
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(FirebaseError::InvalidInput(format!(
                "{field} contains an invalid path segment"
            )));
        }
        segments.push(segment.to_string());
    }
    Ok(segments)
}

fn parse_document_path(path: &str) -> FirebaseResult<Vec<String>> {
    let segments = parse_resource_path(path, "document_path")?;
    if segments.is_empty() || segments.len() % 2 != 0 {
        return Err(FirebaseError::InvalidInput(
            "document_path must contain alternating collection/document segments".into(),
        ));
    }
    Ok(segments)
}

fn parse_collection_path(path: &str) -> FirebaseResult<Vec<String>> {
    let segments = parse_resource_path(path, "collection_path")?;
    if segments.is_empty() || segments.len() % 2 == 0 {
        return Err(FirebaseError::InvalidInput(
            "collection_path must end with a collection segment".into(),
        ));
    }
    Ok(segments)
}

fn parse_parent_path(path: &str) -> FirebaseResult<Vec<String>> {
    let segments = parse_resource_path(path, "parent_path")?;
    if segments.len() % 2 != 0 {
        return Err(FirebaseError::InvalidInput(
            "parent_path must be empty or point to a Firestore document".into(),
        ));
    }
    Ok(segments)
}

fn top_level_field_paths(document: &Value) -> FirebaseResult<Vec<String>> {
    let object = document
        .as_object()
        .ok_or_else(|| FirebaseError::InvalidInput("document must be a JSON object".into()))?;
    if object.is_empty() {
        return Err(FirebaseError::InvalidInput(
            "document must include at least one field".into(),
        ));
    }
    Ok(object.keys().cloned().collect())
}

fn encode_segments(segments: &[String]) -> String {
    segments
        .iter()
        .map(|segment| encode_path_segment(segment))
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn repeated_query(name: &str, values: &[String]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|value| (name.to_string(), value.clone()))
        .collect()
}

fn redact_url(url: &str) -> String {
    Url::parse(url).map_or_else(
        |_| url.to_string(),
        |mut parsed| {
            parsed.set_query(None);
            parsed.to_string()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_path_requires_even_segments() {
        let error = parse_document_path("users").unwrap_err();
        assert!(matches!(error, FirebaseError::InvalidInput(_)));
    }

    #[test]
    fn collection_path_requires_odd_segments() {
        let error = parse_collection_path("users/alice").unwrap_err();
        assert!(matches!(error, FirebaseError::InvalidInput(_)));
    }
}
