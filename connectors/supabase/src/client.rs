use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde_json::json;
use tracing::debug;

use crate::error::{SupabaseError, SupabaseResult};
use crate::types::{
    ApiErrorResponse, BinaryHttpResponse, DeleteRequest, InsertRequest, JsonHttpResponse,
    OpenApiDocument, QueryFilter, QueryOrder, ReturningMode, RpcRequest, SchemaTablesRequest,
    SchemaTablesResponse, StorageDeleteRequest, StorageDownloadRequest, StorageUploadRequest,
    TableCatalogEntry, TableQueryRequest, UpdateRequest, UpsertRequest,
};

/// Default project URL placeholder.
pub const DEFAULT_PROJECT_URL: &str = "https://project-ref.supabase.co";

/// Authentication mode for the Supabase API.
#[derive(Clone)]
pub enum SupabaseAuth {
    /// Project API key, used for both `apikey` and bearer auth headers.
    ApiKey(String),
    /// Secretless mode - no key supplied; egress proxy must inject.
    Secretless,
}

impl SupabaseAuth {
    #[must_use]
    pub fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::Secretless => "secretless",
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::Secretless)
    }
}

impl fmt::Debug for SupabaseAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f
                .debug_struct("ApiKey")
                .field("api_key", &"[REDACTED]")
                .finish(),
            Self::Secretless => f.debug_struct("Secretless").finish(),
        }
    }
}

/// Supabase API client with retry support.
pub struct SupabaseClient {
    client: Client,
    auth: SupabaseAuth,
    project_url: String,
    rest_url: String,
    storage_url: String,
    default_schema: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SupabaseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupabaseClient")
            .field("auth", &self.auth)
            .field("project_url", &self.project_url)
            .field("rest_url", &self.rest_url)
            .field("storage_url", &self.storage_url)
            .field("default_schema", &self.default_schema)
            .finish()
    }
}

impl SupabaseClient {
    /// Create a new Supabase API client.
    pub fn new(
        auth: SupabaseAuth,
        project_url: &str,
        default_schema: &str,
        request_timeout_ms: u64,
    ) -> SupabaseResult<Self> {
        let project_url = project_url.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .user_agent("fcp-supabase/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            rest_url: format!("{project_url}/rest/v1"),
            storage_url: format!("{project_url}/storage/v1"),
            project_url,
            default_schema: normalize_identifier(default_schema, "schema")?.to_string(),
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

    /// Shut down the client runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Project URL.
    #[must_use]
    pub fn project_url(&self) -> &str {
        &self.project_url
    }

    /// REST root URL.
    #[must_use]
    pub fn rest_url(&self) -> &str {
        &self.rest_url
    }

    /// Storage root URL.
    #[must_use]
    pub fn storage_url(&self) -> &str {
        &self.storage_url
    }

    /// Default schema.
    #[must_use]
    pub fn default_schema(&self) -> &str {
        &self.default_schema
    }

    /// Check if client uses secretless auth.
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    /// Query table or view rows through PostgREST.
    pub async fn query(&self, request: &TableQueryRequest) -> SupabaseResult<JsonHttpResponse> {
        let table = normalize_identifier(&request.table, "table")?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/{}", self.rest_url, table);

        let select = if request.select.trim().is_empty() {
            "*".to_string()
        } else {
            request.select.trim().to_string()
        };

        let mut query = vec![("select".to_string(), select)];
        query.extend(build_filter_query(&request.filters)?);
        if !request.order.is_empty() {
            query.push(("order".to_string(), build_order_query(&request.order)?));
        }
        if let Some(limit) = request.limit {
            query.push(("limit".to_string(), limit.to_string()));
        }
        if let Some(offset) = request.offset {
            query.push(("offset".to_string(), offset.to_string()));
        }

        self.request_json(
            Method::GET,
            url,
            Some(schema),
            None,
            query,
            Vec::new(),
            request.single,
        )
        .await
    }

    /// Insert rows through PostgREST.
    pub async fn insert(&self, request: &InsertRequest) -> SupabaseResult<JsonHttpResponse> {
        let table = normalize_identifier(&request.table, "table")?;
        ensure_rows(&request.rows)?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/{}", self.rest_url, table);
        let prefer = vec![format!("return={}", request.returning.as_prefer_token())];

        self.request_json(
            Method::POST,
            url,
            Some(schema),
            Some(json!(request.rows)),
            Vec::new(),
            prefer,
            false,
        )
        .await
    }

    /// Update rows through PostgREST.
    pub async fn update(&self, request: &UpdateRequest) -> SupabaseResult<JsonHttpResponse> {
        let table = normalize_identifier(&request.table, "table")?;
        ensure_nonempty_filters(&request.filters, "update")?;
        ensure_json_object(&request.values, "values")?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/{}", self.rest_url, table);
        let query = build_filter_query(&request.filters)?;
        let prefer = vec![format!("return={}", request.returning.as_prefer_token())];

        self.request_json(
            Method::PATCH,
            url,
            Some(schema),
            Some(request.values.clone()),
            query,
            prefer,
            false,
        )
        .await
    }

    /// Upsert rows through PostgREST.
    pub async fn upsert(&self, request: &UpsertRequest) -> SupabaseResult<JsonHttpResponse> {
        let table = normalize_identifier(&request.table, "table")?;
        ensure_rows(&request.rows)?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/{}", self.rest_url, table);
        let mut query = Vec::new();
        if !request.on_conflict.is_empty() {
            for column in &request.on_conflict {
                normalize_identifier(column, "on_conflict column")?;
            }
            query.push(("on_conflict".to_string(), request.on_conflict.join(",")));
        }
        let resolution = if request.ignore_duplicates {
            "ignore-duplicates"
        } else {
            "merge-duplicates"
        };
        let prefer = vec![
            format!("resolution={resolution}"),
            format!("return={}", request.returning.as_prefer_token()),
        ];

        self.request_json(
            Method::POST,
            url,
            Some(schema),
            Some(json!(request.rows)),
            query,
            prefer,
            false,
        )
        .await
    }

    /// Delete rows through PostgREST.
    pub async fn delete(&self, request: &DeleteRequest) -> SupabaseResult<JsonHttpResponse> {
        let table = normalize_identifier(&request.table, "table")?;
        ensure_nonempty_filters(&request.filters, "delete")?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/{}", self.rest_url, table);
        let query = build_filter_query(&request.filters)?;
        let prefer = vec![format!("return={}", request.returning.as_prefer_token())];

        self.request_json(
            Method::DELETE,
            url,
            Some(schema),
            None,
            query,
            prefer,
            false,
        )
        .await
    }

    /// Invoke a Postgres function exposed through `/rpc`.
    pub async fn rpc(&self, request: &RpcRequest) -> SupabaseResult<JsonHttpResponse> {
        let function = normalize_identifier(&request.function, "function")?;
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let url = format!("{}/rpc/{}", self.rest_url, function);
        self.request_json(
            Method::POST,
            url,
            Some(schema),
            Some(request.args.clone()),
            Vec::new(),
            vec![format!(
                "return={}",
                ReturningMode::Representation.as_prefer_token()
            )],
            false,
        )
        .await
    }

    /// List exposed PostgREST tables/views by parsing the OpenAPI root.
    pub async fn schema_tables(
        &self,
        request: &SchemaTablesRequest,
    ) -> SupabaseResult<SchemaTablesResponse> {
        let schema = request_schema(request.schema.as_deref(), &self.default_schema)?;
        let openapi = self.openapi_root(Some(schema.clone())).await?;
        let document: OpenApiDocument = serde_json::from_value(openapi.data)?;

        let mut tables = document
            .paths
            .into_iter()
            .filter(|(path, _)| path.starts_with('/') && !path.starts_with("/rpc/"))
            .map(|(path, value)| {
                let methods = value
                    .as_object()
                    .map(|map| {
                        let mut methods = map.keys().cloned().collect::<Vec<_>>();
                        methods.sort();
                        methods
                    })
                    .unwrap_or_default();
                let name = path.trim_start_matches('/').to_string();
                TableCatalogEntry {
                    name,
                    path,
                    methods,
                }
            })
            .collect::<Vec<_>>();
        tables.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(SchemaTablesResponse { schema, tables })
    }

    /// Upload a file to Supabase Storage.
    pub async fn storage_upload(
        &self,
        request: &StorageUploadRequest,
    ) -> SupabaseResult<JsonHttpResponse> {
        let bucket = normalize_identifier(&request.bucket, "bucket")?;
        let path = normalize_storage_path(&request.path)?;
        let url = format!(
            "{}/object/{bucket}/{}",
            self.storage_url,
            encode_path(&path)
        );
        let body = BASE64_STANDARD.decode(request.content_base64.as_bytes())?;
        let content_type = request
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream")
            .to_string();
        let upsert = request.upsert;

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let auth = self.auth.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let client = client.clone();
            let auth = auth.clone();
            let url = url.clone();
            let body = body.clone();
            let content_type = content_type.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Supabase storage upload");
                let mut req = apply_auth(client.post(&url), &auth)
                    .header("Content-Type", content_type)
                    .header("x-upsert", if upsert { "true" } else { "false" });
                req = req.body(body);
                // br-kxd3e: read the upload's own signal, same as the
                // PostgREST path. With `x-upsert: true` a replay overwrites
                // the same object key and converges; without it, a replay
                // uploads a second object.
                handle_json_response(req, attempt, upsert).await
            }
        })
        .await
    }

    /// Download a file from Supabase Storage.
    pub async fn storage_download(
        &self,
        request: &StorageDownloadRequest,
    ) -> SupabaseResult<BinaryHttpResponse> {
        let bucket = normalize_identifier(&request.bucket, "bucket")?;
        let path = normalize_storage_path(&request.path)?;
        let scope = if request.public {
            "public"
        } else {
            "authenticated"
        };
        let url = format!(
            "{}/object/{scope}/{bucket}/{}",
            self.storage_url,
            encode_path(&path)
        );
        let mut query = Vec::new();
        if let Some(download) = request.download_filename.as_deref()
            && !download.trim().is_empty()
        {
            query.push(("download".to_string(), download.trim().to_string()));
        }
        self.request_binary(url, query).await
    }

    /// Delete a file from Supabase Storage.
    pub async fn storage_delete(
        &self,
        request: &StorageDeleteRequest,
    ) -> SupabaseResult<JsonHttpResponse> {
        let bucket = normalize_identifier(&request.bucket, "bucket")?;
        let path = normalize_storage_path(&request.path)?;
        let url = format!(
            "{}/object/{bucket}/{}",
            self.storage_url,
            encode_path(&path)
        );
        self.request_json(
            Method::DELETE,
            url,
            None,
            None,
            Vec::new(),
            Vec::new(),
            false,
        )
        .await
    }

    /// Check Supabase PostgREST reachability.
    pub async fn health(&self) -> SupabaseResult<serde_json::Value> {
        let openapi = self.openapi_root(None).await?;
        let document: OpenApiDocument = serde_json::from_value(openapi.data.clone())?;
        Ok(json!({
            "status": "ok",
            "project_url": self.project_url,
            "rest_url": self.rest_url,
            "storage_url": self.storage_url,
            "default_schema": self.default_schema,
            "openapi_title": document.info.as_ref().and_then(|info| info.title.clone()),
            "openapi_version": document.info.as_ref().and_then(|info| info.version.clone()),
        }))
    }

    async fn openapi_root(&self, schema: Option<String>) -> SupabaseResult<JsonHttpResponse> {
        self.request_json(
            Method::GET,
            format!("{}/", self.rest_url),
            schema,
            None,
            Vec::new(),
            Vec::new(),
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_json(
        &self,
        method: Method,
        url: String,
        schema: Option<String>,
        body: Option<serde_json::Value>,
        query: Vec<(String, String)>,
        prefer: Vec<String>,
        accept_object: bool,
    ) -> SupabaseResult<JsonHttpResponse> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let auth = self.auth.clone();
        let is_write = !matches!(method, Method::GET | Method::HEAD);
        // br-kxd3e: replay safety is READ OFF THE REQUEST rather than declared
        // per call site, so it stays correct as operations change.
        //
        // PostgREST semantics: GET/HEAD read; PATCH and DELETE carry a filter
        // and converge on the same rows; PUT is an upsert. Only a bare POST
        // inserts, and a replay of that inserts the rows a SECOND time.
        //
        // The exception is the connector's own upsert path, which announces
        // itself in the `Prefer` header (`resolution=merge-duplicates` or
        // `ignore-duplicates`). PostgREST resolves the conflict server-side,
        // so replaying it converges — the same shape as square reading its
        // own idempotency_key off the body.
        let is_conflict_resolving_upsert =
            prefer.iter().any(|value| value.starts_with("resolution="));
        let replay_safe = method != Method::POST || is_conflict_resolving_upsert;

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let method = method.clone();
            let url = url.clone();
            let schema = schema.clone();
            let body = body.clone();
            let query = query.clone();
            let prefer = prefer.clone();
            let client = client.clone();
            let auth = auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), method = %method.as_str(), "Supabase JSON request");
                let mut req = apply_auth(client.request(method.clone(), &url), &auth).header(
                    "Accept",
                    if accept_object {
                        "application/vnd.pgrst.object+json"
                    } else {
                        "application/json"
                    },
                );
                if let Some(schema) = schema.as_deref() {
                    req = apply_schema_headers(req, schema, is_write);
                }
                if !query.is_empty() {
                    req = req.query(&query);
                }
                if !prefer.is_empty() {
                    req = req.header("Prefer", prefer.join(","));
                }
                if let Some(body) = body {
                    req = req.header("Content-Type", "application/json").json(&body);
                }
                handle_json_response(req, attempt, replay_safe).await
            }
        })
        .await
    }

    async fn request_binary(
        &self,
        url: String,
        query: Vec<(String, String)>,
    ) -> SupabaseResult<BinaryHttpResponse> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let auth = self.auth.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let query = query.clone();
            let client = client.clone();
            let auth = auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Supabase binary request");
                let mut req = apply_auth(client.get(&url), &auth);
                if !query.is_empty() {
                    req = req.query(&query);
                }
                handle_binary_response(req, attempt).await
            }
        })
        .await
    }
}

fn apply_auth(req: RequestBuilder, auth: &SupabaseAuth) -> RequestBuilder {
    match auth {
        SupabaseAuth::ApiKey(key) => {
            if key.is_empty() {
                req
            } else {
                req.header("apikey", key).bearer_auth(key)
            }
        }
        SupabaseAuth::Secretless => req,
    }
}

fn apply_schema_headers(req: RequestBuilder, schema: &str, is_write: bool) -> RequestBuilder {
    let req = req.header("Accept-Profile", schema);
    if is_write {
        req.header("Content-Profile", schema)
    } else {
        req
    }
}

async fn handle_json_response(
    req: RequestBuilder,
    attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<JsonHttpResponse, SupabaseError> {
    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            // Only a connect-phase failure proves the insert never reached
            // PostgREST.
            let replayable = replay_safe || !transport_error_reached_service(&err);
            return AttemptOutcome::retryable_if_replayable(
                SupabaseError::Http(err),
                None,
                replayable,
            );
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return handle_error_response::<JsonHttpResponse>(resp, replay_safe).await;
    }

    let headers = clone_json_headers(&resp);
    let text = match resp.text().await {
        Ok(text) => text,
        Err(err) => return AttemptOutcome::Terminal(SupabaseError::Http(err)),
    };
    let data = if text.is_empty() {
        json!({})
    } else {
        match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(err) => {
                debug!(attempt, "Failed to parse JSON response: {err}");
                return AttemptOutcome::Terminal(SupabaseError::Json(err));
            }
        }
    };

    AttemptOutcome::Success(JsonHttpResponse {
        data,
        status_code: status.as_u16(),
        content_range: headers.content_range,
        content_type: headers.content_type,
    })
}

async fn handle_binary_response(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<BinaryHttpResponse, SupabaseError> {
    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            return AttemptOutcome::Retryable {
                error: SupabaseError::Http(err),
                retry_after: None,
            };
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return handle_error_response::<BinaryHttpResponse>(resp, true).await;
    }

    let headers = clone_binary_headers(&resp);
    let bytes = match resp.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => return AttemptOutcome::Terminal(SupabaseError::Http(err)),
    };

    AttemptOutcome::Success(BinaryHttpResponse {
        content_base64: BASE64_STANDARD.encode(bytes),
        status_code: status.as_u16(),
        content_type: headers.content_type,
        content_length: headers.content_length,
        etag: headers.etag,
        cache_control: headers.cache_control,
    })
}

/// Classify a PostgREST error response.
///
/// `replay_safe` gates only the post-transmission retry classes; the 429 arm
/// above it stays retryable because PostgREST refused the request WITHOUT
/// performing it (br-kxd3e).
async fn handle_error_response<T>(
    resp: Response,
    replay_safe: bool,
) -> AttemptOutcome<T, SupabaseError> {
    let status = resp.status();
    let retry_after = retry_after_header(resp.headers());
    let body = resp.text().await.unwrap_or_default();
    let detail = extract_error_detail(status, &body);

    if status == StatusCode::UNAUTHORIZED {
        return AttemptOutcome::Terminal(SupabaseError::Auth(detail));
    }
    if status == StatusCode::FORBIDDEN {
        return AttemptOutcome::Terminal(SupabaseError::PermissionDenied(detail));
    }
    if status == StatusCode::NOT_FOUND {
        return AttemptOutcome::Terminal(SupabaseError::NotFound(detail));
    }
    if status == StatusCode::CONFLICT {
        return AttemptOutcome::Terminal(SupabaseError::Conflict(detail));
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return AttemptOutcome::Retryable {
            error: SupabaseError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(30))
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    let error = if status == StatusCode::REQUEST_TIMEOUT {
        SupabaseError::Timeout(detail)
    } else {
        SupabaseError::Api {
            status_code: status.as_u16(),
            message: detail,
        }
    };

    if matches!(
        classify_http_status(status.as_u16(), retry_after),
        RetryDecision::Terminal
    ) {
        AttemptOutcome::Terminal(error)
    } else {
        // A 5xx means PostgREST received the statement and may already have
        // committed the insert.
        AttemptOutcome::retryable_if_replayable(error, retry_after, replay_safe)
    }
}

fn extract_error_detail(status: StatusCode, body: &str) -> String {
    serde_json::from_str::<ApiErrorResponse>(body)
        .ok()
        .map(|payload| {
            let mut parts = Vec::new();
            if let Some(message) = payload.message.or(payload.error)
                && !message.trim().is_empty()
            {
                parts.push(message.trim().to_string());
            }
            if let Some(details) = payload.details
                && !details.trim().is_empty()
            {
                parts.push(details.trim().to_string());
            }
            if let Some(hint) = payload.hint
                && !hint.trim().is_empty()
            {
                parts.push(format!("hint: {}", hint.trim()));
            }
            if let Some(code) = payload.code
                && !code.trim().is_empty()
            {
                parts.push(format!("code: {}", code.trim()));
            }
            if parts.is_empty() {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.to_string()
                }
            } else {
                parts.join(" | ")
            }
        })
        .unwrap_or_else(|| {
            if body.is_empty() {
                format!("HTTP {}", status.as_u16())
            } else {
                body.to_string()
            }
        })
}

fn retry_after_header(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

struct JsonHeaders {
    content_range: Option<String>,
    content_type: Option<String>,
}

fn clone_json_headers(resp: &Response) -> JsonHeaders {
    JsonHeaders {
        content_range: header_to_string(resp.headers(), "content-range"),
        content_type: header_to_string(resp.headers(), "content-type"),
    }
}

struct BinaryHeaders {
    content_type: Option<String>,
    content_length: Option<u64>,
    etag: Option<String>,
    cache_control: Option<String>,
}

fn clone_binary_headers(resp: &Response) -> BinaryHeaders {
    BinaryHeaders {
        content_type: header_to_string(resp.headers(), "content-type"),
        content_length: resp
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok()),
        etag: header_to_string(resp.headers(), "etag"),
        cache_control: header_to_string(resp.headers(), "cache-control"),
    }
}

fn header_to_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn normalize_identifier<'a>(value: &'a str, field: &str) -> Result<&'a str, SupabaseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SupabaseError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(SupabaseError::InvalidInput(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(trimmed)
}

fn request_schema(schema: Option<&str>, default_schema: &str) -> Result<String, SupabaseError> {
    match schema {
        Some(schema) => Ok(normalize_identifier(schema, "schema")?.to_string()),
        None => Ok(default_schema.to_string()),
    }
}

fn normalize_storage_path(path: &str) -> Result<String, SupabaseError> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Err(SupabaseError::InvalidInput(
            "path must not be empty".to_string(),
        ));
    }
    if trimmed.split('/').any(|segment| segment.is_empty()) {
        return Err(SupabaseError::InvalidInput(
            "path contains empty segments".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn ensure_rows(rows: &[serde_json::Value]) -> Result<(), SupabaseError> {
    if rows.is_empty() {
        return Err(SupabaseError::InvalidInput(
            "rows must contain at least one object".to_string(),
        ));
    }
    Ok(())
}

fn ensure_nonempty_filters(filters: &[QueryFilter], operation: &str) -> Result<(), SupabaseError> {
    if filters.is_empty() {
        return Err(SupabaseError::InvalidInput(format!(
            "{operation} requires at least one filter"
        )));
    }
    Ok(())
}

fn ensure_json_object(value: &serde_json::Value, field: &str) -> Result<(), SupabaseError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(SupabaseError::InvalidInput(format!(
            "{field} must be a JSON object"
        )))
    }
}

fn build_filter_query(filters: &[QueryFilter]) -> Result<Vec<(String, String)>, SupabaseError> {
    filters
        .iter()
        .map(|filter| {
            let column = normalize_identifier(&filter.column, "filter column")?.to_string();
            let operator = normalize_identifier(&filter.operator, "filter operator")?.to_string();
            let value = format_filter_value(&operator, &filter.value)?;
            Ok((column, format!("{operator}.{value}")))
        })
        .collect()
}

fn format_filter_value(operator: &str, value: &serde_json::Value) -> Result<String, SupabaseError> {
    match operator {
        "in" => {
            let values = value.as_array().ok_or_else(|| {
                SupabaseError::InvalidInput("`in` filters require an array value".to_string())
            })?;
            if values.is_empty() {
                return Err(SupabaseError::InvalidInput(
                    "`in` filters require at least one item".to_string(),
                ));
            }
            let joined = values
                .iter()
                .map(scalar_filter_literal)
                .collect::<Result<Vec<_>, _>>()?
                .join(",");
            Ok(format!("({joined})"))
        }
        "is" => match value {
            serde_json::Value::Null => Ok("null".to_string()),
            serde_json::Value::Bool(boolean) => Ok(boolean.to_string()),
            _ => scalar_filter_literal(value),
        },
        _ => scalar_filter_literal(value),
    }
}

fn scalar_filter_literal(value: &serde_json::Value) -> Result<String, SupabaseError> {
    match value {
        serde_json::Value::String(string) => Ok(string.clone()),
        serde_json::Value::Number(number) => Ok(number.to_string()),
        serde_json::Value::Bool(boolean) => Ok(boolean.to_string()),
        serde_json::Value::Null => Ok("null".to_string()),
        _ => Err(SupabaseError::InvalidInput(
            "filter values must be scalar JSON values".to_string(),
        )),
    }
}

fn build_order_query(order: &[QueryOrder]) -> Result<String, SupabaseError> {
    order
        .iter()
        .map(|entry| {
            let column = normalize_identifier(&entry.column, "order column")?;
            let direction = if entry.ascending { "asc" } else { "desc" };
            let mut parts = vec![column.to_string(), direction.to_string()];
            if let Some(nulls_first) = entry.nulls_first {
                parts.push(if nulls_first {
                    "nullsfirst".to_string()
                } else {
                    "nullslast".to_string()
                });
            }
            Ok(parts.join("."))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let client = SupabaseClient::new(
            SupabaseAuth::ApiKey("super-secret".into()),
            DEFAULT_PROJECT_URL,
            "public",
            30_000,
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn client_debug_contains_urls() {
        let client = SupabaseClient::new(
            SupabaseAuth::ApiKey("test-key".into()),
            DEFAULT_PROJECT_URL,
            "public",
            30_000,
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains(DEFAULT_PROJECT_URL));
        assert!(debug.contains("/rest/v1"));
        assert!(debug.contains("/storage/v1"));
    }

    #[test]
    fn secretless_detection() {
        let c1 = SupabaseClient::new(
            SupabaseAuth::Secretless,
            DEFAULT_PROJECT_URL,
            "public",
            30_000,
        )
        .unwrap();
        assert!(c1.is_secretless());

        let c2 = SupabaseClient::new(
            SupabaseAuth::ApiKey("key".into()),
            DEFAULT_PROJECT_URL,
            "public",
            30_000,
        )
        .unwrap();
        assert!(!c2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let client = SupabaseClient::new(
            SupabaseAuth::ApiKey("t".into()),
            "https://demo.supabase.co/",
            "public",
            30_000,
        )
        .unwrap();
        assert!(!client.project_url().ends_with('/'));
        assert!(client.rest_url().contains("/rest/v1"));
    }

    #[test]
    fn normalize_identifier_rejects_empty() {
        assert!(normalize_identifier("", "table").is_err());
        assert!(normalize_identifier("  ", "table").is_err());
    }

    #[test]
    fn normalize_identifier_rejects_special_chars() {
        assert!(normalize_identifier("tbl;drop", "table").is_err());
        assert!(normalize_identifier("tbl/path", "table").is_err());
    }

    #[test]
    fn normalize_identifier_accepts_valid() {
        assert_eq!(
            normalize_identifier("my_table", "table").unwrap(),
            "my_table"
        );
        assert_eq!(
            normalize_identifier("my-table", "table").unwrap(),
            "my-table"
        );
        assert_eq!(
            normalize_identifier("my.schema", "table").unwrap(),
            "my.schema"
        );
    }

    #[test]
    fn normalize_storage_path_rejects_empty() {
        assert!(normalize_storage_path("").is_err());
        assert!(normalize_storage_path("/").is_err());
    }

    #[test]
    fn normalize_storage_path_rejects_empty_segments() {
        assert!(normalize_storage_path("a//b").is_err());
    }

    #[test]
    fn normalize_storage_path_trims_slashes() {
        assert_eq!(normalize_storage_path("/a/b/").unwrap(), "a/b");
    }

    #[test]
    fn encode_path_percent_encodes() {
        let encoded = encode_path("folder/file name.txt");
        assert!(encoded.contains("file%20name%2Etxt"));
    }

    #[test]
    fn ensure_rows_rejects_empty() {
        assert!(ensure_rows(&[]).is_err());
    }

    #[test]
    fn ensure_rows_accepts_nonempty() {
        assert!(ensure_rows(&[json!({"a": 1})]).is_ok());
    }

    #[test]
    fn ensure_nonempty_filters_rejects_empty() {
        assert!(ensure_nonempty_filters(&[], "delete").is_err());
    }

    #[test]
    fn ensure_json_object_rejects_non_object() {
        assert!(ensure_json_object(&json!("string"), "values").is_err());
        assert!(ensure_json_object(&json!(42), "values").is_err());
    }

    #[test]
    fn ensure_json_object_accepts_object() {
        assert!(ensure_json_object(&json!({"a": 1}), "values").is_ok());
    }

    #[test]
    fn build_filter_eq() {
        let filters = vec![QueryFilter {
            column: "id".into(),
            operator: "eq".into(),
            value: json!(42),
        }];
        let result = build_filter_query(&filters).unwrap();
        assert_eq!(result, vec![("id".into(), "eq.42".into())]);
    }

    #[test]
    fn build_filter_in() {
        let filters = vec![QueryFilter {
            column: "status".into(),
            operator: "in".into(),
            value: json!(["open", "closed"]),
        }];
        let result = build_filter_query(&filters).unwrap();
        assert_eq!(result, vec![("status".into(), "in.(open,closed)".into())]);
    }

    #[test]
    fn build_filter_is_null() {
        let filters = vec![QueryFilter {
            column: "deleted_at".into(),
            operator: "is".into(),
            value: json!(null),
        }];
        let result = build_filter_query(&filters).unwrap();
        assert_eq!(result, vec![("deleted_at".into(), "is.null".into())]);
    }

    #[test]
    fn build_order_query_single() {
        let order = vec![QueryOrder {
            column: "id".into(),
            ascending: true,
            nulls_first: None,
        }];
        assert_eq!(build_order_query(&order).unwrap(), "id.asc");
    }

    #[test]
    fn build_order_query_desc_nulls_last() {
        let order = vec![QueryOrder {
            column: "created_at".into(),
            ascending: false,
            nulls_first: Some(false),
        }];
        assert_eq!(
            build_order_query(&order).unwrap(),
            "created_at.desc.nullslast"
        );
    }

    #[test]
    fn auth_debug_redacts_key() {
        let auth = SupabaseAuth::ApiKey("secret".into());
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn auth_redacted_label() {
        assert_eq!(SupabaseAuth::ApiKey("x".into()).redacted_label(), "api_key");
        assert_eq!(SupabaseAuth::Secretless.redacted_label(), "secretless");
    }
}
