//! Google Drive API v3 HTTP client.
//!
//! Uses `fcp-google-discovery` shared auth substrate.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor, GoogleUploadMode, GoogleUploadPayload,
    validate_upload_content_type,
};
use fcp_google_discovery::{DiscoveryMediaUpload, DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, Url, header};
use tracing::debug;

use crate::{
    error::{DriveError, DriveResult},
    types::{AboutResponse, DriveFile, DrivePermission, FileListResponse},
};

/// Default Google Drive API v3 base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/drive/v3";

/// Maximum decoded file size for this buffered upload operation.
pub const MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_MULTIPART_UPLOAD_BYTES: usize = 5 * 1024 * 1024;
const RESUMABLE_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_RESUMABLE_RECOVERIES: u32 = 3;
const MAX_RESUMABLE_REQUESTS: usize = 64;
const RESUMABLE_TIMEOUT: Duration = Duration::from_secs(55);
const MAX_UPLOAD_METADATA_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

/// Google Drive API v3 client.
pub struct DriveClient {
    executor: GoogleRestExecutor,
    upload_executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for DriveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriveClient")
            .field("auth", &self.auth_redacted_label())
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl DriveClient {
    /// Create a new Drive client with shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> DriveResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let client = Client::builder()
            .default_headers(headers.clone())
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-drive/0.1.0")
            .build()
            .map_err(DriveError::Http)?;
        // Upload redirects can replay a file-creation request. Keep this policy
        // isolated from ordinary media downloads, which may follow redirects.
        let upload_client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("fcp-google-drive/0.1.0")
            .build()
            .map_err(DriveError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            upload_executor: GoogleRestExecutor::new().with_client(upload_client),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
            total_requests: AtomicU64::new(0),
        })
    }

    /// Get current auth.
    #[must_use]
    pub const fn auth(&self) -> &GoogleMaterializedAuth {
        &self.auth
    }

    /// Render a redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// Get the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    // ── File operations ─────────────────────────────────────────

    /// List files in Drive, optionally filtered by query.
    pub async fn list_files(
        &self,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> DriveResult<FileListResponse> {
        let mut url = format!(
            "{}/files?fields=kind,nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,parents,webViewLink,trashed,shared)",
            self.base_url,
        );
        if let Some(q) = query {
            let _ = write!(url, "&q={}", urlencoding::encode(q));
        }
        if let Some(max) = max_results {
            let _ = write!(url, "&pageSize={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(url, "&pageToken={}", urlencoding::encode(token));
        }
        self.get_json(&url).await
    }

    /// Get a file's metadata by ID.
    pub async fn get_file(&self, file_id: &str) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?fields=id,name,mimeType,size,description,createdTime,modifiedTime,parents,webViewLink,webContentLink,thumbnailLink,trashed,shared,owners,permissions",
            self.base_url,
            urlencoding::encode(file_id),
        );
        self.get_json(&url).await
    }

    /// Create a folder in Drive.
    pub async fn create_folder(
        &self,
        name: &str,
        parent_id: Option<&str>,
    ) -> DriveResult<DriveFile> {
        let url = format!("{}/files?fields=id,name,mimeType,parents", self.base_url);
        let mut body = serde_json::json!({
            "name": name,
            "mimeType": "application/vnd.google-apps.folder"
        });
        if let Some(parent) = parent_id {
            body["parents"] = serde_json::json!([parent]);
        }
        self.post_json(&url, &body).await
    }

    /// Upload metadata and decoded file bytes, with bounded in-process recovery.
    ///
    /// Files up to 5 MiB use multipart/related. Larger files, up to 16 MiB,
    /// use a resumable session whose acknowledged offsets are reconciled after
    /// interruptions. Sessions are not persisted across calls or process restarts.
    pub async fn upload_file(
        &self,
        name: &str,
        mime_type: &str,
        parent_id: Option<&str>,
        content_base64: &str,
    ) -> DriveResult<DriveFile> {
        let mut upload = validate_upload_input(name, mime_type, parent_id, content_base64)?;
        let mut url = Url::parse(&self.base_url).map_err(|_| DriveError::Api {
            status_code: 400,
            message: "invalid Drive upload base URL".to_string(),
        })?;
        let upload_path = format!("/upload{}/files", url.path().trim_end_matches('/'));
        url.set_path(&upload_path);
        url.set_query(Some("fields=id,name,mimeType,size"));
        if upload.bytes.len() > MAX_MULTIPART_UPLOAD_BYTES {
            upload.mode = GoogleUploadMode::Resumable;
            let ctx = self.runtime.request_context_with_timeout(RESUMABLE_TIMEOUT);
            return ctx
                .run(self.upload_resumable(&ctx, &url, &upload))
                .await
                .map_err(|_| DriveError::UploadOutcomeUnknown)?;
        }
        let response = self
            .execute_with_retry(
                "POST",
                url.as_str(),
                None,
                GoogleResponseMode::Json,
                false,
                Some(&upload),
            )
            .await
            .map_err(upload_error)?;
        let file: DriveFile = decode_json_response(response).map_err(upload_error)?;
        if file.id.trim().is_empty() {
            return Err(DriveError::UploadOutcomeUnknown);
        }
        Ok(file)
    }

    async fn upload_resumable(
        &self,
        ctx: &fcp_async_core::ExecutionContext,
        upload_url: &Url,
        upload: &GoogleUploadPayload,
    ) -> DriveResult<DriveFile> {
        let initiation = self
            .execute_with_retry(
                "POST",
                upload_url.as_str(),
                None,
                GoogleResponseMode::Json,
                false,
                Some(upload),
            )
            .await
            .map_err(upload_error)?;
        if initiation.status_code != 200 {
            return Err(DriveError::UploadOutcomeUnknown);
        }
        let location =
            resumable_header(&initiation, "location")?.ok_or(DriveError::UploadOutcomeUnknown)?;
        let mut session_url = validate_resumable_session_url(location, upload_url)?;
        let total = upload.bytes.len();
        let mut offset = 0usize;
        let mut sent_until = 0usize;
        let mut probe = false;
        let mut recoveries = 0u32;

        for _ in 0..MAX_RESUMABLE_REQUESTS {
            let (content_range, body) = if probe || offset == total {
                probe = true;
                (format!("bytes */{total}"), Vec::new())
            } else {
                let end = offset.saturating_add(RESUMABLE_CHUNK_BYTES).min(total);
                sent_until = sent_until.max(end);
                (
                    format!("bytes {offset}-{}/{total}", end - 1),
                    upload.bytes[offset..end].to_vec(),
                )
            };
            let timeout = ctx
                .remaining_budget()
                .unwrap_or(RESUMABLE_TIMEOUT)
                .min(Duration::from_secs(30));
            if timeout.is_zero() {
                return Err(DriveError::UploadOutcomeUnknown);
            }
            self.total_requests.fetch_add(1, Ordering::Relaxed);
            debug!(offset, total, probe, "drive resumable upload request");
            let result = self
                .upload_executor
                .execute_resumable_put(
                    &session_url,
                    &self.auth,
                    &content_range,
                    body,
                    MAX_UPLOAD_RESPONSE_BYTES,
                    timeout,
                )
                .await
                .map_err(map_resumable_error);
            match result {
                Ok(response) if response.status_code == 308 => {
                    if let Some(location) = resumable_header(&response, "location")? {
                        session_url = validate_resumable_session_url(location, upload_url)?;
                    }
                    let received =
                        resumable_received_bytes(resumable_header(&response, "range")?, total)?;
                    if received < offset || received > sent_until {
                        return Err(DriveError::UploadOutcomeUnknown);
                    }
                    if received == offset && (!probe || received == total) {
                        recoveries += 1;
                        self.wait_for_upload_recovery(ctx, recoveries, None).await?;
                    }
                    offset = received;
                    probe = offset == total;
                }
                Ok(response) if matches!(response.status_code, 200 | 201) => {
                    if sent_until != total {
                        return Err(DriveError::UploadOutcomeUnknown);
                    }
                    if let Ok(file) = decode_json_response::<DriveFile>(response)
                        && !file.id.trim().is_empty()
                    {
                        return Ok(file);
                    }
                    // A lost/malformed final response is reconciled using the
                    // same session, never by creating another file.
                    recoveries += 1;
                    self.wait_for_upload_recovery(ctx, recoveries, None).await?;
                    probe = true;
                }
                Ok(_) => return Err(DriveError::UploadOutcomeUnknown),
                Err(error) if resumable_error_can_be_reconciled(&error) => {
                    recoveries += 1;
                    self.wait_for_upload_recovery(ctx, recoveries, error.retry_after())
                        .await?;
                    probe = true;
                }
                Err(_) if probe && sent_until == total => {
                    return Err(DriveError::UploadOutcomeUnknown);
                }
                Err(error) => return Err(error),
            }
        }
        Err(DriveError::UploadOutcomeUnknown)
    }

    async fn wait_for_upload_recovery(
        &self,
        ctx: &fcp_async_core::ExecutionContext,
        recoveries: u32,
        retry_after: Option<Duration>,
    ) -> DriveResult<()> {
        if recoveries > MAX_RESUMABLE_RECOVERIES {
            return Err(DriveError::UploadOutcomeUnknown);
        }
        let delay = retry_after.unwrap_or_else(|| {
            Duration::from_millis(
                self.retry_config
                    .initial_delay_ms
                    .saturating_mul(1u64 << (recoveries - 1))
                    .min(self.retry_config.max_delay_ms),
            )
        });
        ctx.sleep(delay)
            .await
            .map_err(|_| DriveError::UploadOutcomeUnknown)
    }

    /// Download a file's content as bytes (returned as base64).
    pub async fn download_file(&self, file_id: &str) -> DriveResult<String> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?alt=media",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let response = self
            .execute_with_retry("GET", &url, None, GoogleResponseMode::Binary, true, None)
            .await?;
        match response.body {
            GoogleResponseBody::Binary(bytes) => Ok(base64_encode(&bytes)),
            GoogleResponseBody::Json(value) => Ok(value.to_string()),
            GoogleResponseBody::Empty => Ok(String::new()),
        }
    }

    /// Trash a file (move to trash).
    pub async fn trash_file(&self, file_id: &str) -> DriveResult<DriveFile> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}?fields=id,name,trashed",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let body = serde_json::json!({ "trashed": true });
        self.patch_json(&url, &body).await
    }

    /// Share a file with a user.
    pub async fn share_file(
        &self,
        file_id: &str,
        email: &str,
        role: &str,
    ) -> DriveResult<DrivePermission> {
        let file_id = sanitize_path_segment(file_id, "file_id")?;
        let url = format!(
            "{}/files/{}/permissions",
            self.base_url,
            urlencoding::encode(file_id),
        );
        let body = serde_json::json!({
            "type": "user",
            "role": role,
            "emailAddress": email,
        });
        self.post_json(&url, &body).await
    }

    /// Get Drive storage quota and user info.
    pub async fn about(&self) -> DriveResult<AboutResponse> {
        let url = format!("{}/about?fields=kind,user,storageQuota", self.base_url);
        self.get_json(&url).await
    }

    /// Health check via about endpoint.
    pub async fn health_check(&self) -> DriveResult<()> {
        let _about = self.about().await?;
        Ok(())
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> DriveResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true, None)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry(
                "POST",
                url,
                Some(body),
                GoogleResponseMode::Json,
                false,
                None,
            )
            .await?;
        decode_json_response(response)
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DriveResult<T> {
        let response = self
            .execute_with_retry(
                "PATCH",
                url,
                Some(body),
                GoogleResponseMode::Json,
                true,
                None,
            )
            .await?;
        decode_json_response(response)
    }

    /// Execute with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It is a parameter rather than a function of
    /// `http_method` because Google models several state changes — and some
    /// pure reads — as POSTs, so the verb alone decides nothing.
    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
        upload: Option<&GoogleUploadPayload>,
    ) -> DriveResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "drive request");

            match self
                .execute_once(http_method, url, body, response_mode, upload)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    // A rate limit was refused WITHOUT performing the work, so
                    // it stays retryable; a 5xx means Google received the
                    // request and may already have done it.
                    let replayable = replay_safe || error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        http_method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        upload: Option<&GoogleUploadPayload>,
    ) -> DriveResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| DriveError::Api {
            status_code: 400,
            message: format!("invalid request url: {error}"),
        })?;

        let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in parsed_url.query_pairs() {
            parameters
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }

        let method_parameters = parameters
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    DiscoveryParameter {
                        location: Some("query".to_string()),
                        required: false,
                        repeated: true,
                        type_name: Some("string".to_string()),
                        format: None,
                        description: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let path = parsed_url.path().trim_start_matches('/').to_string();
        let method = DiscoveryMethod {
            key: format!("drive.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("drive.transport.{}", http_method.to_ascii_lowercase()),
            http_method: http_method.to_string(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path.clone(),
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: http_method == "GET",
            supports_media_upload: upload.is_some(),
            media_upload: upload.map(|_| DiscoveryMediaUpload {
                accept: vec!["*/*".to_string()],
                max_size: Some(MAX_UPLOAD_BYTES.to_string()),
                simple_path: Some(path.clone()),
                resumable_path: Some(path),
            }),
        };

        let schemas = BTreeMap::new();
        let mut base_url = parsed_url.origin().ascii_serialization();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }

        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.parameters = parameters;
        request.body = body.cloned();
        request.upload = upload.cloned();
        request.response_mode = response_mode;
        request.auth = Some(&self.auth);

        if upload.is_some() {
            self.upload_executor
                .execute_bounded(&request, MAX_UPLOAD_RESPONSE_BYTES)
                .await
                .map_err(map_rest_error)
        } else {
            self.executor
                .execute(&request)
                .await
                .map_err(map_rest_error)
        }
    }
}

/// Validate before any provider request; shared with invoke/simulate preflight.
pub(crate) fn validate_upload_input(
    name: &str,
    mime_type: &str,
    parent_id: Option<&str>,
    content_base64: &str,
) -> DriveResult<GoogleUploadPayload> {
    let invalid = |message: &str| DriveError::InvalidInput {
        message: message.to_string(),
    };
    if name.trim().is_empty() {
        return Err(invalid("name must not be empty"));
    }
    if parent_id.is_some_and(|parent| parent.trim().is_empty()) {
        return Err(invalid("parent_id must not be empty when provided"));
    }
    if name
        .len()
        .saturating_add(parent_id.map_or(0, str::len))
        .saturating_add(mime_type.len())
        > MAX_UPLOAD_METADATA_BYTES
    {
        return Err(invalid("upload metadata exceeds the 64 KiB limit"));
    }
    validate_upload_content_type(mime_type).map_err(|_| {
        invalid("mime_type must be a concrete MIME type without control characters")
    })?;
    let mut metadata = serde_json::json!({ "name": name, "mimeType": mime_type });
    if let Some(parent) = parent_id {
        metadata["parents"] = serde_json::json!([parent]);
    }
    if metadata.to_string().len() > MAX_UPLOAD_METADATA_BYTES {
        return Err(invalid("upload metadata exceeds the 64 KiB limit"));
    }
    let encoded_limit = MAX_UPLOAD_BYTES.div_ceil(3) * 4;
    if content_base64.len() > encoded_limit {
        return Err(invalid("decoded upload content must not exceed 16 MiB"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|_| invalid("content_base64 must be canonical standard padded base64"))?;
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(invalid("decoded upload content must not exceed 16 MiB"));
    }
    Ok(GoogleUploadPayload::multipart(mime_type, bytes, metadata))
}

fn validate_resumable_session_url(raw: &str, upload_url: &Url) -> DriveResult<Url> {
    let invalid = || DriveError::UploadOutcomeUnknown;
    if raw.len() > 8192 || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid());
    }
    let session = Url::parse(raw).map_err(|_| invalid())?;
    let production = upload_url.scheme() == "https"
        && upload_url.host_str() == Some("www.googleapis.com")
        && upload_url.port_or_known_default() == Some(443);
    let fixture = upload_url.scheme() == "http"
        && upload_url.host_str().is_some_and(|host| {
            let address = host
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host);
            host == "localhost"
                || address
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if (!production && !fixture)
        || session.origin() != upload_url.origin()
        || session.path() != upload_url.path()
        || !session.username().is_empty()
        || session.password().is_some()
        || session.fragment().is_some()
    {
        return Err(invalid());
    }
    let mut upload_types = 0usize;
    let mut upload_ids = 0usize;
    let mut fields = 0usize;
    for (name, value) in session.query_pairs() {
        match name.as_ref() {
            "uploadType" if value == "resumable" => upload_types += 1,
            "upload_id"
                if !value.is_empty()
                    && value.len() <= 4096
                    && !value
                        .bytes()
                        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) =>
            {
                upload_ids += 1;
            }
            "fields" if value == "id,name,mimeType,size" => fields += 1,
            _ => return Err(invalid()),
        }
    }
    if upload_types != 1 || upload_ids != 1 || fields > 1 {
        return Err(invalid());
    }
    Ok(session)
}

fn resumable_header<'a>(
    response: &'a GoogleExecuteResponse,
    name: &str,
) -> DriveResult<Option<&'a str>> {
    let mut values = response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values.next().map(|(_, value)| value.as_str());
    if values.next().is_some() {
        return Err(DriveError::UploadOutcomeUnknown);
    }
    Ok(value)
}

fn resumable_received_bytes(range: Option<&str>, total: usize) -> DriveResult<usize> {
    let Some(range) = range else {
        return Ok(0);
    };
    let end = range
        .trim()
        .strip_prefix("bytes=0-")
        .filter(|end| !end.is_empty() && end.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|end| end.parse::<usize>().ok())
        .ok_or(DriveError::UploadOutcomeUnknown)?;
    let received = end.checked_add(1).ok_or(DriveError::UploadOutcomeUnknown)?;
    if received > total {
        return Err(DriveError::UploadOutcomeUnknown);
    }
    Ok(received)
}

fn map_resumable_error(error: GoogleRestError) -> DriveError {
    if let GoogleRestError::Api { error, .. } = error {
        if error.status_code == 429
            || (error.status_code == 403
                && matches!(
                    error.reason.as_deref(),
                    Some("rateLimitExceeded" | "userRateLimitExceeded")
                ))
        {
            return DriveError::RateLimited {
                retry_after_secs: error.retry_after_ms.map_or(1, |ms| ms.div_ceil(1000)),
            };
        }
        // Provider text may contain the opaque upload URI. Keep session
        // diagnostics static rather than exposing its query or response body.
        return DriveError::Api {
            status_code: error.status_code,
            message: if matches!(error.status_code, 404 | 410) {
                "Drive upload session is unavailable or expired".into()
            } else {
                "Drive resumable upload request was rejected".into()
            },
        };
    }
    map_rest_error(error)
}

fn resumable_error_can_be_reconciled(error: &DriveError) -> bool {
    match error {
        DriveError::Http(_)
        | DriveError::Json(_)
        | DriveError::RateLimited { .. }
        | DriveError::UploadOutcomeUnknown => true,
        DriveError::Api { status_code, .. } => matches!(status_code, 0 | 408 | 500..=599),
        _ => false,
    }
}

fn upload_error(error: DriveError) -> DriveError {
    let uncertain = match &error {
        DriveError::Http(_) => !error.replay_is_safe(),
        DriveError::Json(_) => true,
        DriveError::Api { status_code, .. } => {
            matches!(status_code, 0 | 200..=299 | 408 | 500..=599)
        }
        _ => false,
    };
    if uncertain {
        DriveError::UploadOutcomeUnknown
    } else {
        error
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> DriveResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(DriveError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(DriveError::Json)
        }
        GoogleResponseBody::Empty => Err(DriveError::Api {
            status_code: response.status_code,
            message: "expected JSON response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> DriveError {
    match error {
        GoogleRestError::Http { source } => DriveError::Http(source),
        GoogleRestError::JsonDecode { source } => DriveError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        GoogleRestError::InvalidUploadContentType { .. }
        | GoogleRestError::InvalidUploadConfiguration { .. } => DriveError::InvalidInput {
            message: "invalid Drive media upload configuration".to_string(),
        },
        GoogleRestError::ResponseTooLarge { .. } => DriveError::UploadOutcomeUnknown,
        other => DriveError::Api {
            status_code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> DriveError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => DriveError::Unauthorized,
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => DriveError::RateLimited {
            retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
        },
        code if code == StatusCode::NOT_FOUND.as_u16() => DriveError::FileNotFound {
            file_id: error.message,
        },
        code if code == StatusCode::FORBIDDEN.as_u16() => DriveError::Forbidden {
            message: error.message,
        },
        code => DriveError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants that could reappear after double decoding.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DriveResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DriveError::Api {
            status_code: 400,
            message: format!("{field} must not be empty"),
        });
    }

    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%25")
    {
        return Err(DriveError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }

    Ok(value)
}

/// Fuzz-only entry points for Drive client parsers.
///
/// Exposed for the Drive path-segment fuzz target so the fuzz crate can
/// exercise the private guard before Drive file IDs enter REST URL paths.
///
/// Bead flywheel_connectors-grb4c.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Drive URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "file_id").is_ok()
    }
}

#[must_use]
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_google_discovery::auth::GoogleAuthSourceKind;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    fn upload_client(server: &MockServer) -> DriveClient {
        let mut client = DriveClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: "upload-test-token".to_string(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
        .unwrap()
        .with_base_url(&format!("{}/drive/v3", server.uri()));
        client.retry_config.initial_delay_ms = 1;
        client.retry_config.max_delay_ms = 1;
        client.retry_config.jitter_enabled = false;
        client
    }

    fn large_upload_media() -> Vec<u8> {
        (0..MAX_MULTIPART_UPLOAD_BYTES + 17)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    fn resumable_test_url(server: &MockServer) -> String {
        format!(
            "{}/upload/drive/v3/files?uploadType=resumable&upload_id=opaque-session-secret",
            server.uri()
        )
    }

    async fn mount_resumable_start(server: &MockServer, total: usize, location: &str) {
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .and(query_param("uploadType", "resumable"))
            .and(header("authorization", "Bearer upload-test-token"))
            .and(header("x-upload-content-length", total.to_string()))
            .and(header("x-upload-content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200).insert_header("location", location))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_remaining_upload_chunks(server: &MockServer, total: usize, mut offset: usize) {
        while offset < total {
            let end = (offset + RESUMABLE_CHUNK_BYTES).min(total);
            let response = if end == total {
                ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id":"uploaded-large", "name":"binary.bin", "mimeType":"application/octet-stream",
                    "size":total.to_string()
                }))
            } else {
                ResponseTemplate::new(308).insert_header("range", format!("bytes=0-{}", end - 1))
            };
            Mock::given(method("PUT"))
                .and(path("/upload/drive/v3/files"))
                .and(query_param("uploadType", "resumable"))
                .and(query_param("upload_id", "opaque-session-secret"))
                .and(header("authorization", "Bearer upload-test-token"))
                .and(header(
                    "content-range",
                    format!("bytes {offset}-{}/{total}", end - 1),
                ))
                .respond_with(response)
                .expect(1)
                .mount(server)
                .await;
            offset = end;
        }
    }

    #[test]
    fn resumable_session_urls_require_exact_trusted_origin_path_and_query() {
        let upload = Url::parse("https://www.googleapis.com/upload/drive/v3/files").unwrap();
        let valid = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret";
        assert!(validate_resumable_session_url(valid, &upload).is_ok());
        assert!(
            validate_resumable_session_url(
                &format!("{valid}&fields=id,name,mimeType,size"),
                &upload
            )
            .is_ok()
        );
        for invalid in [
            "http://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "https://www.googleapis.com.evil.example/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "https://www.googleapis.com:8443/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "https://user:secret@www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "https://www.googleapis.com/drive/v3/files?uploadType=resumable&upload_id=secret",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret#fragment",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=media&upload_id=secret",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&uploadType=media&upload_id=secret",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret&upload_id=another",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=%0Asecret",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=secret&alt=media",
            "http://127.0.0.1:9000/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
        ] {
            let error = validate_resumable_session_url(invalid, &upload).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        let fixture = Url::parse("http://127.0.0.1:9000/upload/drive/v3/files").unwrap();
        assert!(
            validate_resumable_session_url(
                "http://127.0.0.1:9000/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
                &fixture,
            )
            .is_ok()
        );
        for invalid in [
            "http://127.0.0.1:9001/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "http://localhost:9000/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
            "http://127.0.0.2:9000/upload/drive/v3/files?uploadType=resumable&upload_id=secret",
        ] {
            assert!(validate_resumable_session_url(invalid, &fixture).is_err());
        }
    }

    #[test]
    fn resumable_ranges_use_inclusive_offsets_and_reject_invalid_evidence() {
        assert_eq!(resumable_received_bytes(None, 1024).unwrap(), 0);
        assert_eq!(
            resumable_received_bytes(Some("bytes=0-0"), 1024).unwrap(),
            1
        );
        assert_eq!(
            resumable_received_bytes(Some("bytes=0-1023"), 1024).unwrap(),
            1024
        );
        for invalid in [
            "",
            "bytes=1-20",
            "bytes=0-1024",
            "bytes=0--1",
            "bytes=0-+1",
            "bytes=0-1,2-3",
            "bytes=0-NaN",
            "bytes=0-18446744073709551615",
        ] {
            assert!(
                resumable_received_bytes(Some(invalid), 1024).is_err(),
                "{invalid}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_chunks_preserve_binary_metadata_and_auth() {
        let server = MockServer::start().await;
        let media = large_upload_media();
        let total = media.len();
        mount_resumable_start(&server, total, &resumable_test_url(&server)).await;
        mount_remaining_upload_chunks(&server, total, 0).await;
        let file = upload_client(&server)
            .upload_file(
                "binary.bin",
                "application/octet-stream",
                Some("parent-folder"),
                &base64::engine::general_purpose::STANDARD.encode(&media),
            )
            .await
            .unwrap();
        assert_eq!(file.id, "uploaded-large");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1 + total.div_ceil(RESUMABLE_CHUNK_BYTES));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
            serde_json::json!({
                "name":"binary.bin", "mimeType":"application/octet-stream", "parents":["parent-folder"]
            }),
        );
        for (index, request) in requests.iter().skip(1).enumerate() {
            let start = index * RESUMABLE_CHUNK_BYTES;
            let end = (start + RESUMABLE_CHUNK_BYTES).min(total);
            assert_eq!(request.body, media[start..end]);
            assert_eq!(
                request.headers["content-length"]
                    .to_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                end - start,
            );
            if end != total {
                assert_eq!(request.body.len() % (256 * 1024), 0);
            }
            assert_eq!(
                request
                    .url
                    .query_pairs()
                    .filter(|(key, _)| key == "uploadType")
                    .count(),
                1
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_probes_after_failure_and_continues_from_actual_range() {
        let server = MockServer::start().await;
        let media = large_upload_media();
        let total = media.len();
        let received = 256 * 1024;
        mount_resumable_start(&server, total, &resumable_test_url(&server)).await;
        Mock::given(method("PUT"))
            .and(header(
                "content-range",
                format!("bytes 0-{}/{total}", RESUMABLE_CHUNK_BYTES - 1),
            ))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(header("content-range", format!("bytes */{total}")))
            .and(header("content-length", "0"))
            .and(header("authorization", "Bearer upload-test-token"))
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("range", format!("bytes=0-{}", received - 1)),
            )
            .expect(1)
            .mount(&server)
            .await;
        mount_remaining_upload_chunks(&server, total, received).await;
        let file = upload_client(&server)
            .upload_file(
                "binary.bin",
                "application/octet-stream",
                None,
                &base64::engine::general_purpose::STANDARD.encode(&media),
            )
            .await
            .unwrap();
        assert_eq!(file.id, "uploaded-large");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[1].body, media[..RESUMABLE_CHUNK_BYTES]);
        assert!(requests[2].body.is_empty());
        for (index, request) in requests.iter().skip(3).enumerate() {
            let start = received + index * RESUMABLE_CHUNK_BYTES;
            let end = (start + RESUMABLE_CHUNK_BYTES).min(total);
            assert_eq!(request.body, media[start..end]);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_rejects_untrusted_locations_and_redirects_without_leaking_auth() {
        for phase in ["initiation", "progress", "redirect"] {
            let server = MockServer::start().await;
            let untrusted = MockServer::start().await;
            let media = large_upload_media();
            let total = media.len();
            let untrusted_url = resumable_test_url(&untrusted);
            let trusted_url = resumable_test_url(&server);
            mount_resumable_start(
                &server,
                total,
                if phase == "initiation" {
                    &untrusted_url
                } else {
                    &trusted_url
                },
            )
            .await;
            if phase != "initiation" {
                Mock::given(method("PUT"))
                    .respond_with(
                        ResponseTemplate::new(if phase == "progress" { 308 } else { 307 })
                            .insert_header("location", untrusted_url.as_str())
                            .insert_header(
                                "range",
                                format!("bytes=0-{}", RESUMABLE_CHUNK_BYTES - 1),
                            ),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let error = upload_client(&server)
                .upload_file(
                    "binary.bin",
                    "application/octet-stream",
                    None,
                    &base64::engine::general_purpose::STANDARD.encode(&media),
                )
                .await
                .unwrap_err();
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("opaque-session-secret"));
            assert!(untrusted.received_requests().await.unwrap().is_empty());
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                if phase == "initiation" { 1 } else { 2 }
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_reconciles_lost_completion_and_never_restarts_an_unknown_result() {
        for (case, response) in [
            ("complete", ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":"completed-by-probe", "name":"binary.bin", "mimeType":"application/octet-stream"
            }))),
            ("expired", ResponseTemplate::new(404)),
            ("unusable", ResponseTemplate::new(200).set_body_json(serde_json::json!({"name":"no-id"}))),
        ] {
            let server = MockServer::start().await;
            let media = large_upload_media();
            let total = media.len();
            let last_offset = total / RESUMABLE_CHUNK_BYTES * RESUMABLE_CHUNK_BYTES;
            mount_resumable_start(&server, total, &resumable_test_url(&server)).await;
            for offset in (0..last_offset).step_by(RESUMABLE_CHUNK_BYTES) {
                let end = offset + RESUMABLE_CHUNK_BYTES;
                Mock::given(method("PUT"))
                    .and(header("content-range", format!("bytes {offset}-{}/{total}", end - 1)))
                    .respond_with(ResponseTemplate::new(308).insert_header("range", format!("bytes=0-{}", end - 1)))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            Mock::given(method("PUT"))
                .and(header("content-range", format!("bytes {last_offset}-{}/{total}", total - 1)))
                .respond_with(ResponseTemplate::new(503))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(header("content-range", format!("bytes */{total}")))
                .and(header("content-length", "0"))
                .respond_with(response)
                .expect(if case == "unusable" { 3 } else { 1 })
                .mount(&server)
                .await;
            let result = upload_client(&server)
                .upload_file("binary.bin", "application/octet-stream", None, &base64::engine::general_purpose::STANDARD.encode(&media))
                .await;
            if case == "complete" {
                assert_eq!(result.unwrap().id, "completed-by-probe");
            } else {
                let error = result.unwrap_err();
                assert!(matches!(error, DriveError::UploadOutcomeUnknown));
                assert!(!error.is_retryable());
            }
            let requests = server.received_requests().await.unwrap();
            let chunk_count = total.div_ceil(RESUMABLE_CHUNK_BYTES);
            for request in requests.iter().skip(1 + chunk_count) {
                assert!(request.body.is_empty(), "completion recovery must only probe");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_recovery_budget_stops_repeated_provider_failure() {
        let server = MockServer::start().await;
        let media = large_upload_media();
        let total = media.len();
        mount_resumable_start(&server, total, &resumable_test_url(&server)).await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "error":{"message":"provider failed at opaque-session-secret"}
            })))
            .expect(4)
            .mount(&server)
            .await;
        let error = upload_client(&server)
            .upload_file(
                "binary.bin",
                "application/octet-stream",
                None,
                &base64::engine::general_purpose::STANDARD.encode(&media),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DriveError::UploadOutcomeUnknown));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("opaque-session-secret"));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[1].body, media[..RESUMABLE_CHUNK_BYTES]);
        for request in requests.iter().skip(2) {
            assert!(request.body.is_empty());
            assert_eq!(
                request.headers["content-range"].to_str().unwrap(),
                format!("bytes */{total}")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_resumable_rejects_regressing_missing_or_impossible_range() {
        for (confirmed, range) in [
            (false, Some("bytes=1-20")),
            (false, Some("bytes=0-9999999")),
            (true, Some("bytes=0-1023")),
            (true, None),
        ] {
            let server = MockServer::start().await;
            let media = large_upload_media();
            let total = media.len();
            mount_resumable_start(&server, total, &resumable_test_url(&server)).await;
            if confirmed {
                Mock::given(method("PUT"))
                    .and(header(
                        "content-range",
                        format!("bytes 0-{}/{total}", RESUMABLE_CHUNK_BYTES - 1),
                    ))
                    .respond_with(
                        ResponseTemplate::new(308).insert_header(
                            "range",
                            format!("bytes=0-{}", RESUMABLE_CHUNK_BYTES - 1),
                        ),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let offset = if confirmed { RESUMABLE_CHUNK_BYTES } else { 0 };
            let mut response = ResponseTemplate::new(308);
            if let Some(range) = range {
                response = response.insert_header("range", range);
            }
            Mock::given(method("PUT"))
                .and(header(
                    "content-range",
                    format!(
                        "bytes {offset}-{}/{total}",
                        offset + RESUMABLE_CHUNK_BYTES - 1
                    ),
                ))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let error = upload_client(&server)
                .upload_file(
                    "binary.bin",
                    "application/octet-stream",
                    None,
                    &base64::engine::general_purpose::STANDARD.encode(&media),
                )
                .await
                .unwrap_err();
            assert!(matches!(error, DriveError::UploadOutcomeUnknown));
            assert!(!error.is_retryable());
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                if confirmed { 3 } else { 2 }
            );
        }
    }

    #[test]
    fn upload_validation_decodes_canonical_base64_and_allows_empty_files() {
        let upload = validate_upload_input(
            "binary.bin",
            "application/octet-stream",
            Some("folder"),
            "AP8=",
        )
        .unwrap();
        assert_eq!(upload.bytes, [0, 255]);
        assert_eq!(
            upload.metadata.unwrap()["parents"],
            serde_json::json!(["folder"])
        );
        assert!(
            validate_upload_input("empty.txt", "text/plain", None, "")
                .unwrap()
                .bytes
                .is_empty()
        );
        for invalid in ["AP8", "AP9=", "AP8==", "AP 8=", "_w==", "@@@=", "\nAP8="] {
            assert!(
                matches!(
                    validate_upload_input("x", "text/plain", None, invalid),
                    Err(DriveError::InvalidInput { .. }),
                ),
                "accepted noncanonical base64 {invalid:?}"
            );
        }
    }

    #[test]
    fn upload_validation_enforces_media_and_serialized_metadata_limits() {
        let maximum = base64::engine::general_purpose::STANDARD.encode(vec![0; MAX_UPLOAD_BYTES]);
        assert_eq!(
            validate_upload_input("x", "text/plain", None, &maximum)
                .unwrap()
                .bytes
                .len(),
            MAX_UPLOAD_BYTES
        );
        let oversized =
            base64::engine::general_purpose::STANDARD.encode(vec![0; MAX_UPLOAD_BYTES + 1]);
        assert!(validate_upload_input("x", "text/plain", None, &oversized).is_err());
        assert!(
            validate_upload_input(
                &"\n".repeat(MAX_UPLOAD_METADATA_BYTES / 2),
                "text/plain",
                None,
                ""
            )
            .is_err()
        );
        assert!(validate_upload_input("", "text/plain", None, "").is_err());
        assert!(validate_upload_input("x", "text/plain", Some(" "), "").is_err());
        assert!(validate_upload_input("x", "text/plain\r\nX-Injected: yes", None, "").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn upload_sends_empty_media_to_upload_endpoint_without_parent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .and(query_param("uploadType", "multipart"))
            .and(query_param("fields", "id,name,mimeType,size"))
            .and(header("authorization", "Bearer upload-test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "empty-file", "name": "empty.txt", "mimeType": "text/plain", "size": "0"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = upload_client(&server);
        let file = client
            .upload_file("empty.txt", "text/plain", None, "")
            .await
            .unwrap();
        assert_eq!(file.id, "empty-file");
        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        assert_eq!(
            request
                .url
                .query_pairs()
                .filter(|(key, _)| key == "uploadType")
                .count(),
            1
        );
        let content_type = request
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        let boundary = content_type
            .strip_prefix("multipart/related; boundary=")
            .unwrap();
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(body.contains("\"name\":\"empty.txt\""));
        assert!(!body.contains("\"parents\""));
        assert!(body.ends_with(&format!(
            "Content-Type: text/plain\r\n\r\n\r\n--{boundary}--\r\n"
        )));
        assert_eq!(
            request
                .headers
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            request.body.len()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn upload_rejects_invalid_payload_before_sending() {
        let server = MockServer::start().await;
        let client = upload_client(&server);
        assert!(matches!(
            client
                .upload_file("x", "text/plain", None, "not base64")
                .await,
            Err(DriveError::InvalidInput { .. })
        ));
        assert!(matches!(
            client
                .upload_file("x", "text/plain\r\nX-Bad: yes", None, "eA==")
                .await,
            Err(DriveError::InvalidInput { .. })
        ));
        assert_eq!(client.total_requests(), 0);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn upload_does_not_retry_ambiguous_server_failures_or_unusable_successes() {
        for response in [
            ResponseTemplate::new(503)
                .set_body_json(serde_json::json!({"error":{"message":"provider failed"}})),
            ResponseTemplate::new(200).set_body_string("invalid json"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"name":"missing-file-id"})),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":"", "name":"x", "mimeType":"text/plain"
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":" \t ", "name":"x", "mimeType":"text/plain"
            })),
            ResponseTemplate::new(200),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/upload/drive/v3/files"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let error = upload_client(&server)
                .upload_file("x", "text/plain", None, "eA==")
                .await
                .unwrap_err();
            assert!(matches!(error, DriveError::UploadOutcomeUnknown));
            assert!(!error.is_retryable());
            assert!(matches!(
                error.to_fcp_error(),
                fcp_core::FcpError::External {
                    retryable: false,
                    ..
                }
            ));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn upload_retries_a_confirmed_rate_limit_with_identical_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":"after-limit", "name":"x", "mimeType":"text/plain"
            })))
            .expect(1)
            .with_priority(2)
            .mount(&server)
            .await;
        let file = upload_client(&server)
            .upload_file("x", "text/plain", None, "eA==")
            .await
            .unwrap();
        assert_eq!(file.id, "after-limit");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
    }

    #[fcp_async_core::runtime::test]
    async fn upload_does_not_follow_redirects_while_downloads_still_do() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files/download-file"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer upload-test-token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/media/download-file", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/media/download-file"))
            .and(header("authorization", "Bearer upload-test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("redirected download"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/redirected", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/redirected"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let client = upload_client(&server);
        assert_eq!(
            client.download_file("download-file").await.unwrap(),
            base64::engine::general_purpose::STANDARD.encode(b"redirected download"),
        );
        assert!(matches!(
            client.upload_file("x", "text/plain", None, "eA==").await,
            Err(DriveError::Api {
                status_code: 307,
                ..
            }),
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "file_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "file_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "file_id").is_err());
        assert!(sanitize_path_segment("file?alt=media", "file_id").is_err());
        assert!(sanitize_path_segment("file#frag", "file_id").is_err());
        assert!(sanitize_path_segment("file%3Falt=media", "file_id").is_err());
        assert!(sanitize_path_segment("file%23frag", "file_id").is_err());
        assert!(sanitize_path_segment("", "file_id").is_err());
        assert!(sanitize_path_segment("  ", "file_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        assert!(sanitize_path_segment("foo%252Fbar", "file_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "file_id").is_err());
        assert!(sanitize_path_segment("file%2523frag", "file_id").is_err());
        assert!(sanitize_path_segment("file%2523FRAG", "file_id").is_err());
        assert!(sanitize_path_segment("foo%25", "file_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert!(matches!(
            sanitize_path_segment("1AbC_def-123", "file_id"),
            Ok("1AbC_def-123")
        ));
        assert!(matches!(
            sanitize_path_segment("drive.file.id", "file_id"),
            Ok("drive.file.id")
        ));
    }
}

/// Simple URL encoding helper.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}
