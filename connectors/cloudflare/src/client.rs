use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use chrono::{DateTime, Utc};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, RequestBuilder, header::HeaderMap};
use serde_json::json;
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{CloudflareError, CloudflareResult};
use crate::types::{
    CloudflareAuth, CloudflareResponse, CreateDnsRecord, DnsRecord, PagesDeployment, PagesProject,
    UpdateDnsRecord, VerifyToken, Worker, WorkerScript, Zone,
};

const MAX_RETRY_AFTER_SECS: u64 = 300;
const MAX_ERROR_MESSAGE_CHARS: usize = 512;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> CloudflareResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CloudflareError::InvalidInput(format!(
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
        return Err(CloudflareError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Validate and percent-encode a KV key for use in a URL path.
///
/// KV keys can contain `/` and other special characters in their logical name,
/// but they must be percent-encoded when placed in the URL path so the HTTP
/// server treats them as a single path segment.
fn encode_kv_key(value: &str, field: &str) -> CloudflareResult<String> {
    if value.trim().is_empty() {
        return Err(CloudflareError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('\\') || value.contains("..") || lower.contains("%5c") {
        return Err(CloudflareError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(utf8_percent_encode(value, NON_ALPHANUMERIC).to_string())
}

/// Cloudflare API client with retry support.
pub struct CloudflareClient {
    client: Client,
    base_url: String,
    auth: CloudflareAuth,
    account_id: String,
    retry_config: HttpRetryConfig,
    timeout: Duration,
}

impl std::fmt::Debug for CloudflareClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("account_id", &self.account_id)
            .field("retry_config", &self.retry_config)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl CloudflareClient {
    /// Create a Cloudflare API client.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError::Http`] if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        auth: CloudflareAuth,
        account_id: &str,
        retry_config: HttpRetryConfig,
        timeout: Duration,
    ) -> CloudflareResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(CloudflareError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            account_id: account_id.to_string(),
            retry_config,
            timeout,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // ── Health check ──

    /// Verify the configured token as a health check.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on transport failure or a non-2xx response.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> CloudflareResult<VerifyToken> {
        let url = format!("{}/user/tokens/verify", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Verifying Cloudflare token");
                let req = authenticate_request(client.get(&url), &auth);
                handle_response::<VerifyToken>(req, attempt, true).await
            }
        })
        .await
    }

    // ── Zones ──

    /// List zones for the account.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on transport failure or a non-2xx response.
    pub async fn list_zones(&self, runtime: &ConnectorRuntime) -> CloudflareResult<Vec<Zone>> {
        let url = format!("{}/zones", self.base_url);
        self.get_list(runtime, &url).await
    }

    // ── DNS ──

    /// List DNS records for a zone.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn list_dns_records(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
    ) -> CloudflareResult<Vec<DnsRecord>> {
        let zone_id = sanitize_path_segment(zone_id, "zone_id")?;
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        self.get_list(runtime, &url).await
    }

    /// Create a DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record: &CreateDnsRecord,
    ) -> CloudflareResult<DnsRecord> {
        let zone_id = sanitize_path_segment(zone_id, "zone_id")?;
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        self.post_json(
            runtime,
            &url,
            &serde_json::to_value(record).map_err(CloudflareError::Json)?,
        )
        .await
    }

    /// Update a DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn update_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record_id: &str,
        record: &UpdateDnsRecord,
    ) -> CloudflareResult<DnsRecord> {
        let zone_id = sanitize_path_segment(zone_id, "zone_id")?;
        let record_id = sanitize_path_segment(record_id, "record_id")?;
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        self.put_json(
            runtime,
            &url,
            &serde_json::to_value(record).map_err(CloudflareError::Json)?,
        )
        .await
    }

    /// Delete a DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn delete_dns_record(
        &self,
        runtime: &ConnectorRuntime,
        zone_id: &str,
        record_id: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let zone_id = sanitize_path_segment(zone_id, "zone_id")?;
        let record_id = sanitize_path_segment(record_id, "record_id")?;
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        self.delete(runtime, &url).await
    }

    // ── Workers ──

    /// List Workers scripts.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on transport failure or a non-2xx response.
    pub async fn list_workers(&self, runtime: &ConnectorRuntime) -> CloudflareResult<Vec<Worker>> {
        let url = format!(
            "{}/accounts/{}/workers/scripts",
            self.base_url, self.account_id
        );
        self.get_list(runtime, &url).await
    }

    /// Fetch a Worker script.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
    ) -> CloudflareResult<WorkerScript> {
        let script_name = sanitize_path_segment(script_name, "script_name")?;
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        self.get_single(runtime, &url).await
    }

    /// Deploy a Worker script.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn deploy_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
        script_content: &str,
    ) -> CloudflareResult<WorkerScript> {
        let script_name = sanitize_path_segment(script_name, "script_name")?;
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let content = script_content.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = content.clone();
            async move {
                debug!(attempt, script_name, "Deploying worker");
                let req = authenticate_request(client.put(&url), &auth)
                    .header("Content-Type", "application/javascript")
                    .body(body);
                handle_response::<WorkerScript>(req, attempt, true).await
            }
        })
        .await
    }

    /// Delete a Worker script.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn delete_worker(
        &self,
        runtime: &ConnectorRuntime,
        script_name: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let script_name = sanitize_path_segment(script_name, "script_name")?;
        let url = format!(
            "{}/accounts/{}/workers/scripts/{script_name}",
            self.base_url, self.account_id
        );
        self.delete(runtime, &url).await
    }

    // ── Pages ──

    /// List Pages projects.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn list_pages_projects(
        &self,
        runtime: &ConnectorRuntime,
    ) -> CloudflareResult<Vec<PagesProject>> {
        let url = format!(
            "{}/accounts/{}/pages/projects",
            self.base_url, self.account_id
        );
        self.get_list(runtime, &url).await
    }

    /// Create a Pages deployment.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_pages_deployment(
        &self,
        runtime: &ConnectorRuntime,
        project_name: &str,
        branch: &str,
    ) -> CloudflareResult<PagesDeployment> {
        let project_name = sanitize_path_segment(project_name, "project_name")?;
        let url = format!(
            "{}/accounts/{}/pages/projects/{project_name}/deployments",
            self.base_url, self.account_id
        );
        let body = json!({ "branch": branch });
        self.post_json(runtime, &url, &body).await
    }

    // ── KV ──

    /// Read a key from a KV namespace.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn kv_get(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
    ) -> CloudflareResult<String> {
        let namespace_id = sanitize_path_segment(namespace_id, "namespace_id")?;
        let key = encode_kv_key(key, "key")?;
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let key_log = key.to_owned();
        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let key_log = key_log.clone();
            async move {
                debug!(attempt, key = %key_log, "KV get");
                let req = authenticate_request(client.get(&url), &auth);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: CloudflareError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<String>(status, resp.headers()) {
                    return outcome;
                }
                match resp.text().await {
                    Ok(text) => AttemptOutcome::Success(text),
                    Err(e) => AttemptOutcome::Terminal(CloudflareError::Http(e)),
                }
            }
        })
        .await
    }

    /// Write a key to a KV namespace.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn kv_put(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
        value: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let namespace_id = sanitize_path_segment(namespace_id, "namespace_id")?;
        let key = encode_kv_key(key, "key")?;
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let val = value.to_owned();
        let key_log = key.to_owned();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = val.clone();
            let key_log = key_log.clone();
            async move {
                debug!(attempt, key = %key_log, "KV put");
                let req = authenticate_request(client.put(&url), &auth).body(body);
                handle_response::<serde_json::Value>(req, attempt, true).await
            }
        })
        .await
    }

    /// Delete a key from a KV namespace.
    ///
    /// # Errors
    ///
    /// Returns [`CloudflareError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn kv_delete(
        &self,
        runtime: &ConnectorRuntime,
        namespace_id: &str,
        key: &str,
    ) -> CloudflareResult<serde_json::Value> {
        let namespace_id = sanitize_path_segment(namespace_id, "namespace_id")?;
        let key = encode_kv_key(key, "key")?;
        let url = format!(
            "{}/accounts/{}/storage/kv/namespaces/{namespace_id}/values/{key}",
            self.base_url, self.account_id
        );
        self.delete(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_list<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<Vec<T>> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET list");
                let req = authenticate_request(client.get(&url), &auth);
                handle_list_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET single");
                let req = authenticate_request(client.get(&url), &auth);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: NOT replay-safe. Every caller of this helper CREATES a
    /// resource and the provider offers no idempotency key, so a duplicate is a second DNS record.
    /// Only a connect-phase failure is retried. A converging POST added
    /// later needs its own helper rather than reusing this one.
    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CloudflareResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "POST");
                let req = authenticate_request(client.post(&url), &auth).json(&body);
                handle_response::<T>(req, attempt, false).await
            }
        })
        .await
    }

    async fn put_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CloudflareResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "PUT");
                let req = authenticate_request(client.put(&url), &auth).json(&body);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CloudflareResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "DELETE");
                let req = authenticate_request(client.delete(&url), &auth);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }
}

// ── Free functions for request handling ──

fn authenticate_request(req: RequestBuilder, auth: &CloudflareAuth) -> RequestBuilder {
    match auth {
        CloudflareAuth::ApiToken { api_token } => {
            if api_token.is_empty() {
                req
            } else {
                req.bearer_auth(api_token)
            }
        }
        CloudflareAuth::ApiKey { api_key, email } => {
            if api_key.is_empty() {
                req
            } else {
                req.header("X-Auth-Key", api_key.as_str())
                    .header("X-Auth-Email", email.as_str())
            }
        }
    }
}

fn check_error_status<T>(
    status: u16,
    headers: &HeaderMap,
) -> Option<AttemptOutcome<T, CloudflareError>> {
    if status == 429 {
        return Some(rate_limited_outcome(headers));
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(CloudflareError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(CloudflareError::NotFound(
            format!("Resource not found (HTTP {status})"),
        )));
    }
    None
}

/// Classify a response.
///
/// `replay_safe` gates only the post-transmission classes; the 429 arm stays
/// retryable because the provider refused the request WITHOUT performing it
/// (br-kxd3e).
async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<T, CloudflareError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(
                CloudflareError::Http(e),
                None,
                replayable,
            );
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        return rate_limited_outcome(resp.headers());
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(CloudflareError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(CloudflareError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = CloudflareError::Api {
            code: u32::from(status),
            message: sanitize_error_message(&text),
        };
        if status >= 500 {
            // A 5xx means the provider received the request and may already
            // have created the resource.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    // Parse the Cloudflare API envelope
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(CloudflareError::Http(e)),
    };

    // Try to parse as CloudflareResponse<T> first
    if let Ok(cf_resp) = serde_json::from_str::<CloudflareResponse<T>>(&text) {
        if cf_resp.success
            && let Some(result) = cf_resp.result
        {
            return AttemptOutcome::Success(result);
        }
        if !cf_resp.errors.is_empty() {
            let err = &cf_resp.errors[0];
            let cf_err = CloudflareError::Api {
                code: err.code,
                message: sanitize_error_message(&err.message),
            };
            if cf_err.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: cf_err,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(cf_err);
        }
    }

    // Fallback: try to parse as raw T
    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(CloudflareError::Json(e))
        }
    }
}

async fn handle_list_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
) -> AttemptOutcome<Vec<T>, CloudflareError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            // Read path: always retryable.
            return AttemptOutcome::Retryable {
                error: CloudflareError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        return rate_limited_outcome(resp.headers());
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(CloudflareError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = CloudflareError::Api {
            code: u32::from(status),
            message: sanitize_error_message(&text),
        };
        if status >= 500 {
            // A 5xx means the provider received the request and may already
            // have created the resource.
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(CloudflareError::Http(e)),
    };

    if let Ok(cf_resp) = serde_json::from_str::<CloudflareResponse<Vec<T>>>(&text) {
        if cf_resp.success {
            return AttemptOutcome::Success(cf_resp.result.unwrap_or_default());
        }
        if !cf_resp.errors.is_empty() {
            let err = &cf_resp.errors[0];
            return AttemptOutcome::Terminal(CloudflareError::Api {
                code: err.code,
                message: sanitize_error_message(&err.message),
            });
        }
    }

    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(CloudflareError::Json(e))
        }
    }
}

fn duration_millis_saturated(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn clamp_retry_after(duration: Duration) -> Duration {
    duration.min(Duration::from_secs(MAX_RETRY_AFTER_SECS))
}

fn parse_retry_after_value(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        let duration = Duration::from_secs(u64::try_from(seconds).unwrap_or(u64::MAX));
        return Some(clamp_retry_after(duration));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        Some(clamp_retry_after(
            wait.to_std().unwrap_or(Duration::from_secs(u64::MAX)),
        ))
    }
}

fn parse_retry_after_header(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_value)
}

fn rate_limited_outcome<T>(headers: &HeaderMap) -> AttemptOutcome<T, CloudflareError> {
    let retry_after = parse_retry_after_header(headers).unwrap_or(Duration::from_secs(30));
    AttemptOutcome::Retryable {
        error: CloudflareError::RateLimited {
            retry_after_ms: duration_millis_saturated(retry_after),
        },
        retry_after: Some(retry_after),
    }
}

fn sanitize_error_message(message: &str) -> String {
    let collapsed = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= MAX_ERROR_MESSAGE_CHARS {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4",
            CloudflareAuth::ApiToken {
                api_token: "secret-token".into(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn secretless_detection() {
        let rt = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4",
            CloudflareAuth::ApiToken {
                api_token: String::new(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4",
            CloudflareAuth::ApiToken {
                api_token: "token".into(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4/",
            CloudflareAuth::ApiToken {
                api_token: "t".into(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "zone_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "zone_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "zone_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "zone_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "zone_id").is_err());
        assert!(sanitize_path_segment("", "zone_id").is_err());
        assert!(sanitize_path_segment("  ", "zone_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("abc123", "zone_id").unwrap(),
            "abc123"
        );
        assert_eq!(
            sanitize_path_segment("zone-id-42", "zone_id").unwrap(),
            "zone-id-42"
        );
    }

    #[test]
    fn api_key_auth_secretless() {
        let rt = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4",
            CloudflareAuth::ApiKey {
                api_key: String::new(),
                email: "user@example.com".into(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(rt.is_secretless());
    }

    #[test]
    fn client_uses_configured_timeout() {
        let rt = CloudflareClient::new(
            "https://api.cloudflare.com/client/v4",
            CloudflareAuth::ApiToken {
                api_token: "token".into(),
            },
            "acc123",
            HttpRetryConfig::default(),
            Duration::from_millis(1_234),
        )
        .unwrap();
        assert_eq!(rt.timeout, Duration::from_millis(1_234));
    }

    #[test]
    fn retry_after_header_is_clamped() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "999999".parse().unwrap());
        assert_eq!(
            parse_retry_after_header(&headers),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
    }

    #[test]
    fn retry_after_header_trims_delta_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", " 7 ".parse().unwrap());

        assert_eq!(
            parse_retry_after_header(&headers),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn retry_after_header_accepts_http_date() {
        let retry_at = (Utc::now() + chrono::Duration::seconds(120))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", retry_at.parse().unwrap());

        assert!(
            matches!(
                parse_retry_after_header(&headers),
                Some(retry_after)
                    if retry_after >= Duration::from_secs(118)
                        && retry_after <= Duration::from_secs(121)
            ),
            "future HTTP-date should parse to a delay near 120 seconds"
        );
    }

    #[test]
    fn retry_after_header_clamps_http_date() {
        let retry_at = (Utc::now() + chrono::Duration::seconds(600))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", retry_at.parse().unwrap());

        assert_eq!(
            parse_retry_after_header(&headers),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
    }

    #[test]
    fn retry_after_header_past_http_date_is_zero() {
        let retry_at = (Utc::now() - chrono::Duration::seconds(30))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", retry_at.parse().unwrap());

        assert_eq!(parse_retry_after_header(&headers), Some(Duration::ZERO));
    }

    #[test]
    fn rate_limited_outcome_uses_default_retry_after_when_header_missing() {
        let headers = HeaderMap::new();

        assert!(matches!(
            rate_limited_outcome::<String>(&headers),
            AttemptOutcome::Retryable {
                error: CloudflareError::RateLimited {
                    retry_after_ms: 30_000,
                },
                retry_after: Some(delay),
            } if delay == Duration::from_secs(30)
        ));
    }

    #[test]
    fn sanitize_error_message_truncates_and_collapses_whitespace() {
        let msg = format!("{}\n{}", "x".repeat(MAX_ERROR_MESSAGE_CHARS + 10), "tail");
        let sanitized = sanitize_error_message(&msg);
        assert!(sanitized.len() <= MAX_ERROR_MESSAGE_CHARS);
        assert!(!sanitized.contains('\n'));
    }
}
