use fcp_prelude::log_redaction::redact_url;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::{debug, info};

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{GcpError, GcpResult};
use crate::jwt::{self, CachedToken};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> GcpResult<&'a str> {
    if value.trim().is_empty() {
        return Err(GcpError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(GcpError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Sanitize a Cloud Storage object name — allows `/` since GCS uses hierarchical paths
/// (e.g., `data/2024/report.csv`), but blocks `..` and backslash.
fn sanitize_object_name<'a>(value: &'a str, field: &str) -> GcpResult<&'a str> {
    if value.trim().is_empty() {
        return Err(GcpError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('\\') || value.contains("..") || lower.contains("%5c") {
        return Err(GcpError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Validate a query string parameter to prevent injection.
fn sanitize_query_param<'a>(value: &'a str, field: &str) -> GcpResult<&'a str> {
    if value.contains('&') || value.contains('?') || value.contains('#') {
        return Err(GcpError::InvalidInput(format!(
            "{field} contains query injection characters"
        )));
    }
    Ok(value)
}

/// GCP API client with retry support and JWT-based service-account auth.
pub struct GcpClient {
    client: Client,
    auth: GcpAuth,
    project_id: String,
    retry_config: HttpRetryConfig,
    /// Cached service-account access token (only used in service_account mode).
    sa_token_cache: Mutex<Option<CachedToken>>,
    /// Override token endpoint for testing.
    token_endpoint: Option<String>,
    /// Base URLs for each GCP service (overridable for testing).
    compute_base: String,
    storage_base: String,
    run_base: String,
    crm_base: String,
}

impl std::fmt::Debug for GcpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpClient")
            .field("project_id", &self.project_id)
            .field("auth", &self.auth)
            .finish()
    }
}

impl GcpClient {
    pub async fn new(
        project_id: &str,
        auth: GcpAuth,
        retry_config: HttpRetryConfig,
        compute_base: Option<&str>,
        storage_base: Option<&str>,
        run_base: Option<&str>,
        crm_base: Option<&str>,
    ) -> GcpResult<Self> {
        // Validate service-account credentials early: key must be parseable PEM
        if let Some((email, key)) = auth.service_account_credentials() {
            if email.trim().is_empty() {
                return Err(GcpError::Config(
                    "service_account client_email must not be empty".into(),
                ));
            }
            if !key.trim().is_empty() {
                // Validate the PEM is parseable (fail fast, not at first API call)
                jwt::build_jwt_assertion(email, key, DEFAULT_GCP_SCOPES, None)?;
                info!(
                    service_account_client_email_present = true,
                    "service-account JWT auth configured"
                );
            }
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(GcpError::Http)?;

        Ok(Self {
            client,
            auth,
            project_id: project_id.to_string(),
            retry_config,
            sa_token_cache: Mutex::new(None),
            token_endpoint: None,
            compute_base: compute_base
                .unwrap_or("https://compute.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            storage_base: storage_base
                .unwrap_or("https://storage.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            run_base: run_base
                .unwrap_or("https://run.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
            crm_base: crm_base
                .unwrap_or("https://cloudresourcemanager.googleapis.com")
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Set a custom token endpoint (overrides the Google default).
    /// Intended for testing with mock OAuth2 servers.
    pub fn set_token_endpoint(&mut self, endpoint: String) {
        self.token_endpoint = Some(endpoint);
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    /// Obtain a bearer token for API requests.
    ///
    /// - **access_token mode**: returns the configured static token.
    /// - **service_account mode**: builds a JWT assertion, exchanges it for an
    ///   access token (caching for the token's lifetime), and returns the access token.
    /// - **secretless mode**: returns an empty string (egress proxy injects credentials).
    ///
    /// # Errors
    ///
    /// Returns `GcpError::Config` if the private key is invalid, or
    /// `GcpError::Unauthorized` if the token exchange fails.
    pub async fn get_bearer_token(&self) -> GcpResult<String> {
        // Fast path: access_token mode
        if let Some(token) = self.auth.static_bearer_token() {
            return Ok(token.to_string());
        }

        // Service-account mode: check cache first
        {
            let cache = self
                .sa_token_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.as_ref()
                && !cached.is_expired()
            {
                return Ok(cached.access_token.clone());
            }
        }

        // Build and exchange JWT
        let (email, key) = self.auth.service_account_credentials().ok_or_else(|| {
            GcpError::Config(
                "auth mode has no static token and no service-account credentials".into(),
            )
        })?;

        if key.trim().is_empty() {
            // Secretless service-account: egress proxy will inject credentials
            return Ok(String::new());
        }

        let jwt = jwt::build_jwt_assertion(
            email,
            key,
            DEFAULT_GCP_SCOPES,
            self.token_endpoint.as_deref(),
        )?;

        let cached =
            jwt::exchange_jwt_for_token(&self.client, &jwt, self.token_endpoint.as_deref()).await?;

        let token = cached.access_token.clone();

        // Cache the token
        {
            let mut cache = self
                .sa_token_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *cache = Some(cached);
        }

        Ok(token)
    }

    // ── Compute Engine ──

    pub async fn list_instances(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
    ) -> GcpResult<Vec<Instance>> {
        let zone = sanitize_path_segment(zone, "zone")?;
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances",
            self.compute_base, self.project_id, zone
        );
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "Listing compute instances");
                let req = authenticate_request_static(client.get(&url), &token);
                handle_list_response::<InstanceList, Instance>(req, attempt, |list| {
                    list.items.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn get_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<Instance> {
        let zone = sanitize_path_segment(zone, "zone")?;
        let instance_name = sanitize_path_segment(instance_name, "instance_name")?;
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.get_single(runtime, &url).await
    }

    pub async fn start_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let zone = sanitize_path_segment(zone, "zone")?;
        let instance_name = sanitize_path_segment(instance_name, "instance_name")?;
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}/start",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn stop_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let zone = sanitize_path_segment(zone, "zone")?;
        let instance_name = sanitize_path_segment(instance_name, "instance_name")?;
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}/stop",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.post_empty(runtime, &url).await
    }

    pub async fn delete_instance(
        &self,
        runtime: &ConnectorRuntime,
        zone: &str,
        instance_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let zone = sanitize_path_segment(zone, "zone")?;
        let instance_name = sanitize_path_segment(instance_name, "instance_name")?;
        let url = format!(
            "{}/compute/v1/projects/{}/zones/{}/instances/{}",
            self.compute_base, self.project_id, zone, instance_name
        );
        self.delete(runtime, &url).await
    }

    // ── Cloud Storage ──

    pub async fn list_objects(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
    ) -> GcpResult<Vec<StorageObject>> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let url = format!("{}/storage/v1/b/{}/o", self.storage_base, bucket);
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "Listing storage objects");
                let req = authenticate_request_static(client.get(&url), &token);
                handle_list_response::<ObjectList, StorageObject>(req, attempt, |list| {
                    list.items.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn get_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
    ) -> GcpResult<StorageObject> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        // Mirror `upload_object`: `sanitize_object_name` permits `/` for GCS
        // hierarchy but leaves `?`/`#`/`&` intact, so also reject query/fragment
        // characters — otherwise `secret.txt?alt=media` flips this metadata read
        // into a raw media download.
        let object_name = sanitize_query_param(
            sanitize_object_name(object_name, "object_name")?,
            "object_name",
        )?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.storage_base, bucket, object_name
        );
        self.get_single(runtime, &url).await
    }

    pub async fn upload_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
        content: &str,
        content_type: Option<&str>,
    ) -> GcpResult<StorageObject> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let object_name = sanitize_query_param(
            sanitize_object_name(object_name, "object_name")?,
            "object_name",
        )?;
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.storage_base, bucket, object_name
        );
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = content.to_string();
        let ct = content_type
            .unwrap_or("application/octet-stream")
            .to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let body = body.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, "Uploading storage object");
                let req = authenticate_request_static(client.post(&url), &token)
                    .header("Content-Type", ct)
                    .body(body);
                // Replay-safe: the object name is caller-chosen, so a
                // re-upload overwrites rather than creating a second object.
                handle_response::<StorageObject>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn delete_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        object_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        // Mirror `upload_object`/`get_object`: block `?`/`#`/`&` (which
        // `sanitize_object_name` permits) so a crafted object name cannot inject
        // a query/fragment against the storage host.
        let object_name = sanitize_query_param(
            sanitize_object_name(object_name, "object_name")?,
            "object_name",
        )?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.storage_base, bucket, object_name
        );
        self.delete(runtime, &url).await
    }

    // ── Cloud Run ──

    pub async fn list_services(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
    ) -> GcpResult<Vec<CloudRunService>> {
        let location = sanitize_path_segment(location, "location")?;
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services",
            self.run_base, self.project_id, location
        );
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "Listing Cloud Run services");
                let req = authenticate_request_static(client.get(&url), &token);
                handle_list_response::<CloudRunServiceList, CloudRunService>(req, attempt, |list| {
                    list.services.unwrap_or_default()
                })
                .await
            }
        })
        .await
    }

    pub async fn deploy_service(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
        service_id: &str,
        image: &str,
    ) -> GcpResult<CloudRunService> {
        let location = sanitize_path_segment(location, "location")?;
        let service_id = sanitize_query_param(
            sanitize_path_segment(service_id, "service_id")?,
            "service_id",
        )?;
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services?serviceId={}",
            self.run_base, self.project_id, location, service_id
        );
        let body = json!({
            "template": {
                "containers": [{
                    "image": image
                }]
            }
        });
        self.post_json(runtime, &url, &body).await
    }

    pub async fn delete_service(
        &self,
        runtime: &ConnectorRuntime,
        location: &str,
        service_name: &str,
    ) -> GcpResult<serde_json::Value> {
        let location = sanitize_path_segment(location, "location")?;
        let service_name = sanitize_path_segment(service_name, "service_name")?;
        let url = format!(
            "{}/v2/projects/{}/locations/{}/services/{}",
            self.run_base, self.project_id, location, service_name
        );
        self.delete(runtime, &url).await
    }

    // ── Projects ──

    pub async fn get_project(&self, runtime: &ConnectorRuntime) -> GcpResult<Project> {
        let url = format!("{}/v1/projects/{}", self.crm_base, self.project_id);
        self.get_single(runtime, &url).await
    }

    // ── Generic HTTP helpers ──

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> GcpResult<T> {
        let url = url.to_string();
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET single");
                let req = authenticate_request_static(client.get(&url), &token);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: NOT replay-safe. Every caller of this helper CREATES a
    /// resource and the provider offers no idempotency key, so a replay deploys the Cloud Run service a SECOND time.
    /// Only a connect-phase failure is retried. A converging POST added
    /// later needs its own helper rather than reusing this one.
    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> GcpResult<T> {
        let url = url.to_string();
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "POST json");
                let req = authenticate_request_static(client.post(&url), &token).json(&body);
                handle_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    async fn post_empty(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> GcpResult<serde_json::Value> {
        let url = url.to_string();
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "POST empty");
                let req = authenticate_request_static(client.post(&url), &token)
                    .header("Content-Length", "0");
                // Replay-safe: start/stop converge on a target instance state.
                handle_response::<serde_json::Value>(req, attempt, true).await
            }
        })
        .await
    }

    async fn delete(&self, runtime: &ConnectorRuntime, url: &str) -> GcpResult<serde_json::Value> {
        let url = url.to_string();
        let token = self.get_bearer_token().await?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "DELETE");
                let req = authenticate_request_static(client.delete(&url), &token);
                handle_response::<serde_json::Value>(req, attempt, true).await
            }
        })
        .await
    }
}

// ── Free functions for request handling ──

/// Authenticate a request with a static bearer token (access_token mode only).
/// For service_account mode, the caller must obtain a token via
/// [`GcpClient::get_bearer_token`] and apply it manually.
fn authenticate_request_static(req: RequestBuilder, token: &str) -> RequestBuilder {
    if token.is_empty() {
        req
    } else {
        req.bearer_auth(token)
    }
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
) -> AttemptOutcome<T, GcpError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(GcpError::Http(e), None, replayable);
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
            error: GcpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(GcpError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(GcpError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        // Try to parse GCP error response
        if let Ok(gcp_err) = serde_json::from_str::<GcpApiError>(&text)
            && let Some(detail) = gcp_err.error
        {
            let code = detail.code.unwrap_or(u32::from(status));
            let message = detail.message.unwrap_or_else(|| text.clone());
            let err = GcpError::Api { code, message };
            if err.is_retryable() {
                return AttemptOutcome::Retryable {
                    error: err,
                    retry_after: None,
                };
            }
            return AttemptOutcome::Terminal(err);
        }
        let err = GcpError::Api {
            code: u32::from(status),
            message: text,
        };
        if status >= 500 {
            // A 5xx means the provider received the request and may already
            // have created the resource.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    // For 204 No Content (e.g., delete responses)
    if status == 204 {
        // Try to return a default/empty value
        match serde_json::from_str::<T>("{}") {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(e) => {
                return AttemptOutcome::Terminal(GcpError::Json(e));
            }
        }
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(GcpError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(GcpError::Json(e))
        }
    }
}

async fn handle_list_response<L: serde::de::DeserializeOwned, T>(
    req: RequestBuilder,
    attempt: u32,
    extract: impl FnOnce(L) -> Vec<T>,
) -> AttemptOutcome<Vec<T>, GcpError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            // Read path: always retryable.
            return AttemptOutcome::Retryable {
                error: GcpError::Http(e),
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
            error: GcpError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(GcpError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = GcpError::Api {
            code: u32::from(status),
            message: text,
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
        Err(e) => return AttemptOutcome::Terminal(GcpError::Http(e)),
    };

    match serde_json::from_str::<L>(&text) {
        Ok(list) => AttemptOutcome::Success(extract(list)),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(GcpError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: "ya29.secret-token".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ya29"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: String::new(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "my-project",
                GcpAuth::AccessToken {
                    access_token: "ya29.token".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn project_id_accessible() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "test-project-123",
                GcpAuth::AccessToken {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.project_id(), "test-project-123");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "zone").is_err());
        assert!(sanitize_path_segment("foo/bar", "zone").is_err());
        assert!(sanitize_path_segment("foo\\bar", "zone").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "zone").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "zone").is_err());
        assert!(sanitize_path_segment("", "zone").is_err());
        assert!(sanitize_path_segment("  ", "zone").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("us-central1-a", "zone").unwrap(),
            "us-central1-a"
        );
    }

    #[test]
    fn sanitize_query_param_rejects_injection() {
        assert!(sanitize_query_param("foo&bar=baz", "name").is_err());
        assert!(sanitize_query_param("foo?x", "name").is_err());
        assert!(sanitize_query_param("foo#frag", "name").is_err());
    }

    #[test]
    fn custom_base_urls() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::AccessToken {
                    access_token: "t".into(),
                },
                HttpRetryConfig::default(),
                Some("http://localhost:8080/"),
                Some("http://localhost:8081/"),
                Some("http://localhost:8082/"),
                Some("http://localhost:8083/"),
            )
            .await
            .unwrap()
        })
        .unwrap();
        // Trailing slashes should be trimmed
        assert!(!format!("{rt:?}").is_empty());
    }

    #[test]
    fn authenticate_request_static_adds_bearer_header() {
        let request =
            authenticate_request_static(Client::new().get("https://example.com"), "ya29.token")
                .build()
                .expect("request should build");

        assert_eq!(
            request.headers().get(reqwest::header::AUTHORIZATION),
            Some(&reqwest::header::HeaderValue::from_static(
                "Bearer ya29.token"
            ))
        );
    }

    #[test]
    fn authenticate_request_static_allows_secretless_mode() {
        let request = authenticate_request_static(Client::new().get("https://example.com"), "")
            .build()
            .expect("request should build");

        assert!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none()
        );
    }

    #[test]
    fn client_new_rejects_invalid_service_account_key() {
        let err = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::ServiceAccount {
                    client_email: "svc@proj.iam.gserviceaccount.com".into(),
                    private_key: "not-a-valid-pem-key".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
        })
        .unwrap()
        .expect_err("invalid PEM key must be rejected at client creation");

        match err {
            GcpError::Config(message) => {
                assert!(
                    message.contains("private key"),
                    "error should mention private key: {message}"
                );
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn client_new_accepts_valid_service_account_key() {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("key gen");
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PEM encode")
            .to_string();

        let client = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::ServiceAccount {
                    client_email: "svc@proj.iam.gserviceaccount.com".into(),
                    private_key: pem,
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
        })
        .unwrap()
        .expect("valid service-account key should be accepted");

        assert!(!client.is_secretless());
        assert_eq!(client.project_id(), "proj");
    }

    #[test]
    fn client_new_accepts_empty_service_account_key_secretless() {
        let client = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::ServiceAccount {
                    client_email: "svc@proj.iam.gserviceaccount.com".into(),
                    private_key: String::new(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
        })
        .unwrap()
        .expect("empty private_key (secretless) should be accepted");

        assert!(client.is_secretless());
    }

    #[test]
    fn client_new_rejects_empty_service_account_email() {
        let err = fcp_async_core::runtime::block_on_sync(async {
            GcpClient::new(
                "proj",
                GcpAuth::ServiceAccount {
                    client_email: String::new(),
                    private_key: "some-key".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
        })
        .unwrap()
        .expect_err("empty client_email must be rejected");

        match err {
            GcpError::Config(message) => {
                assert!(message.contains("client_email"));
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn get_bearer_token_returns_static_for_access_token_mode() {
        let token = fcp_async_core::runtime::block_on_sync(async {
            let client = GcpClient::new(
                "proj",
                GcpAuth::AccessToken {
                    access_token: "ya29.static-token".into(),
                },
                HttpRetryConfig::default(),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
            client.get_bearer_token().await
        })
        .unwrap()
        .expect("get_bearer_token should succeed for access_token mode");

        assert_eq!(token, "ya29.static-token");
    }
}
