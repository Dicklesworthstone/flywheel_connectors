use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};

use crate::error::{NetlifyError, NetlifyResult};
use crate::types::{
    CreateDeployRequest, CreateSiteRequest, Deploy, DnsZone, EnvVar, NetlifyAuth, SetEnvVarRequest,
    Site, User,
};

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> NetlifyResult<&'a str> {
    if value.trim().is_empty() {
        return Err(NetlifyError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    // Path segments are interpolated before the `?site_id=` query suffix, so a
    // `?`/`#`/`&` inside a segment would open the query/fragment early and
    // truncate or re-target the intended endpoint (e.g. `.../accounts/acme?x=1/env`
    // parses as `GET /accounts/acme`). Reject the query/fragment delimiters here
    // too, matching `sanitize_query_param`.
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || value.contains('&')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(NetlifyError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Validate a query string parameter to prevent injection.
fn sanitize_query_param<'a>(value: &'a str, field: &str) -> NetlifyResult<&'a str> {
    if value.contains('&') || value.contains('?') || value.contains('#') {
        return Err(NetlifyError::InvalidInput(format!(
            "{field} contains query injection characters"
        )));
    }
    Ok(value)
}

/// Netlify API client with retry support.
pub struct NetlifyClient {
    client: Client,
    base_url: String,
    auth: NetlifyAuth,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for NetlifyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetlifyClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl NetlifyClient {
    /// Create a Netlify API client for the given base URL.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError::Http`] if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        auth: NetlifyAuth,
        retry_config: HttpRetryConfig,
    ) -> NetlifyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(NetlifyError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            retry_config,
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

    // Health check

    /// Fetch the authenticated user as a lightweight health check.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on transport failure or a non-2xx response.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> NetlifyResult<User> {
        let url = format!("{}/api/v1/user", self.base_url);
        self.get_single(runtime, &url).await
    }

    // Sites

    /// List sites visible to the configured token.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on transport failure or a non-2xx response.
    pub async fn list_sites(&self, runtime: &ConnectorRuntime) -> NetlifyResult<Vec<Site>> {
        let url = format!("{}/api/v1/sites", self.base_url);
        self.get_list(runtime, &url).await
    }

    /// Fetch a single site by id.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_site(&self, runtime: &ConnectorRuntime, site_id: &str) -> NetlifyResult<Site> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let url = format!("{}/api/v1/sites/{site_id}", self.base_url);
        self.get_single(runtime, &url).await
    }

    /// Create a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_site(
        &self,
        runtime: &ConnectorRuntime,
        req: &CreateSiteRequest,
    ) -> NetlifyResult<Site> {
        let url = format!("{}/api/v1/sites", self.base_url);
        let body = serde_json::to_value(req).map_err(NetlifyError::Json)?;
        // NOT replay-safe: a duplicate is a second Netlify site.
        self.post_json(runtime, &url, &body, false).await
    }

    /// Delete a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn delete_site(
        &self,
        runtime: &ConnectorRuntime,
        site_id: &str,
    ) -> NetlifyResult<serde_json::Value> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let url = format!("{}/api/v1/sites/{site_id}", self.base_url);
        self.delete(runtime, &url).await
    }

    // Deploys

    /// List deploys for a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn list_deploys(
        &self,
        runtime: &ConnectorRuntime,
        site_id: &str,
    ) -> NetlifyResult<Vec<Deploy>> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let url = format!("{}/api/v1/sites/{site_id}/deploys", self.base_url);
        self.get_list(runtime, &url).await
    }

    /// Fetch a single deploy by id.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_deploy(
        &self,
        runtime: &ConnectorRuntime,
        site_id: &str,
        deploy_id: &str,
    ) -> NetlifyResult<Deploy> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let deploy_id = sanitize_path_segment(deploy_id, "deploy_id")?;
        let url = format!(
            "{}/api/v1/sites/{site_id}/deploys/{deploy_id}",
            self.base_url
        );
        self.get_single(runtime, &url).await
    }

    /// Create a deploy for a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_deploy(
        &self,
        runtime: &ConnectorRuntime,
        site_id: &str,
        req: &CreateDeployRequest,
    ) -> NetlifyResult<Deploy> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let url = format!("{}/api/v1/sites/{site_id}/deploys", self.base_url);
        let body = serde_json::to_value(req).map_err(NetlifyError::Json)?;
        // NOT replay-safe: a replay starts a SECOND build and ships it.
        self.post_json(runtime, &url, &body, false).await
    }

    /// Roll back a deploy.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn rollback_deploy(
        &self,
        runtime: &ConnectorRuntime,
        site_id: &str,
        deploy_id: &str,
    ) -> NetlifyResult<Deploy> {
        let site_id = sanitize_path_segment(site_id, "site_id")?;
        let deploy_id = sanitize_path_segment(deploy_id, "deploy_id")?;
        let url = format!(
            "{}/api/v1/sites/{site_id}/rollback/{deploy_id}",
            self.base_url
        );
        // Replay-safe: rollback restores a NAMED deploy, so it converges.
        self.post_json(runtime, &url, &json!({}), true).await
    }

    // DNS

    /// List DNS zones.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on transport failure or a non-2xx response.
    pub async fn list_dns_zones(&self, runtime: &ConnectorRuntime) -> NetlifyResult<Vec<DnsZone>> {
        let url = format!("{}/api/v1/dns_zones", self.base_url);
        self.get_list(runtime, &url).await
    }

    // Environment Variables

    /// List environment variables for a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn list_env_vars(
        &self,
        runtime: &ConnectorRuntime,
        account_slug: &str,
        site_id: &str,
    ) -> NetlifyResult<Vec<EnvVar>> {
        let account_slug = sanitize_path_segment(account_slug, "account_slug")?;
        let site_id = sanitize_query_param(site_id, "site_id")?;
        let url = format!(
            "{}/api/v1/accounts/{account_slug}/env?site_id={site_id}",
            self.base_url
        );
        self.get_list(runtime, &url).await
    }

    /// Set an environment variable on a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn set_env_var(
        &self,
        runtime: &ConnectorRuntime,
        account_slug: &str,
        site_id: &str,
        req: &[SetEnvVarRequest],
    ) -> NetlifyResult<Vec<EnvVar>> {
        let account_slug = sanitize_path_segment(account_slug, "account_slug")?;
        let site_id = sanitize_query_param(site_id, "site_id")?;
        let url = format!(
            "{}/api/v1/accounts/{account_slug}/env?site_id={site_id}",
            self.base_url
        );
        let body = serde_json::to_value(req).map_err(NetlifyError::Json)?;
        // Replay-safe: setting an env var to a value converges.
        self.post_json_list(runtime, &url, &body, true).await
    }

    /// Delete an environment variable from a site.
    ///
    /// # Errors
    ///
    /// Returns [`NetlifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn delete_env_var(
        &self,
        runtime: &ConnectorRuntime,
        account_slug: &str,
        site_id: &str,
        key: &str,
    ) -> NetlifyResult<serde_json::Value> {
        let account_slug = sanitize_path_segment(account_slug, "account_slug")?;
        let key = sanitize_path_segment(key, "key")?;
        let site_id = sanitize_query_param(site_id, "site_id")?;
        let url = format!(
            "{}/api/v1/accounts/{account_slug}/env/{key}?site_id={site_id}",
            self.base_url
        );
        self.delete(runtime, &url).await
    }

    // Generic HTTP helpers

    async fn get_list<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> NetlifyResult<Vec<T>> {
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
                handle_list_response::<T>(req, attempt, true).await
            }
        })
        .await
    }

    async fn get_single<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> NetlifyResult<T> {
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
    /// `replay_safe` states whether repeating this request can duplicate a side
    /// effect (br-kxd3e). Netlify has no idempotency key, so a create must pass
    /// `false` — a replayed `create_deploy` starts a SECOND build and ships it.
    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        replay_safe: bool,
    ) -> NetlifyResult<T> {
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
                handle_response::<T>(req, attempt, replay_safe).await
            }
        })
        .await
    }

    async fn post_json_list<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        replay_safe: bool,
    ) -> NetlifyResult<Vec<T>> {
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
                debug!(attempt, url = %redact_url(&url), "POST list");
                let req = authenticate_request(client.post(&url), &auth).json(&body);
                handle_list_response::<T>(req, attempt, replay_safe).await
            }
        })
        .await
    }

    async fn delete<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> NetlifyResult<T> {
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

// Free functions

fn authenticate_request(req: RequestBuilder, auth: &NetlifyAuth) -> RequestBuilder {
    if auth.access_token.is_empty() {
        req
    } else {
        req.bearer_auth(&auth.access_token)
    }
}

/// Classify a Netlify response.
///
/// `replay_safe` gates only the post-transmission classes; the 429 arm stays
/// retryable because Netlify refused the request WITHOUT performing it
/// (br-kxd3e).
async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<T, NetlifyError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(
                NetlifyError::Http(e),
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
            error: NetlifyError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(30)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(NetlifyError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(NetlifyError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = NetlifyError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            // A 5xx means Netlify received the request and may already have
            // started the deploy.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    // Netlify returns direct JSON (no envelope)
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(NetlifyError::Http(e)),
    };

    // Handle actual 204 responses without allowing other 2xx calls to fake success.
    if text.trim().is_empty() {
        if status != 204 {
            return AttemptOutcome::Terminal(NetlifyError::Api {
                status,
                message: "empty response body".into(),
            });
        }
        if let Ok(v) = serde_json::from_str::<T>("null") {
            return AttemptOutcome::Success(v);
        }
        if let Ok(v) = serde_json::from_str::<T>("{}") {
            return AttemptOutcome::Success(v);
        }
    }

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse response: {e}");
            AttemptOutcome::Terminal(NetlifyError::Json(e))
        }
    }
}

async fn handle_list_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<Vec<T>, NetlifyError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(
                NetlifyError::Http(e),
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
            error: NetlifyError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(30)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(NetlifyError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = NetlifyError::Api {
            status,
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(NetlifyError::Http(e)),
    };

    match serde_json::from_str::<Vec<T>>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            debug!(attempt, "Failed to parse list response: {e}");
            AttemptOutcome::Terminal(NetlifyError::Json(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_auth_value() -> String {
        ["sample", "netlify", "access"].join("-")
    }

    #[test]
    fn client_debug_redacts_auth() {
        let auth_value = sample_auth_value();
        let rt = NetlifyClient::new(
            "https://api.netlify.com",
            NetlifyAuth {
                access_token: auth_value.clone(),
            },
            HttpRetryConfig::default(),
        )
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&auth_value));
    }

    #[test]
    fn secretless_detection() {
        let rt = NetlifyClient::new(
            "https://api.netlify.com",
            NetlifyAuth {
                access_token: String::new(),
            },
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = NetlifyClient::new(
            "https://api.netlify.com",
            NetlifyAuth {
                access_token: sample_auth_value(),
            },
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "site_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "site_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "site_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "site_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "site_id").is_err());
        assert!(sanitize_path_segment("", "site_id").is_err());
        assert!(sanitize_path_segment("  ", "site_id").is_err());
        // Query/fragment delimiters must be rejected in path segments too: they
        // are interpolated before the `?site_id=` suffix, so an embedded `?`/`#`
        // would open the query early and re-target the endpoint.
        assert!(sanitize_path_segment("acme?x=1", "account_slug").is_err());
        assert!(sanitize_path_segment("acme#frag", "account_slug").is_err());
        assert!(sanitize_path_segment("acme&y=2", "account_slug").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("site-abc123", "site_id").unwrap(),
            "site-abc123"
        );
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = NetlifyClient::new(
            "https://api.netlify.com/",
            NetlifyAuth {
                access_token: sample_auth_value(),
            },
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }
}
