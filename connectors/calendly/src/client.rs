//! Calendly API client.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use reqwest::{Client, RequestBuilder, Url};
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{CalendlyError, CalendlyResult};
use crate::types::{
    ApiErrorResponse, AvailabilityScheduleListResponse, CurrentUserResponse, EventListResponse,
    EventResponse, EventTypeListResponse, InviteeListResponse, SchedulingLinkResponse,
};

/// Calendly API client with retry and runtime integration.
pub struct CalendlyClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for CalendlyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalendlyClient")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Sanitize a path segment to prevent path traversal.
fn sanitize_path_segment(segment: &str) -> CalendlyResult<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
    {
        return Err(CalendlyError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

impl CalendlyClient {
    /// Create a new Calendly client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> CalendlyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(CalendlyError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
            retry_config,
        })
    }

    fn authenticate(&self, request: RequestBuilder) -> RequestBuilder {
        if self.access_token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.access_token)
        }
    }

    /// Get the current authenticated user.
    pub async fn get_current_user(
        &self,
        runtime: &ConnectorRuntime,
    ) -> CalendlyResult<CurrentUserResponse> {
        let url = format!("{}/users/me", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// List scheduled events.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_events(
        &self,
        runtime: &ConnectorRuntime,
        user_uri: &str,
        count: Option<u32>,
        page_token: Option<&str>,
        status: Option<&str>,
        min_start_time: Option<&str>,
        max_start_time: Option<&str>,
    ) -> CalendlyResult<EventListResponse> {
        let base = format!("{}/scheduled_events", self.base_url);
        let mut url = Url::parse(&base).map_err(|e| CalendlyError::Api {
            status: 0,
            message: format!("invalid base URL: {e}"),
            title: None,
        })?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("user", user_uri);
            if let Some(c) = count {
                q.append_pair("count", &c.to_string());
            }
            if let Some(pt) = page_token {
                q.append_pair("page_token", pt);
            }
            if let Some(s) = status {
                q.append_pair("status", s);
            }
            if let Some(min) = min_start_time {
                q.append_pair("min_start_time", min);
            }
            if let Some(max) = max_start_time {
                q.append_pair("max_start_time", max);
            }
        }
        self.get_json(runtime, url.as_str()).await
    }

    /// Get a single scheduled event by UUID.
    pub async fn get_event(
        &self,
        runtime: &ConnectorRuntime,
        event_uuid: &str,
    ) -> CalendlyResult<EventResponse> {
        let uuid = sanitize_path_segment(event_uuid)?;
        let url = format!("{}/scheduled_events/{}", self.base_url, uuid);
        self.get_json(runtime, &url).await
    }

    /// List event types for a user.
    pub async fn list_event_types(
        &self,
        runtime: &ConnectorRuntime,
        user_uri: &str,
        count: Option<u32>,
        page_token: Option<&str>,
    ) -> CalendlyResult<EventTypeListResponse> {
        let base = format!("{}/event_types", self.base_url);
        let mut url = Url::parse(&base).map_err(|e| CalendlyError::Api {
            status: 0,
            message: format!("invalid base URL: {e}"),
            title: None,
        })?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("user", user_uri);
            if let Some(c) = count {
                q.append_pair("count", &c.to_string());
            }
            if let Some(pt) = page_token {
                q.append_pair("page_token", pt);
            }
        }
        self.get_json(runtime, url.as_str()).await
    }

    /// List invitees for an event.
    pub async fn list_invitees(
        &self,
        runtime: &ConnectorRuntime,
        event_uuid: &str,
        count: Option<u32>,
        page_token: Option<&str>,
    ) -> CalendlyResult<InviteeListResponse> {
        let uuid = sanitize_path_segment(event_uuid)?;
        let base = format!("{}/scheduled_events/{}/invitees", self.base_url, uuid);
        let mut url = Url::parse(&base).map_err(|e| CalendlyError::Api {
            status: 0,
            message: format!("invalid base URL: {e}"),
            title: None,
        })?;
        if count.is_some() || page_token.is_some() {
            let mut q = url.query_pairs_mut();
            if let Some(c) = count {
                q.append_pair("count", &c.to_string());
            }
            if let Some(pt) = page_token {
                q.append_pair("page_token", pt);
            }
        }
        self.get_json(runtime, url.as_str()).await
    }

    /// Create a scheduling link.
    pub async fn create_scheduling_link(
        &self,
        runtime: &ConnectorRuntime,
        owner_uri: &str,
        owner_type: &str,
        max_event_count: Option<u32>,
    ) -> CalendlyResult<SchedulingLinkResponse> {
        let url = format!("{}/scheduling_links", self.base_url);
        let mut body = serde_json::json!({
            "owner": owner_uri,
            "owner_type": owner_type,
        });
        if let Some(max) = max_event_count {
            body["max_event_count"] = serde_json::json!(max);
        }
        self.post_json(runtime, &url, &body).await
    }

    /// Cancel a scheduled event.
    pub async fn cancel_event(
        &self,
        runtime: &ConnectorRuntime,
        event_uuid: &str,
        reason: Option<&str>,
    ) -> CalendlyResult<()> {
        let uuid = sanitize_path_segment(event_uuid)?;
        let url = format!("{}/scheduled_events/{}/cancellation", self.base_url, uuid);
        let body = match reason {
            Some(r) => serde_json::json!({ "reason": r }),
            None => serde_json::json!({}),
        };

        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Cancelling Calendly event");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                }
                .json(&body);

                match send_request(request, "cancel_event").await {
                    Ok(_) => AttemptOutcome::Success(()),
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

    /// List user availability schedules.
    pub async fn list_availability(
        &self,
        runtime: &ConnectorRuntime,
        user_uri: &str,
    ) -> CalendlyResult<AvailabilityScheduleListResponse> {
        let base = format!("{}/user_availability_schedules", self.base_url);
        let mut url = Url::parse(&base).map_err(|e| CalendlyError::Api {
            status: 0,
            message: format!("invalid base URL: {e}"),
            title: None,
        })?;
        url.query_pairs_mut().append_pair("user", user_uri);
        self.get_json(runtime, url.as_str()).await
    }

    /// Health check: validate API reachability with GET /users/me.
    pub async fn health_check(&self) -> CalendlyResult<()> {
        let url = format!("{}/users/me", self.base_url);
        let resp = self
            .authenticate(self.client.get(&url))
            .send()
            .await
            .map_err(CalendlyError::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(CalendlyError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(CalendlyError::Unauthorized("Invalid access token".into()))
        } else {
            Err(CalendlyError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
                title: None,
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.access_token.is_empty()
    }

    /// Generic GET with retry + JSON deserialization.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> CalendlyResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Calendly GET");
                let request = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };

                match send_request(request, "GET").await {
                    Ok(text) => match serde_json::from_str::<T>(&text) {
                        Ok(v) => AttemptOutcome::Success(v),
                        Err(e) => AttemptOutcome::Terminal(CalendlyError::Json(e)),
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
    /// POST with retry.
    ///
    /// br-kxd3e: NOT replay-safe. Every caller of this helper CREATES a
    /// resource and the provider offers no idempotency key, so a duplicate is a second scheduling link.
    /// Only a connect-phase failure is retried. A converging POST added
    /// later needs its own helper rather than reusing this one.
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> CalendlyResult<T> {
        // br-kxd3e: NOT replay-safe. The only caller creates a scheduling
        // link and Calendly offers no idempotency key.
        let replay_safe = false;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Calendly POST");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                }
                .json(&body);

                match send_request(request, "POST").await {
                    Ok(text) => match serde_json::from_str::<T>(&text) {
                        Ok(v) => AttemptOutcome::Success(v),
                        Err(e) => AttemptOutcome::Terminal(CalendlyError::Json(e)),
                    },
                    Err(e) if e.is_retryable() => {
                        // 429 stays retryable — refused WITHOUT performing the
                        // work. A 5xx means the request arrived.
                        let replayable =
                            replay_safe || matches!(e, CalendlyError::RateLimited { .. });
                        let retry_after = e.retry_after();
                        AttemptOutcome::retryable_if_replayable(e, retry_after, replayable)
                    }
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }
}

/// Send a request and handle common error statuses.
async fn send_request(request: RequestBuilder, label: &str) -> CalendlyResult<String> {
    let resp = request.send().await.map_err(CalendlyError::Http)?;
    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after_ms = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|s| s * 1000)
            .unwrap_or(30_000);
        return Err(CalendlyError::RateLimited { retry_after_ms });
    }

    if status == 401 {
        return Err(CalendlyError::Unauthorized("Invalid access token".into()));
    }

    if status == 404 {
        return Err(CalendlyError::NotFound("Resource not found".into()));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let message = if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
            api_err
                .message
                .unwrap_or_else(|| api_err.title.unwrap_or_else(|| text.clone()))
        } else {
            text
        };
        warn!(status, label, "Calendly API error");
        return Err(CalendlyError::Api {
            status,
            message,
            title: None,
        });
    }

    resp.text().await.map_err(CalendlyError::Http)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = CalendlyClient::new(
            "https://api.calendly.com",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = CalendlyClient::new(
            "https://api.calendly.com/",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client =
            CalendlyClient::new("https://api.calendly.com", "", HttpRetryConfig::default())
                .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn debug_redacts_access_token() {
        let client = CalendlyClient::new(
            "https://api.calendly.com",
            "super_secret_token_value",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_token_value"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for access_token"
        );
    }

    #[test]
    fn non_secretless() {
        let client = CalendlyClient::new(
            "https://api.calendly.com",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn sanitize_path_segment_valid() {
        assert!(sanitize_path_segment("abc123").is_ok());
        assert!(sanitize_path_segment("event-uuid-456").is_ok());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../etc/passwd").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
    }
}
