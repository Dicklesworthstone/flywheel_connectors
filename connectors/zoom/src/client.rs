//! Zoom API client with Server-to-Server OAuth.

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{ZoomError, ZoomResult};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> ZoomResult<&'a str> {
    if value.trim().is_empty() {
        return Err(ZoomError::InvalidInput(format!(
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
        return Err(ZoomError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    if value.len() > 256 {
        return Err(ZoomError::InvalidInput(format!(
            "{field} exceeds maximum length of 256"
        )));
    }
    Ok(value)
}

/// Zoom API client with Server-to-Server OAuth.
pub struct ZoomClient {
    client: Client,
    base_url: String,
    oauth_base_url: String,
    account_id: String,
    client_id: String,
    client_secret: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for ZoomClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoomClient")
            .field("base_url", &self.base_url)
            .field("oauth_base_url", &self.oauth_base_url)
            .field("account_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl ZoomClient {
    /// Create a new Zoom client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        oauth_base_url: &str,
        account_id: &str,
        client_id: &str,
        client_secret: &str,
        retry_config: HttpRetryConfig,
    ) -> ZoomResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(ZoomError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            oauth_base_url: oauth_base_url.trim_end_matches('/').to_string(),
            account_id: account_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            retry_config,
        })
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the OAuth base URL (for diagnostics).
    pub fn oauth_base_url(&self) -> &str {
        &self.oauth_base_url
    }

    /// Check if using secretless mode (credential injection).
    pub fn is_secretless(&self) -> bool {
        self.client_id.is_empty() || self.client_secret.is_empty()
    }

    fn token_url(&self) -> String {
        format!("{}/oauth/token", self.oauth_base_url)
    }

    /// Obtain an access token via Server-to-Server OAuth.
    async fn get_access_token(&self) -> ZoomResult<String> {
        let url = self.token_url();
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=account_credentials&account_id={}",
                self.account_id
            ))
            .send()
            .await
            .map_err(ZoomError::Http)?;

        let status = resp.status().as_u16();
        if status == 401 {
            return Err(ZoomError::Unauthorized("Invalid OAuth credentials".into()));
        }
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ZoomError::Api {
                code: u32::from(status),
                message: format!("OAuth token request failed: {text}"),
            });
        }

        let token_resp: TokenResponse = resp.json().await.map_err(ZoomError::Http)?;
        Ok(token_resp.access_token)
    }

    /// Execute a GET request with retry and token acquisition.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        query: &[(String, String)],
    ) -> ZoomResult<T> {
        let url = format!("{}{path}", self.base_url);
        let token_url = self.token_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let token_url = token_url.clone();
            let client = self.client.clone();
            let query = query.to_vec();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let account_id = self.account_id.clone();
            async move {
                debug!(attempt, path, "Zoom API GET");

                // Get fresh token for each attempt
                let token_resp = client
                    .post(&token_url)
                    .basic_auth(&client_id, Some(&client_secret))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!(
                        "grant_type=account_credentials&account_id={account_id}"
                    ))
                    .send()
                    .await;

                let token = match token_resp {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<TokenResponse>().await {
                            Ok(t) => t.access_token,
                            Err(e) => {
                                return AttemptOutcome::Retryable {
                                    error: ZoomError::Http(e),
                                    retry_after: None,
                                };
                            }
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if status == 401 {
                            return AttemptOutcome::Terminal(ZoomError::Unauthorized(
                                "Invalid OAuth credentials".into(),
                            ));
                        }
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Api {
                                code: u32::from(status),
                                message: "OAuth token request failed".into(),
                            },
                            retry_after: None,
                        };
                    }
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let resp = match client
                    .get(&url)
                    .bearer_auth(&token)
                    .query(&query)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
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
                        error: ZoomError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(ZoomError::Unauthorized(
                        "Invalid access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Zoom API request failed");
                    if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
                        let err = ZoomError::Api {
                            code: api_err.code,
                            message: api_err.message,
                        };
                        let decision = classify_http_status(status, None);
                        if !matches!(decision, RetryDecision::Terminal) {
                            return AttemptOutcome::Retryable {
                                error: err,
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(err);
                    }
                    let decision = classify_http_status(status, None);
                    let err = ZoomError::Api {
                        code: u32::from(status),
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(ZoomError::Http(e)),
                }
            }
        })
        .await
    }

    /// List meetings for a user.
    pub async fn list_meetings(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        page_size: Option<u32>,
        next_page_token: Option<&str>,
    ) -> ZoomResult<MeetingList> {
        let user_id = sanitize_path_segment(user_id, "user_id")?;
        let path = format!("/users/{user_id}/meetings");
        let mut query = Vec::new();
        if let Some(ps) = page_size {
            query.push(("page_size".into(), ps.to_string()));
        }
        if let Some(npt) = next_page_token {
            query.push(("next_page_token".into(), npt.to_string()));
        }
        self.get_json(runtime, &path, &query).await
    }

    /// Get a specific meeting.
    pub async fn get_meeting(
        &self,
        runtime: &ConnectorRuntime,
        meeting_id: &str,
    ) -> ZoomResult<Meeting> {
        let meeting_id = sanitize_path_segment(meeting_id, "meeting_id")?;
        let path = format!("/meetings/{meeting_id}");
        self.get_json(runtime, &path, &[]).await
    }

    /// Create a new meeting.
    pub async fn create_meeting(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        request: &CreateMeetingRequest,
    ) -> ZoomResult<Meeting> {
        let user_id = sanitize_path_segment(user_id, "user_id")?;
        let path = format!("/users/{user_id}/meetings");
        let body = serde_json::to_value(request).map_err(ZoomError::Json)?;
        self.post_json(runtime, &path, &body).await
    }

    /// Update a meeting.
    pub async fn update_meeting(
        &self,
        runtime: &ConnectorRuntime,
        meeting_id: &str,
        request: &UpdateMeetingRequest,
    ) -> ZoomResult<()> {
        let meeting_id = sanitize_path_segment(meeting_id, "meeting_id")?;
        let path = format!("/meetings/{meeting_id}");
        let body = serde_json::to_value(request).map_err(ZoomError::Json)?;
        self.patch_no_content(runtime, &path, &body).await
    }

    /// Delete a meeting.
    pub async fn delete_meeting(
        &self,
        runtime: &ConnectorRuntime,
        meeting_id: &str,
    ) -> ZoomResult<()> {
        let meeting_id = sanitize_path_segment(meeting_id, "meeting_id")?;
        let path = format!("/meetings/{meeting_id}");
        self.delete_no_content(runtime, &path).await
    }

    /// List users.
    pub async fn list_users(
        &self,
        runtime: &ConnectorRuntime,
        page_size: Option<u32>,
        next_page_token: Option<&str>,
    ) -> ZoomResult<UserList> {
        let mut query = Vec::new();
        if let Some(ps) = page_size {
            query.push(("page_size".into(), ps.to_string()));
        }
        if let Some(npt) = next_page_token {
            query.push(("next_page_token".into(), npt.to_string()));
        }
        self.get_json(runtime, "/users", &query).await
    }

    /// Get a specific user.
    pub async fn get_user(&self, runtime: &ConnectorRuntime, user_id: &str) -> ZoomResult<User> {
        let user_id = sanitize_path_segment(user_id, "user_id")?;
        let path = format!("/users/{user_id}");
        self.get_json(runtime, &path, &[]).await
    }

    /// List recordings for a user.
    pub async fn list_recordings(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        from: Option<&str>,
        to: Option<&str>,
    ) -> ZoomResult<RecordingList> {
        let user_id = sanitize_path_segment(user_id, "user_id")?;
        let path = format!("/users/{user_id}/recordings");
        let mut query = Vec::new();
        if let Some(f) = from {
            query.push(("from".into(), f.to_string()));
        }
        if let Some(t) = to {
            query.push(("to".into(), t.to_string()));
        }
        self.get_json(runtime, &path, &query).await
    }

    /// List webinars for a user.
    pub async fn list_webinars(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        page_size: Option<u32>,
    ) -> ZoomResult<WebinarList> {
        let user_id = sanitize_path_segment(user_id, "user_id")?;
        let path = format!("/users/{user_id}/webinars");
        let mut query = Vec::new();
        if let Some(ps) = page_size {
            query.push(("page_size".into(), ps.to_string()));
        }
        self.get_json(runtime, &path, &query).await
    }

    /// Health check: get the current user to verify API reachability.
    pub async fn health_check(&self) -> ZoomResult<()> {
        let token = self.get_access_token().await?;
        let url = format!("{}/users/me", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(ZoomError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() || status == 400 {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(ZoomError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(ZoomError::Unauthorized("Invalid credentials".into()))
        } else {
            Err(ZoomError::Api {
                code: u32::from(status),
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Execute a POST request with retry and token acquisition.
    /// Execute a POST request.
    ///
    /// br-kxd3e: every caller CREATES a Zoom resource and Zoom has no
    /// idempotency key, so a replay that reached Zoom schedules a second
    /// meeting. Note the token-mint failures above stay retryable on purpose:
    /// if minting the OAuth token failed, the create request was never sent.
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        body: &serde_json::Value,
    ) -> ZoomResult<T> {
        let url = format!("{}{path}", self.base_url);
        let token_url = self.token_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let token_url = token_url.clone();
            let client = self.client.clone();
            let body = body_clone.clone();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let account_id = self.account_id.clone();
            async move {
                debug!(attempt, path, "Zoom API POST");

                let token_resp = client
                    .post(&token_url)
                    .basic_auth(&client_id, Some(&client_secret))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!(
                        "grant_type=account_credentials&account_id={account_id}"
                    ))
                    .send()
                    .await;

                let token = match token_resp {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<TokenResponse>().await {
                            Ok(t) => t.access_token,
                            Err(e) => {
                                return AttemptOutcome::Retryable {
                                    error: ZoomError::Http(e),
                                    retry_after: None,
                                };
                            }
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if status == 401 {
                            return AttemptOutcome::Terminal(ZoomError::Unauthorized(
                                "Invalid OAuth credentials".into(),
                            ));
                        }
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Api {
                                code: u32::from(status),
                                message: "OAuth token request failed".into(),
                            },
                            retry_after: None,
                        };
                    }
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let resp = match client
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        // Only a connect-phase failure proves the create never
                        // reached Zoom.
                        let replayable = !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            ZoomError::Http(e),
                            None,
                            replayable,
                        );
                    }
                };

                let status = resp.status().as_u16();
                // 429 stays retryable: refused WITHOUT scheduling anything.
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: ZoomError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    // Every remaining retryable class here is a 5xx, which
                    // means Zoom RECEIVED the create and may already have
                    // scheduled the meeting. 429 is handled above, before this
                    // point, because it was refused without scheduling.
                    let err = if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
                        ZoomError::Api {
                            code: api_err.code,
                            message: api_err.message,
                        }
                    } else {
                        ZoomError::Api {
                            code: u32::from(status),
                            message: text,
                        }
                    };
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(ZoomError::Http(e)),
                }
            }
        })
        .await
    }

    /// Execute a PATCH request that returns 204 No Content.
    async fn patch_no_content(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        body: &serde_json::Value,
    ) -> ZoomResult<()> {
        let url = format!("{}{path}", self.base_url);
        let token_url = self.token_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let token_url = token_url.clone();
            let client = self.client.clone();
            let body = body_clone.clone();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let account_id = self.account_id.clone();
            async move {
                debug!(attempt, path, "Zoom API PATCH");

                let token_resp = client
                    .post(&token_url)
                    .basic_auth(&client_id, Some(&client_secret))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!(
                        "grant_type=account_credentials&account_id={account_id}"
                    ))
                    .send()
                    .await;

                let token = match token_resp {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<TokenResponse>().await {
                            Ok(t) => t.access_token,
                            Err(e) => {
                                return AttemptOutcome::Retryable {
                                    error: ZoomError::Http(e),
                                    retry_after: None,
                                };
                            }
                        }
                    }
                    Ok(_) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Api {
                                code: 500,
                                message: "OAuth token request failed".into(),
                            },
                            retry_after: None,
                        };
                    }
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let resp = match client
                    .patch(&url)
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if resp.status().is_success() || status == 204 {
                    return AttemptOutcome::Success(());
                }

                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: ZoomError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                let text = resp.text().await.unwrap_or_default();
                let decision = classify_http_status(status, None);
                let err = ZoomError::Api {
                    code: u32::from(status),
                    message: text,
                };
                if !matches!(decision, RetryDecision::Terminal) {
                    AttemptOutcome::Retryable {
                        error: err,
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Terminal(err)
                }
            }
        })
        .await
    }

    /// Execute a DELETE request that returns 204 No Content.
    async fn delete_no_content(&self, runtime: &ConnectorRuntime, path: &str) -> ZoomResult<()> {
        let url = format!("{}{path}", self.base_url);
        let token_url = self.token_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let token_url = token_url.clone();
            let client = self.client.clone();
            let client_id = self.client_id.clone();
            let client_secret = self.client_secret.clone();
            let account_id = self.account_id.clone();
            async move {
                debug!(attempt, path, "Zoom API DELETE");

                let token_resp = client
                    .post(&token_url)
                    .basic_auth(&client_id, Some(&client_secret))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!(
                        "grant_type=account_credentials&account_id={account_id}"
                    ))
                    .send()
                    .await;

                let token = match token_resp {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<TokenResponse>().await {
                            Ok(t) => t.access_token,
                            Err(e) => {
                                return AttemptOutcome::Retryable {
                                    error: ZoomError::Http(e),
                                    retry_after: None,
                                };
                            }
                        }
                    }
                    Ok(_) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Api {
                                code: 500,
                                message: "OAuth token request failed".into(),
                            },
                            retry_after: None,
                        };
                    }
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let resp = match client.delete(&url).bearer_auth(&token).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ZoomError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if resp.status().is_success() || status == 204 {
                    return AttemptOutcome::Success(());
                }

                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: ZoomError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                let text = resp.text().await.unwrap_or_default();
                let decision = classify_http_status(status, None);
                let err = ZoomError::Api {
                    code: u32::from(status),
                    message: text,
                };
                if !matches!(decision, RetryDecision::Terminal) {
                    AttemptOutcome::Retryable {
                        error: err,
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Terminal(err)
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us",
            "acc_123",
            "client_id",
            "client_secret",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2/",
            "https://zoom.us/",
            "acc_123",
            "cid",
            "csec",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us",
            "acc_123",
            "",
            "csec",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());

        let client2 = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us",
            "acc_123",
            "cid",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client2.is_secretless());
    }

    #[test]
    fn non_secretless() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us",
            "acc_123",
            "cid",
            "csec",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn debug_redacts_credentials() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us",
            "secret_account_id",
            "secret_client_id",
            "secret_client_secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("secret_account_id"),
            "Debug output must not contain the raw account_id"
        );
        assert!(
            !debug_output.contains("secret_client_id"),
            "Debug output must not contain the raw client_id"
        );
        assert!(
            !debug_output.contains("secret_client_secret"),
            "Debug output must not contain the raw client_secret"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn oauth_base_url_trimmed() {
        let client = ZoomClient::new(
            "https://api.zoom.us/v2",
            "https://zoom.us/",
            "acc_123",
            "cid",
            "csec",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert_eq!(client.oauth_base_url(), "https://zoom.us");
    }

    #[test]
    fn sanitize_rejects_empty() {
        let result = sanitize_path_segment("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        assert!(sanitize_path_segment("../etc", "test").is_err());
        assert!(sanitize_path_segment("foo/bar", "test").is_err());
        assert!(sanitize_path_segment("foo\\bar", "test").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "test").is_err());
        assert!(sanitize_path_segment("foo%5cbar", "test").is_err());
    }

    #[test]
    fn sanitize_rejects_oversized() {
        let long = "a".repeat(257);
        assert!(sanitize_path_segment(&long, "test").is_err());
    }

    #[test]
    fn sanitize_accepts_valid() {
        assert!(sanitize_path_segment("me", "test").is_ok());
        assert!(sanitize_path_segment("user-abc-123", "test").is_ok());
        assert!(sanitize_path_segment("123456789", "test").is_ok());
    }
}
