//! `Home Assistant` API client.

use fcp_prelude::log_redaction::redact_url;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

use fcp_async_core::time::sleep;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_streaming::{StreamError, WsClient, WsConfig, WsConnection, WsMessage};
use reqwest::{Client, Response, StatusCode, Url};
use serde_json::{Value, json};
use tracing::{debug, instrument};

use crate::{
    error::{HomeAssistantError, HomeAssistantResult},
    types::{
        ApiErrorResponse, HomeAssistantEvent, HomeAssistantEventSubscription,
        HomeAssistantEventSubscriptionRequest, HomeAssistantSubscriptionStats,
    },
};

/// Default `Home Assistant` API base URL.
pub const DEFAULT_BASE_URL: &str = "http://homeassistant.local:8123/api";
const HOME_ASSISTANT_WS_RECONNECT_BASE_MS: u64 = 250;

/// Authentication mode for the `Home Assistant` API.
#[derive(Clone)]
pub enum HomeAssistantAuth {
    /// Long-lived access token (Bearer).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl HomeAssistantAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn has_token(&self) -> bool {
        matches!(self, Self::BearerToken(_))
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for HomeAssistantAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Sanitize a path segment to prevent path traversal.
///
/// Permits `:`, `.`, and `+` so entity IDs (`light.kitchen`) and ISO-8601
/// history timestamps (`2026-01-01T00:00:00+02:00`) pass unchanged.
fn sanitize_path_segment(segment: &str) -> HomeAssistantResult<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
        || segment.contains('?')
        || segment.contains('#')
    {
        return Err(HomeAssistantError::InvalidInput(
            "Invalid path segment: contains illegal characters".into(),
        ));
    }
    Ok(segment)
}

/// `Home Assistant` API client.
pub struct HomeAssistantClient {
    client: Client,
    auth: HomeAssistantAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for HomeAssistantClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HomeAssistantClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl HomeAssistantClient {
    /// Create a new `Home Assistant` client.
    pub fn new(auth: HomeAssistantAuth, base_url: Option<&str>) -> HomeAssistantResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-homeassistant/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            HomeAssistantAuth::BearerToken(token) => req.bearer_auth(token),
            HomeAssistantAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    fn stream_error(error: StreamError) -> HomeAssistantError {
        match error {
            StreamError::HttpError {
                status: 401,
                message: _,
                retry_after: _,
            } => HomeAssistantError::Unauthorized,
            StreamError::HttpError {
                status,
                message,
                retry_after: _,
            } => HomeAssistantError::Api {
                status_code: status,
                message,
            },
            StreamError::Timeout(timeout) => HomeAssistantError::WebSocket {
                message: format!("WebSocket receive timed out after {timeout:?}"),
                retryable: true,
            },
            other => HomeAssistantError::WebSocket {
                message: other.to_string(),
                retryable: true,
            },
        }
    }

    fn websocket_protocol_error(message: impl Into<String>, retryable: bool) -> HomeAssistantError {
        HomeAssistantError::WebSocket {
            message: message.into(),
            retryable,
        }
    }

    /// Return the Home Assistant WebSocket endpoint derived from the REST base URL.
    pub fn websocket_url(&self) -> HomeAssistantResult<String> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|error| HomeAssistantError::InvalidInput(error.to_string()))?;
        let ws_scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            "ws" => "ws",
            "wss" => "wss",
            scheme => {
                return Err(HomeAssistantError::InvalidInput(format!(
                    "unsupported base_url scheme for WebSocket: {scheme}"
                )));
            }
        };
        url.set_scheme(ws_scheme).map_err(|()| {
            HomeAssistantError::InvalidInput("failed to set WebSocket URL scheme".into())
        })?;
        url.set_query(None);
        url.set_fragment(None);

        let path = url.path().trim_end_matches('/');
        let websocket_path = if path.is_empty() || path == "/" {
            "/api/websocket".to_string()
        } else if path.ends_with("/api") {
            format!("{path}/websocket")
        } else {
            format!("{path}/api/websocket")
        };
        url.set_path(&websocket_path);
        Ok(url.to_string())
    }

    async fn connect_websocket(
        &self,
        request: &HomeAssistantEventSubscriptionRequest,
    ) -> HomeAssistantResult<WsConnection> {
        let timeout = Duration::from_millis(request.timeout_ms);
        let mut config = WsConfig::new()
            .with_connect_timeout(timeout)
            .with_ping_interval(None)
            .with_auto_reconnect(false);
        config.pong_timeout = timeout;

        WsClient::with_config(self.websocket_url()?, config)
            .connect()
            .await
            .map_err(Self::stream_error)
    }

    async fn next_json_message(connection: &mut WsConnection) -> HomeAssistantResult<Value> {
        loop {
            let frame = connection.recv().await.map_err(Self::stream_error)?;
            match frame {
                Some(WsMessage::Text(text)) => return Ok(serde_json::from_str(&text)?),
                Some(WsMessage::Binary(data)) => return Ok(serde_json::from_slice(data.as_ref())?),
                Some(WsMessage::Ping(data)) => {
                    connection
                        .send(WsMessage::Pong(data))
                        .await
                        .map_err(Self::stream_error)?;
                }
                Some(WsMessage::Pong(_)) => {}
                Some(WsMessage::Close(frame)) => {
                    let reason = frame.map_or_else(
                        || "server closed connection".to_string(),
                        |frame| format!("{} ({})", frame.reason, frame.code),
                    );
                    return Err(Self::websocket_protocol_error(
                        format!("WebSocket closed before subscription completed: {reason}"),
                        true,
                    ));
                }
                None => {
                    return Err(Self::websocket_protocol_error(
                        "WebSocket closed before subscription completed",
                        true,
                    ));
                }
            }
        }
    }

    async fn authenticate_websocket(
        &self,
        connection: &mut WsConnection,
    ) -> HomeAssistantResult<()> {
        let bearer = match &self.auth {
            HomeAssistantAuth::BearerToken(bearer) => bearer,
            HomeAssistantAuth::CredentialId(_) => {
                return Err(HomeAssistantError::InvalidInput(
                    "credential_id mode cannot authenticate Home Assistant WebSocket frames without host token injection"
                        .into(),
                ));
            }
        };

        let greeting = Self::next_json_message(connection).await?;
        if greeting.get("type").and_then(Value::as_str) != Some("auth_required") {
            return Err(Self::websocket_protocol_error(
                "Home Assistant WebSocket did not request auth",
                false,
            ));
        }

        connection
            .send_text(json!({ "type": "auth", "access_token": bearer }).to_string())
            .await
            .map_err(Self::stream_error)?;

        let auth_response = Self::next_json_message(connection).await?;
        match auth_response.get("type").and_then(Value::as_str) {
            Some("auth_ok") => Ok(()),
            Some("auth_invalid") => Err(HomeAssistantError::Unauthorized),
            other => Err(Self::websocket_protocol_error(
                format!("unexpected Home Assistant auth response: {other:?}"),
                false,
            )),
        }
    }

    async fn open_event_subscription(
        &self,
        request: &HomeAssistantEventSubscriptionRequest,
        subscription_id: u64,
    ) -> HomeAssistantResult<WsConnection> {
        let mut connection = self.connect_websocket(request).await?;
        self.authenticate_websocket(&mut connection).await?;

        let mut subscribe = serde_json::Map::new();
        subscribe.insert("id".to_string(), json!(subscription_id));
        subscribe.insert("type".to_string(), json!("subscribe_events"));
        if let Some(event_type) = &request.event_type {
            subscribe.insert("event_type".to_string(), json!(event_type));
        }

        connection
            .send_text(Value::Object(subscribe).to_string())
            .await
            .map_err(Self::stream_error)?;

        let ack = Self::next_json_message(&mut connection).await?;
        validate_subscription_ack(&ack, subscription_id)?;
        Ok(connection)
    }

    async fn collect_subscription_events(
        connection: &mut WsConnection,
        request: &HomeAssistantEventSubscriptionRequest,
        filter: &mut HomeAssistantEventFilter,
        stats: &mut HomeAssistantSubscriptionStats,
        events: &mut Vec<HomeAssistantEvent>,
    ) -> HomeAssistantResult<()> {
        while events.len() < request.max_events {
            let frame = Self::next_json_message(connection).await?;
            let event = match parse_homeassistant_event_frame(&frame) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(_) => {
                    stats.malformed = stats.malformed.saturating_add(1);
                    continue;
                }
            };
            stats.received = stats.received.saturating_add(1);
            match filter.decide(&event, Instant::now()) {
                EventFilterDecision::Emit => {
                    stats.emitted = stats.emitted.saturating_add(1);
                    events.push(event);
                }
                EventFilterDecision::DropIgnored => {
                    stats.dropped_ignored = stats.dropped_ignored.saturating_add(1);
                }
                EventFilterDecision::DropFilter => {
                    stats.dropped_filter = stats.dropped_filter.saturating_add(1);
                }
                EventFilterDecision::DropCooldown => {
                    stats.dropped_cooldown = stats.dropped_cooldown.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    /// Subscribe to Home Assistant events via the native WebSocket API and
    /// return a bounded batch of matching, redacted events.
    pub async fn subscribe_events(
        &self,
        mut request: HomeAssistantEventSubscriptionRequest,
    ) -> HomeAssistantResult<HomeAssistantEventSubscription> {
        request
            .validate()
            .map_err(HomeAssistantError::InvalidInput)?;

        let mut stats = HomeAssistantSubscriptionStats::default();
        let mut filter = HomeAssistantEventFilter::new(&request);
        let mut events = Vec::with_capacity(request.max_events);
        let mut subscription_id = 1_u64;
        let max_attempts = request.max_reconnect_attempts.saturating_add(1);
        let mut last_error = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                stats.reconnects = stats.reconnects.saturating_add(1);
                let delay_ms = HOME_ASSISTANT_WS_RECONNECT_BASE_MS
                    .saturating_mul(u64::from(attempt))
                    .min(2_000);
                sleep(Duration::from_millis(delay_ms)).await;
            }

            let mut connection = match self
                .open_event_subscription(&request, subscription_id)
                .await
            {
                Ok(connection) => connection,
                Err(error) if error.is_retryable() && attempt + 1 < max_attempts => {
                    last_error = Some(error);
                    subscription_id = subscription_id.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(error),
            };

            let result = Self::collect_subscription_events(
                &mut connection,
                &request,
                &mut filter,
                &mut stats,
                &mut events,
            )
            .await;

            let _ = connection.close().await;
            if events.len() >= request.max_events {
                let first_event = events.first().cloned().ok_or_else(|| {
                    Self::websocket_protocol_error("subscription completed without events", false)
                })?;
                return Ok(HomeAssistantEventSubscription {
                    subscription_id,
                    event_type: request.event_type.take(),
                    event: first_event,
                    events,
                    stats,
                    replay_supported: false,
                    persistent: false,
                });
            }

            match result {
                Ok(()) => {}
                Err(error) if error.is_retryable() && attempt + 1 < max_attempts => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
            subscription_id = subscription_id.saturating_add(1);
        }

        Err(last_error.unwrap_or_else(|| {
            Self::websocket_protocol_error("subscription ended before any matching events", true)
        }))
    }

    async fn handle_response(&self, resp: Response) -> HomeAssistantResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.trim().is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> HomeAssistantResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(HomeAssistantError::Unauthorized),
            404 => Err(HomeAssistantError::EntityNotFound { entity_id: detail }),
            429 => Err(HomeAssistantError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            503 => Err(HomeAssistantError::Unavailable),
            code => Err(HomeAssistantError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> HomeAssistantResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Check connectivity by hitting the root API endpoint.
    pub async fn health_check(&self) -> HomeAssistantResult<()> {
        self.get("", None).await.map(|_| ())
    }

    // -- States --

    /// List all entity states.
    pub async fn list_states(&self) -> HomeAssistantResult<serde_json::Value> {
        self.get("/states", None).await
    }

    /// Get a single entity state.
    pub async fn get_state(&self, entity_id: &str) -> HomeAssistantResult<serde_json::Value> {
        let entity_id = sanitize_path_segment(entity_id)?;
        self.get(&format!("/states/{entity_id}"), None).await
    }

    /// Set an entity state.
    pub async fn set_state(
        &self,
        entity_id: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        let entity_id = sanitize_path_segment(entity_id)?;
        self.post(&format!("/states/{entity_id}"), body).await
    }

    // -- Services --

    /// Call a service.
    pub async fn call_service(
        &self,
        domain: &str,
        service: &str,
        body: &serde_json::Value,
    ) -> HomeAssistantResult<serde_json::Value> {
        let domain = sanitize_path_segment(domain)?;
        let service = sanitize_path_segment(service)?;
        self.post(&format!("/services/{domain}/{service}"), body)
            .await
    }

    /// List all services.
    pub async fn list_services(&self) -> HomeAssistantResult<serde_json::Value> {
        self.get("/services", None).await
    }

    // -- History --

    /// Get state history for a period.
    pub async fn get_history(
        &self,
        timestamp: &str,
        filter_entity_id: Option<&str>,
        end_time: Option<&str>,
        minimal_response: Option<bool>,
        significant_changes_only: Option<bool>,
    ) -> HomeAssistantResult<serde_json::Value> {
        let timestamp = sanitize_path_segment(timestamp)?;
        let mut q = Vec::new();
        if let Some(e) = filter_entity_id {
            q.push(("filter_entity_id", e.to_string()));
        }
        if let Some(e) = end_time {
            q.push(("end_time", e.to_string()));
        }
        if minimal_response.unwrap_or(false) {
            q.push(("minimal_response", String::new()));
        }
        if significant_changes_only.unwrap_or(false) {
            q.push(("significant_changes_only", String::new()));
        }
        self.get(
            &format!("/history/period/{timestamp}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Template API for areas/devices --

    /// Get all states (used to filter by domain prefix for automations, scenes, areas, devices).
    pub async fn get_states_by_domain(
        &self,
        domain_prefix: &str,
    ) -> HomeAssistantResult<Vec<serde_json::Value>> {
        let states = self.list_states().await?;
        let filtered = match states.as_array() {
            Some(arr) => arr
                .iter()
                .filter(|s| {
                    s.get("entity_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| id.starts_with(domain_prefix))
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        Ok(filtered)
    }
}

fn validate_subscription_ack(ack: &Value, subscription_id: u64) -> HomeAssistantResult<()> {
    if ack.get("type").and_then(Value::as_str) != Some("result")
        || ack.get("id").and_then(Value::as_u64) != Some(subscription_id)
    {
        return Err(HomeAssistantClient::websocket_protocol_error(
            format!("unexpected Home Assistant subscription ack: {ack}"),
            false,
        ));
    }

    if ack.get("success").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }

    let message = ack
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("Home Assistant rejected event subscription");
    Err(HomeAssistantClient::websocket_protocol_error(
        message.to_string(),
        false,
    ))
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "access_token"
            | "authorization"
            | "bearer"
            | "client_secret"
            | "password"
            | "refresh_token"
            | "secret"
            | "token"
    )
}

fn redacted_event_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let redacted = map
                .iter()
                .map(|(key, value)| {
                    let value = if sensitive_key(key) {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        redacted_event_value(value)
                    };
                    (key.clone(), value)
                })
                .collect();
            Value::Object(redacted)
        }
        Value::Array(values) => Value::Array(values.iter().map(redacted_event_value).collect()),
        other => other.clone(),
    }
}

fn parse_homeassistant_event_frame(
    frame: &Value,
) -> HomeAssistantResult<Option<HomeAssistantEvent>> {
    if frame.get("type").and_then(Value::as_str) != Some("event") {
        return Ok(None);
    }

    let event_value = frame.get("event").ok_or_else(|| {
        HomeAssistantClient::websocket_protocol_error("event frame missing event payload", false)
    })?;
    let event_value = redacted_event_value(event_value);
    let event_type = event_value
        .get("event_type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            HomeAssistantClient::websocket_protocol_error(
                "event frame missing event.event_type",
                false,
            )
        })?
        .to_string();

    let data = event_value
        .get("data")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let entity_id = data
        .get("entity_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let domain = entity_id.as_deref().and_then(|entity_id| {
        entity_id
            .split_once('.')
            .map(|(domain, _)| domain.to_string())
    });

    Ok(Some(HomeAssistantEvent {
        event_type,
        entity_id,
        domain,
        old_state: data.get("old_state").cloned(),
        new_state: data.get("new_state").cloned(),
        context: event_value.get("context").cloned(),
        origin: event_value
            .get("origin")
            .and_then(Value::as_str)
            .map(str::to_string),
        time_fired: event_value
            .get("time_fired")
            .and_then(Value::as_str)
            .map(str::to_string),
        data,
        raw: redacted_event_value(frame),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventFilterDecision {
    Emit,
    DropIgnored,
    DropFilter,
    DropCooldown,
}

struct HomeAssistantEventFilter {
    watch_domains: HashSet<String>,
    watch_entities: HashSet<String>,
    ignore_entities: HashSet<String>,
    watch_all: bool,
    cooldown: Duration,
    last_emit: HashMap<String, Instant>,
}

impl HomeAssistantEventFilter {
    fn new(request: &HomeAssistantEventSubscriptionRequest) -> Self {
        Self {
            watch_domains: request.watch_domains.iter().cloned().collect(),
            watch_entities: request.watch_entities.iter().cloned().collect(),
            ignore_entities: request.ignore_entities.iter().cloned().collect(),
            watch_all: request.watch_all,
            cooldown: Duration::from_millis(request.cooldown_ms),
            last_emit: HashMap::new(),
        }
    }

    fn decide(&mut self, event: &HomeAssistantEvent, now: Instant) -> EventFilterDecision {
        if event
            .entity_id
            .as_ref()
            .is_some_and(|entity_id| self.ignore_entities.contains(entity_id))
        {
            return EventFilterDecision::DropIgnored;
        }

        let selected = self.watch_all
            || event
                .entity_id
                .as_ref()
                .is_some_and(|entity_id| self.watch_entities.contains(entity_id))
            || event
                .domain
                .as_ref()
                .is_some_and(|domain| self.watch_domains.contains(domain));
        if !selected {
            return EventFilterDecision::DropFilter;
        }

        let Some(entity_id) = &event.entity_id else {
            return EventFilterDecision::Emit;
        };

        if !self.cooldown.is_zero() {
            if let Some(previous) = self.last_emit.get(entity_id) {
                if now.duration_since(*previous) < self.cooldown {
                    return EventFilterDecision::DropCooldown;
                }
            }
        }

        self.last_emit.insert(entity_id.clone(), now);
        EventFilterDecision::Emit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = HomeAssistantAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn sanitize_path_segment_valid() {
        assert!(sanitize_path_segment("light.kitchen").is_ok());
        assert!(sanitize_path_segment("turn_on").is_ok());
        assert!(sanitize_path_segment("2026-01-01T00:00:00+02:00").is_ok());
        assert!(sanitize_path_segment("2026-01-01T00:00:00.123Z").is_ok());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../etc/passwd").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("foo\\bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("   ").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
        assert!(sanitize_path_segment("foo?bar=1").is_err());
        assert!(sanitize_path_segment("foo#frag").is_err());
    }

    #[test]
    fn auth_secretless_detection() {
        let token = HomeAssistantAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = HomeAssistantAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn default_base_url_has_api_prefix() {
        assert!(DEFAULT_BASE_URL.contains("/api"));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("http://localhost:8123/api/"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_uses_default_url() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_debug_format() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("secret".into()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("HomeAssistantClient"));
    }

    #[test]
    fn auth_clone_bearer() {
        let auth = HomeAssistantAuth::BearerToken("tok123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_clone_credential() {
        let auth = HomeAssistantAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client =
            HomeAssistantClient::new(HomeAssistantAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = HomeAssistantClient::new(HomeAssistantAuth::CredentialId(cred), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn default_base_url_is_http() {
        assert!(DEFAULT_BASE_URL.starts_with("http://"));
    }

    #[test]
    fn default_base_url_contains_8123() {
        assert!(DEFAULT_BASE_URL.contains("8123"));
    }

    #[test]
    fn auth_bearer_is_not_secretless() {
        let auth = HomeAssistantAuth::BearerToken("any".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_is_secretless() {
        let auth = HomeAssistantAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = HomeAssistantAuth::BearerToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = HomeAssistantAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("k".into()),
            Some("http://localhost:8123/api////"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_custom_url_preserved() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("https://ha.example.com:443/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://ha.example.com:443/api");
    }

    #[test]
    fn websocket_url_uses_api_websocket_for_api_base() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("https://ha.example.com:8123/api"),
        )
        .unwrap();
        assert_eq!(
            client.websocket_url().unwrap(),
            "wss://ha.example.com:8123/api/websocket"
        );
    }

    #[test]
    fn websocket_url_adds_api_path_for_root_base() {
        let client = HomeAssistantClient::new(
            HomeAssistantAuth::BearerToken("tok".into()),
            Some("http://localhost:8123"),
        )
        .unwrap();
        assert_eq!(
            client.websocket_url().unwrap(),
            "ws://localhost:8123/api/websocket"
        );
    }

    #[test]
    fn subscription_request_requires_explicit_filters() {
        let mut request = HomeAssistantEventSubscriptionRequest::default();
        let err = request.validate().unwrap_err();
        assert!(err.contains("watch_all"));

        request.watch_domains.push(" light ".into());
        request.validate().unwrap();
        assert_eq!(request.watch_domains, vec!["light"]);
    }

    #[test]
    fn event_parser_redacts_sensitive_fields() {
        let frame = json!({
            "type": "event",
            "event": {
                "event_type": "state_changed",
                "data": {
                    "entity_id": "light.kitchen",
                    "new_state": {
                        "state": "on",
                        "attributes": {
                            "access_token": "secret-token",
                            "friendly_name": "Kitchen"
                        }
                    }
                },
                "origin": "LOCAL",
                "time_fired": "2026-05-05T12:00:00Z",
                "context": {"id": "ctx-1"}
            }
        });

        let event = parse_homeassistant_event_frame(&frame)
            .unwrap()
            .expect("event frame");
        assert_eq!(event.entity_id.as_deref(), Some("light.kitchen"));
        assert_eq!(event.domain.as_deref(), Some("light"));
        assert_eq!(
            event.new_state.unwrap()["attributes"]["access_token"],
            "[REDACTED]"
        );
        assert_eq!(
            event.raw["event"]["data"]["new_state"]["attributes"]["access_token"],
            "[REDACTED]"
        );
    }

    #[test]
    fn event_filter_applies_ignore_domain_and_cooldown() {
        let mut request = HomeAssistantEventSubscriptionRequest {
            watch_domains: vec!["light".into()],
            ignore_entities: vec!["light.secret".into()],
            cooldown_ms: 1_000,
            ..HomeAssistantEventSubscriptionRequest::default()
        };
        request.validate().unwrap();
        let mut filter = HomeAssistantEventFilter::new(&request);
        let now = Instant::now();

        let ignored = HomeAssistantEvent {
            event_type: "state_changed".into(),
            entity_id: Some("light.secret".into()),
            domain: Some("light".into()),
            old_state: None,
            new_state: None,
            context: None,
            origin: None,
            time_fired: None,
            data: json!({}),
            raw: json!({}),
        };
        assert_eq!(
            filter.decide(&ignored, now),
            EventFilterDecision::DropIgnored
        );

        let emitted = HomeAssistantEvent {
            entity_id: Some("light.kitchen".into()),
            domain: Some("light".into()),
            ..ignored.clone()
        };
        assert_eq!(filter.decide(&emitted, now), EventFilterDecision::Emit);
        assert_eq!(
            filter.decide(&emitted, now + Duration::from_millis(10)),
            EventFilterDecision::DropCooldown
        );
        assert_eq!(
            filter.decide(&emitted, now + Duration::from_millis(1_001)),
            EventFilterDecision::Emit
        );
    }
}
