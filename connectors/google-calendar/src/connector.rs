//! FCP Google Calendar Connector implementation.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    provisioning::load_default_google_provisioning_bundle,
};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
    SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::StandaloneSession;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_calendar_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("www.googleapis.com")
}

/// Validate a google-calendar `base_url` override.
///
/// Rejects any non-Calendar API host unless the override targets a
/// local test listener. Rejects non-https except for local tests.
/// Parses the URL host properly so substring-smuggle payloads like
/// `https://evil.com/calendar.googleapis.com` are rejected.
fn validate_calendar_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_calendar_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target www.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

use crate::{
    client::{
        DEFAULT_BASE_URL, GoogleCalendarClient, google_auth_is_secretless,
        google_auth_redacted_label,
    },
    error::GoogleCalendarError,
    types::{Attendee, Event, FreeBusyRequest, FreeBusyRequestItem},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOKE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Validated configuration for the Google Calendar connector.
struct GoogleCalendarConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl GoogleCalendarConfig {
    /// Parse and validate configuration from FCP params.
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("calendar");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "calendar" || service.api_version != "v3" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to calendar:v3 (got {})",
                    service.identity()
                ),
            });
        }

        let required_scopes = resolve_calendar_required_scopes(params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "configure params must be a JSON object".into(),
            })?;
        auth_object.insert(
            "required_scopes".to_string(),
            json!(required_scopes.clone()),
        );

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(map_auth_error)?;
        let auth = selection
            .materialize()
            .await
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Failed to materialize Google auth source: {error}"),
            })?;

        let base_url = match params.get("base_url") {
            Some(value) => {
                validate_calendar_base_url(value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "`base_url` must be a string".into(),
                })?)?
            }
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
            required_scopes,
        })
    }
}

fn parse_string_array_field(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("`{field}` must be an array of strings"),
    })?;
    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must not be empty"),
        });
    }

    let mut deduped = BTreeSet::new();
    for value in values {
        let item = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must contain only strings"),
        })?;
        let item = item.trim();
        if item.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("`{field}` entries must not be empty"),
            });
        }
        deduped.insert(item.to_string());
    }

    Ok(Some(deduped.into_iter().collect()))
}

fn resolve_calendar_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let explicit_scopes = parse_string_array_field(params, "required_scopes")?;
    let scope_triggers = parse_string_array_field(params, "scope_triggers")?.unwrap_or_default();
    if explicit_scopes.is_some() && !scope_triggers.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide either `required_scopes` or `scope_triggers`, not both".into(),
        });
    }
    if let Some(scopes) = explicit_scopes {
        return Ok(scopes);
    }

    let bundle = load_default_google_provisioning_bundle("calendar").map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Failed to load embedded Google Calendar provisioning bundle: {error}"
            ),
        }
    })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid calendar scope trigger selection: {error}"),
        })
}

#[allow(clippy::needless_pass_by_value)] // required by map_err(fn) signature
fn map_auth_error(error: GoogleAuthError) -> FcpError {
    match &error {
        GoogleAuthError::ExactlyOneSourceRequired { count: 0 } => FcpError::InvalidRequest {
            code: 1003,
            message: "Missing authentication: supply one Google auth source".into(),
        },
        GoogleAuthError::ExactlyOneSourceRequired { .. } => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Provide exactly one Google auth source: {error}"),
        },
        _ => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Google auth configuration: {error}"),
        },
    }
}

fn self_check_report_from_result(result: Result<(), GoogleCalendarError>) -> SelfCheckReport {
    match result {
        Ok(()) => SelfCheckReport::ok(),
        Err(err) => {
            if err.is_retryable() {
                SelfCheckReport::degraded("self_check_retryable", err.to_string())
            } else {
                SelfCheckReport::failed("self_check_failed", err.to_string())
            }
        }
    }
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Google Calendar Connector.
pub struct GoogleCalendarConnector {
    base: Arc<BaseConnector>,
    config: Option<GoogleCalendarConfig>,
    client: Option<GoogleCalendarClient>,
    authority: Option<StandaloneSession>,
    bound_zone: Option<ZoneId>,
    started_at: Instant,
    stopped: bool,
}

impl GoogleCalendarConnector {
    /// Create a new Google Calendar connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "fcp.google-calendar",
            ))),
            config: None,
            client: None,
            authority: None,
            bound_zone: None,
            started_at: Instant::now(),
            stopped: false,
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.authority.as_ref().map_or_else(
            || self.base.instance_id.as_str(),
            |authority| authority.instance_id().as_str(),
        )
    }

    fn invalidate_authority(&mut self) {
        if let Some(authority) = &mut self.authority {
            authority.invalidate();
        }
        self.base.set_handshaken(false);
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Replacing credentials invalidates all prior tokens, including when
        // the replacement configuration is rejected before client creation.
        self.invalidate_authority();
        self.base.set_configured(false);
        self.config = None;
        self.bound_zone = None;
        self.stopped = false;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        let config = GoogleCalendarConfig::from_params(&params).await?;

        let client = GoogleCalendarClient::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Google Calendar connector configured"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        let config = self.config.as_ref().expect("config stored after configure");
        Ok(json!({
            "status": "configured",
            "details": {
                "service_identity": config.service_identity,
                "required_scopes": config.required_scopes,
                "auth_mode": google_auth_redacted_label(&config.auth),
                "base_url": config.base_url,
            }
        }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_authority();
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;
        if self
            .bound_zone
            .as_ref()
            .is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "gcal.handshake".into(),
                reason: "Reconfigure before binding Calendar credentials to another zone".into(),
            });
        }
        let zone = req.zone.clone();
        let mut authority = StandaloneSession::new(MANIFEST_TOML)?;
        let mut response = authority.handshake(req)?;
        response.event_caps = Some(EventCaps {
            streaming: false,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        });
        let mut result = serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        // A preferred host identifier is not an authority generation. Always
        // disclose the SDK's actual, freshly rotated binding for token issuance.
        result["instance_id"] = json!(authority.instance_id());
        result["connector_id"] = json!("fcp.google-calendar");
        result["protocol_version"] = json!("2.0");
        self.authority = Some(authority);
        self.bound_zone = Some(zone);
        self.base.set_handshaken(true);
        Ok(result)
    }

    /// Handle health check using the canonical native-host response schema.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some() && self.client.is_some();
        let handshaken = self
            .authority
            .as_ref()
            .is_some_and(StandaloneSession::is_established);
        let status = if self.stopped {
            HealthState::Stopping
        } else if configured && handshaken {
            HealthState::Ready
        } else if configured {
            HealthState::Degraded {
                reason: "No negotiated capability authority".into(),
            }
        } else {
            HealthState::Starting
        };
        let metrics = self.base.metrics();
        let mut details = json!({
            "connector_id": "fcp.google-calendar",
            "instance_id": self.instance_id(),
            "configured": configured,
            "handshaken": handshaken,
            "zone_id": self.bound_zone,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            details["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            details["base_url"] = json!(config.base_url);
            details["service_identity"] = json!(config.service_identity);
            details["required_scopes"] = json!(config.required_scopes);
        }
        serde_json::to_value(HealthSnapshot {
            status,
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: Some(details),
            rate_limit: None,
        })
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize health: {e}"),
        })
    }

    /// Handle doctor readiness check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization fails.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Base URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Base URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Healthy,
                message: format!("Discovery service: {}", config.service_identity),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", google_auth_redacted_label(&config.auth)),
            });
            checks.push(DoctorCheck {
                name: "required_scopes".into(),
                status: DoctorStatus::Healthy,
                message: format!("Required scopes: {}", config.required_scopes.join(", ")),
            });
        } else {
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Unhealthy,
                message: "Discovery service not set (not configured)".into(),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
            checks.push(DoctorCheck {
                name: "required_scopes".into(),
                status: DoctorStatus::Unhealthy,
                message: "Required scopes not set (not configured)".into(),
            });
        }

        // 5. Network constraints
        let egress_target = self.config.as_ref().map_or("www.googleapis.com", |c| {
            c.base_url
                .strip_prefix("https://")
                .or_else(|| c.base_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("www.googleapis.com")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        // 6. Credential injection
        if let Some(config) = &self.config {
            if google_auth_is_secretless(&config.auth) {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct token mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization fails.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if let Some(config) = &self.config {
            if google_auth_is_secretless(&config.auth) {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = self_check_report_from_result(client.health_check().await);

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "gcal.list_calendars",
                    "List all calendars for the authenticated user",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "calendars": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all calendars accessible by the authenticated user."
                            .into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("gcal.list_events")],
                    },
                ),
                op_info(
                    "gcal.get_event",
                    "Get a single calendar event by ID",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID (use 'primary' for the main calendar)" },
                            "event_id": { "type": "string", "description": "Event ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve full details of a specific calendar event.".into(),
                        common_mistakes: vec![
                            "Using email address instead of calendar ID".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123def456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.list_events"),
                            CapabilityId::from_static("gcal.update_event"),
                        ],
                    },
                ),
                op_info(
                    "gcal.list_events",
                    "List events in a calendar with optional time range",
                    json!({
                        "type": "object",
                        "required": ["calendar_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID (use 'primary' for the main calendar)" },
                            "time_min": { "type": "string", "description": "Lower bound (RFC 3339) for event start time" },
                            "time_max": { "type": "string", "description": "Upper bound (RFC 3339) for event end time" },
                            "max_results": { "type": "integer", "description": "Max events to return" },
                            "page_token": { "type": "string", "description": "Pagination token" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "events": { "type": "array" },
                            "next_page_token": { "type": ["string", "null"] },
                            "summary": { "type": ["string", "null"] }
                        }
                    }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "List or search calendar events. Use time_min/time_max for date ranges."
                                .into(),
                        common_mistakes: vec![
                            "Not using RFC 3339 format for time_min/time_max".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "time_min": "2026-01-01T00:00:00Z", "max_results": 10}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.get_event")],
                    },
                ),
                op_info(
                    "gcal.create_event",
                    "Create a new calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "summary", "start", "end"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "event_id": {
                                "type": "string", "minLength": 5, "maxLength": 1024,
                                "pattern": "^[a-v0-9]+$",
                                "description": "Optional stable provider ID. Reuse it with identical input to recover a create safely; omit for an unkeyed create."
                            },
                            "summary": { "type": "string", "description": "Event title" },
                            "description": { "type": "string", "description": "Event description" },
                            "location": { "type": "string", "description": "Event location" },
                            "start": { "type": "string", "description": "Start time (RFC 3339)" },
                            "end": { "type": "string", "description": "End time (RFC 3339)" },
                            "attendees": { "type": "array", "items": { "type": "object" }, "description": "List of attendee objects with email" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new event on a calendar. Requires start and end times in RFC 3339 format. Supply event_id to permit provider-keyed retries and reuse the same ID with identical input when recovering an uncertain result.".into(),
                        common_mistakes: vec![
                            "Forgetting to specify time zone in the datetime string".into(),
                            "Reusing an event_id with different event fields causes a conflict; use gcal.update_event for changes".into(),
                            "Retrying an uncertain create without event_id can create a duplicate event".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "summary": "Team Meeting", "start": "2026-01-15T10:00:00-05:00", "end": "2026-01-15T11:00:00-05:00"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.update_event"),
                            CapabilityId::from_static("gcal.quick_add"),
                        ],
                    },
                ),
                op_info(
                    "gcal.update_event",
                    "Update an existing calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "anyOf": [
                            { "required": ["summary"] }, { "required": ["description"] },
                            { "required": ["location"] }, { "required": ["start"] },
                            { "required": ["end"] }, { "required": ["attendees"] }
                        ],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "event_id": { "type": "string", "description": "Event ID to update" },
                            "summary": { "type": "string", "description": "New event title" },
                            "description": { "type": "string", "description": "New event description" },
                            "location": { "type": "string", "description": "New event location" },
                            "start": { "type": "string", "description": "New start time (RFC 3339)" },
                            "end": { "type": "string", "description": "New end time (RFC 3339)" },
                            "attendees": { "type": "array", "items": { "type": "object" }, "description": "Replace attendee list; [] removes all attendees. Omit to preserve existing attendees." }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update fields of an existing calendar event. Only specified fields are changed; omitted fields are preserved. Provide at least one change.".into(),
                        common_mistakes: vec![
                            "Not providing the event_id of the existing event".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123", "summary": "Updated Meeting Title"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.get_event"),
                            CapabilityId::from_static("gcal.create_event"),
                        ],
                    },
                ),
                op_info(
                    "gcal.delete_event",
                    "Delete a calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "event_id": { "type": "string", "description": "Event ID to delete" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
                    "gcal.delete",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Permanently delete a calendar event. This cannot be undone."
                            .into(),
                        common_mistakes: vec![
                            "Deleting recurring event instances instead of the series".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123def456"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.get_event")],
                    },
                ),
                op_info(
                    "gcal.quick_add",
                    "Quick-add an event using natural language text",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "text"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "text": { "type": "string", "description": "Natural language event description (e.g., 'Lunch with John tomorrow at noon')" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Quickly create an event using natural language. Google Calendar parses the text to extract date, time, and title.".into(),
                        common_mistakes: vec![
                            "Using ambiguous dates without specifying the year".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "text": "Meeting with Alice tomorrow at 3pm"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.create_event")],
                    },
                ),
                op_info(
                    "gcal.freebusy",
                    "Query free/busy information for calendars",
                    json!({
                        "type": "object",
                        "required": ["time_min", "time_max", "items"],
                        "properties": {
                            "time_min": { "type": "string", "description": "Start of time range (RFC3339)" },
                            "time_max": { "type": "string", "description": "End of time range (RFC3339)" },
                            "items": { "type": "array", "description": "Calendar IDs to query, e.g. [{\"id\": \"primary\"}]" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "calendars": { "type": "object", "description": "Map of calendar ID to busy times" }
                        }
                    }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check when people are free or busy across one or more calendars.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"time_min": "2026-03-01T00:00:00Z", "time_max": "2026-03-02T00:00:00Z", "items": [{"id": "primary"}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.list_events")],
                    },
                ),
                op_info(
                    "gcal.list_event_instances",
                    "List instances of a recurring event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string" },
                            "event_id": { "type": "string", "description": "ID of the recurring event" },
                            "time_min": { "type": "string", "description": "Lower bound (RFC3339)" },
                            "time_max": { "type": "string", "description": "Upper bound (RFC3339)" },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "events": { "type": "array" },
                            "next_page_token": { "type": ["string", "null"] }
                        }
                    }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get individual instances of a recurring event, optionally filtered by time range.".into(),
                        common_mistakes: vec![
                            "Using a non-recurring event ID (only works for events with recurrence rules)".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123_R20260301"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.get_event"),
                            CapabilityId::from_static("gcal.list_events"),
                        ],
                    },
                ),
                op_info(
                    "gcal.get_calendar",
                    "Get details of a specific calendar",
                    json!({
                        "type": "object",
                        "required": ["calendar_id"],
                        "properties": {
                            "calendar_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "calendar": { "type": "object" } } }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details of a specific calendar by its ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"calendar_id": "primary"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("gcal.list_calendars"),
                            CapabilityId::from_static("gcal.list_events"),
                        ],
                    },
                ),
                op_info(
                    "gcal.sync_events",
                    "Incremental sync of calendar events using syncToken",
                    json!({
                        "type": "object",
                        "required": ["calendar_id"],
                        "properties": {
                            "calendar_id": { "type": "string" },
                            "sync_token": { "type": "string", "description": "Token from a previous sync response. Omit for initial full sync." },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "events": { "type": "array" },
                            "next_page_token": { "type": ["string", "null"] },
                            "next_sync_token": { "type": ["string", "null"] }
                        }
                    }),
                    "gcal.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Sync calendar events incrementally. First call without sync_token for full sync; subsequent calls with the returned next_sync_token for changes only.".into(),
                        common_mistakes: vec![
                            "Do not mix sync_token with timeMin/timeMax filters.".into(),
                            "Deleted events appear with status 'cancelled'.".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary"}"#.into(),
                            r#"{"calendar_id": "primary", "sync_token": "CPDAlvXk..."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.list_events"),
                        ],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;
        let checked = (|| {
            self.base.check_ready()?;
            if req.r#type != "simulate" || req.id.0.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Simulation requires type simulate and a non-empty ID".into(),
                });
            }
            validate_calendar_input(req.operation.as_str(), &req.input)?;
            let resources = calendar_resource_uris(req.operation.as_str(), &req.input)?;
            self.authority
                .as_ref()
                .ok_or(FcpError::NotHandshaken)?
                .authorize(
                    &req.connector_id,
                    &req.zone_id,
                    &req.operation,
                    req.capability_token,
                    &resources,
                )?;
            Ok(())
        })();
        let response = match checked {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(error) => SimulateResponse::denied(req.id, error.to_string(), error.error_code()),
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        self.base.check_ready()?;
        if request.deadline_ms == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation deadline has expired".into(),
            });
        }
        let operation = request.operation.as_str();
        validate_calendar_input(operation, &request.input)?;
        let resources = calendar_resource_uris(operation, &request.input)?;
        let authority = self.authority.as_ref().ok_or(FcpError::NotHandshaken)?;
        let admission = authority.admit_bounded(&request, &resources, MAX_INVOKE_RESPONSE_BYTES)?;
        let input = request.input;
        let result = match operation {
            "gcal.list_calendars" => self.invoke_list_calendars().await,
            "gcal.get_event" => self.invoke_get_event(input).await,
            "gcal.list_events" => self.invoke_list_events(input).await,
            "gcal.create_event" => self.invoke_create_event(input).await,
            "gcal.update_event" => self.invoke_update_event(input).await,
            "gcal.delete_event" => self.invoke_delete_event(input).await,
            "gcal.quick_add" => self.invoke_quick_add(input).await,
            "gcal.freebusy" => self.invoke_freebusy(input).await,
            "gcal.list_event_instances" => self.invoke_list_event_instances(input).await,
            "gcal.get_calendar" => self.invoke_get_calendar(input).await,
            "gcal.sync_events" => self.invoke_sync_events(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };
        // Settle the same complete envelope the JSONL adapter returns. A failed
        // provider call retains its reservation because effects may be unknown.
        let response = match &result {
            Ok(value) => InvokeResponse::ok(request.id, value.clone()),
            Err(error) => InvokeResponse::error(request.id, error.clone()),
        };
        admission.finish_response(&response)?;
        result
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_list_calendars(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let result = client
            .list_calendars()
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "calendars": result.items }))
    }

    async fn invoke_get_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;

        let event = client
            .get_event(calendar_id, event_id)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": event }))
    }

    async fn invoke_list_events(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let time_min = input.get("time_min").and_then(|v| v.as_str());
        let time_max = input.get("time_max").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_events(calendar_id, time_min, time_max, max_results, page_token)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({
            "events": result.items,
            "next_page_token": result.next_page_token,
            "summary": result.summary
        }))
    }

    async fn invoke_create_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        for field in ["summary", "start", "end"] {
            require_str(&input, field)?;
        }
        let event_id = input
            .get("event_id")
            .map(|_| require_str(&input, "event_id"))
            .transpose()?;
        // Apply the same strict field validation as updates before attaching a
        // replay key. Invalid optional fields must not silently alter intent.
        let mut event: Event =
            serde_json::from_value(event_update_patch(&input)?).map_err(|_| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid event fields".into(),
                }
            })?;
        event.id = event_id.map(String::from);

        let created = client
            .create_event(calendar_id, &event)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": created }))
    }

    async fn invoke_update_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;
        let patch = event_update_patch(&input)?;

        let updated = client
            .update_event(calendar_id, event_id, &patch)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": updated }))
    }

    async fn invoke_delete_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;

        client
            .delete_event(calendar_id, event_id)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "status": "deleted" }))
    }

    async fn invoke_quick_add(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let text = require_str(&input, "text")?;

        let event = client
            .quick_add(calendar_id, text)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": event }))
    }

    async fn invoke_get_calendar(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;

        let calendar = client
            .get_calendar(calendar_id)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "calendar": calendar }))
    }

    async fn invoke_freebusy(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let time_min = require_str(&input, "time_min")?;
        let time_max = require_str(&input, "time_max")?;

        let items_raw = input.get("items").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: items".into(),
        })?;
        let items: Vec<FreeBusyRequestItem> =
            serde_json::from_value(items_raw.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid items format: {e}"),
            })?;

        let request = FreeBusyRequest {
            time_min: time_min.to_string(),
            time_max: time_max.to_string(),
            items,
        };

        let result = client
            .freebusy(&request)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "calendars": result.calendars }))
    }

    async fn invoke_list_event_instances(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;
        let time_min = input.get("time_min").and_then(|v| v.as_str());
        let time_max = input.get("time_max").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_event_instances(
                calendar_id,
                event_id,
                time_min,
                time_max,
                max_results,
                page_token,
            )
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({
            "events": result.items,
            "next_page_token": result.next_page_token
        }))
    }

    async fn invoke_sync_events(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let sync_token = input.get("sync_token").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .sync_events(calendar_id, sync_token, max_results, page_token)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({
            "events": result.items,
            "next_page_token": result.next_page_token,
            "next_sync_token": result.next_sync_token
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Google Calendar connector shutting down");
        self.invalidate_authority();
        self.base.set_configured(false);
        self.config = None;
        self.bound_zone = None;
        self.stopped = true;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GoogleCalendarConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

/// Resource identities follow the exact calendar/event IDs sent to Google.
/// Encoding each segment prevents separators and wildcard characters in an ID
/// from being interpreted as a different authorization resource.
fn calendar_resource_uris(operation: &str, input: &serde_json::Value) -> FcpResult<Vec<String>> {
    let calendar_uri = |calendar_id: &str| {
        format!(
            "gcal://calendars/{}",
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC),
        )
    };
    match operation {
        "gcal.list_calendars" => Ok(vec!["gcal://calendars".into()]),
        "gcal.freebusy" => {
            let items = calendar_freebusy_items(input)?;
            Ok(items.iter().map(|item| calendar_uri(&item.id)).collect())
        }
        "gcal.get_calendar" => Ok(vec![calendar_uri(calendar_identifier(
            input,
            "calendar_id",
        )?)]),
        "gcal.list_events" | "gcal.sync_events" | "gcal.create_event" | "gcal.quick_add" => {
            let calendar = calendar_uri(calendar_identifier(input, "calendar_id")?);
            Ok(vec![format!("{calendar}/events")])
        }
        "gcal.get_event"
        | "gcal.update_event"
        | "gcal.delete_event"
        | "gcal.list_event_instances" => {
            let calendar = calendar_uri(calendar_identifier(input, "calendar_id")?);
            let event = percent_encoding::utf8_percent_encode(
                calendar_identifier(input, "event_id")?,
                percent_encoding::NON_ALPHANUMERIC,
            );
            Ok(vec![format!("{calendar}/events/{event}")])
        }
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn calendar_identifier<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    let value = require_str(input, field)?;
    validate_calendar_identifier(value, field)?;
    Ok(value)
}

fn validate_calendar_identifier(value: &str, field: &str) -> FcpResult<()> {
    if value.trim().is_empty() || matches!(value, "." | "..") || value.chars().any(char::is_control)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Field {field} must be a non-empty resource identifier without dot segments or controls"
            ),
        });
    }
    Ok(())
}

fn calendar_freebusy_items(input: &serde_json::Value) -> FcpResult<Vec<FreeBusyRequestItem>> {
    let raw = input.get("items").ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "Missing required field: items".into(),
    })?;
    let items: Vec<FreeBusyRequestItem> =
        serde_json::from_value(raw.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Field items must be an array of calendar ID objects".into(),
        })?;
    if items.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Free/busy requires at least one calendar".into(),
        });
    }
    for item in &items {
        validate_calendar_identifier(&item.id, "items.id")?;
    }
    Ok(items)
}

fn validate_calendar_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    if !input.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Calendar input must be an object".into(),
        });
    }
    match operation {
        "gcal.list_calendars" => return Ok(()),
        "gcal.freebusy" => {
            require_str(input, "time_min")?;
            require_str(input, "time_max")?;
            calendar_freebusy_items(input)?;
            return Ok(());
        }
        "gcal.get_calendar" | "gcal.list_events" | "gcal.sync_events" => {
            calendar_identifier(input, "calendar_id")?;
        }
        "gcal.get_event" | "gcal.delete_event" | "gcal.list_event_instances" => {
            calendar_identifier(input, "calendar_id")?;
            calendar_identifier(input, "event_id")?;
        }
        "gcal.update_event" => {
            calendar_identifier(input, "calendar_id")?;
            calendar_identifier(input, "event_id")?;
            event_update_patch(input)?;
        }
        "gcal.create_event" => {
            calendar_identifier(input, "calendar_id")?;
            for field in ["summary", "start", "end"] {
                require_str(input, field)?;
            }
            event_update_patch(input)?;
            if input.get("event_id").is_some() {
                let event_id = calendar_identifier(input, "event_id")?;
                crate::client::validate_create_event_id(event_id)
                    .map_err(|error| error.to_fcp_error())?;
            }
        }
        "gcal.quick_add" => {
            calendar_identifier(input, "calendar_id")?;
            require_str(input, "text")?;
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    for field in ["time_min", "time_max", "page_token", "sync_token"] {
        if input.get(field).is_some() {
            require_str(input, field)?;
        }
    }
    if let Some(value) = input.get("max_results")
        && !value
            .as_u64()
            .is_some_and(|number| u32::try_from(number).is_ok())
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Field max_results must be an unsigned 32-bit integer".into(),
        });
    }
    Ok(())
}

/// Build a sparse provider patch without converting absent fields to null or
/// empty arrays. In particular, a title-only update must not remove guests.
fn event_update_patch(input: &serde_json::Value) -> FcpResult<serde_json::Value> {
    let mut patch = serde_json::Map::new();
    for field in ["summary", "description", "location", "start", "end"] {
        if let Some(value) = input.get(field) {
            let text = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Field {field} must be a string"),
            })?;
            let value = if matches!(field, "start" | "end") {
                chrono::DateTime::parse_from_rfc3339(text).map_err(|_| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "Field {field} must be an RFC 3339 datetime with an offset"
                        ),
                    }
                })?;
                json!({ "dateTime": text })
            } else {
                value.clone()
            };
            patch.insert(field.to_string(), value);
        }
    }
    if let Some(attendees) = input.get("attendees") {
        if !attendees
            .as_array()
            .is_some_and(|entries| entries.iter().all(serde_json::Value::is_object))
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Field attendees must be an array of attendee objects".into(),
            });
        }
        serde_json::from_value::<Vec<Attendee>>(attendees.clone()).map_err(|_| {
            FcpError::InvalidRequest {
                code: 1003,
                message: "Field attendees must be an array of attendee objects".into(),
            }
        })?;
        patch.insert("attendees".into(), attendees.clone());
    }
    if patch.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "At least one event field must be supplied for an update".into(),
        });
    }
    Ok(serde_json::Value::Object(patch))
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: Some(match id {
            "gcal.create_event" | "gcal.update_event" | "gcal.quick_add" => {
                fcp_prelude::ApprovalMode::Policy
            }
            "gcal.delete_event" => fcp_prelude::ApprovalMode::Interactive,
            _ => fcp_prelude::ApprovalMode::None,
        }),
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken};

    #[test]
    fn event_patch_preserves_omission_and_wraps_only_supplied_times() {
        let patch = event_update_patch(&json!({
            "calendar_id": "primary", "event_id": "evt123",
            "start": "2026-10-23T10:00:00-04:00",
            "location": "Room 2"
        }))
        .unwrap();
        assert_eq!(
            patch,
            json!({
                "start": { "dateTime": "2026-10-23T10:00:00-04:00" },
                "location": "Room 2"
            })
        );
    }

    #[test]
    fn validate_calendar_base_url_accepts_googleapis_hosts() {
        let a = validate_calendar_base_url("https://www.googleapis.com/calendar/v3").unwrap();
        assert_eq!(a, "https://www.googleapis.com/calendar/v3");
    }

    #[test]
    fn validate_calendar_base_url_allows_local_http() {
        validate_calendar_base_url("http://localhost:9999").unwrap();
        validate_calendar_base_url("http://127.0.0.1/cal").unwrap();
        validate_calendar_base_url("http://[::1]:9999/cal").unwrap();
    }

    #[test]
    fn validate_calendar_base_url_rejects_foreign_host() {
        let err = validate_calendar_base_url("https://evil.example.com/calendar/v3").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("www.googleapis.com"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_calendar_base_url_rejects_substring_smuggle() {
        let err =
            validate_calendar_base_url("https://evil.com/calendar.googleapis.com/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_calendar_base_url_rejects_plain_http_on_public_host() {
        let err = validate_calendar_base_url("http://calendar.googleapis.com/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_calendar_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_calendar_base_url("https://www.googleapis.com/calendar/v3?leak=x")
                .unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_calendar_base_url("https://www.googleapis.com/calendar/v3#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err = validate_calendar_base_url("https://attacker:pw@www.googleapis.com/calendar/v3")
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_calendar_base_url_rejects_empty_and_malformed() {
        assert!(matches!(
            validate_calendar_base_url("   ").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_calendar_base_url("not a url").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn host_is_calendar_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_calendar_googleapis("www.googleapis.com"));
        assert!(!host_is_calendar_googleapis("googleapis.com"));
        assert!(!host_is_calendar_googleapis("calendar.googleapis.com"));
        assert!(!host_is_calendar_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_calendar_googleapis("evil-googleapis.com"));
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        op: &str,
    ) -> CapabilityToken {
        let cap = match op {
            "gcal.list_calendars" | "gcal.get_event" | "gcal.list_events" => "gcal.read",
            "gcal.create_event" | "gcal.update_event" | "gcal.quick_add" => "gcal.write",
            "gcal.delete_event" => "gcal.delete",
            _ => "gcal.read",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({ "token": "fixture-token" }))
            .await
            .unwrap();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
        assert_eq!(result["instance_id"], connector.instance_id());
        assert_eq!(result["connector_id"], "fcp.google-calendar");
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(health.is_ready());
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(GoogleCalendarConnector::manifest_hash(), expected);
        assert_ne!(
            GoogleCalendarConnector::manifest_hash(),
            "sha256:google-calendar-connector-v1"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_health().await.unwrap();
        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        assert!(matches!(health.status, HealthState::Starting));
        assert_eq!(health.details.unwrap()["configured"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GoogleCalendarConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let handshake_error = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.read"]
            }))
            .await
            .unwrap_err();
        assert!(matches!(handshake_error, FcpError::NotConfigured));

        let token =
            generate_valid_token(&signing_key, connector.instance_id(), "gcal.list_calendars");

        let result = connector
            .handle_invoke(json!({
                "type": "invoke", "id": "unconfigured",
                "connector_id": "fcp.google-calendar", "zone_id": "z:work",
                "operation": "gcal.list_calendars",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake_key",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, connector.instance_id(), "gcal.get_event");

        let result = connector
            .handle_invoke(json!({
                "type": "invoke", "id": "missing-field",
                "connector_id": "fcp.google-calendar", "zone_id": "z:work",
                "operation": "gcal.get_event",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("calendar_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"gcal.list_calendars"));
        assert!(op_ids.contains(&"gcal.get_event"));
        assert!(op_ids.contains(&"gcal.list_events"));
        assert!(op_ids.contains(&"gcal.create_event"));
        assert!(op_ids.contains(&"gcal.update_event"));
        assert!(op_ids.contains(&"gcal.delete_event"));
        assert!(op_ids.contains(&"gcal.quick_add"));
        assert!(op_ids.contains(&"gcal.freebusy"));
        assert!(op_ids.contains(&"gcal.list_event_instances"));
        assert!(op_ids.contains(&"gcal.get_calendar"));
        assert!(op_ids.contains(&"gcal.sync_events"));
        assert_eq!(ops.len(), 11);
    }

    // ── Provisioning automation tests ──────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token() {
        let mut connector = GoogleCalendarConnector::new();
        let result = connector
            .handle_configure(json!({ "token": "test-token-abc" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.service_identity, "calendar:v3");
        assert_eq!(
            config.required_scopes,
            vec!["https://www.googleapis.com/auth/calendar.readonly".to_string()]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = GoogleCalendarConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        let config = connector.config.as_ref().unwrap();
        assert!(google_auth_is_secretless(&config.auth));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth() {
        let mut connector = GoogleCalendarConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "tok",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = GoogleCalendarConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing authentication"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_service_selector_alias() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({
                "token": "tok",
                "service_selector": "gcal"
            }))
            .await
            .unwrap();

        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.service_identity, "calendar:v3");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_scope_triggers_widen_required_scopes() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({
                "token": "tok",
                "scope_triggers": [
                    "User enables event create, update, delete, or quick-add workflows."
                ]
            }))
            .await
            .unwrap();

        let config = connector.config.as_ref().unwrap();
        assert_eq!(
            config.required_scopes,
            vec![
                "https://www.googleapis.com/auth/calendar.events".to_string(),
                "https://www.googleapis.com/auth/calendar.readonly".to_string()
            ]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_service_selector() {
        let mut connector = GoogleCalendarConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "tok",
                "service_selector": "gmail"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("service_selector"));
                assert!(message.contains("calendar:v3"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_base_url() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({
                "token": "tok",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_base_url_override() {
        let mut connector = GoogleCalendarConnector::new();
        let err = connector
            .handle_configure(json!({
                "token": "tok",
                "base_url": 123
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
            "expected base_url validation error, got {err:?}"
        );

        let mut connector = GoogleCalendarConnector::new();
        let err = connector
            .handle_configure(json!({
                "token": "tok",
                "base_url": ""
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
            "expected empty base_url validation error, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_shows_auth_info() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({ "token": "tok" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"]["state"], "degraded");
        assert_eq!(
            health["details"]["auth_mode"],
            "google_auth:bearer:redacted"
        );
        assert!(health["details"]["base_url"].as_str().is_some());
        assert_eq!(health["details"]["service_identity"], "calendar:v3");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_unconfigured() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({ "token": "tok" }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.iter().all(|c| c["status"] == "healthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = GoogleCalendarConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_returns_degraded() {
        let mut connector = GoogleCalendarConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[test]
    fn test_retryable_self_check_error_maps_to_degraded() {
        let report = serde_json::to_value(self_check_report_from_result(Err(
            GoogleCalendarError::Api {
                code: 503,
                message: "backend unavailable".into(),
            },
        )))
        .unwrap();
        assert_eq!(report["status"], "degraded");
        assert_eq!(report["reason_code"], "self_check_retryable");
    }

    #[test]
    fn test_non_retryable_self_check_error_maps_to_failed() {
        let report = serde_json::to_value(self_check_report_from_result(Err(
            GoogleCalendarError::Unauthorized,
        )))
        .unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["reason_code"], "self_check_failed");
    }

    // ── Schema completeness tests ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_input_and_output_schemas() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap_or("<missing>");
            assert!(
                op.get("input_schema").is_some(),
                "{id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "{id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"].as_str(),
                Some("object"),
                "{id} input_schema type should be object"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str(),
                Some("object"),
                "{id} output_schema type should be object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_is_deterministic() {
        let c1 = GoogleCalendarConnector::new();
        let c2 = GoogleCalendarConnector::new();
        let r1 = c1.handle_introspect().await.unwrap();
        let r2 = c2.handle_introspect().await.unwrap();

        let ids1: Vec<&str> = r1["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        let ids2: Vec<&str> = r2["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids1, ids2, "introspect should be deterministic");
    }

    #[fcp_async_core::runtime::test]
    async fn test_no_duplicate_operation_ids() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let mut seen = std::collections::HashSet::new();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(seen.insert(id), "duplicate operation ID: {id}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_rejected() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(
            !ops.iter()
                .any(|o| o["id"].as_str() == Some("gcal.nonexistent")),
            "unknown operation should not exist"
        );
    }

    // ── Introspection metadata tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_required_metadata() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap_or("<missing>");
            assert!(op.get("summary").is_some(), "{id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap_or("").is_empty(),
                "{id} has empty summary"
            );
            assert!(op.get("risk_level").is_some(), "{id} missing risk_level");
            assert!(op.get("safety_tier").is_some(), "{id} missing safety_tier");
            assert!(op.get("capability").is_some(), "{id} missing capability");
            assert!(op.get("ai_hints").is_some(), "{id} missing ai_hints");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_risk_levels() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&risk), "{id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_safety_tiers() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid = ["safe", "risky", "dangerous"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "{id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_ai_hints_have_when_to_use() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hint = &op["ai_hints"];
            let when = hint["when_to_use"].as_str().unwrap_or("");
            assert!(!when.is_empty(), "{id} has empty ai_hints.when_to_use");
        }
    }

    // ── Capability mapping tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_capabilities_start_with_gcal() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("gcal."),
                "{id} capability should start with gcal.: {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_use_read_capabilities() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let read_ops = [
            "gcal.list_calendars",
            "gcal.get_calendar",
            "gcal.get_event",
            "gcal.list_events",
            "gcal.freebusy",
            "gcal.list_event_instances",
            "gcal.sync_events",
        ];

        for op_id in &read_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.contains(".read"),
                "{op_id} should have read capability, got {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_use_write_capabilities() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let write_ops = ["gcal.create_event", "gcal.update_event", "gcal.quick_add"];

        for op_id in &write_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.contains(".write"),
                "{op_id} should have write capability, got {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_op_uses_delete_capability() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some("gcal.delete_event"))
            .expect("delete_event op");
        let cap = op["capability"].as_str().unwrap();
        assert!(
            cap.contains(".delete") || cap.contains(".write"),
            "delete_event should have delete/write capability, got {cap}"
        );
    }

    // ── Safety tier verification ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_safe() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let safe_ops = [
            "gcal.list_calendars",
            "gcal.get_calendar",
            "gcal.get_event",
            "gcal.list_events",
            "gcal.freebusy",
            "gcal.list_event_instances",
            "gcal.sync_events",
        ];

        for op_id in &safe_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["safety_tier"].as_str(),
                Some("safe"),
                "{op_id} should be safe"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_are_risky() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let risky_ops = [
            "gcal.create_event",
            "gcal.update_event",
            "gcal.delete_event",
            "gcal.quick_add",
        ];

        for op_id in &risky_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["safety_tier"].as_str(),
                Some("risky"),
                "{op_id} should be risky"
            );
        }
    }

    // ── Required field validation ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_required_fields_in_schemas() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let expected: &[(&str, &[&str])] = &[
            ("gcal.get_event", &["calendar_id", "event_id"]),
            ("gcal.list_events", &["calendar_id"]),
            (
                "gcal.create_event",
                &["calendar_id", "summary", "start", "end"],
            ),
            ("gcal.update_event", &["calendar_id", "event_id"]),
            ("gcal.delete_event", &["calendar_id", "event_id"]),
            ("gcal.quick_add", &["calendar_id", "text"]),
            ("gcal.freebusy", &["time_min", "time_max", "items"]),
            ("gcal.list_event_instances", &["calendar_id", "event_id"]),
            ("gcal.get_calendar", &["calendar_id"]),
            ("gcal.sync_events", &["calendar_id"]),
        ];

        for (op_id, required_fields) in expected {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            let schema = &op["input_schema"];
            let req = schema["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{op_id} missing required array"));
            for field in *required_fields {
                assert!(
                    req.iter().any(|r| r.as_str() == Some(field)),
                    "{op_id} missing required field '{field}'"
                );
            }
        }
    }

    // ── Idempotency class tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_have_strict_idempotency() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let strict_ops = [
            "gcal.list_calendars",
            "gcal.get_calendar",
            "gcal.get_event",
            "gcal.list_events",
            "gcal.freebusy",
            "gcal.list_event_instances",
            "gcal.sync_events",
        ];

        for op_id in &strict_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["idempotency"].as_str(),
                Some("strict"),
                "{op_id} should have strict idempotency"
            );
        }
    }

    // ── Event capabilities tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_event_caps() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let event_caps = &result["event_caps"];
        assert!(
            event_caps.get("streaming").is_some() || event_caps.is_null(),
            "event_caps should be present or absent entirely"
        );
    }

    // ── Shutdown test ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = GoogleCalendarConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"].as_str(), Some("shutdown"));
    }

    // ── Risk level classification tests ──────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_delete_is_high_risk() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some("gcal.delete_event"))
            .expect("delete_event op");
        assert_eq!(
            op["risk_level"].as_str(),
            Some("high"),
            "delete_event should be high risk"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_update_are_medium_risk() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op_id in &["gcal.create_event", "gcal.update_event", "gcal.quick_add"] {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["risk_level"].as_str(),
                Some("medium"),
                "{op_id} should be medium risk"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_low_risk() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let low_risk_ops = [
            "gcal.list_calendars",
            "gcal.get_calendar",
            "gcal.get_event",
            "gcal.list_events",
            "gcal.freebusy",
            "gcal.list_event_instances",
            "gcal.sync_events",
        ];

        for op_id in &low_risk_ops {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing {op_id}"));
            assert_eq!(
                op["risk_level"].as_str(),
                Some("low"),
                "{op_id} should be low risk"
            );
        }
    }

    // ── Additional connector tests (2026-03-07) ──────────────────────────

    #[test]
    fn connector_default_impl() {
        let c = GoogleCalendarConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.authority.is_none());
        assert!(c.bound_zone.is_none());
    }

    #[test]
    fn require_str_returns_value() {
        let input = json!({"calendar_id": "primary"});
        let v = require_str(&input, "calendar_id").unwrap();
        assert_eq!(v, "primary");
    }

    #[test]
    fn require_str_missing_field_returns_error() {
        let input = json!({});
        let result = require_str(&input, "calendar_id");
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("calendar_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn require_str_null_value_returns_error() {
        let input = json!({"calendar_id": null});
        assert!(require_str(&input, "calendar_id").is_err());
    }

    #[test]
    fn require_str_integer_value_returns_error() {
        let input = json!({"calendar_id": 42});
        assert!(require_str(&input, "calendar_id").is_err());
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({"field": ""});
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn self_check_ok_result() {
        let report = self_check_report_from_result(Ok(()));
        let v = serde_json::to_value(report).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_eq!(DoctorStatus::Degraded, DoctorStatus::Degraded);
        assert_eq!(DoctorStatus::Unhealthy, DoctorStatus::Unhealthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for s in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(s).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn doctor_check_serialize() {
        let check = DoctorCheck {
            name: "test_check".into(),
            status: DoctorStatus::Healthy,
            message: "all good".into(),
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "test_check");
        assert_eq!(v["status"], "healthy");
        assert_eq!(v["message"], "all good");
    }

    #[test]
    fn doctor_result_serialize() {
        let result = DoctorResult {
            status: DoctorStatus::Degraded,
            checks: vec![DoctorCheck {
                name: "c1".into(),
                status: DoctorStatus::Degraded,
                message: "warning".into(),
            }],
        };
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"].as_array().unwrap().len(), 1);
    }
}
