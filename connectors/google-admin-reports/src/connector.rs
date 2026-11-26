//! FCP Google Admin Reports Connector implementation.

use std::collections::BTreeSet;
use std::sync::Arc;

use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    policy::{GooglePolicyCatalog, PolicyApprovalMode, PolicyRiskLevel, PolicySafetyTier},
    provisioning::load_default_google_provisioning_bundle,
};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{
        AdminReportsClient, DEFAULT_BASE_URL, google_auth_is_secretless, google_auth_redacted_label,
    },
    error::AdminReportsError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

struct AdminReportsConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl AdminReportsConfig {
    async fn from_params(params: &Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("admin-reports");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "admin" || service.api_version != "reports_v1" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to admin:reports_v1 (got {})",
                    service.identity()
                ),
            });
        }

        let required_scopes = resolve_admin_reports_required_scopes(params)?;
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
                message: format!("Failed to materialize Google auth: {error}"),
            })?;

        let base_url = match params.get("base_url") {
            Some(value) => validate_admin_reports_base_url(value.as_str().ok_or(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: "`base_url` must be a string".into(),
                },
            )?)?,
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

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_admin_reports_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("admin.googleapis.com")
}

/// Validate a google-admin-reports `base_url` override.
///
/// Pins the host to the Admin Reports API host (localhost permitted for tests),
/// requires https on non-local hosts, and rejects userinfo / query /
/// fragment because AdminReportsClient concatenates the returned
/// string into downstream request URLs.
fn validate_admin_reports_base_url(raw: &str) -> FcpResult<String> {
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
    if !local && !host_is_admin_reports_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target admin.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn parse_string_array_field(params: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
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

fn resolve_admin_reports_required_scopes(params: &Value) -> FcpResult<Vec<String>> {
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

    let bundle = load_default_google_provisioning_bundle("admin_reports").map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Failed to load embedded Google Admin Reports provisioning bundle: {error}"
            ),
        }
    })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid admin reports scope trigger selection: {error}"),
        })
}

#[allow(clippy::needless_pass_by_value)]
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

fn self_check_report_from_result(result: Result<(), AdminReportsError>) -> SelfCheckReport {
    match result {
        Ok(()) => SelfCheckReport::ok(),
        Err(error) => {
            if error.is_retryable() {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            } else {
                SelfCheckReport::failed("self_check_failed", error.to_string())
            }
        }
    }
}

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

pub struct AdminReportsConnector {
    base: Arc<BaseConnector>,
    config: Option<AdminReportsConfig>,
    client: Option<AdminReportsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl AdminReportsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-admin-reports",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = AdminReportsConfig::from_params(&params).await?;

        let client = AdminReportsClient::new_with_auth(config.auth.clone())
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to create HTTP client: {error}"),
            })?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Admin Reports connector configured"
        );

        let status = if google_auth_is_secretless(&config.auth) {
            "configured_pending_token_materialization"
        } else {
            "configured"
        };
        let details = json!({
            "service_identity": config.service_identity,
            "required_scopes": config.required_scopes,
            "auth_mode": google_auth_redacted_label(&config.auth),
            "base_url": config.base_url,
        });

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        Ok(json!({
            "status": status,
            "details": details
        }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if let Some(requested_instance_id) = req.requested_instance_id {
            let base = Arc::get_mut(&mut self.base).ok_or_else(|| FcpError::Internal {
                message: "Cannot assign requested instance ID after connector state is shared"
                    .into(),
            })?;
            base.instance_id = requested_instance_id;
        }

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            health["base_url"] = json!(config.base_url);
            health["service_identity"] = json!(config.service_identity);
            health["required_scopes"] = json!(config.required_scopes);
        }
        Ok(health)
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = Vec::new();

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
                message: "Connector is not configured - call `configure` first".into(),
            }
        });

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
            checks.push(DoctorCheck {
                name: "admin_context".into(),
                status: DoctorStatus::Healthy,
                message:
                    "Connector expects Workspace admin or delegated-admin credentials for the target tenant"
                        .into(),
            });
        } else {
            for name in [
                "service_identity",
                "auth_mode",
                "required_scopes",
                "admin_context",
            ] {
                checks.push(DoctorCheck {
                    name: name.to_string(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("{name} not set (not configured)"),
                });
            }
        }

        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: "Egress target: admin.googleapis.com".into(),
        });

        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Unhealthy)
        {
            DoctorStatus::Unhealthy
        } else if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Degraded)
        {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        serde_json::to_value(DoctorResult {
            status: overall,
            checks,
        })
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {error}"),
        })
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        };

        if let Some(config) = &self.config
            && google_auth_is_secretless(&config.auth)
        {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection required for checks",
            );
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        }

        let report = self_check_report_from_result(client.health_check().await);
        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let policy = load_admin_reports_policy_catalog()?;
        let introspection = Introspection {
            operations: vec![
                policy_backed_operation_info(
                    &policy,
                    "admin.list_activities",
                    "activities.list",
                    "List admin activity events for a Workspace application",
                    json!({
                        "type": "object",
                        "required": ["user_key", "application_name"],
                        "properties": {
                            "user_key": { "type": "string", "description": "User email, profile ID, or `all`." },
                            "application_name": { "type": "string", "description": "Workspace application name such as admin, login, drive, calendar, gmail, or chat." },
                            "start_time": { "type": "string", "description": "RFC 3339 timestamp." },
                            "end_time": { "type": "string", "description": "RFC 3339 timestamp." },
                            "event_name": { "type": "string" },
                            "filters": { "type": "string", "description": "Raw Admin Reports filter expression." },
                            "customer_id": { "type": "string" },
                            "org_unit_id": { "type": "string" },
                            "group_id_filter": { "type": "string" },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["items", "next_page_token"],
                        "properties": {
                            "items": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "kind": { "type": "string" },
                            "etag": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read domain-wide Workspace audit logs for a specific product or admin surface.".into(),
                        common_mistakes: vec![
                            "This is an admin-only audit surface and requires admin.reports.audit.readonly.".into(),
                            "Some applications impose extra constraints such as Gmail requiring bounded start/end times.".into(),
                        ],
                        examples: vec![
                            r#"{"user_key":"all","application_name":"login","max_results":100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.audit.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_user_usage",
                    "userUsageReport.get",
                    "List user usage reports for a given date",
                    json!({
                        "type": "object",
                        "required": ["user_key", "date"],
                        "properties": {
                            "user_key": { "type": "string" },
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "filters": { "type": "string", "description": "Comma-separated relational filters." },
                            "org_unit_id": { "type": "string" },
                            "group_id_filter": { "type": "string" },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["usage_reports", "next_page_token"],
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "kind": { "type": "string" },
                            "etag": { "type": "string" },
                            "warnings": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect per-user Workspace usage metrics for a specific date.".into(),
                        common_mistakes: vec![
                            "Usage reports require admin.reports.usage.readonly, not the audit scope.".into(),
                            "Usage data often lags by roughly 1-2 days.".into(),
                        ],
                        examples: vec![
                            r#"{"user_key":"all","date":"2026-03-12"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_customer_usage",
                    "customerUsageReports.get",
                    "List customer-wide usage reports for a given date",
                    json!({
                        "type": "object",
                        "required": ["date"],
                        "not": { "required": ["max_results"] },
                        "properties": {
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["usage_reports", "next_page_token"],
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "kind": { "type": "string" },
                            "etag": { "type": "string" },
                            "warnings": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read customer-wide Workspace usage totals for a specific date.".into(),
                        common_mistakes: vec![
                            "This is domain-level telemetry, not a personal-user analytics surface.".into(),
                        ],
                        examples: vec![
                            r#"{"date":"2026-03-12","parameters":"accounts:num_users,gmail:num_emails_sent"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_entity_usage",
                    "entityUsageReports.get",
                    "List entity usage reports for a date",
                    json!({
                        "type": "object",
                        "required": ["entity_type", "entity_key", "date"],
                        "properties": {
                            "entity_type": { "type": "string", "description": "Admin Reports entity type such as gplus_communities." },
                            "entity_key": { "type": "string" },
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "filters": { "type": "string", "description": "Comma-separated relational filters." },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["usage_reports", "next_page_token"],
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "kind": { "type": "string" },
                            "etag": { "type": "string" },
                            "warnings": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect entity-specific Workspace usage data for niche admin reports surfaces.".into(),
                        common_mistakes: vec![
                            "Entity usage is narrow and still requires the usage.readonly scope.".into(),
                        ],
                        examples: vec![
                            r#"{"entity_type":"gplus_communities","entity_key":"all","date":"2026-03-12"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize introspection: {error}"),
        })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let capability = match admin_reports_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = validate_admin_reports_input(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let resource_uris = admin_reports_resource_uris(req.operation.as_str(), &req.input);
        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let is_grant_mismatch = matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                );
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if is_grant_mismatch {
                    response =
                        response.with_missing_capabilities(vec![capability.as_str().to_string()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;
        let input = params.get("input").cloned().unwrap_or(json!({}));
        validate_admin_reports_input(operation, &input)?;
        self.base.check_ready()?;

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;
        let parsed_capability = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID".into(),
        })?;
        let cap_id = admin_reports_capability_for_operation(operation)?;
        let resource_uris = admin_reports_resource_uris(operation, &input);

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(parsed_capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "admin.list_activities" => self.invoke_list_activities(input).await,
            "admin.list_user_usage" => self.invoke_list_user_usage(input).await,
            "admin.list_customer_usage" => self.invoke_list_customer_usage(input).await,
            "admin.list_entity_usage" => self.invoke_list_entity_usage(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_list_activities(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_key = require_str(&input, "user_key")?;
        let app_name = require_str(&input, "application_name")?;
        let start = input.get("start_time").and_then(|v| v.as_str());
        let end = input.get("end_time").and_then(|v| v.as_str());
        let event_name = input.get("event_name").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let org_unit_id = input.get("org_unit_id").and_then(|v| v.as_str());
        let group_id_filter = input.get("group_id_filter").and_then(|v| v.as_str());
        let (max, page_cursor) = parse_admin_reports_pagination("admin.list_activities", &input)?;

        let result = client
            .list_activities(
                user_key,
                app_name,
                start,
                end,
                event_name,
                filters,
                max,
                page_cursor,
                customer_id,
                org_unit_id,
                group_id_filter,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        Ok(result.into_public_response())
    }

    async fn invoke_list_user_usage(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_key = require_str(&input, "user_key")?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let org_unit_id = input.get("org_unit_id").and_then(|v| v.as_str());
        let group_id_filter = input.get("group_id_filter").and_then(|v| v.as_str());
        let (max, page_cursor) = parse_admin_reports_pagination("admin.list_user_usage", &input)?;

        let result = client
            .list_user_usage(
                user_key,
                date,
                customer_id,
                parameters,
                filters,
                max,
                page_cursor,
                org_unit_id,
                group_id_filter,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        Ok(result.into_public_response())
    }

    async fn invoke_list_customer_usage(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let (_, page_cursor) = parse_admin_reports_pagination("admin.list_customer_usage", &input)?;

        let result = client
            .list_customer_usage(date, customer_id, parameters, page_cursor)
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        Ok(result.into_public_response())
    }

    async fn invoke_list_entity_usage(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let entity_type = require_str(&input, "entity_type")?;
        let entity_key = require_str(&input, "entity_key")?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let (max, page_cursor) = parse_admin_reports_pagination("admin.list_entity_usage", &input)?;

        let result = client
            .list_entity_usage(
                entity_type,
                entity_key,
                date,
                customer_id,
                parameters,
                filters,
                max,
                page_cursor,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        Ok(result.into_public_response())
    }

    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Admin Reports connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AdminReportsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn load_admin_reports_policy_catalog() -> FcpResult<GooglePolicyCatalog> {
    let catalog = GooglePolicyCatalog::load_default().map_err(|error| FcpError::Internal {
        message: format!("Failed to load embedded Google policy catalog: {error}"),
    })?;
    catalog.service("admin").ok_or(FcpError::Internal {
        message: "Embedded Google policy catalog is missing admin:reports_v1 service rules".into(),
    })?;
    Ok(catalog)
}

fn admin_reports_discovery_method_key(operation: &str) -> FcpResult<&'static str> {
    match operation {
        "admin.list_activities" => Ok("activities.list"),
        "admin.list_user_usage" => Ok("userUsageReport.get"),
        "admin.list_customer_usage" => Ok("customerUsageReports.get"),
        "admin.list_entity_usage" => Ok("entityUsageReports.get"),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn admin_reports_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let discovery_method_key = admin_reports_discovery_method_key(operation)?;
    let policy = load_admin_reports_policy_catalog()?;
    let resolved = policy
        .classify_operation("admin", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing Admin Reports policy mapping for `{discovery_method_key}`"),
        })?;
    CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| FcpError::Internal {
        message: format!(
            "Invalid capability `{}` in Admin Reports policy catalog: {error}",
            resolved.rule.capability
        ),
    })
}

fn validate_admin_reports_input(operation: &str, input: &Value) -> FcpResult<()> {
    if !input.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Admin Reports input must be an object".into(),
        });
    }
    let optional_fields: &[&str] = match operation {
        "admin.list_activities" => {
            require_str(input, "user_key")?;
            require_str(input, "application_name")?;
            &[
                "start_time",
                "end_time",
                "event_name",
                "filters",
                "customer_id",
                "org_unit_id",
                "group_id_filter",
            ]
        }
        "admin.list_user_usage" => {
            require_str(input, "user_key")?;
            require_str(input, "date")?;
            &[
                "customer_id",
                "parameters",
                "filters",
                "org_unit_id",
                "group_id_filter",
            ]
        }
        "admin.list_customer_usage" => {
            require_str(input, "date")?;
            &["customer_id", "parameters"]
        }
        "admin.list_entity_usage" => {
            require_str(input, "entity_type")?;
            require_str(input, "entity_key")?;
            require_str(input, "date")?;
            &["customer_id", "parameters", "filters"]
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    for field in optional_fields {
        optional_nonempty_string(input, field)?;
    }
    parse_admin_reports_pagination(operation, input)?;
    Ok(())
}

fn optional_nonempty_string<'a>(input: &'a Value, field: &str) -> FcpResult<Option<&'a str>> {
    input
        .get(field)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must be a non-empty string when provided"),
                })
        })
        .transpose()
}

fn parse_admin_reports_pagination<'a>(
    operation: &str,
    input: &'a Value,
) -> FcpResult<(Option<u32>, Option<&'a str>)> {
    let max_results = input
        .get("max_results")
        .map(|value| {
            if operation == "admin.list_customer_usage" {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "admin.list_customer_usage does not support max_results".into(),
                });
            }
            // Google's Reports discovery document specifies 1..=1000 for each of
            // activities.list, userUsageReport.get and entityUsageReports.get.
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| (1..=1000).contains(value))
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "max_results must be an integer between 1 and 1000".into(),
                })
        })
        .transpose()?;
    let page_token = optional_nonempty_string(input, "page_token")?;
    Ok((max_results, page_token))
}

fn encoded_input(input: &Value, field: &str) -> Option<String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(|value| urlencoding::encode(value).into_owned())
}

fn admin_reports_resource_uris(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        "admin.list_activities" => match (
            encoded_input(input, "user_key"),
            encoded_input(input, "application_name"),
        ) {
            (Some(user_key), Some(application_name)) => {
                vec![format!(
                    "google-admin-reports://activities/users/{user_key}/applications/{application_name}"
                )]
            }
            _ => Vec::new(),
        },
        "admin.list_user_usage" => match (
            encoded_input(input, "user_key"),
            encoded_input(input, "date"),
        ) {
            (Some(user_key), Some(date)) => {
                vec![format!(
                    "google-admin-reports://usage/users/{user_key}/dates/{date}"
                )]
            }
            _ => Vec::new(),
        },
        "admin.list_customer_usage" => encoded_input(input, "date").map_or_else(Vec::new, |date| {
            vec![format!(
                "google-admin-reports://usage/customers/all/dates/{date}"
            )]
        }),
        "admin.list_entity_usage" => match (
            encoded_input(input, "entity_type"),
            encoded_input(input, "entity_key"),
            encoded_input(input, "date"),
        ) {
            (Some(entity_type), Some(entity_key), Some(date)) => {
                vec![format!(
                    "google-admin-reports://usage/entities/{entity_type}/{entity_key}/dates/{date}"
                )]
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn policy_backed_operation_info(
    policy: &GooglePolicyCatalog,
    id: &'static str,
    discovery_method_key: &'static str,
    summary: &str,
    mut input_schema: Value,
    output_schema: Value,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> FcpResult<OperationInfo> {
    // Required path selectors and optional query strings use the same
    // non-empty validation. In particular, opaque cursors must never silently
    // become a first-page request when the caller supplied a malformed value.
    if let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
    {
        for property in properties.values_mut() {
            if property.get("type").and_then(Value::as_str) == Some("string") {
                property["minLength"] = json!(1);
                property["pattern"] = json!("\\S");
            }
        }
    }
    let resolved = policy
        .classify_operation("admin", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing Admin Reports policy mapping for `{discovery_method_key}`"),
        })?;
    let capability = CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Invalid capability `{}` in Admin Reports policy catalog: {error}",
                resolved.rule.capability
            ),
        }
    })?;

    Ok(OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability,
        risk_level: map_policy_risk_level(resolved.rule.risk_level),
        description: None,
        rate_limit: None,
        requires_approval: map_policy_approval_mode(resolved.rule.approval_mode),
        safety_tier: map_policy_safety_tier(resolved.rule.safety_tier),
        idempotency,
        ai_hints,
    })
}

const fn map_policy_risk_level(level: PolicyRiskLevel) -> RiskLevel {
    match level {
        PolicyRiskLevel::Low => RiskLevel::Low,
        PolicyRiskLevel::Medium => RiskLevel::Medium,
        PolicyRiskLevel::High => RiskLevel::High,
        PolicyRiskLevel::Critical => RiskLevel::Critical,
    }
}

const fn map_policy_safety_tier(tier: PolicySafetyTier) -> SafetyTier {
    match tier {
        PolicySafetyTier::Safe => SafetyTier::Safe,
        PolicySafetyTier::Risky => SafetyTier::Risky,
        PolicySafetyTier::Dangerous => SafetyTier::Dangerous,
        PolicySafetyTier::Critical => SafetyTier::Critical,
        PolicySafetyTier::Forbidden => SafetyTier::Forbidden,
    }
}

const fn map_policy_approval_mode(mode: PolicyApprovalMode) -> Option<ApprovalMode> {
    match mode {
        PolicyApprovalMode::None => None,
        PolicyApprovalMode::Policy => Some(ApprovalMode::Policy),
        PolicyApprovalMode::Interactive => Some(ApprovalMode::Interactive),
        PolicyApprovalMode::ElevationToken /* explicit approval */ => {
            Some(ApprovalMode::ElevationToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, ZoneId};
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUDIT_CAPABILITY: &str = "admin.reports.audit.read";
    const USAGE_CAPABILITY: &str = "admin.reports.usage.read";
    const LIST_ACTIVITIES: &str = "admin.list_activities";

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));
        let actual = AdminReportsConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:google-admin-reports-v1");
    }

    fn config_with_test_bearer(extra: &[(&str, Value)]) -> Value {
        let mut params = serde_json::Map::new();
        params.insert(
            ["access", "token"].join("_"),
            json!(["ya29", "test"].join(".")),
        );
        for (key, value) in extra {
            params.insert((*key).to_string(), value.clone());
        }
        Value::Object(params)
    }

    fn valid_activity_input() -> Value {
        json!({
            "user_key": "all",
            "application_name": "login"
        })
    }

    fn generate_capability(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operation: &'static str,
    ) -> CapabilityToken {
        generate_capability_for_instance(signing_key, capability, operation, None)
    }

    fn generate_capability_for_instance(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operation: &'static str,
        instance_id: Option<&fcp_prelude::InstanceId>,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let mut builder = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate");
        if let Some(instance_id) = instance_id {
            builder = builder.target_instance(instance_id.as_str());
        }
        let cose = builder.sign(signing_key).unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        operation: &'static str,
        input: Value,
        capability: CapabilityToken,
    ) -> Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("google-admin-reports"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_connector() -> AdminReportsConnector {
        let mut connector = AdminReportsConnector::new();
        connector
            .handle_configure(config_with_test_bearer(&[]))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_connector() -> (AdminReportsConnector, Ed25519SigningKey) {
        let mut connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [AUDIT_CAPABILITY]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    async fn loopback_connector(base_url: &str) -> (AdminReportsConnector, Ed25519SigningKey) {
        let mut connector = AdminReportsConnector::new();
        connector
            .handle_configure(config_with_test_bearer(&[
                ("base_url", json!(base_url)),
                (
                    "required_scopes",
                    json!([
                        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                        "https://www.googleapis.com/auth/admin.reports.usage.readonly"
                    ]),
                ),
            ]))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [AUDIT_CAPABILITY, USAGE_CAPABILITY]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    async fn assert_two_public_pages(
        operation: &'static str,
        input: Value,
        provider_path: &str,
        expected_query: &[(&str, &str)],
    ) {
        let server = MockServer::start().await;
        let cursor = "page+/=&?opaque";
        let is_usage = operation != LIST_ACTIVITIES;
        let warnings = json!([{
            "code": "200",
            "message": "Partial data is available",
            "data": [{ "key": "application", "value": "gmail" }]
        }]);
        for page in 1..=2 {
            let mut body = if is_usage {
                json!({
                    "usageReports": [{
                        "date": "2026-03-13",
                        "entity": { "userEmail": format!("user-{page}@example.test") },
                        "parameters": [{
                            "name": "accounts:num_logins",
                            "intValue": page.to_string()
                        }]
                    }],
                    "warnings": warnings,
                    "etag": format!("page-{page}")
                })
            } else {
                json!({
                    "items": [{
                        "id": { "uniqueQualifier": page.to_string(), "applicationName": "login" },
                        "actor": { "profileId": format!("profile-{page}") },
                        "ipAddress": "192.0.2.1"
                    }],
                    "etag": format!("page-{page}")
                })
            };
            let mut mock = Mock::given(method("GET"))
                .and(path(provider_path))
                .and(header("authorization", "Bearer ya29.test"));
            for (key, value) in expected_query {
                mock = mock.and(query_param(*key, *value));
            }
            if operation == "admin.list_customer_usage" {
                mock = mock.and(query_param_is_missing("maxResults"));
            }
            if page == 1 {
                body["nextPageToken"] = json!(cursor);
                body["kind"] = json!(if is_usage {
                    "admin#reports#usageReports"
                } else {
                    "admin#reports#activities"
                });
                mock = mock.and(query_param_is_missing("pageToken"));
            } else {
                mock = mock.and(query_param("pageToken", cursor));
            }
            mock.respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let (connector, signing_key) =
            loopback_connector(&format!("{}/admin/reports/v1", server.uri())).await;
        let capability = generate_capability_for_instance(
            &signing_key,
            if is_usage {
                USAGE_CAPABILITY
            } else {
                AUDIT_CAPABILITY
            },
            operation,
            Some(&connector.base.instance_id),
        );
        let first = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": input,
                "capability_token": capability
            }))
            .await
            .expect("fetch first report page through public invocation");
        assert_eq!(first["next_page_token"], cursor);
        assert_eq!(first["etag"], "page-1");
        assert!(first["kind"].is_string());
        assert!(first.get("nextPageToken").is_none());
        assert!(first.get("usageReports").is_none());

        let mut continued_input = input.clone();
        continued_input["page_token"] = first["next_page_token"].clone();
        let second = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": continued_input,
                "capability_token": capability
            }))
            .await
            .expect("continue using the returned public cursor");
        assert_eq!(second.get("next_page_token"), Some(&Value::Null));
        assert_eq!(second["etag"], "page-2");
        assert!(second.get("kind").is_none());
        assert!(second.get("nextPageToken").is_none());
        assert!(second.get("usageReports").is_none());
        if is_usage {
            assert_eq!(
                first["usage_reports"][0]["entity"]["userEmail"],
                "user-1@example.test"
            );
            assert_eq!(
                second["usage_reports"][0]["entity"]["userEmail"],
                "user-2@example.test"
            );
            assert_eq!(second["usage_reports"][0]["parameters"][0]["intValue"], "2");
            assert_eq!(first["warnings"], warnings);
            assert_eq!(second["warnings"], warnings);
        } else {
            assert_eq!(first["items"][0]["id"]["uniqueQualifier"], "1");
            assert_eq!(second["items"][0]["id"]["uniqueQualifier"], "2");
            assert_eq!(second["items"][0]["actor"]["profileId"], "profile-2");
            assert_eq!(second["items"][0]["ipAddress"], "192.0.2.1");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn public_activity_pagination_preserves_all_filters() {
        assert_two_public_pages(
            LIST_ACTIVITIES,
            json!({
                "user_key": "all",
                "application_name": "login",
                "start_time": "2026-03-13T00:00:00Z",
                "end_time": "2026-03-14T00:00:00Z",
                "event_name": "login_success",
                "filters": "ip_address==192.0.2.1",
                "customer_id": "C123",
                "org_unit_id": "id:engineering",
                "group_id_filter": "id:abc123,id:xyz456",
                "max_results": 1
            }),
            "/admin/reports/v1/activity/users/all/applications/login",
            &[
                ("startTime", "2026-03-13T00:00:00Z"),
                ("endTime", "2026-03-14T00:00:00Z"),
                ("eventName", "login_success"),
                ("filters", "ip_address==192.0.2.1"),
                ("customerId", "C123"),
                ("orgUnitID", "id:engineering"),
                ("groupIdFilter", "id:abc123,id:xyz456"),
                ("maxResults", "1"),
            ],
        )
        .await;
    }

    #[fcp_async_core::runtime::test]
    async fn public_user_usage_pagination_preserves_all_filters() {
        assert_two_public_pages(
            "admin.list_user_usage",
            json!({
                "user_key": "all",
                "date": "2026-03-13",
                "customer_id": "C123",
                "parameters": "accounts:num_logins,gmail:num_emails_sent",
                "filters": "accounts:num_logins>=1",
                "org_unit_id": "id:engineering",
                "group_id_filter": "id:abc123,id:xyz456",
                "max_results": 1
            }),
            "/admin/reports/v1/usage/users/all/dates/2026-03-13",
            &[
                ("customerId", "C123"),
                ("parameters", "accounts:num_logins,gmail:num_emails_sent"),
                ("filters", "accounts:num_logins>=1"),
                ("orgUnitID", "id:engineering"),
                ("groupIdFilter", "id:abc123,id:xyz456"),
                ("maxResults", "1"),
            ],
        )
        .await;
    }

    #[fcp_async_core::runtime::test]
    async fn public_customer_usage_pagination_preserves_all_filters() {
        assert_two_public_pages(
            "admin.list_customer_usage",
            json!({
                "date": "2026-03-13",
                "customer_id": "C123",
                "parameters": "accounts:num_users,gmail:num_emails_sent"
            }),
            "/admin/reports/v1/usage/dates/2026-03-13",
            &[
                ("customerId", "C123"),
                ("parameters", "accounts:num_users,gmail:num_emails_sent"),
            ],
        )
        .await;
    }

    #[fcp_async_core::runtime::test]
    async fn public_entity_usage_pagination_preserves_all_filters() {
        assert_two_public_pages(
            "admin.list_entity_usage",
            json!({
                "entity_type": "gplus_communities",
                "entity_key": "all",
                "date": "2026-03-13",
                "customer_id": "C123",
                "parameters": "gplus:num_total_communities",
                "filters": "gplus:num_total_communities>=1",
                "max_results": 1
            }),
            "/admin/reports/v1/usage/gplus_communities/all/dates/2026-03-13",
            &[
                ("customerId", "C123"),
                ("parameters", "gplus:num_total_communities"),
                ("filters", "gplus:num_total_communities>=1"),
                ("maxResults", "1"),
            ],
        )
        .await;
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_pagination_is_rejected_before_admission_or_provider_io() {
        let server = MockServer::start().await;
        let (connector, signing_key) =
            loopback_connector(&format!("{}/admin/reports/v1", server.uri())).await;
        for (operation, input) in [
            (LIST_ACTIVITIES, valid_activity_input()),
            (
                "admin.list_user_usage",
                json!({"user_key":"all", "date":"2026-03-13"}),
            ),
            ("admin.list_customer_usage", json!({"date":"2026-03-13"})),
            (
                "admin.list_entity_usage",
                json!({
                    "entity_type":"gplus_communities", "entity_key":"all", "date":"2026-03-13"
                }),
            ),
        ] {
            let capability = generate_capability_for_instance(
                &signing_key,
                if operation == LIST_ACTIVITIES {
                    AUDIT_CAPABILITY
                } else {
                    USAGE_CAPABILITY
                },
                operation,
                Some(&connector.base.instance_id),
            );
            let mut cases: Vec<(&str, Value)> = [
                Value::Null,
                json!(true),
                json!(7),
                json!([]),
                json!({}),
                json!(""),
                json!(" \t\n"),
            ]
            .into_iter()
            .map(|value| ("page_token", value))
            .collect();
            cases.extend(
                [
                    json!(0),
                    json!(1001),
                    json!(u64::MAX),
                    json!(-1),
                    json!(1.5),
                    json!("2"),
                    json!(true),
                    Value::Null,
                ]
                .into_iter()
                .map(|value| ("max_results", value)),
            );
            if operation == "admin.list_customer_usage" {
                cases.push(("max_results", json!(1)));
                cases.push(("parameters", json!([])));
            } else {
                cases.push(("filters", json!(42)));
            }
            for (field, value) in cases {
                let mut malformed = input.clone();
                malformed[field] = value;
                // No token: input rejection must precede the admission failure.
                let error = connector
                    .handle_invoke(json!({
                        "operation":operation, "input":malformed
                    }))
                    .await
                    .unwrap_err();
                assert!(
                    matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains(field)),
                    "{operation}: expected {field} validation before capability admission, got {error:?}"
                );
                let simulation = parse_simulate_response(
                    connector
                        .handle_simulate(simulate_request(operation, malformed, capability.clone()))
                        .await
                        .unwrap(),
                );
                assert!(!simulation.would_succeed, "{operation}: {field}");
                assert_eq!(
                    simulation.denial_code,
                    Some(error.error_code()),
                    "{operation}: {field}"
                );
            }
            let mut valid = input.clone();
            valid["page_token"] = json!("opaque+/=&?");
            for limit in [None, Some(1), Some(1000)] {
                if operation == "admin.list_customer_usage" && limit.is_some() {
                    continue;
                }
                if let Some(limit) = limit {
                    valid["max_results"] = json!(limit);
                }
                let simulation = parse_simulate_response(
                    connector
                        .handle_simulate(simulate_request(
                            operation,
                            valid.clone(),
                            capability.clone(),
                        ))
                        .await
                        .unwrap(),
                );
                assert!(
                    simulation.would_succeed,
                    "{operation}: valid boundary {limit:?}"
                );
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn admitted_manifest_and_introspection_have_matching_pagination_contracts() {
        let manifest = fcp_manifest::ConnectorManifest::parse_str(MANIFEST_TOML)
            .expect("bundled manifest must pass semantic admission");
        let introspection = AdminReportsConnector::new()
            .handle_introspect()
            .await
            .unwrap();
        let operations = introspection["operations"].as_array().unwrap();
        assert_eq!(manifest.provides.operations.len(), operations.len());
        for runtime in operations {
            let id = runtime["id"].as_str().unwrap();
            let declared = manifest.provides.operations.get(id).unwrap();
            assert_eq!(
                declared.output_schema, runtime["output_schema"],
                "{id}: output"
            );
            assert_eq!(
                declared.input_schema["required"], runtime["input_schema"]["required"],
                "{id}: required inputs"
            );
            assert_eq!(
                declared.input_schema["not"], runtime["input_schema"]["not"],
                "{id}: unsupported fields"
            );
            let declared_properties = declared.input_schema["properties"].as_object().unwrap();
            let runtime_properties = runtime["input_schema"]["properties"].as_object().unwrap();
            assert_eq!(
                declared_properties
                    .keys()
                    .collect::<std::collections::BTreeSet<_>>(),
                runtime_properties
                    .keys()
                    .collect::<std::collections::BTreeSet<_>>(),
                "{id}: exposed inputs"
            );
            for (name, schema) in declared_properties {
                for constraint in ["type", "minimum", "maximum", "minLength", "pattern"] {
                    assert_eq!(
                        schema[constraint], runtime_properties[name][constraint],
                        "{id}: {name}.{constraint}"
                    );
                }
            }
        }
    }

    #[test]
    fn validate_admin_reports_base_url_accepts_googleapis() {
        let out = validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1")
            .unwrap();
        assert_eq!(out, "https://admin.googleapis.com/admin/reports/v1");
    }

    #[test]
    fn validate_admin_reports_base_url_allows_localhost_http() {
        validate_admin_reports_base_url("http://localhost:9999").unwrap();
        validate_admin_reports_base_url("http://127.0.0.1/admin").unwrap();
        validate_admin_reports_base_url("http://[::1]:9999/admin").unwrap();
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_foreign_host() -> Result<(), String> {
        let err = validate_admin_reports_base_url("https://evil.example.com/admin/reports/v1")
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("admin.googleapis.com"), "got: {message}");
                Ok(())
            }
            other => Err(format!("expected InvalidRequest, got {other:?}")),
        }
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_substring_smuggle() {
        let err =
            validate_admin_reports_base_url("https://evil.com/admin.googleapis.com/reports/v1")
                .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_q_f_u() -> Result<(), String> {
        assert!(matches!(
            validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1?leak=x")
                .unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1#frag")
                .unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err = validate_admin_reports_base_url(
            "https://attacker:pw@admin.googleapis.com/admin/reports/v1",
        )
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
                Ok(())
            }
            other => Err(format!("expected InvalidRequest, got {other:?}")),
        }
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_plain_http_on_public_host() {
        let err = validate_admin_reports_base_url("http://admin.googleapis.com/admin/reports/v1")
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn host_is_admin_reports_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_admin_reports_googleapis("admin.googleapis.com"));
        assert!(!host_is_admin_reports_googleapis("googleapis.com"));
        assert!(!host_is_admin_reports_googleapis("www.googleapis.com"));
        assert!(!host_is_admin_reports_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_admin_reports_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resolve_admin_reports_required_scopes_defaults_to_audit_readonly() {
        let scopes = resolve_admin_reports_required_scopes(&json!({})).unwrap();
        assert_eq!(
            scopes,
            vec!["https://www.googleapis.com/auth/admin.reports.audit.readonly".to_string()]
        );
    }

    #[test]
    fn resolve_admin_reports_required_scopes_applies_usage_trigger() {
        let scopes = resolve_admin_reports_required_scopes(&json!({
            "scope_triggers": [
                "User enables usage-report workflows (user, customer, or entity usage metrics)."
            ]
        }))
        .unwrap();
        assert!(
            scopes.contains(
                &"https://www.googleapis.com/auth/admin.reports.audit.readonly".to_string()
            )
        );
        assert!(
            scopes.contains(
                &"https://www.googleapis.com/auth/admin.reports.usage.readonly".to_string()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_all_operations() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"admin.list_activities"));
        assert!(ids.contains(&"admin.list_user_usage"));
        assert!(ids.contains(&"admin.list_customer_usage"));
        assert!(ids.contains(&"admin.list_entity_usage"));

        let activity = ops
            .iter()
            .find(|op| op["id"] == "admin.list_activities")
            .unwrap();
        assert_eq!(activity["capability"], "admin.reports.audit.read");
        assert_eq!(activity["requires_approval"], "policy");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_bearer_and_admin_alias() {
        let mut connector = AdminReportsConnector::new();
        let result = connector
            .handle_configure(config_with_test_bearer(&[(
                "service_selector",
                json!("admin-reports"),
            )]))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert_eq!(result["details"]["service_identity"], "admin:reports_v1");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_no_auth_fails() {
        let mut connector = AdminReportsConnector::new();
        assert!(connector.handle_configure(json!({})).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_base_url_override() {
        let mut connector = AdminReportsConnector::new();
        let err = connector
            .handle_configure(config_with_test_bearer(&[("base_url", json!(123))]))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
            "expected base_url validation error, got {err:?}"
        );

        let mut connector = AdminReportsConnector::new();
        let err = connector
            .handle_configure(config_with_test_bearer(&[("base_url", json!(""))]))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
            "expected empty base_url validation error, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_configure_denied() {
        let connector = AdminReportsConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_capability(&signing_key, AUDIT_CAPABILITY, LIST_ACTIVITIES);
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    LIST_ACTIVITIES,
                    valid_activity_input(),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_handshake_denied() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_capability(&signing_key, AUDIT_CAPABILITY, LIST_ACTIVITIES);
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    LIST_ACTIVITIES,
                    valid_activity_input(),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotHandshaken.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_wrong_capability_denied() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_capability_for_instance(
            &signing_key,
            USAGE_CAPABILITY,
            LIST_ACTIVITIES,
            Some(&connector.base.instance_id),
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    LIST_ACTIVITIES,
                    valid_activity_input(),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.missing_capabilities,
            vec![AUDIT_CAPABILITY.to_string()]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation_allowed() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_capability_for_instance(
            &signing_key,
            AUDIT_CAPABILITY,
            LIST_ACTIVITIES,
            Some(&connector.base.instance_id),
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    LIST_ACTIVITIES,
                    valid_activity_input(),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_capability(&signing_key, AUDIT_CAPABILITY, LIST_ACTIVITIES);
        let err = connector
            .handle_invoke(json!({
                "operation": LIST_ACTIVITIES,
                "input": valid_activity_input(),
                "capability_token": capability
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation_denied() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_capability(&signing_key, AUDIT_CAPABILITY, LIST_ACTIVITIES);
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "admin.unknown_operation",
                    valid_activity_input(),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: "admin.unknown_operation".into()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[test]
    fn default_impl() {
        let _c = AdminReportsConnector::default();
    }
}
