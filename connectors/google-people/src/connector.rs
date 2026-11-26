//! FCP Google People Connector implementation.

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
        DEFAULT_BASE_URL, GooglePeopleClient, google_auth_is_secretless, google_auth_redacted_label,
    },
    error::GooglePeopleError,
};

const DEFAULT_CONTACT_FIELDS: &[&str] =
    &["names", "emailAddresses", "phoneNumbers", "organizations"];
const DEFAULT_OTHER_CONTACT_FIELDS: &[&str] = &["names", "emailAddresses", "phoneNumbers"];
const DEFAULT_DIRECTORY_FIELDS: &[&str] = &["names", "emailAddresses", "organizations"];
const DEFAULT_GROUP_FIELDS: &[&str] = &["name", "groupType", "memberCount"];
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn validate_people_base_url(raw: &str) -> FcpResult<String> {
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
    if !matches!(parsed.scheme(), "http" | "https") {
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
    if !local && !host.eq_ignore_ascii_case("people.googleapis.com") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target people.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

/// Validated configuration for the Google People connector.
struct GooglePeopleConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl GooglePeopleConfig {
    async fn from_params(params: &Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("people");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "people" || service.api_version != "v1" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to people:v1 (got {})",
                    service.identity()
                ),
            });
        }

        let required_scopes = resolve_people_required_scopes(params)?;
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
                validate_people_base_url(value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url must be a string".into(),
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

fn parse_string_list_or_csv(input: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    match value {
        Value::String(raw) => {
            let values = raw
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("`{field}` must not be empty"),
                });
            }
            Ok(Some(values))
        }
        Value::Array(_) => parse_string_array_field(input, field),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must be a string or array of strings"),
        }),
    }
}

fn resolve_people_required_scopes(params: &Value) -> FcpResult<Vec<String>> {
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

    let bundle =
        load_default_google_provisioning_bundle("people").map_err(|error| FcpError::Internal {
            message: format!("Failed to load embedded Google People provisioning bundle: {error}"),
        })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid people scope trigger selection: {error}"),
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

fn self_check_report_from_result(result: Result<(), GooglePeopleError>) -> SelfCheckReport {
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

/// FCP Google People Connector.
pub struct GooglePeopleConnector {
    base: Arc<BaseConnector>,
    config: Option<GooglePeopleConfig>,
    client: Option<GooglePeopleClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GooglePeopleConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-people",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = GooglePeopleConfig::from_params(&params).await?;

        let client = GooglePeopleClient::new_with_auth(config.auth.clone())
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to create HTTP client: {error}"),
            })?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Google People connector configured"
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

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {error}"),
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

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
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

        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
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
                message: "Connector is not configured – call `configure` first".into(),
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
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
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
            for name in [
                "base_url",
                "service_identity",
                "auth_mode",
                "required_scopes",
            ] {
                checks.push(DoctorCheck {
                    name: name.to_string(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("{name} not set (not configured)"),
                });
            }
        }

        let egress_target = self
            .config
            .as_ref()
            .map_or("people.googleapis.com", |config| {
                config
                    .base_url
                    .strip_prefix("https://")
                    .or_else(|| config.base_url.strip_prefix("http://"))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("people.googleapis.com")
            });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Healthy,
                message: if google_auth_is_secretless(&config.auth) {
                    "Secretless mode – egress proxy will inject credentials".into()
                } else {
                    "Direct token mode – no proxy injection needed".into()
                },
            });
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

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
        let policy = load_people_policy_catalog()?;
        let introspection = Introspection {
            operations: vec![
                policy_backed_operation_info(
                    &policy,
                    "people.list_connections",
                    "people.connections.list",
                    "List the authenticated user's contacts",
                    json!({
                        "type": "object",
                        "properties": {
                            "person_fields": { "type": "array", "items": { "type": "string" }, "description": "Explicit People field mask entries to return." },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string", "minLength": 1 },
                            "sort_order": { "type": "string", "description": "People API sort order such as LAST_MODIFIED_ASCENDING." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "connections": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "next_sync_token": { "type": ["string", "null"] },
                            "total_people": { "type": ["integer", "null"] },
                            "total_items": { "type": ["integer", "null"] }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Enumerate the authenticated user's contact corpus with an explicit field mask.".into(),
                        common_mistakes: vec![
                            "Broad field masks widen privacy exposure; request only the fields you need.".into(),
                            "Pass next_page_token as page_token with the same field mask, page size, and sort order until no token remains.".into(),
                        ],
                        examples: vec![
                            r#"{"person_fields":["names","emailAddresses"],"page_size":50}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.profile.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.get_person",
                    "people.get",
                    "Get a single contact or directory person by resource name",
                    json!({
                        "type": "object",
                        "required": ["resource_name"],
                        "properties": {
                            "resource_name": { "type": "string", "description": "Google People resource name such as people/c123. `people/me` is intentionally rejected by this connector." },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "sources": { "type": "array", "items": { "type": "string" }, "description": "Optional People source filters." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Fetch one People resource when you already have its resource name.".into(),
                        common_mistakes: vec![
                            "This connector intentionally does not expose `people/me` because self-profile reads can require broader personal-profile scopes.".into(),
                        ],
                        examples: vec![
                            r#"{"resource_name":"people/c123","person_fields":["names","emailAddresses"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.search_contacts",
                    "people.searchContacts",
                    "Search the authenticated user's contacts",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 30 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "results": { "type": "array", "items": { "type": "object" } } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Find matching contacts by name, email, or phone fragments.".into(),
                        common_mistakes: vec![
                            "Remember that `person_fields` controls the returned fields, not the search query.".into(),
                            "Contact search returns at most 30 matches and does not support page_token; use list_connections to enumerate contacts.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"alice","person_fields":["names","emailAddresses"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.list_other_contacts",
                    "otherContacts.list",
                    "List Google-suggested other contacts",
                    json!({
                        "type": "object",
                        "properties": {
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string", "minLength": 1 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "other_contacts": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "total_size": { "type": ["integer", "null"] }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read the separate Google-suggested Other Contacts corpus after explicitly opting into that data surface.".into(),
                        common_mistakes: vec![
                            "Other Contacts requires its own scope trigger above ordinary contacts.readonly.".into(),
                        ],
                        examples: vec![
                            r#"{"person_fields":["names","emailAddresses"],"page_size":25}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.other_contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.search_directory_people",
                    "people.searchDirectoryPeople",
                    "Search Google Workspace directory people",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 500 },
                            "page_token": { "type": "string", "minLength": 1, "description": "Continuation token; keep all other query options unchanged." },
                            "sources": { "type": "array", "items": { "type": "string" }, "description": "Optional directory source filters. Defaults to DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array", "items": { "type": "object" }, "description": "Matching Person resources from the directory." },
                            "next_page_token": { "type": ["string", "null"] },
                            "total_size": { "type": ["integer", "null"] }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search org-wide directory profiles after explicitly opting into directory.readonly.".into(),
                        common_mistakes: vec![
                            "Directory results are not the same as the user's personal contacts corpus.".into(),
                            "Pass next_page_token as page_token with the same query, person_fields, page_size, and sources until no token remains.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"alice","person_fields":["names","emailAddresses","organizations"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.directory.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.list_contact_groups",
                    "contactGroups.list",
                    "List contact groups",
                    json!({
                        "type": "object",
                        "properties": {
                            "group_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string", "minLength": 1 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "contact_groups": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": ["string", "null"] },
                            "total_items": { "type": ["integer", "null"] }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect contact-group metadata without mutating memberships.".into(),
                        common_mistakes: vec![
                            "Group membership mutation is intentionally out of scope for this first slice.".into(),
                        ],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("people.contact_groups.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.create_contact",
                    "people.createContact",
                    "Create a new contact",
                    json!({
                        "type": "object",
                        "required": ["person"],
                        "properties": {
                            "person": { "type": "object", "description": "Raw People person payload containing the contact fields to create." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a durable contact entry after explicitly opting into contacts write scope.".into(),
                        common_mistakes: vec![
                            "Do not rely on hidden defaults; provide the actual People fields you intend to write.".into(),
                        ],
                        examples: vec![
                            r#"{"person":{"names":[{"givenName":"Alice","familyName":"Ng"}],"emailAddresses":[{"value":"alice@example.com"}]}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.write")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.update_contact",
                    "people.updateContact",
                    "Update an existing contact with explicit field-mask semantics",
                    json!({
                        "type": "object",
                        "required": ["resource_name", "person"],
                        "properties": {
                            "resource_name": { "type": "string" },
                            "person": { "type": "object", "description": "Raw People person payload. Must include `etag`." },
                            "update_person_fields": { "type": "array", "items": { "type": "string" }, "description": "Optional explicit update field mask. If omitted, the connector derives it from non-empty top-level keys in `person`." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Patch a contact while keeping the updated field mask explicit.".into(),
                        common_mistakes: vec![
                            "People updateContact expects an `etag`; omitting it turns a safe concurrency check into a confusing API failure.".into(),
                        ],
                        examples: vec![
                            r#"{"resource_name":"people/c123","person":{"etag":"%EgUBAQMEBQY=","emailAddresses":[{"value":"alice@example.com"}]}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.write")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.delete_contact",
                    "people.deleteContact",
                    "Delete an existing contact",
                    json!({
                        "type": "object",
                        "required": ["resource_name"],
                        "properties": {
                            "resource_name": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "deleted": { "type": "boolean" } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a contact after explicit interactive approval.".into(),
                        common_mistakes: vec![
                            "Deletion is irreversible; confirm you are targeting the correct People resource name before calling.".into(),
                        ],
                        examples: vec![r#"{"resource_name":"people/c123"}"#.into()],
                        related: vec![CapabilityId::from_static("people.contacts.delete")],
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

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {error}"),
            })?;

        let capability = match people_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                    message: format!("Failed to serialize response: {error}"),
                });
            }
        };

        if let Err(error) = validate_people_simulate_input(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize response: {error}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize response: {error}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize response: {error}"),
            });
        };

        let response =
            match verifier.verify_bound(req.capability_token, &capability, &req.operation, &[]) {
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
                            response.with_missing_capabilities(vec![capability.as_str().into()]);
                    }
                    response
                }
            };
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
        let operation =
            params
                .get("operation")
                .and_then(Value::as_str)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;
        let parsed_capability = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {error}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = people_capability_for_operation(operation)?;
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(parsed_capability, &cap_id, &op_id, &[])?;

        match operation {
            "people.list_connections" => self.invoke_list_connections(input).await,
            "people.get_person" => self.invoke_get_person(input).await,
            "people.search_contacts" => self.invoke_search_contacts(input).await,
            "people.list_other_contacts" => self.invoke_list_other_contacts(input).await,
            "people.search_directory_people" => self.invoke_search_directory_people(input).await,
            "people.list_contact_groups" => self.invoke_list_contact_groups(input).await,
            "people.create_contact" => self.invoke_create_contact(input).await,
            "people.update_contact" => self.invoke_update_contact(input).await,
            "people.delete_contact" => self.invoke_delete_contact(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_list_connections(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let (page_size, page_cursor) = parse_people_pagination("people.list_connections", &input)?;
        let sort_order = input.get("sort_order").and_then(Value::as_str);

        let response = client
            .list_connections(&person_fields, page_size, page_cursor, sort_order)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "connections": response.connections,
            "next_page_token": response.next_page_token,
            "next_sync_token": response.next_sync_token,
            "total_people": response.total_people,
            "total_items": response.total_items
        }))
    }

    async fn invoke_get_person(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        if resource_name == "people/me" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`people/me` is intentionally not exposed by this connector; request a concrete contact or directory resource instead".into(),
            });
        }

        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let sources = parse_string_list_or_csv(&input, "sources")?.unwrap_or_default();
        let person = client
            .get_person(resource_name, &person_fields, &sources)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": person }))
    }

    async fn invoke_search_contacts(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let (page_size, _) = parse_people_pagination("people.search_contacts", &input)?;

        let response = client
            .search_contacts(query, &person_fields, page_size)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_list_other_contacts(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_OTHER_CONTACT_FIELDS)?;
        let (page_size, page_cursor) =
            parse_people_pagination("people.list_other_contacts", &input)?;

        let response = client
            .list_other_contacts(&person_fields, page_size, page_cursor)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "other_contacts": response.other_contacts,
            "next_page_token": response.next_page_token,
            "total_size": response.total_size
        }))
    }

    async fn invoke_search_directory_people(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_DIRECTORY_FIELDS)?;
        let (page_size, page_cursor) =
            parse_people_pagination("people.search_directory_people", &input)?;
        let sources = parse_string_list_or_csv(&input, "sources")?
            .unwrap_or_else(|| vec!["DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE".to_string()]);

        let response = client
            .search_directory_people(query, &person_fields, page_size, page_cursor, &sources)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "results": response.people,
            "next_page_token": response.next_page_token,
            "total_size": response.total_size
        }))
    }

    async fn invoke_list_contact_groups(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let group_fields = field_list_with_default(&input, "group_fields", DEFAULT_GROUP_FIELDS)?;
        let (page_size, page_cursor) =
            parse_people_pagination("people.list_contact_groups", &input)?;

        let response = client
            .list_contact_groups(&group_fields, page_size, page_cursor)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "contact_groups": response.contact_groups,
            "next_page_token": response.next_page_token,
            "total_items": response.total_items
        }))
    }

    async fn invoke_create_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person = input.get("person").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: person".into(),
        })?;
        if !person.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`person` must be a JSON object".into(),
            });
        }

        let created = client
            .create_contact(person)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": created }))
    }

    async fn invoke_update_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        let mut person = input
            .get("person")
            .cloned()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: person".into(),
            })?;
        let person_object = person.as_object_mut().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "`person` must be a JSON object".into(),
        })?;

        if let Some(existing) = person_object.get("resourceName").and_then(Value::as_str)
            && existing != resource_name
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`resource_name` must match `person.resourceName` when both are supplied"
                    .into(),
            });
        }
        person_object.insert("resourceName".to_string(), json!(resource_name));

        if person_object.get("etag").and_then(Value::as_str).is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`person.etag` is required for update_contact to keep People API concurrency semantics explicit".into(),
            });
        }

        let update_person_fields = parse_string_list_or_csv(&input, "update_person_fields")?
            .unwrap_or_else(|| derive_update_person_fields(&person).unwrap_or_default());
        if update_person_fields.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "update_contact requires at least one non-empty mutable field or an explicit `update_person_fields` list".into(),
            });
        }

        let updated = client
            .update_contact(resource_name, &update_person_fields, &person)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": updated }))
    }

    async fn invoke_delete_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        client
            .delete_contact(resource_name)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    pub async fn handle_shutdown(&self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Google People connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GooglePeopleConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn load_people_policy_catalog() -> FcpResult<GooglePolicyCatalog> {
    GooglePolicyCatalog::load_default().map_err(|error| FcpError::Internal {
        message: format!("Failed to load embedded Google policy catalog: {error}"),
    })
}

fn people_discovery_method_key(operation: &str) -> FcpResult<&'static str> {
    match operation {
        "people.list_connections" => Ok("people.connections.list"),
        "people.get_person" => Ok("people.get"),
        "people.search_contacts" => Ok("people.searchContacts"),
        "people.list_other_contacts" => Ok("otherContacts.list"),
        "people.search_directory_people" => Ok("people.searchDirectoryPeople"),
        "people.list_contact_groups" => Ok("contactGroups.list"),
        "people.create_contact" => Ok("people.createContact"),
        "people.update_contact" => Ok("people.updateContact"),
        "people.delete_contact" => Ok("people.deleteContact"),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn people_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let discovery_method_key = people_discovery_method_key(operation)?;
    let policy = load_people_policy_catalog()?;
    let resolved = policy
        .classify_operation("people", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing People policy mapping for `{discovery_method_key}`"),
        })?;
    CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| FcpError::Internal {
        message: format!(
            "Invalid capability `{}` in Google People policy catalog: {error}",
            resolved.rule.capability
        ),
    })
}

fn require_object<'a>(
    input: &'a Value,
    field: &str,
) -> FcpResult<&'a serde_json::Map<String, Value>> {
    input
        .get(field)
        .and_then(Value::as_object)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must be a JSON object"),
        })
}

fn validate_people_simulate_input(operation: &str, input: &Value) -> FcpResult<()> {
    match operation {
        "people.get_person" => {
            let resource_name = require_str(input, "resource_name")?;
            if resource_name == "people/me" {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "`people/me` is intentionally not exposed by this connector; request a concrete contact or directory resource instead".into(),
                });
            }
        }
        "people.search_contacts" | "people.search_directory_people" => {
            require_str(input, "query")?;
            parse_people_pagination(operation, input)?;
        }
        "people.create_contact" => {
            require_object(input, "person")?;
        }
        "people.update_contact" => {
            let resource_name = require_str(input, "resource_name")?;
            let person_object = require_object(input, "person")?;
            if let Some(existing) = person_object.get("resourceName").and_then(Value::as_str)
                && existing != resource_name
            {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "`resource_name` must match `person.resourceName` when both are supplied"
                            .into(),
                });
            }
            if person_object.get("etag").and_then(Value::as_str).is_none() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "`person.etag` is required for update_contact to keep People API concurrency semantics explicit".into(),
                });
            }
            let update_person_fields = parse_string_list_or_csv(input, "update_person_fields")?
                .unwrap_or_else(|| {
                    derive_update_person_fields(&input["person"]).unwrap_or_default()
                });
            if update_person_fields.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "update_contact requires at least one non-empty mutable field or an explicit `update_person_fields` list".into(),
                });
            }
        }
        "people.delete_contact" => {
            require_str(input, "resource_name")?;
        }
        "people.list_connections" | "people.list_other_contacts" | "people.list_contact_groups" => {
            parse_people_pagination(operation, input)?;
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn policy_backed_operation_info(
    policy: &GooglePolicyCatalog,
    operation_id: &'static str,
    discovery_method_key: &'static str,
    summary: &str,
    input_schema: Value,
    output_schema: Value,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> FcpResult<OperationInfo> {
    let resolved = policy
        .classify_operation("people", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing People policy mapping for `{discovery_method_key}`"),
        })?;
    let capability = CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Invalid capability `{}` in Google People policy catalog: {error}",
                resolved.rule.capability
            ),
        }
    })?;

    Ok(OperationInfo {
        id: OperationId::from_static(operation_id),
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

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn parse_people_pagination<'a>(
    operation: &str,
    input: &'a Value,
) -> FcpResult<(Option<u32>, Option<&'a str>)> {
    if !input.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "People input must be an object".into(),
        });
    }
    let max_page_size = match operation {
        "people.search_contacts" => 30,
        "people.search_directory_people" => 500,
        _ => 1000,
    };
    let page_size = input
        .get("page_size")
        .map(|value| {
            value
                .as_u64()
                .filter(|size| (1..=max_page_size).contains(size))
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "`page_size` must be an integer between 1 and {max_page_size}"
                    ),
                })
        })
        .transpose()?;
    let page_token = input
        .get("page_token")
        .map(|value| {
            if operation == "people.search_contacts" {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Contact search does not support `page_token`; use list_connections to enumerate contacts".into(),
                });
            }
            value
                .as_str()
                .filter(|token| !token.trim().is_empty())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "`page_token` must be a non-empty string".into(),
                })
        })
        .transpose()?;
    Ok((page_size, page_token))
}

fn field_list_with_default(
    input: &Value,
    field: &str,
    default_fields: &[&str],
) -> FcpResult<Vec<String>> {
    Ok(parse_string_list_or_csv(input, field)?.unwrap_or_else(|| {
        default_fields
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    }))
}

fn derive_update_person_fields(person: &Value) -> FcpResult<Vec<String>> {
    let person_object = person.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "`person` must be a JSON object".into(),
    })?;
    let candidates = [
        "addresses",
        "biographies",
        "emailAddresses",
        "memberships",
        "names",
        "organizations",
        "phoneNumbers",
    ];
    let mut fields = Vec::new();
    for key in candidates {
        if person_object
            .get(key)
            .is_some_and(value_has_meaningful_content)
        {
            fields.push(key.to_string());
        }
    }
    Ok(fields)
}

fn value_has_meaningful_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(raw) => !raw.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_google_discovery::{
        DiscoveryEndpointKind, DiscoveryServiceId, generator::generate_google_service_artifacts,
        normalize_snapshot_bytes,
    };
    use fcp_prelude::{CapabilityConstraints, ZoneId};
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_with_test_bearer(extra: &[(&str, Value)]) -> Value {
        let mut params = serde_json::Map::new();
        params.insert(
            ["access", "token"].join("_"),
            json!(["ya29", "people-test"].join(".")),
        );
        for (key, value) in extra {
            params.insert((*key).to_string(), value.clone());
        }
        Value::Object(params)
    }

    fn generate_token_with_cap(
        signing_key: &Ed25519SigningKey,
        connector: &GooglePeopleConnector,
        capability: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &GooglePeopleConnector,
        operation: &str,
    ) -> CapabilityToken {
        let capability = people_capability_for_operation(operation).unwrap();
        generate_token_with_cap(signing_key, connector, capability.as_str(), &[operation])
    }

    fn simulate_request(
        operation: &'static str,
        input: Value,
        capability: CapabilityToken,
    ) -> Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("google-people"),
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

    async fn configured_connector() -> GooglePeopleConnector {
        let mut connector = GooglePeopleConnector::new();
        connector
            .handle_configure(config_with_test_bearer(&[]))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_connector() -> (GooglePeopleConnector, Ed25519SigningKey) {
        let mut connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["people.contacts.read", "people.contacts.write"]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    async fn handshaken_loopback_connector(
        server: &MockServer,
    ) -> (GooglePeopleConnector, Ed25519SigningKey) {
        let mut connector = GooglePeopleConnector::new();
        connector
            .handle_configure(config_with_test_bearer(&[
                ("base_url", json!(format!("{}/v1", server.uri()))),
                (
                    "required_scopes",
                    json!([
                        "https://www.googleapis.com/auth/contacts.readonly",
                        "https://www.googleapis.com/auth/contacts.other.readonly",
                        "https://www.googleapis.com/auth/directory.readonly"
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
                "capabilities_requested": [
                    "people.contacts.read",
                    "people.other_contacts.read",
                    "people.contact_groups.read",
                    "people.directory.read"
                ]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    #[fcp_async_core::runtime::test]
    async fn directory_search_invocation_preserves_people_and_continues_with_unchanged_filters() {
        let server = MockServer::start().await;
        let cursor = "next+/=&?opaque";
        for (page_token, resource_name, next_page_token) in [
            (None, "people/directory-1", Some(cursor)),
            (Some(cursor), "people/directory-2", None),
        ] {
            let mock = Mock::given(method("GET"))
                .and(path("/v1/people:searchDirectoryPeople"))
                .and(query_param("query", "Ada + Research"))
                .and(query_param("readMask", "emailAddresses,names"))
                .and(query_param("pageSize", "1"))
                .and(query_param(
                    "sources",
                    "DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE",
                ))
                .and(header("authorization", "Bearer ya29.people-test"));
            let mock = if let Some(page_token) = page_token {
                mock.and(query_param("pageToken", page_token))
            } else {
                mock.and(query_param_is_missing("pageToken"))
            };
            let mut response = json!({
                "people": [{
                    "resourceName": resource_name,
                    "emailAddresses": [{ "value": "ada@example.com" }]
                }],
                "totalSize": 2
            });
            if let Some(next_page_token) = next_page_token {
                response["nextPageToken"] = json!(next_page_token);
            }
            mock.respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
        }

        let (connector, signing_key) = handshaken_loopback_connector(&server).await;
        let operation = "people.search_directory_people";
        let capability = generate_valid_token(&signing_key, &connector, operation);
        let mut input = json!({
            "query": "Ada + Research",
            "person_fields": ["names", "emailAddresses"],
            "page_size": 1,
            "sources": ["DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE"]
        });
        let first = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": input,
                "capability_token": capability
            }))
            .await
            .unwrap();
        assert_eq!(first["results"][0]["resourceName"], "people/directory-1");
        assert_eq!(
            first["results"][0]["emailAddresses"][0]["value"],
            "ada@example.com"
        );
        assert!(first["results"][0].get("person").is_none());
        assert_eq!(first["next_page_token"], cursor);
        assert_eq!(first["total_size"], 2);
        assert!(first.get("nextPageToken").is_none());

        input["page_token"] = first["next_page_token"].clone();
        let second = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": input,
                "capability_token": capability
            }))
            .await
            .unwrap();
        assert_eq!(second["results"][0]["resourceName"], "people/directory-2");
        assert!(second["next_page_token"].is_null());
        assert_eq!(second["total_size"], 2);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let query_options = |request: &wiremock::Request| {
            request
                .url
                .query_pairs()
                .filter(|(key, _)| key != "pageToken")
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(query_options(&requests[0]), query_options(&requests[1]));
        server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn list_invocations_expose_continuation_tokens_and_public_collection_names() {
        let server = MockServer::start().await;
        let (connector, signing_key) = handshaken_loopback_connector(&server).await;
        for (operation, endpoint, wire_field, public_field, wire_total, public_total) in [
            (
                "people.list_connections",
                "/v1/people/me/connections",
                "connections",
                "connections",
                "totalPeople",
                "total_people",
            ),
            (
                "people.list_other_contacts",
                "/v1/otherContacts",
                "otherContacts",
                "other_contacts",
                "totalSize",
                "total_size",
            ),
            (
                "people.list_contact_groups",
                "/v1/contactGroups",
                "contactGroups",
                "contact_groups",
                "totalItems",
                "total_items",
            ),
        ] {
            let cursor = format!("{operation}+/=&?page-2");
            let (mask_parameter, default_mask) = match operation {
                "people.list_connections" => (
                    "personFields",
                    "names,emailAddresses,phoneNumbers,organizations",
                ),
                "people.list_other_contacts" => ("readMask", "names,emailAddresses,phoneNumbers"),
                "people.list_contact_groups" => ("groupFields", "name,groupType,memberCount"),
                _ => unreachable!(),
            };
            for (page_token, resource_name, next_page_token) in [
                (None, "first-resource", Some(cursor.as_str())),
                (Some(cursor.as_str()), "second-resource", None),
            ] {
                let mock = Mock::given(method("GET"))
                    .and(path(endpoint))
                    .and(query_param("pageSize", "1"))
                    .and(query_param(mask_parameter, default_mask))
                    .and(header("authorization", "Bearer ya29.people-test"));
                let mock = if let Some(page_token) = page_token {
                    mock.and(query_param("pageToken", page_token))
                } else {
                    mock.and(query_param_is_missing("pageToken"))
                };
                let mut response = json!({
                    (wire_field): [{ "resourceName": resource_name }],
                    (wire_total): 2
                });
                if let Some(next_page_token) = next_page_token {
                    response["nextPageToken"] = json!(next_page_token);
                }
                mock.respond_with(ResponseTemplate::new(200).set_body_json(response))
                    .expect(1)
                    .mount(&server)
                    .await;
            }

            let capability = generate_valid_token(&signing_key, &connector, operation);
            let first = connector
                .handle_invoke(json!({
                    "operation": operation,
                    "input": { "page_size": 1 },
                    "capability_token": capability
                }))
                .await
                .unwrap();
            assert_eq!(first[public_field][0]["resourceName"], "first-resource");
            assert_eq!(first["next_page_token"], cursor);
            assert_eq!(first[public_total], 2);
            assert!(first.get("nextPageToken").is_none());
            if wire_field != public_field {
                assert!(first.get(wire_field).is_none());
            }
            let second = connector
                .handle_invoke(json!({
                    "operation": operation,
                    "input": { "page_size": 1, "page_token": first["next_page_token"] },
                    "capability_token": capability
                }))
                .await
                .unwrap();
            assert_eq!(second[public_field][0]["resourceName"], "second-resource");
            assert!(second["next_page_token"].is_null());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 6);
        server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_pagination_is_denied_by_invoke_and_simulate_before_provider_io() {
        let server = MockServer::start().await;
        let (connector, signing_key) = handshaken_loopback_connector(&server).await;
        for (operation, max_page_size) in [
            ("people.list_connections", 1000),
            ("people.list_other_contacts", 1000),
            ("people.list_contact_groups", 1000),
            ("people.search_directory_people", 500),
            ("people.search_contacts", 30),
        ] {
            let capability = generate_valid_token(&signing_key, &connector, operation);
            for invalid_field in [
                json!({ "page_token": null }),
                json!({ "page_token": false }),
                json!({ "page_token": 7 }),
                json!({ "page_token": [] }),
                json!({ "page_token": {} }),
                json!({ "page_token": "" }),
                json!({ "page_token": " \t" }),
                json!({ "page_size": null }),
                json!({ "page_size": "1" }),
                json!({ "page_size": 0 }),
                json!({ "page_size": -1 }),
                json!({ "page_size": 1.5 }),
                json!({ "page_size": max_page_size + 1 }),
                json!({ "page_size": u64::MAX }),
            ] {
                let mut input = json!({ "query": "Ada" });
                input
                    .as_object_mut()
                    .unwrap()
                    .extend(invalid_field.as_object().unwrap().clone());
                let result = connector
                    .handle_invoke(json!({
                        "operation": operation,
                        "input": input,
                        "capability_token": capability
                    }))
                    .await;
                assert!(
                    matches!(result, Err(FcpError::InvalidRequest { .. })),
                    "{operation}: {input}"
                );
                let simulation = connector
                    .handle_simulate(simulate_request(operation, input, capability.clone()))
                    .await
                    .unwrap();
                assert!(
                    !parse_simulate_response(simulation).would_succeed,
                    "{operation}"
                );
            }
            assert!(
                parse_people_pagination(operation, &json!({ "page_size": max_page_size })).is_ok()
            );
        }
        assert!(
            parse_people_pagination("people.search_contacts", &json!({ "page_token": "next" }))
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(connector.client.as_ref().unwrap().total_requests(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn contact_search_keeps_person_wrappers_and_refuses_continuation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/people:searchContacts"))
            .and(query_param("query", "Ada"))
            .and(query_param("pageSize", "30"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{ "person": { "resourceName": "people/contact-1" } }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let (connector, signing_key) = handshaken_loopback_connector(&server).await;
        let operation = "people.search_contacts";
        let capability = generate_valid_token(&signing_key, &connector, operation);
        let result = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": { "query": "Ada", "page_size": 30 },
                "capability_token": capability
            }))
            .await
            .unwrap();
        assert_eq!(
            result["results"][0]["person"]["resourceName"],
            "people/contact-1"
        );
        assert!(result.get("next_page_token").is_none());
        let input = json!({ "query": "Ada", "page_token": "unsupported" });
        let result = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": input,
                "capability_token": capability
            }))
            .await;
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        let simulation = connector
            .handle_simulate(simulate_request(operation, input, capability))
            .await
            .unwrap();
        assert!(!parse_simulate_response(simulation).would_succeed);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(GooglePeopleConnector::manifest_hash(), expected);
        assert_ne!(
            GooglePeopleConnector::manifest_hash(),
            "sha256:google-people-connector-v1"
        );
    }

    #[test]
    fn resolve_people_required_scopes_defaults_to_contacts_readonly() {
        let scopes = resolve_people_required_scopes(&json!({})).unwrap();
        assert_eq!(
            scopes,
            vec!["https://www.googleapis.com/auth/contacts.readonly".to_string()]
        );
    }

    #[test]
    fn resolve_people_required_scopes_applies_scope_triggers() {
        let scopes = resolve_people_required_scopes(&json!({
            "scope_triggers": [
                "User enables contact create, update, photo update, or group-membership mutation workflows.",
                "User enables Google Workspace directory search or lookup workflows."
            ]
        }))
        .unwrap();
        assert!(scopes.contains(&"https://www.googleapis.com/auth/contacts.readonly".to_string()));
        assert!(scopes.contains(&"https://www.googleapis.com/auth/contacts".to_string()));
        assert!(scopes.contains(&"https://www.googleapis.com/auth/directory.readonly".to_string()));
    }

    #[test]
    fn resolve_people_required_scopes_rejects_mixed_inputs() {
        let error = resolve_people_required_scopes(&json!({
            "required_scopes": ["https://www.googleapis.com/auth/contacts.readonly"],
            "scope_triggers": ["User enables reads from Google-suggested other contacts."]
        }))
        .unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("Provide either `required_scopes` or `scope_triggers`")),
            "expected invalid request, got {error:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_service_selector_alias_contacts() {
        let mut connector = GooglePeopleConnector::new();
        let response = connector
            .handle_configure(config_with_test_bearer(&[(
                "service_selector",
                json!("contacts"),
            )]))
            .await
            .unwrap();
        assert_eq!(response["details"]["service_identity"], json!("people:v1"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_service_selector() {
        let mut connector = GooglePeopleConnector::new();
        let error = connector
            .handle_configure(config_with_test_bearer(&[(
                "service_selector",
                json!("gmail"),
            )]))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("service_selector")),
            "expected invalid request, got {error:?}"
        );
    }

    #[test]
    fn validate_people_base_url_accepts_googleapis() {
        let out = validate_people_base_url("https://people.googleapis.com/v1/").unwrap();
        assert_eq!(out, "https://people.googleapis.com/v1");
    }

    #[test]
    fn validate_people_base_url_allows_localhost_http() {
        validate_people_base_url("http://localhost:9999/v1").unwrap();
        validate_people_base_url("http://127.0.0.1/people").unwrap();
        validate_people_base_url("http://[::1]:9999/v1").unwrap();
    }

    #[test]
    fn validate_people_base_url_rejects_foreign_host() {
        let error = validate_people_base_url("https://evil.example.com/v1").unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("people.googleapis.com")),
            "expected people.googleapis.com validation error, got {error:?}"
        );
    }

    #[test]
    fn validate_people_base_url_rejects_substring_smuggle() {
        let error =
            validate_people_base_url("https://evil.com/people.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("people.googleapis.com")),
            "expected host validation error, got {error:?}"
        );
    }

    #[test]
    fn validate_people_base_url_rejects_query_fragment_userinfo() {
        assert!(
            validate_people_base_url("https://people.googleapis.com/v1?leak=x")
                .unwrap_err()
                .to_string()
                .contains("query string")
        );
        assert!(
            validate_people_base_url("https://people.googleapis.com/v1#frag")
                .unwrap_err()
                .to_string()
                .contains("fragment")
        );
        let error =
            validate_people_base_url("https://attacker:pw@people.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected userinfo validation error, got {error:?}"
        );
    }

    #[test]
    fn validate_people_base_url_rejects_plain_http_on_public_host() {
        let error = validate_people_base_url("http://people.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("https")),
            "expected https validation error, got {error:?}"
        );
    }

    #[test]
    fn validate_people_base_url_rejects_empty_and_malformed() {
        assert!(
            matches!(validate_people_base_url("   ").unwrap_err(), FcpError::InvalidRequest { message, .. } if message.contains("empty"))
        );
        assert!(
            matches!(validate_people_base_url("not a url").unwrap_err(), FcpError::InvalidRequest { message, .. } if message.contains("parsed"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_base_url_override() {
        let mut connector = GooglePeopleConnector::new();
        let error = connector
            .handle_configure(config_with_test_bearer(&[(
                "base_url",
                json!("https://evil.example.com/v1"),
            )]))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("people.googleapis.com")),
            "expected base_url validation error, got {error:?}"
        );

        let error = connector
            .handle_configure(config_with_test_bearer(&[("base_url", json!(123))]))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
            "expected base_url type error, got {error:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_exposes_policy_backed_approval_modes() {
        let connector = GooglePeopleConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let operations = result["operations"].as_array().unwrap();

        let list_connections = operations
            .iter()
            .find(|op| op["id"] == "people.list_connections")
            .unwrap();
        let delete_contact = operations
            .iter()
            .find(|op| op["id"] == "people.delete_contact")
            .unwrap();

        assert_eq!(list_connections["capability"], "people.contacts.read");
        assert_eq!(list_connections["requires_approval"], "policy");
        assert_eq!(delete_contact["capability"], "people.contacts.delete");
        assert_eq!(delete_contact["requires_approval"], "interactive");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_configure_denies() {
        let connector = GooglePeopleConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "people.list_connections");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "people.list_connections",
                    json!({}),
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
    async fn simulate_before_handshake_denies() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "people.list_connections");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "people.list_connections",
                    json!({}),
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
    async fn simulate_known_operation_allows_valid_token() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "people.list_connections");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "people.list_connections",
                    json!({}),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_wrong_capability_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "people.contacts.write",
            &["people.list_connections"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "people.list_connections",
                    json!({}),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(response.missing_capabilities, vec!["people.contacts.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_missing_required_input_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "people.get_person");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request("people.get_person", json!({}), capability))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: String::new()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "people.contacts.read",
            &["people.unknown_operation"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "people.unknown_operation",
                    json!({}),
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
                    operation: "people.unknown_operation".into()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "people.list_connections");
        let result = connector
            .handle_invoke(json!({
                "operation": "people.list_connections",
                "input": {},
                "capability_token": capability
            }))
            .await;
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[test]
    fn derive_update_person_fields_requires_mutated_keys() {
        let fields = derive_update_person_fields(&json!({
            "etag": "%EgUBAQMEBQY=",
            "names": [{"givenName": "Alice"}],
            "emailAddresses": [{"value": "alice@example.com"}]
        }))
        .unwrap();
        assert_eq!(
            fields,
            vec!["emailAddresses".to_string(), "names".to_string()]
        );
    }

    #[test]
    fn people_generated_operations_cover_core_connector_surface() {
        let service = DiscoveryServiceId::new("people", "v1").unwrap();
        let discovery_json = json!({
            "name": "people",
            "version": "v1",
            "rootUrl": "https://people.googleapis.com/",
            "servicePath": "",
            "auth": {
                "oauth2": {
                    "scopes": {
                        "https://www.googleapis.com/auth/contacts": { "description": "contacts" },
                        "https://www.googleapis.com/auth/contacts.readonly": { "description": "contacts readonly" },
                        "https://www.googleapis.com/auth/contacts.other.readonly": { "description": "other contacts readonly" },
                        "https://www.googleapis.com/auth/directory.readonly": { "description": "directory readonly" }
                    }
                }
            },
            "resources": {
                "people": {
                    "methods": {
                        "get": { "path": "v1/{+resourceName}", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] },
                        "searchContacts": { "path": "v1/people:searchContacts", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] },
                        "searchDirectoryPeople": { "path": "v1/people:searchDirectoryPeople", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/directory.readonly"] },
                        "createContact": { "path": "v1/people:createContact", "httpMethod": "POST", "scopes": ["https://www.googleapis.com/auth/contacts"] },
                        "updateContact": { "path": "v1/{+resourceName}:updateContact", "httpMethod": "PATCH", "scopes": ["https://www.googleapis.com/auth/contacts"] },
                        "deleteContact": { "path": "v1/{+resourceName}:deleteContact", "httpMethod": "DELETE", "scopes": ["https://www.googleapis.com/auth/contacts"] }
                    },
                    "resources": {
                        "connections": {
                            "methods": {
                                "list": { "path": "v1/people/me/connections", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] }
                            }
                        }
                    }
                },
                "otherContacts": {
                    "methods": {
                        "list": { "path": "v1/otherContacts", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.other.readonly"] }
                    }
                },
                "contactGroups": {
                    "methods": {
                        "list": { "path": "v1/contactGroups", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] }
                    }
                }
            }
        });

        let snapshot = normalize_snapshot_bytes(
            &service,
            serde_json::to_vec(&discovery_json).unwrap().as_slice(),
            DiscoveryEndpointKind::Alternate,
            "https://example.test/people",
        )
        .unwrap()
        .snapshot;
        let policy = GooglePolicyCatalog::load_default().unwrap();
        let generated = generate_google_service_artifacts(&snapshot, &policy).unwrap();

        let connections = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.people.connections.list")
            .unwrap();
        let delete_contact = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.people.delete_contact")
            .unwrap();
        let groups = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.contact_groups.list")
            .unwrap();

        assert_eq!(connections.capability, "people.contacts.read");
        assert_eq!(delete_contact.capability, "people.contacts.delete");
        assert_eq!(
            delete_contact.approval_mode,
            Some(ApprovalMode::Interactive)
        );
        assert_eq!(groups.capability, "people.contact_groups.read");
    }
}
