//! FCP Notion Connector implementation.

use std::sync::OnceLock;
use std::time::Instant;

use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, HandshakeRequest,
    HealthSnapshot, InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{
        DEFAULT_API_URL, DEFAULT_NOTION_VERSION, NotionAuth, NotionClient, normalize_notion_version,
    },
    error::NotionError,
};

const MAX_NOTION_CURSOR_BYTES: usize = 512;
const MAX_INVOKE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_IDS: [&str; 16] = [
    "notion.create_page",
    "notion.get_page",
    "notion.update_page",
    "notion.delete_page",
    "notion.get_database",
    "notion.create_database",
    "notion.update_database",
    "notion.query_database",
    "notion.search",
    "notion.get_block",
    "notion.update_block",
    "notion.delete_block",
    "notion.get_block_children",
    "notion.append_blocks",
    "notion.add_comment",
    "notion.list_comments",
];

/// Validated configuration for the Notion connector.
struct NotionConfig {
    auth: NotionAuth,
    api_url: String,
    notion_version: Option<String>,
}

impl NotionConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Strict auth: exactly one of `token` or `credential_id` must be supplied.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let token = optional_nonempty_string(params, "token")?;
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (token, credential_id) {
            (Some(t), None) => NotionAuth::Token(t),
            (None, Some(cid)) => NotionAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of `token` or `credential_id`, not both".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply `token` or `credential_id`".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();
        let api_url = validate_api_url_for_auth(&api_url, &auth)?;

        let notion_version = match params.get("notion_version") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "notion_version must be a string".into(),
                })?;
                Some(
                    normalize_notion_version(raw).ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "notion_version must look like YYYY-MM-DD".into(),
                    })?,
                )
            }
            None => None,
        };

        Ok(Self {
            auth,
            api_url,
            notion_version,
        })
    }
}

fn optional_nonempty_string(params: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };

    let raw = value.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a string"),
    })?;
    if raw.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a non-empty string"),
        });
    }

    Ok(Some(raw.to_string()))
}

fn validate_api_url_for_auth(raw_url: &str, auth: &NotionAuth) -> FcpResult<String> {
    let parsed = reqwest::Url::parse(raw_url).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "api_url must be an absolute URL".into(),
    })?;
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "api_url must include a host".into(),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        // Query/fragment components would be preserved by parsed.to_string()
        // and then corrupt downstream format!("{api_url}/path", ...) URL
        // construction — e.g. "https://api.notion.com/?leak=x" would turn
        // into "https://api.notion.com/?leak=x/v1/databases/...".
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include a query string or fragment".into(),
        });
    }
    let host_lower = host.to_ascii_lowercase();
    let is_local = matches!(host_lower.as_str(), "localhost" | "127.0.0.1" | "::1");
    let scheme = parsed.scheme();
    let token_origin_allowed = match auth {
        NotionAuth::Token(_) => {
            (scheme == "https" && host_lower == "api.notion.com")
                || (is_local && matches!(scheme, "http" | "https"))
        }
        NotionAuth::CredentialId(_) => true,
    };

    if !token_origin_allowed {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must target https://api.notion.com for direct token mode".into(),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn optional_safe_cursor(input: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    let Some(raw) = optional_nonempty_string(input, field)? else {
        return Ok(None);
    };

    if raw.len() > MAX_NOTION_CURSOR_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} exceeds maximum length of {MAX_NOTION_CURSOR_BYTES} bytes"),
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not contain control characters"),
        });
    }

    Ok(Some(raw))
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

/// FCP Notion Connector.
pub struct NotionConnector {
    base: BaseConnector,
    config: Option<NotionConfig>,
    client: Option<NotionClient>,
    authority: Option<StandaloneSession>,
    session_id: Option<SessionId>,
    bound_zone: Option<ZoneId>,
    started_at: Instant,
}

impl NotionConnector {
    /// Create a new Notion connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.notion")),
            config: None,
            client: None,
            authority: None,
            session_id: None,
            bound_zone: None,
            started_at: Instant::now(),
        }
    }

    /// Return the connector instance ID used for bound capability verification.
    #[must_use]
    pub fn instance_id(&self) -> &fcp_prelude::InstanceId {
        &self.base.instance_id
    }

    fn invalidate_authority(&mut self) {
        self.authority = None;
        self.session_id = None;
        self.base.set_handshaken(false);
        self.base.instance_id = InstanceId::new();
    }

    fn clear_configuration(&mut self) {
        self.invalidate_authority();
        self.bound_zone = None;
        self.base.set_configured(false);
        self.config = None;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // A rejected configuration must not leave the old account or grants
        // usable. New authority requires a successful configure and handshake.
        self.clear_configuration();
        let config = NotionConfig::from_params(&params)?;

        let client =
            NotionClient::new_with_version(config.auth.clone(), config.notion_version.as_deref())
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                })?
                .with_api_url(&config.api_url);

        info!(auth = %config.auth.redacted_label(), "Notion connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_authority();
        if self.client.is_none() || self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid handshake request".into(),
            })?;

        if self
            .bound_zone
            .as_ref()
            .is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "notion.handshake".into(),
                reason: "Reconfigure before binding this workspace to another zone".into(),
            });
        }
        let zone = req.zone.clone();
        let mut authority = StandaloneSession::new(MANIFEST_TOML)?;
        let response = authority.handshake(req)?;
        let mut result = serde_json::to_value(&response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        result["instance_id"] = json!(authority.instance_id());
        result["connector_id"] = json!("fcp.notion");
        result["protocol_version"] = json!("2.0");
        self.base.instance_id = authority.instance_id().clone();
        self.session_id = Some(response.session_id);
        self.bound_zone = Some(zone);
        self.authority = Some(authority);
        self.base.set_handshaken(true);
        Ok(result)
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some() && self.config.is_some();
        let handshaken = configured
            && self
                .authority
                .as_ref()
                .is_some_and(StandaloneSession::is_established);
        let metrics = self.base.metrics();
        let mut health = if handshaken {
            HealthSnapshot::ready()
        } else if configured {
            HealthSnapshot::degraded("handshake required")
        } else {
            HealthSnapshot::degraded("not configured")
        };
        health.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut details = json!({
            "connector_id": "fcp.notion",
            "configured": configured,
            "handshaken": handshaken,
            "instance_id": self.base.instance_id,
            "zone": self.bound_zone,
            "session_id": self.session_id,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            details["auth_mode"] = json!(config.auth.redacted_label());
            details["api_url"] = json!(config.api_url);
            details["notion_version"] = json!(
                self.client.as_ref().map_or(
                    config
                        .notion_version
                        .as_deref()
                        .unwrap_or(DEFAULT_NOTION_VERSION),
                    NotionClient::notion_version,
                )
            );
        }
        health.details = Some(details);
        serde_json::to_value(health).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize health: {error}"),
        })
    }

    /// Handle doctor readiness check.
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

        // 3. API URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("API URL: {}", config.api_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "API URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Effective Notion API version
        let notion_version = self.client.as_ref().map_or_else(
            || {
                self.config
                    .as_ref()
                    .and_then(|config| config.notion_version.clone())
                    .unwrap_or_else(|| DEFAULT_NOTION_VERSION.to_string())
            },
            |client| client.notion_version().to_string(),
        );
        checks.push(DoctorCheck {
            name: "notion_version".into(),
            status: DoctorStatus::Healthy,
            message: format!("Notion-Version header: {notion_version}"),
        });

        // 6. Network constraints
        let egress_target = self.config.as_ref().map_or("api.notion.com", |c| {
            c.api_url
                .strip_prefix("https://")
                .or_else(|| c.api_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("api.notion.com")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        // 7. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
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
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: operations_info()?.to_vec(),
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
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid simulate request".into(),
            })?;

        if req.r#type != "simulate" || req.id.0.is_empty() || !req.input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Simulation requires a typed request, non-empty ID and object input"
                    .into(),
            });
        }
        let authorization = self
            .validate_operation(&req.operation, &req.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &req.connector_id,
                        &req.zone_id,
                        &req.operation,
                        req.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        let response = match authorization {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Some(operation) = operations_info()?
                    .iter()
                    .find(|operation| operation.id == req.operation)
                {
                    response = response
                        .with_missing_capabilities(vec![operation.capability.as_str().to_owned()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Validate the advertised input and derive its actual resource scopes.
    fn validate_operation(
        &self,
        operation: &OperationId,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        if self.client.is_none() || self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        operations_info()?
            .iter()
            .find(|metadata| metadata.id == *operation)
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.as_str().to_owned(),
            })?;
        operation_contracts()?.validate_input(operation, input)?;
        if operation.as_str() == "notion.query_database" {
            optional_safe_cursor(input, "start_cursor")?;
        }
        resource_uris_for_operation(operation.as_str(), input)
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        if !request.input.is_object() || request.deadline_ms == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation requires object input and an unexpired deadline".into(),
            });
        }
        let resources = self.validate_operation(&request.operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_INVOKE_RESPONSE_BYTES)?;
        let operation = request.operation.as_str();
        let input = request.input;
        let result = match operation {
            "notion.create_page" => self.invoke_create_page(input).await,
            "notion.get_page" => self.invoke_get_page(input).await,
            "notion.update_page" => self.invoke_update_page(input).await,
            "notion.delete_page" => self.invoke_delete_page(input).await,
            "notion.get_database" => self.invoke_get_database(input).await,
            "notion.create_database" => self.invoke_create_database(input).await,
            "notion.update_database" => self.invoke_update_database(input).await,
            "notion.query_database" => self.invoke_query_database(input).await,
            "notion.search" => self.invoke_search(input).await,
            "notion.get_block" => self.invoke_get_block(input).await,
            "notion.update_block" => self.invoke_update_block(input).await,
            "notion.delete_block" => self.invoke_delete_block(input).await,
            "notion.get_block_children" => self.invoke_get_block_children(input).await,
            "notion.append_blocks" => self.invoke_append_blocks(input).await,
            "notion.add_comment" => self.invoke_add_comment(input).await,
            "notion.list_comments" => self.invoke_list_comments(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };
        let response = match &result {
            Ok(value) => InvokeResponse::ok(request.id.clone(), value.clone()),
            Err(error) => InvokeResponse::error(request.id.clone(), error.clone()),
        };
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        witness.finish_response(&response)?;
        result
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let page = client
            .create_page(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_get_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .get_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_update_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;
        let properties = input.get("properties").cloned().unwrap_or(json!({}));

        let body = json!({ "properties": properties });
        let page = client
            .update_page(page_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_delete_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .delete_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_get_database(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;

        let db = client
            .get_database(database_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_create_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }
        if input.get("title").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: title".into(),
            });
        }
        if input.get("properties").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: properties".into(),
            });
        }

        let db = client
            .create_database(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_update_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;

        let mut body = json!({});
        if let Some(title) = input.get("title") {
            body["title"] = title.clone();
        }
        if let Some(props) = input.get("properties") {
            body["properties"] = props.clone();
        }
        if let Some(desc) = input.get("description") {
            body["description"] = desc.clone();
        }

        let db = client
            .update_database(database_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_query_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;
        let filter = input.get("filter").cloned();
        let start_cursor = optional_safe_cursor(&input, "start_cursor")?;

        let result = client
            .query_database(database_id, filter, start_cursor.as_deref())
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let filter = input.get("filter").cloned();

        let result = client
            .search(query, filter)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        // Redact PII from search results — search can expose data across
        // the entire workspace, so strip email/person fields before returning.
        let redacted: Vec<serde_json::Value> = result
            .results
            .into_iter()
            .map(redact_search_result)
            .collect();

        Ok(json!({
            "results": redacted,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor,
            "result_count": redacted.len(),
            "sensitivity": "workspace_wide",
            "provenance": {
                "source": "notion.search",
                "derived": false,
                "scope": "workspace"
            },
            "taint": ["external_input", "cross_workspace"]
        }))
    }

    async fn invoke_get_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let block = client
            .get_block(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_update_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        // Extract the block content (everything except block_id)
        let mut body = input.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("block_id");
        }

        let block = client
            .update_block(block_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_delete_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let block = client
            .delete_block(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_get_block_children(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .get_block_children(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_append_blocks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let children = input
            .get("children")
            .cloned()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: children".into(),
            })?;

        let result = client
            .append_blocks(block_id, children)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "results": result.results }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let comment = client
            .add_comment(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .list_comments(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.clear_configuration();
        info!("Notion connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for NotionConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn resource_uri(kind: &str, id: &str) -> FcpResult<String> {
    crate::client::validate_notion_id(id, kind).map_err(|error| error.to_fcp_error())?;
    // Notion accepts dashed and compact UUIDs for the same object. Use one
    // scope spelling so an equivalent ID cannot evade an explicit resource deny.
    let canonical_id = uuid::Uuid::parse_str(id)
        .map_or_else(|_| id.to_owned(), |uuid| uuid.hyphenated().to_string());
    Ok(format!(
        "notion://{kind}/{}",
        crate::client::encode_path_segment(&canonical_id)
    ))
}

fn parent_resource_uri(input: &serde_json::Value) -> FcpResult<String> {
    let parent = input.get("parent").ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "Missing required field: parent".into(),
    })?;
    let mut resource = None;
    for (field, kind) in [
        ("page_id", "page"),
        ("database_id", "database"),
        ("discussion_id", "discussion"),
    ] {
        if parent.get(field).is_some() {
            if resource.is_some() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "parent must identify exactly one resource".into(),
                });
            }
            resource = Some(resource_uri(kind, require_str(parent, field)?)?);
        }
    }
    if parent.get("workspace").and_then(serde_json::Value::as_bool) == Some(true) {
        if resource.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "parent must identify exactly one resource".into(),
            });
        }
        return Ok("notion://workspace".into());
    }
    resource.ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "parent must identify a page, database, discussion, or workspace".into(),
    })
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let resource = match operation {
        "notion.create_page" | "notion.create_database" | "notion.add_comment" => {
            parent_resource_uri(input)?
        }
        "notion.get_page" | "notion.update_page" | "notion.delete_page" => {
            resource_uri("page", require_str(input, "page_id")?)?
        }
        "notion.get_database" | "notion.update_database" | "notion.query_database" => {
            resource_uri("database", require_str(input, "database_id")?)?
        }
        "notion.get_block"
        | "notion.update_block"
        | "notion.delete_block"
        | "notion.get_block_children"
        | "notion.append_blocks"
        | "notion.list_comments" => resource_uri("block", require_str(input, "block_id")?)?,
        "notion.search" => "notion://workspace/search".into(),
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    Ok(vec![resource])
}

/// Redact PII from a single search result object.
///
/// Search results can include person mentions with email addresses, internal
/// URLs, and other sensitive workspace data. This strips or masks such fields
/// to prevent accidental PII leakage in downstream processing.
fn redact_search_result(mut item: serde_json::Value) -> serde_json::Value {
    // Redact `people` and `person` property values (contain email addresses)
    if let Some(props) = item.get_mut("properties") {
        if let Some(obj) = props.as_object_mut() {
            for value in obj.values_mut() {
                redact_person_fields(value);
            }
        }
    }

    // Redact `created_by` and `last_edited_by` email fields
    for key in &["created_by", "last_edited_by"] {
        if let Some(user) = item.get_mut(*key) {
            redact_user_email(user);
        }
    }

    item
}

/// Redact email addresses from person-type property values.
fn redact_person_fields(prop: &mut serde_json::Value) {
    let prop_type = prop
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned();

    match prop_type.as_str() {
        "people" => {
            if let Some(people) = prop.get_mut("people") {
                if let Some(arr) = people.as_array_mut() {
                    for person in arr.iter_mut() {
                        redact_user_email(person);
                    }
                }
            }
        }
        "created_by" | "last_edited_by" => {
            if let Some(user) = prop.get_mut(&prop_type) {
                redact_user_email(user);
            }
        }
        _ => {}
    }
}

/// Replace an email field on a user object with a redacted placeholder.
fn redact_user_email(user: &mut serde_json::Value) {
    if let Some(person) = user.get_mut("person") {
        if person.get("email").is_some() {
            person["email"] = json!("[redacted]");
        }
    }
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

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn operations_info() -> FcpResult<&'static [OperationInfo]> {
    static OPERATIONS: OnceLock<Result<Vec<OperationInfo>, String>> = OnceLock::new();
    let operations = OPERATIONS.get_or_init(|| {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())?;
        if manifest.provides.operations.len() != OPERATION_IDS.len() {
            return Err("Notion manifest does not match the implemented operation set".into());
        }
        OPERATION_IDS
            .into_iter()
            .map(|id| {
                let operation = manifest
                    .provides
                    .operations
                    .get(id)
                    .ok_or_else(|| format!("Notion manifest is missing {id}"))?;
                Ok(OperationInfo {
                    id: OperationId::from_static(id),
                    summary: operation.description.clone(),
                    description: Some(operation.description.clone()),
                    input_schema: operation.input_schema.clone(),
                    output_schema: operation.output_schema.clone(),
                    capability: operation.capability.clone(),
                    risk_level: operation.risk_level,
                    safety_tier: operation.safety_tier,
                    idempotency: operation.idempotency,
                    ai_hints: operation.ai_hints.clone(),
                    rate_limit: operation.rate_limit.as_ref().map(|limit| limit.0.clone()),
                    requires_approval: Some(ApprovalMode::from(operation.requires_approval)),
                })
            })
            .collect()
    });
    operations.as_deref().map_err(|error| FcpError::Internal {
        message: format!("Embedded Notion manifest is invalid: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityToken, HandshakeResponse};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operations: &[&str],
        instance_id: &fcp_prelude::InstanceId,
    ) -> CapabilityToken {
        generate_scoped_token(
            signing_key,
            cap,
            operations,
            instance_id,
            &fcp_prelude::CapabilityConstraints {
                resource_allow: vec!["*".into()],
                ..Default::default()
            },
        )
    }

    fn generate_scoped_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operations: &[&str],
        instance_id: &InstanceId,
        constraints: &fcp_prelude::CapabilityConstraints,
    ) -> CapabilityToken {
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(constraints, &mut constraints_cbor).unwrap();

        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .target_instance(instance_id.as_str())
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    async fn negotiate(connector: &mut NotionConnector, key: &Ed25519SigningKey) {
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0_u8; 32],
                "capabilities_requested": ["notion.read", "notion.write"]
            }))
            .await
            .unwrap();
    }

    fn page_simulation(token: &CapabilityToken) -> serde_json::Value {
        json!({
            "type": "simulate",
            "id": "simulate-page",
            "connector_id": "fcp.notion",
            "zone_id": "z:work",
            "operation": "notion.get_page",
            "input": {"page_id": "page-1"},
            "capability_token": token
        })
    }

    fn page_invocation(token: &CapabilityToken) -> serde_json::Value {
        let mut request = page_simulation(token);
        request["type"] = json!("invoke");
        request["id"] = json!("invoke-page");
        request
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_attempts_revoke_previous_authority_and_rotate_instance() {
        for transition in [
            "configure",
            "failed_configure",
            "handshake",
            "failed_handshake",
            "shutdown",
        ] {
            let mut connector = NotionConnector::new();
            let config = json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"});
            connector.handle_configure(config.clone()).await.unwrap();
            let key = Ed25519SigningKey::generate();
            negotiate(&mut connector, &key).await;
            let old_instance = connector.instance_id().clone();
            let old_token =
                generate_valid_token(&key, "notion.read", &["notion.get_page"], &old_instance);
            let admitted: SimulateResponse = serde_json::from_value(
                connector
                    .handle_simulate(page_simulation(&old_token))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(admitted.would_succeed);

            match transition {
                "configure" => {
                    connector.handle_configure(config.clone()).await.unwrap();
                }
                "failed_configure" => {
                    assert!(
                        connector
                            .handle_configure(json!({"token": ""}))
                            .await
                            .is_err()
                    );
                }
                "handshake" => negotiate(&mut connector, &key).await,
                "failed_handshake" => {
                    assert!(
                        connector
                            .handle_handshake(json!({"zone": "z:work"}))
                            .await
                            .is_err()
                    );
                }
                "shutdown" => {
                    connector.handle_shutdown(json!({})).await.unwrap();
                }
                _ => unreachable!(),
            }
            assert_ne!(connector.instance_id(), &old_instance, "{transition}");
            let denied: SimulateResponse = serde_json::from_value(
                connector
                    .handle_simulate(page_simulation(&old_token))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(!denied.would_succeed, "{transition}");
            assert!(
                connector
                    .handle_invoke(page_invocation(&old_token))
                    .await
                    .is_err(),
                "{transition}"
            );

            connector.handle_configure(config).await.unwrap();
            negotiate(&mut connector, &key).await;
            let fresh = generate_valid_token(
                &key,
                "notion.read",
                &["notion.get_page"],
                connector.instance_id(),
            );
            let admitted: SimulateResponse = serde_json::from_value(
                connector
                    .handle_simulate(page_simulation(&fresh))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(admitted.would_succeed, "fresh session after {transition}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn negotiated_capabilities_cannot_be_expanded_by_a_valid_host_signature() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        let response = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0_u8; 32],
                "capabilities_requested": ["notion.write", "notion.write", "notion.get_page", "unknown.cap"]
            }))
            .await
            .unwrap();
        let negotiated: HandshakeResponse = serde_json::from_value(response).unwrap();
        assert_eq!(negotiated.capabilities_granted.len(), 1);
        assert_eq!(
            negotiated.capabilities_granted[0].capability.as_str(),
            "notion.write"
        );
        let token = generate_valid_token(
            &key,
            "notion.read",
            &["notion.get_page"],
            connector.instance_id(),
        );
        let denied: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(page_simulation(&token))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!denied.would_succeed);
        assert_eq!(denied.missing_capabilities, vec!["notion.read"]);
        assert!(matches!(
            connector.handle_invoke(page_invocation(&token)).await,
            Err(FcpError::CapabilityDenied { .. })
        ));

        negotiate(&mut connector, &key).await;
        let wrong_capability = generate_valid_token(
            &key,
            "notion.write",
            &["notion.get_page"],
            connector.instance_id(),
        );
        let denied: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(page_simulation(&wrong_capability))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!denied.would_succeed);
        assert_eq!(denied.missing_capabilities, vec!["notion.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_and_invoke_share_schema_identity_signature_and_resource_gates() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_no_io",
                "api_url": format!("http://{}/v1", listener.local_addr().unwrap())
            }))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        negotiate(&mut connector, &key).await;
        let token = generate_valid_token(
            &key,
            "notion.read",
            &["notion.get_page"],
            connector.instance_id(),
        );
        let allowed: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(page_simulation(&token))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(allowed.would_succeed);
        let impostor = Ed25519SigningKey::generate();
        let forged = generate_valid_token(
            &impostor,
            "notion.read",
            &["notion.get_page"],
            connector.instance_id(),
        );
        let denied_resource = generate_scoped_token(
            &key,
            "notion.read",
            &["notion.get_page"],
            connector.instance_id(),
            &fcp_prelude::CapabilityConstraints {
                resource_allow: vec!["*".into()],
                resource_deny: vec!["notion://page/page-1".into()],
                ..Default::default()
            },
        );
        let mut cases = Vec::new();
        for (field, value) in [
            ("connector_id", json!("fcp.other")),
            ("zone_id", json!("z:private")),
            ("operation", json!("notion.nonexistent")),
            ("input", json!({"page_id": 7})),
            ("input", json!({})),
        ] {
            let mut request = page_simulation(&token);
            request[field] = value;
            cases.push(request);
        }
        cases.push(page_simulation(&forged));
        cases.push(page_simulation(&denied_resource));
        for mut request in cases {
            let denied: SimulateResponse =
                serde_json::from_value(connector.handle_simulate(request.clone()).await.unwrap())
                    .unwrap();
            assert!(!denied.would_succeed);
            request["type"] = json!("invoke");
            assert!(connector.handle_invoke(request).await.is_err());
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn compact_uuid_cannot_evade_a_resource_deny() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        negotiate(&mut connector, &key).await;
        let token = generate_scoped_token(
            &key,
            "notion.read",
            &["notion.get_page"],
            connector.instance_id(),
            &fcp_prelude::CapabilityConstraints {
                resource_allow: vec!["*".into()],
                resource_deny: vec!["notion://page/550e8400-e29b-41d4-a716-446655440000".into()],
                ..Default::default()
            },
        );
        for id in [
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400E29B41D4A716446655440000",
        ] {
            let mut request = page_simulation(&token);
            request["input"]["page_id"] = json!(id);
            let denied: SimulateResponse =
                serde_json::from_value(connector.handle_simulate(request.clone()).await.unwrap())
                    .unwrap();
            assert!(!denied.would_succeed, "{id}");
            request["type"] = json!("invoke");
            assert!(connector.handle_invoke(request).await.is_err(), "{id}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn forbidden_zones_and_cross_zone_rebinding_fail_closed() {
        let mut connector = NotionConnector::new();
        let config = json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"});
        connector.handle_configure(config.clone()).await.unwrap();
        let key = Ed25519SigningKey::generate();
        let request = |zone| {
            json!({
                "protocol_version": "2.0.0",
                "zone": zone,
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0_u8; 32],
                "capabilities_requested": ["notion.read"]
            })
        };

        assert!(matches!(
            connector.handle_handshake(request("z:public")).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        connector.handle_handshake(request("z:work")).await.unwrap();
        let previous_instance = connector.instance_id().clone();
        let previous_token = generate_valid_token(
            &key,
            "notion.read",
            &["notion.get_page"],
            &previous_instance,
        );
        assert!(matches!(
            connector.handle_handshake(request("z:private")).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        assert_ne!(connector.instance_id(), &previous_instance);
        let denied: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(page_simulation(&previous_token))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!denied.would_succeed);
        assert_eq!(connector.bound_zone, Some(ZoneId::work()));

        connector.handle_handshake(request("z:work")).await.unwrap();
        connector.handle_configure(config).await.unwrap();
        connector
            .handle_handshake(request("z:private"))
            .await
            .unwrap();
        assert_eq!(connector.bound_zone, Some(ZoneId::private()));
    }

    #[fcp_async_core::runtime::test]
    async fn runtime_catalog_preserves_every_manifest_schema_and_policy() {
        let connector = NotionConnector::new();
        let catalog: Introspection =
            serde_json::from_value(connector.handle_introspect().await.unwrap()).unwrap();
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        assert_eq!(catalog.operations.len(), manifest.provides.operations.len());
        for operation in catalog.operations {
            let declared = &manifest.provides.operations[operation.id.as_str()];
            assert_eq!(operation.input_schema, declared.input_schema);
            assert_eq!(operation.output_schema, declared.output_schema);
            assert_eq!(operation.capability, declared.capability);
            assert_eq!(operation.risk_level, declared.risk_level);
            assert_eq!(operation.safety_tier, declared.safety_tier);
            assert_eq!(operation.idempotency, declared.idempotency);
            assert_eq!(
                operation.requires_approval,
                Some(ApprovalMode::from(declared.requires_approval))
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_health().await.unwrap();
        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        let details = health.details.unwrap();
        assert_eq!(details["configured"], false);
        assert_eq!(details["handshaken"], false);
        assert_eq!(details["instance_id"], connector.instance_id().as_str());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = NotionConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let handshake = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.read"]
            }))
            .await;
        assert!(matches!(handshake, Err(FcpError::NotConfigured)));

        let token = generate_valid_token(
            &signing_key,
            "notion.read",
            &["notion.get_page"],
            &connector.base.instance_id,
        );

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "get-page-unconfigured",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.get_page",
                "input": { "page_id": "page-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "notion.read",
            &["notion.get_page"],
            &connector.base.instance_id,
        );

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "get-page-missing-id",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.get_page",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = NotionConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"notion.create_page"));
        assert!(op_ids.contains(&"notion.get_page"));
        assert!(op_ids.contains(&"notion.update_page"));
        assert!(op_ids.contains(&"notion.delete_page"));
        assert!(op_ids.contains(&"notion.get_database"));
        assert!(op_ids.contains(&"notion.create_database"));
        assert!(op_ids.contains(&"notion.update_database"));
        assert!(op_ids.contains(&"notion.query_database"));
        assert!(op_ids.contains(&"notion.search"));
        assert!(op_ids.contains(&"notion.get_block"));
        assert!(op_ids.contains(&"notion.update_block"));
        assert!(op_ids.contains(&"notion.delete_block"));
        assert!(op_ids.contains(&"notion.get_block_children"));
        assert!(op_ids.contains(&"notion.append_blocks"));
        assert!(op_ids.contains(&"notion.add_comment"));
        assert!(op_ids.contains(&"notion.list_comments"));
        assert_eq!(ops.len(), 16);
    }

    // ── Invoke missing-field tests for new operations ──────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_database_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "notion.read",
            &["notion.get_database"],
            &connector.base.instance_id,
        );

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "get-database-missing-id",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.get_database",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_database_missing_fields() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.write"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "notion.write",
            &["notion.create_database"],
            &connector.base.instance_id,
        );

        // Missing parent
        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "create-database-missing-parent",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.create_database",
                "input": {"title": [], "properties": {}},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest for parent, got: {e:?}"),
        }

        // Missing title
        let token2 = generate_valid_token(
            &signing_key,
            "notion.write",
            &["notion.create_database"],
            &connector.base.instance_id,
        );
        let result2 = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "create-database-missing-title",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.create_database",
                "input": {"parent": {"page_id": "p1"}, "properties": {}},
                "capability_token": token2
            }))
            .await;
        assert!(result2.is_err());
        match result2.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest for title, got: {e:?}"),
        }

        // Missing properties
        let token3 = generate_valid_token(
            &signing_key,
            "notion.write",
            &["notion.create_database"],
            &connector.base.instance_id,
        );
        let result3 = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "create-database-missing-properties",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.create_database",
                "input": {"parent": {"page_id": "p1"}, "title": []},
                "capability_token": token3
            }))
            .await;
        assert!(result3.is_err());
        match result3.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest for properties, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_block_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "notion.read",
            &["notion.get_block"],
            &connector.base.instance_id,
        );

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "get-block-missing-id",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.get_block",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_block_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.delete"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "notion.delete",
            &["notion.delete_block"],
            &connector.base.instance_id,
        );

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "delete-block-missing-id",
                "connector_id": "fcp.notion",
                "zone_id": "z:work",
                "operation": "notion.delete_block",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("declared schema"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels() {
        let connector = NotionConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        // Verify read ops are safe
        for read_op in &[
            "notion.get_page",
            "notion.get_database",
            "notion.query_database",
            "notion.get_block",
            "notion.get_block_children",
            "notion.list_comments",
        ] {
            let op = ops.iter().find(|o| o["id"] == *read_op).unwrap();
            assert_eq!(op["risk_level"], "low", "{read_op} should be low risk");
            assert_eq!(op["safety_tier"], "safe", "{read_op} should be safe");
        }

        // Verify search is medium risk (sensitive cross-workspace operation)
        let search_op = ops.iter().find(|o| o["id"] == "notion.search").unwrap();
        assert_eq!(
            search_op["risk_level"], "medium",
            "search should be medium risk"
        );
        assert_eq!(
            search_op["safety_tier"], "safe",
            "search is safe (read-only)"
        );
        assert_eq!(
            search_op["capability"], "notion.search",
            "search uses dedicated cap"
        );

        // Verify write ops are risky
        for write_op in &[
            "notion.create_page",
            "notion.update_page",
            "notion.create_database",
            "notion.update_database",
            "notion.update_block",
            "notion.append_blocks",
            "notion.add_comment",
        ] {
            let op = ops.iter().find(|o| o["id"] == *write_op).unwrap();
            assert_eq!(
                op["risk_level"], "medium",
                "{write_op} should be medium risk"
            );
            assert_eq!(op["safety_tier"], "risky", "{write_op} should be risky");
        }

        // Verify delete ops are high risk
        for del_op in &["notion.delete_page", "notion.delete_block"] {
            let op = ops.iter().find(|o| o["id"] == *del_op).unwrap();
            assert_eq!(op["risk_level"], "high", "{del_op} should be high risk");
        }
    }

    // ── Provisioning automation tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
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
        let mut connector = NotionConnector::new();
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
    async fn test_configure_with_custom_api_url() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "https://custom-notion.example.com/v1"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api.notion.com"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id_allows_custom_api_url() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "credential_id": cid,
                "api_url": "https://proxy.internal.example/v1"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.api_url, "https://proxy.internal.example/v1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_api_url_with_query_string() {
        let mut connector = NotionConnector::new();
        let err = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "https://api.notion.com/?leak=attacker.com"
            }))
            .await
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_api_url_with_fragment() {
        let mut connector = NotionConnector::new();
        let err = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "https://api.notion.com/#frag"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_api_url_with_userinfo() {
        let mut connector = NotionConnector::new();
        let err = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "https://attacker:pw@api.notion.com/"
            }))
            .await
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_empty_token() {
        let mut connector = NotionConnector::new();
        let result = connector.handle_configure(json!({ "token": "" })).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("non-empty"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_notion_version() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "notion_version": "2025-09-03"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.notion_version.as_deref(), Some("2025-09-03"));
        assert_eq!(
            connector.client.as_ref().unwrap().notion_version(),
            "2025-09-03"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_notion_version() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "notion_version": "2026/03/11"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("notion_version must look like"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        let snapshot: HealthSnapshot = serde_json::from_value(health).unwrap();
        let details = snapshot.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], false);
        assert!(details["auth_mode"].as_str().unwrap().contains("token"));
        assert!(details["api_url"].as_str().is_some());
        assert_eq!(details["notion_version"], DEFAULT_NOTION_VERSION);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 7);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 7);
        let version_check = checks
            .iter()
            .find(|check| check["name"] == "notion_version")
            .unwrap();
        assert_eq!(version_check["status"], "healthy");
        assert_eq!(
            version_check["message"],
            format!("Notion-Version header: {DEFAULT_NOTION_VERSION}")
        );
        for check in checks {
            assert_eq!(check["status"], "healthy");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = NotionConnector::new();
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
        assert_eq!(cred_check["status"], "healthy");
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ── Redaction unit tests (u56.4) ──────────────────────────────────

    #[test]
    fn redact_search_result_strips_person_emails() {
        let mut item = json!({
            "object": "page",
            "id": "pg-1",
            "properties": {
                "Assignee": {
                    "type": "people",
                    "people": [{
                        "object": "user",
                        "id": "u1",
                        "name": "Alice",
                        "person": { "email": "alice@example.com" }
                    }]
                }
            }
        });

        item = super::redact_search_result(item);

        assert_eq!(
            item["properties"]["Assignee"]["people"][0]["person"]["email"],
            "[redacted]"
        );
        assert_eq!(item["properties"]["Assignee"]["people"][0]["name"], "Alice");
    }

    #[test]
    fn redact_search_result_strips_created_by_email() {
        let mut item = json!({
            "object": "page",
            "id": "pg-2",
            "created_by": {
                "object": "user",
                "id": "u1",
                "person": { "email": "alice@acme.com" }
            },
            "last_edited_by": {
                "object": "user",
                "id": "u2",
                "person": { "email": "bob@acme.com" }
            }
        });

        item = super::redact_search_result(item);

        assert_eq!(item["created_by"]["person"]["email"], "[redacted]");
        assert_eq!(item["last_edited_by"]["person"]["email"], "[redacted]");
    }

    #[test]
    fn redact_search_result_preserves_non_pii_fields() {
        let item = json!({
            "object": "page",
            "id": "pg-3",
            "properties": {
                "Title": {
                    "type": "title",
                    "title": [{ "text": { "content": "Important" } }]
                }
            },
            "url": "https://notion.so/Important"
        });

        let redacted = super::redact_search_result(item);

        assert_eq!(redacted["id"], "pg-3");
        assert_eq!(redacted["url"], "https://notion.so/Important");
        assert_eq!(
            redacted["properties"]["Title"]["title"][0]["text"]["content"],
            "Important"
        );
    }

    #[test]
    fn redact_search_result_handles_no_person_data() {
        let item = json!({
            "object": "database",
            "id": "db-1",
            "properties": {
                "Name": { "type": "title", "title": {} }
            }
        });

        // Should not panic or modify anything
        let redacted = super::redact_search_result(item);
        assert_eq!(redacted["id"], "db-1");
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        let response = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0_u8; 32],
                "capabilities_requested": []
            }))
            .await
            .unwrap();
        assert_eq!(response["manifest_hash"], expected);
        assert_eq!(response["instance_id"], json!(connector.instance_id()));
    }
}
