//! FCP Monday.com Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType,
    RecipeId, RequestId, SelfCheckReport, SimulateRequest, SimulateResponse, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, MondayAuth, MondayClient},
    error::MondayError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_BOARDS_LIST: &str = "monday.boards.list";
const OP_BOARDS_GET: &str = "monday.boards.get";
const OP_ITEMS_LIST: &str = "monday.items.list";
const OP_ITEMS_CREATE: &str = "monday.items.create";
const OP_ITEMS_DELETE: &str = "monday.items.delete";
const OP_UPDATES_LIST: &str = "monday.updates.list";
const OP_UPDATES_CREATE: &str = "monday.updates.create";
const OPERATION_ORDER: [&str; 7] = [
    OP_BOARDS_LIST,
    OP_BOARDS_GET,
    OP_ITEMS_LIST,
    OP_ITEMS_CREATE,
    OP_ITEMS_DELETE,
    OP_UPDATES_LIST,
    OP_UPDATES_CREATE,
];

/// Parsed and validated Monday.com connector configuration.
#[derive(Debug, Clone)]
struct MondayConfig {
    auth: MondayAuth,
    base_url: String,
}

impl MondayConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let direct_auth = params
            .get("api_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
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

        let auth = match (direct_auth, credential_id) {
            (Some(key), None) => MondayAuth::ApiToken(key),
            (None, Some(cred_id)) => MondayAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();
        let base_url = validate_base_url_for_auth(&base_url, &auth)?;

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                MondayAuth::ApiToken(_) => "api_token",
                MondayAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, MondayAuth::ApiToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &MondayAuth) -> FcpResult<String> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    // Strip query/fragment/userinfo before scheme/host enforcement. The
    // MondayClient POSTs directly to self.base_url (client.rs:124) so
    // anything in the query string is sent on every GraphQL request.
    // A base_url like `https://api.monday.com/v2?leak=x` would leak
    // attacker-chosen query values on every call; userinfo would bake
    // into the request URL and silently override the Authorization
    // header. Matches the hygiene in airtable / asana / gmail / notion
    // / hubspot / whatsapp / linear / clickup.
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
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    match auth {
        MondayAuth::ApiToken(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        MondayAuth::CredentialId(_) => {
            let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must include a host".into(),
            })?;
            let local = is_local_test_host(host);
            let secure_or_local = parsed.scheme() == "https" || local;
            if !secure_or_local {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                            .into(),
                });
            }
        }
    }

    Ok(canonical)
}

#[derive(Debug, Clone, Serialize)]
// Readiness output exposes independent operator-facing booleans in doctor responses.
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Monday.com Connector.
pub struct MondayConnector {
    base: Arc<BaseConnector>,
    config: Option<MondayConfig>,
    client: Option<Arc<MondayClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MondayConnector {
    /// Create a new Monday.com connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("monday"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MondayConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MondayConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MondayConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Monday.com connector");

        let client = MondayClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.monday",
            "connector_version": "0.1.0",
            "capabilities": [
                "monday.boards.read",
                "monday.items.read",
                "monday.items.write",
                "monday.updates.read",
                "monday.updates.write"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        let ops_value = serde_json::to_value(&ops).unwrap_or_else(|_| json!([]));
        Ok(json!({
            "connector_id": "fcp.monday",
            "version": "0.1.0",
            "operations": ops_value,
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            OP_BOARDS_LIST => self.invoke_boards_list(client, &input).await,
            OP_BOARDS_GET => self.invoke_boards_get(client, &input).await,
            OP_ITEMS_LIST => self.invoke_items_list(client, &input).await,
            OP_ITEMS_CREATE => self.invoke_items_create(client, &input).await,
            OP_ITEMS_DELETE => self.invoke_items_delete(client, &input).await,
            OP_UPDATES_LIST => self.invoke_updates_list(client, &input).await,
            OP_UPDATES_CREATE => self.invoke_updates_create(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let request = parse_simulate_params(&params);
        let Some(capability) = monday_capability_for_operation(&request.operation) else {
            let response =
                SimulateResponse::denied(request.id, "Unknown operation", "unknown_operation");
            return serialize_simulate_response(response);
        };

        if let Err(error) = validate_monday_simulate_input(&request.operation, &request.input) {
            let response =
                SimulateResponse::denied(request.id, error.to_string(), error.error_code());
            return serialize_simulate_response(response);
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                request.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serialize_simulate_response(
                response.with_missing_capabilities(vec![capability.as_str().to_string()]),
            );
        }

        if self.session_id.is_none() {
            let response = SimulateResponse::denied(
                request.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serialize_simulate_response(response);
        }

        serialize_simulate_response(SimulateResponse::allowed(request.id))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Monday.com connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "monday.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Monday.com self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_boards_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(25);
        let resp = client.list_boards(limit).await?;
        let boards = resp.get("boards").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "boards": boards }))
    }

    async fn invoke_items_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.list_items(board_id).await?;
        let items = resp
            .get("boards")
            .and_then(|b| b.as_array())
            .and_then(|a| a.first())
            .and_then(|b| b.get("items_page"))
            .and_then(|ip| ip.get("items"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(json!({ "items": items }))
    }

    async fn invoke_items_create(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let item_name = require_str(input, "item_name")?;
        let column_values = input.get("column_values").map(|v| v.to_string());
        let resp = client
            .create_item(board_id, item_name, column_values.as_deref())
            .await?;
        let item_id = resp
            .get("create_item")
            .and_then(|ci| ci.get("id"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "id": item_id }))
    }

    async fn invoke_items_delete(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        client.delete_item(item_id).await?;
        Ok(json!({}))
    }

    async fn invoke_boards_get(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.get_board(board_id).await?;
        let board = resp
            .get("boards")
            .and_then(|b| b.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "board": board }))
    }

    async fn invoke_updates_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        let resp = client.list_updates(item_id).await?;
        let updates = resp
            .get("items")
            .and_then(|i| i.as_array())
            .and_then(|a| a.first())
            .and_then(|i| i.get("updates"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(json!({ "updates": updates }))
    }

    async fn invoke_updates_create(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        let body = require_str(input, "body")?;
        let resp = client.create_update(item_id, body).await?;
        let update = resp
            .get("create_update")
            .cloned()
            .unwrap_or_else(|| json!({}));
        Ok(update)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MondayError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MondayError::InvalidInput(format!("Missing required field: {field}")))
}

struct ParsedSimulateRequest {
    id: RequestId,
    operation: String,
    input: Value,
}

fn parse_simulate_params(params: &Value) -> ParsedSimulateRequest {
    if let Ok(req) = serde_json::from_value::<SimulateRequest>(params.clone()) {
        return ParsedSimulateRequest {
            id: req.id,
            operation: req.operation.as_str().to_string(),
            input: req.input,
        };
    }

    let id = params
        .get("id")
        .and_then(Value::as_str)
        .map_or_else(|| RequestId::new("monday-simulate"), RequestId::new);
    let operation = params
        .get("operation_id")
        .or_else(|| params.get("operation"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

    ParsedSimulateRequest {
        id,
        operation,
        input,
    }
}

fn monday_capability_for_operation(operation: &str) -> Option<CapabilityId> {
    typed_operations_info()
        .into_iter()
        .find(|info| info.id.as_str() == operation)
        .map(|info| info.capability)
}

fn validate_monday_simulate_input(operation: &str, input: &Value) -> FcpResult<()> {
    match operation {
        OP_BOARDS_LIST => Ok(()),
        OP_BOARDS_GET | OP_ITEMS_LIST => require_str(input, "board_id")
            .map(|_| ())
            .map_err(|error| error.to_fcp_error()),
        OP_ITEMS_CREATE => {
            require_str(input, "board_id").map_err(|error| error.to_fcp_error())?;
            require_str(input, "item_name")
                .map(|_| ())
                .map_err(|error| error.to_fcp_error())
        }
        OP_ITEMS_DELETE | OP_UPDATES_LIST => require_str(input, "item_id")
            .map(|_| ())
            .map_err(|error| error.to_fcp_error()),
        OP_UPDATES_CREATE => {
            require_str(input, "item_id").map_err(|error| error.to_fcp_error())?;
            require_str(input, "body")
                .map(|_| ())
                .map_err(|error| error.to_fcp_error())
        }
        _ => Ok(()),
    }
}

fn serialize_simulate_response(response: SimulateResponse) -> FcpResult<Value> {
    serde_json::to_value(response).map_err(|e| FcpError::Internal {
        message: format!("Failed to serialize simulate response: {e}"),
    })
}

/// Build the provisioning recipe for the Monday.com connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("monday.api_token"),
        "1",
        "Provision Monday.com connector with an API token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_token"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your Monday.com API token".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.monday".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("api.monday.com") || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and api.monday.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build typed operations info for introspection from the embedded manifest.
fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Monday.com manifest should parse");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|known_id| *known_id == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn operation_info_from_manifest(id: String, operation: &OperationSection) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

/// Build the operations info for introspection (JSON format, used by simulate).
fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| serde_json::to_value(typed_operations_info()).unwrap_or_default())
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_monday_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn config_from_api_token() {
        let config = MondayConfig::from_params(&json!({
            "api_token": "test-api-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, MondayAuth::ApiToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = MondayConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://monday.example.com/v2",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_credential_id_allows_custom_base_url() {
        let config = MondayConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://monday.example.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://monday.example.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MondayConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MondayConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MondayConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_token() {
        let config = MondayConfig::from_params(&json!({ "api_token": "  tok_test  " })).unwrap();
        let expected = ["tok", "test"].join("_");
        assert!(matches!(&config.auth, MondayAuth::ApiToken(value) if value == &expected));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"board_id": "123"});
        assert_eq!(require_str(&input, "board_id").unwrap(), "123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"board_id": 42});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"board_id": null});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 7);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_monday_manifest()?;
        let operations = typed_operations_info();

        assert_eq!(operations.len(), OPERATION_ORDER.len());
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for (index, operation) in operations.iter().enumerate() {
            let operation_id = operation.id.as_str();
            assert_eq!(
                operation_id, OPERATION_ORDER[index],
                "operation order changed at index {index}"
            );

            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest missing operation {operation_id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).expect("serialize runtime hints"),
                serde_json::to_value(&manifest_operation.ai_hints)
                    .expect("serialize manifest hints")
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).map_err(|error| error.to_string())?,
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| rate_limit.0.clone()),
                )
                .map_err(|error| error.to_string())?
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{operation_id} should retain manifest network constraints"
            );
        }

        Ok(())
    }

    #[test]
    fn operations_info_json_exposes_manifest_approval_modes() {
        let ops = operations_info();
        let item_create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_ITEMS_CREATE))
            .unwrap();
        let item_delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_ITEMS_DELETE))
            .unwrap();
        let update_create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_UPDATES_CREATE))
            .unwrap();

        assert_eq!(item_create_op["requires_approval"], "policy");
        assert_eq!(item_delete_op["requires_approval"], "interactive");
        assert_eq!(update_create_op["requires_approval"], "policy");
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"monday.boards.list"));
        assert!(ids.contains(&"monday.boards.get"));
        assert!(ids.contains(&"monday.items.list"));
        assert!(ids.contains(&"monday.items.create"));
        assert!(ids.contains(&"monday.items.delete"));
        assert!(ids.contains(&"monday.updates.list"));
        assert!(ids.contains(&"monday.updates.create"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = MondayConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = MondayConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failure reason");
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let s = serde_json::to_string(&check).unwrap();
        let check2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(check2.name, "config");
        assert!(check2.passed);
        assert_eq!(check2.message, Some("ok".into()));
        assert!(check2.critical);
    }

    #[test]
    fn doctor_status_serde_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let ds: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(ds, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let ds: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(ds, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let ds: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(ds, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("issue".into()),
                critical: false,
            },
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.status, DoctorStatus::Degraded);
        assert_eq!(r2.checks.len(), 2);
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let check2 = check.clone();
        assert_eq!(check.name, check2.name);
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "y".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let r2 = r.clone();
        assert_eq!(r.status, r2.status);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"board_id": [1, 2, 3]});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"board_id": true});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"board_id": ""});
        assert_eq!(require_str(&input, "board_id").unwrap(), "");
    }

    #[test]
    fn operations_boards_list_capability() {
        let ops = operations_info();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.boards.list")
            .unwrap();
        assert_eq!(bl["capability"], "monday.boards.read");
    }

    #[test]
    fn operations_boards_get_capability() {
        let ops = operations_info();
        let bg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.boards.get")
            .unwrap();
        assert_eq!(bg["capability"], "monday.boards.read");
    }

    #[test]
    fn operations_items_create_capability() {
        let ops = operations_info();
        let ic = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.create")
            .unwrap();
        assert_eq!(ic["capability"], "monday.items.write");
    }

    #[test]
    fn operations_items_delete_is_dangerous() {
        let ops = operations_info();
        let id = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.delete")
            .unwrap();
        assert_eq!(id["safety_tier"], "dangerous");
        assert_eq!(id["risk_level"], "high");
    }

    #[test]
    fn operations_items_create_is_risky() {
        let ops = operations_info();
        let ic = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.create")
            .unwrap();
        assert_eq!(ic["safety_tier"], "risky");
        assert_eq!(ic["risk_level"], "medium");
    }

    #[test]
    fn operations_updates_create_is_risky() {
        let ops = operations_info();
        let uc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.updates.create")
            .unwrap();
        assert_eq!(uc["safety_tier"], "risky");
        assert_eq!(uc["risk_level"], "medium");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_read_ops_are_strict_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["idempotency"], "strict",
                    "read op {} should be strict",
                    op["id"]
                );
            }
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                let idem = op["idempotency"].as_str().unwrap();
                // Write ops should have idempotency specified (none or strict)
                assert!(
                    idem == "none" || idem == "strict",
                    "write op {} has unexpected idempotency: {idem}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_mixed_critical_and_non_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn write_operations_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                assert_ne!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "write op {} should not be safe",
                    op["id"]
                );
            }
        }
    }

    // -- Provisioning automation tests --

    #[test]
    fn provisioning_readiness_api_token_mode() {
        let config = MondayConfig::from_params(&json!({
            "api_token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = MondayConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = MondayConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = MondayConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.monday.com"));
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "monday.api_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "monday.api_token");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_enter_step_is_prompt_secret() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[0];
        assert!(
            matches!(&step.kind, ProvisioningStepType::PromptSecret { message } if message.contains("Monday.com") && message.contains("API token"))
        );
    }

    #[test]
    fn provisioning_recipe_store_step_is_store_secret() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[1];
        assert!(
            matches!(&step.kind, ProvisioningStepType::StoreSecret { key, value_from, scope }
                if key == "api_token" && value_from.as_str() == "enter_token" && scope == "connector:fcp.monday")
        );
    }

    #[test]
    fn base_url_policy_accepts_monday_https() {
        let (ok, message) = base_url_policy("https://api.monday.com/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://api.monday.com/v2");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.monday.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_case_insensitive_host() {
        let (ok, _) = base_url_policy("https://API.MONDAY.COM/v2");
        assert!(ok);
    }

    #[test]
    fn is_local_test_host_positive() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_negative() {
        assert!(!is_local_test_host("api.monday.com"));
        assert!(!is_local_test_host("evil.com"));
        assert!(!is_local_test_host("192.168.1.1"));
    }

    #[test]
    fn validate_base_url_for_auth_accepts_api_monday_com_with_token() {
        let auth = MondayAuth::ApiToken("mtok".into());
        let out = validate_base_url_for_auth("https://api.monday.com/v2", &auth).unwrap();
        assert_eq!(out, "https://api.monday.com/v2");
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_token() {
        let auth = MondayAuth::ApiToken("mtok".into());
        let err =
            validate_base_url_for_auth("https://api.monday.com/v2?leak=x", &auth).unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains("query"))
        );
    }

    #[test]
    fn validate_base_url_for_auth_rejects_fragment_with_token() {
        let auth = MondayAuth::ApiToken("mtok".into());
        let err = validate_base_url_for_auth("https://api.monday.com/v2#frag", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_rejects_userinfo_with_token() {
        let auth = MondayAuth::ApiToken("mtok".into());
        let err =
            validate_base_url_for_auth("https://attacker:pw@api.monday.com/v2", &auth).unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo"))
        );
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_credential_id() {
        let auth = MondayAuth::CredentialId(CredentialId::new());
        let err =
            validate_base_url_for_auth("https://vault-proxy.example/v2?leak=x", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_rejects_substring_smuggle_with_token() {
        let auth = MondayAuth::ApiToken("mtok".into());
        let err =
            validate_base_url_for_auth("https://evil.com/api.monday.com/v2", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }
}
