//! FCP `Logseq` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OperationId,
    OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId,
    SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, LogseqAuth, LogseqClient},
    error::LogseqError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_PAGES_LIST: &str = "logseq.pages.list";
const OP_PAGES_GET: &str = "logseq.pages.get";
const OP_BLOCKS_LIST: &str = "logseq.blocks.list";
const OP_BLOCKS_CREATE: &str = "logseq.blocks.create";
const OPERATION_ORDER: [&str; 4] = [
    OP_PAGES_LIST,
    OP_PAGES_GET,
    OP_BLOCKS_LIST,
    OP_BLOCKS_CREATE,
];

/// Parsed and validated `Logseq` connector configuration.
#[derive(Debug, Clone)]
struct LogseqConfig {
    auth: LogseqAuth,
    base_url: String,
}

impl LogseqConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => LogseqAuth::BearerToken(token),
            (None, Some(cred_id)) => LogseqAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                LogseqAuth::BearerToken(_) => "bearer_token",
                LogseqAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, LogseqAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
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

/// FCP `Logseq` Connector.
pub struct LogseqConnector {
    base: Arc<BaseConnector>,
    config: Option<LogseqConfig>,
    client: Option<Arc<LogseqClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl LogseqConnector {
    /// Create a new `Logseq` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("logseq"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for LogseqConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl LogseqConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = LogseqConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            base_url = %config.base_url,
            "Configuring Logseq connector"
        );

        let client = LogseqClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.logseq",
            "connector_version": "0.1.0",
            "capabilities": [
                "logseq.pages.read",
                "logseq.blocks.read",
                "logseq.blocks.write"
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
        let ops = introspect_operations()?;
        Ok(json!({
            "connector_id": "fcp.logseq",
            "version": "0.1.0",
            "operations": ops,
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
            OP_PAGES_LIST => self.invoke_pages_list(client).await,
            OP_PAGES_GET => self.invoke_pages_get(client, &input).await,
            OP_BLOCKS_LIST => self.invoke_blocks_list(client, &input).await,
            OP_BLOCKS_CREATE => self.invoke_blocks_create(client, &input).await,
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
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = typed_operations_info()?
            .iter()
            .any(|op| op.id.as_str() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Logseq connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_pages_list(
        &self,
        client: &LogseqClient,
    ) -> Result<serde_json::Value, LogseqError> {
        let data = client.list_pages().await?;
        Ok(data)
    }

    async fn invoke_pages_get(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let name = require_str(input, "name")?;
        let data = client.get_page(name).await?;
        Ok(data)
    }

    async fn invoke_blocks_list(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let page = require_str(input, "page")?;
        let data = client.list_blocks(page).await?;
        Ok(data)
    }

    async fn invoke_blocks_create(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let page = require_str(input, "page")?;
        let content = require_str(input, "content")?;
        let data = client.create_block(page, content).await?;
        Ok(data)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "logseq.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Logseq self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, LogseqError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LogseqError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Logseq connector.
///
/// Logseq uses a local HTTP API with an authorization token that the user
/// obtains from *Settings > Features > Developer > Authorization token*.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("logseq.api_token"),
        "1",
        "Provision Logseq connector with a local API authorization token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_token"),
        ProvisioningStepType::PromptSecret {
            message:
                "Paste your Logseq API authorization token (from Settings > Features > Developer)"
                    .into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.logseq".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
    )
}

/// Validate the configured base URL against the Logseq security policy.
///
/// Logseq runs as a local desktop application, so we only accept `localhost`,
/// `127.0.0.1` and `::1` as valid hosts. Any scheme is fine for these local
/// addresses (typically plain `http`).
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

    if is_local_test_host(host) {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Logseq API must be accessed via localhost/127.0.0.1/::1 (got {host}): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> FcpResult<Vec<OperationInfo>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect())
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> Value {
    static OPERATIONS: OnceLock<Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Value::Array(
                introspect_operations()
                    .expect("embedded Logseq manifest should validate for introspection"),
            )
        })
        .clone()
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Logseq manifest is invalid: {error}"),
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn introspect_operations() -> FcpResult<Vec<Value>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| {
            let operation_info = operation_info_from_manifest(id, &operation);
            introspect_operation_from_manifest(operation_info, &operation)
        })
        .collect())
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

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata =
        serde_json::to_value(operation_info).expect("Logseq operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata
}

fn operation_info_from_manifest(
    id: String,
    operation: &fcp_manifest::OperationSection,
) -> OperationInfo {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_logseq_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML)
            .map_err(|err| format!("Logseq manifest should parse with strict schema: {err}"))
    }

    #[test]
    fn config_from_access_token() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, LogseqAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = LogseqConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:9999/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:9999/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = LogseqConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = LogseqConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = LogseqConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = LogseqConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            LogseqAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            LogseqAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"name": "Daily Notes"});
        assert_eq!(require_str(&input, "name").unwrap(), "Daily Notes");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"name": 42});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"name": null});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"name": true});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"name": ["a", "b"]});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"name": ""});
        assert_eq!(require_str(&input, "name").unwrap(), "");
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 4);
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
        assert_eq!(ids, OPERATION_ORDER.to_vec());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_logseq_manifest()?;
        let operation_catalog =
            typed_operations_info().map_err(|err| format!("typed operation catalog: {err}"))?;
        let operation_metadata = operations_info();
        let runtime_operations = operation_metadata
            .as_array()
            .ok_or_else(|| "runtime operations should serialize as an array".to_owned())?;

        let catalog_ids: Vec<&str> = operation_catalog
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();
        let metadata_ids: Vec<&str> = runtime_operations
            .iter()
            .filter_map(|operation| operation["id"].as_str())
            .collect();

        assert_eq!(catalog_ids, OPERATION_ORDER.to_vec());
        assert_eq!(metadata_ids, OPERATION_ORDER.to_vec());
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        for operation in operation_catalog {
            let operation_id = operation.id.as_str();
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest should declare {operation_id}"))?;
            let metadata = runtime_operations
                .iter()
                .find(|candidate| candidate["id"].as_str() == Some(operation_id))
                .ok_or_else(|| format!("runtime metadata should declare {operation_id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_ref(),
                Some(&manifest_operation.description)
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
                operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
            assert_eq!(
                operation.ai_hints.common_mistakes,
                manifest_operation.ai_hints.common_mistakes
            );
            assert_eq!(
                operation.ai_hints.examples,
                manifest_operation.ai_hints.examples
            );
            assert_eq!(
                operation.ai_hints.related,
                manifest_operation.ai_hints.related
            );
            assert_eq!(
                metadata["requires_approval"],
                json!(manifest_operation.requires_approval)
            );
            assert_eq!(
                metadata["revocation_freshness"],
                json!(manifest_operation.revocation_freshness)
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{operation_id} should declare manifest network constraints"
            );
            assert_eq!(
                metadata["network_constraints"],
                json!(manifest_operation.network_constraints.as_ref().unwrap())
            );
        }

        Ok(())
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
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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

    #[test]
    fn operations_pages_list_capability() {
        let ops = operations_info();
        let pages_list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.list")
            .unwrap();
        assert_eq!(pages_list["capability"], "logseq.pages.read");
    }

    #[test]
    fn operations_blocks_create_capability() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["capability"], "logseq.blocks.write");
    }

    #[test]
    fn operations_pages_get_capability() {
        let ops = operations_info();
        let pg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.get")
            .unwrap();
        assert_eq!(pg["capability"], "logseq.pages.read");
    }

    #[test]
    fn operations_blocks_list_capability() {
        let ops = operations_info();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.list")
            .unwrap();
        assert_eq!(bl["capability"], "logseq.blocks.read");
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
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failed"));
    }

    #[test]
    fn connector_default() {
        let c = LogseqConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = LogseqConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_default_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v2 = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v2, "degraded");
        let v3 = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v3, "unhealthy");
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_check_debug_format() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("test_check"));
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"name": {"nested": true}});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_blocks_create_is_risky() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["safety_tier"], "risky");
        assert_eq!(bc["risk_level"], "medium");
    }

    #[test]
    fn operations_blocks_create_not_idempotent() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["idempotency"], "none");
    }

    #[test]
    fn operations_pages_list_is_strict() {
        let ops = operations_info();
        let pl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.list")
            .unwrap();
        assert_eq!(pl["idempotency"], "strict");
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = LogseqConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_error_count_zero() {
        let c = LogseqConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_clone_preserves_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://custom:9999/api",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "http://custom:9999/api");
        assert_eq!(cloned.base_url, "http://custom:9999/api");
    }

    #[test]
    fn config_debug_does_not_leak_token() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "super-secret-logseq-token",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("LogseqConfig"));
        assert!(!dbg.contains("super-secret-logseq-token"));
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_capabilities_have_logseq_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("logseq."),
                "capability {cap} missing logseq prefix for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(s, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_deserialize_unhealthy() {
        let v = json!({"status": "unhealthy", "checks": [{"name": "cfg", "passed": false, "critical": true}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].critical);
    }

    #[test]
    fn doctor_check_clone_preserves_message() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: false,
            message: Some("server not reachable".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "connectivity");
        assert_eq!(cloned.message, Some("server not reachable".into()));
    }

    #[test]
    fn doctor_result_clone_preserves_checks() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
        assert_eq!(cloned.checks[0].name, "a");
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"page": 1.23});
        assert!(require_str(&input, "page").is_err());
    }

    #[test]
    fn operations_all_ids_have_logseq_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("logseq."),
                "op id {id} missing logseq prefix"
            );
        }
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "none", "idempotent"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    // -- Provisioning automation tests --

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "logseq.api_token");
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
        assert_eq!(v["id"], "logseq.api_token");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_description_mentions_logseq() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.to_lowercase().contains("logseq"));
    }

    #[test]
    fn provisioning_recipe_enter_token_is_prompt_secret() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[0];
        assert!(matches!(
            &step.kind,
            ProvisioningStepType::PromptSecret { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_store_token_is_store_secret() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[1];
        assert!(matches!(
            &step.kind,
            ProvisioningStepType::StoreSecret { .. }
        ));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, msg) = base_url_policy("http://localhost:12315/api");
        assert!(ok);
        assert!(msg.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:12315/api");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, msg) = base_url_policy("http://[::1]:12315/api");
        assert!(ok, "IPv6 loopback should be accepted: {msg}");
    }

    #[test]
    fn base_url_policy_accepts_localhost_any_port() {
        let (ok, _) = base_url_policy("http://localhost:9999");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_remote_host() {
        let (ok, msg) = base_url_policy("https://logseq.example.com/api");
        assert!(!ok);
        assert!(msg.contains("localhost"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, msg) = base_url_policy("not a url");
        assert!(!ok);
        assert!(msg.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_missing_host() {
        let (ok, msg) = base_url_policy("file:///tmp/logseq");
        assert!(!ok);
        // file:// URLs have no host — rejected either by parse or by the host check
        assert!(!ok, "file URL should be rejected: {msg}");
    }

    #[test]
    fn is_local_test_host_recognizes_all() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(is_local_test_host("[::1]"));
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("192.168.1.1"));
    }

    #[test]
    fn provisioning_readiness_bearer_token() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = LogseqConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_remote_url_rejected() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com/api",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("localhost"));
    }

    #[test]
    fn provisioning_readiness_custom_localhost_port() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:9999/api",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, "http://localhost:9999/api");
    }

    #[test]
    fn self_check_report_ok_has_status_ok() {
        let report = SelfCheckReport::ok();
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn self_check_report_degraded_has_reason() {
        let report = SelfCheckReport::degraded("test_code", "test message");
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["reason_code"], "test_code");
        assert_eq!(v["message"], "test message");
    }

    #[test]
    fn self_check_report_failed_has_reason() {
        let report = SelfCheckReport::failed("net_err", "network failed");
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(v["reason_code"], "net_err");
    }

    #[test]
    fn base_url_policy_accepts_https_localhost() {
        let (ok, _) = base_url_policy("https://localhost:12315/api");
        assert!(ok);
    }

    #[test]
    fn provisioning_recipe_store_scope_correct() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        if let ProvisioningStepType::StoreSecret { scope, key, .. } = &store_step.kind {
            assert_eq!(scope, "connector:fcp.logseq");
            assert_eq!(key, "access_token");
        } else {
            panic!("expected StoreSecret step type");
        }
    }
}
