//! FCP `Box` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OAuthRecipe,
    OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType,
    RecipeId, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{BoxAuth, BoxClient, DEFAULT_BASE_URL, DEFAULT_UPLOAD_URL},
    error::BoxError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: &[&str] = &[
    "box.files.get",
    "box.files.upload",
    "box.files.delete",
    "box.folders.list",
    "box.sharing.list",
];

/// Parsed and validated `Box` connector configuration.
#[derive(Debug, Clone)]
struct BoxConfig {
    auth: BoxAuth,
    base_url: String,
    upload_url: String,
}

impl BoxConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let bearer_auth = params
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

        let auth = match (bearer_auth, credential_id) {
            (Some(token), None) => BoxAuth::BearerToken(token),
            (None, Some(cred_id)) => BoxAuth::CredentialId(cred_id),
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
        let base_url = validate_endpoint_url_for_auth(&base_url, &auth, "base_url")?;

        let upload_url = params
            .get("upload_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_UPLOAD_URL)
            .to_string();
        let upload_url = validate_endpoint_url_for_auth(&upload_url, &auth, "upload_url")?;

        Ok(Self {
            auth,
            base_url,
            upload_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                BoxAuth::BearerToken(_) => "bearer_token",
                BoxAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, BoxAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

fn validate_endpoint_url_for_auth(
    endpoint_url: &str,
    auth: &BoxAuth,
    field_name: &str,
) -> FcpResult<String> {
    let parsed = Url::parse(endpoint_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field_name} could not be parsed: {error}"),
    })?;
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    match auth {
        BoxAuth::BearerToken(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        BoxAuth::CredentialId(_) => {
            let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field_name} must include a host"),
            })?;
            let local = is_local_test_host(host);
            let secure_or_local = parsed.scheme() == "https" || local;
            if !secure_or_local {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "{field_name} must use https unless targeting localhost/127.0.0.1/::1 for tests"
                    ),
                });
            }
        }
    }

    Ok(canonical)
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

/// FCP `Box` Connector.
pub struct BoxConnector {
    base: Arc<BaseConnector>,
    config: Option<BoxConfig>,
    client: Option<Arc<BoxClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl BoxConnector {
    /// Create a new `Box` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("box"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for BoxConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl BoxConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BoxConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Box connector");

        let client = BoxClient::new(
            config.auth.clone(),
            Some(&config.base_url),
            Some(&config.upload_url),
        )
        .map_err(|e| e.to_fcp_error())?;

        self.session_id = None;
        self.base.set_handshaken(false);
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
            "connector_id": "fcp.box",
            "connector_version": "0.1.0",
            "capabilities": [
                "box.files.read",
                "box.files.write",
                "box.folders.read",
                "box.sharing.read"
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
        Ok(json!({
            "connector_id": "fcp.box",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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
            "box.files.get" => self.invoke_files_get(client, &input).await,
            "box.files.upload" => self.invoke_files_upload(client, &input).await,
            "box.files.delete" => self.invoke_files_delete(client, &input).await,
            "box.folders.list" => self.invoke_folders_list(client, &input).await,
            "box.sharing.list" => self.invoke_sharing_list(client, &input).await,
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        info!("Box connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations ------------------------------------------------

    async fn invoke_files_get(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.get_file(file_id).await
    }

    async fn invoke_files_upload(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let folder_id = require_str(input, "folder_id")?;
        let name = require_str(input, "name")?;
        let content = input.get("content").and_then(serde_json::Value::as_str);
        client.upload_file(folder_id, name, content).await
    }

    async fn invoke_files_delete(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.delete_file(file_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_folders_list(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let folder_id = require_str(input, "folder_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let offset = input.get("offset").and_then(serde_json::Value::as_i64);
        client.list_folder_items(folder_id, limit, offset).await
    }

    async fn invoke_sharing_list(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.list_file_collaborations(file_id).await
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "box.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Box self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, BoxError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BoxError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the `Box` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("box.oauth2"),
        "1",
        "Provision Box connector with OAuth2 Authorization Code (PKCE)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://account.box.com/api/oauth2/authorize".into(),
                token_url: "https://api.box.com/oauth2/token".into(),
                scopes: vec![],
                auto_browser: true,
                callback_port: 8080,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.box".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.box.com")
        || host.eq_ignore_ascii_case("upload.box.com")
        || local;
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
                "Endpoint must use https and api.box.com or upload.box.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            ordered_manifest_operations()
                .into_iter()
                .map(|(id, operation)| operation_info_from_manifest(id, &operation))
                .collect()
        })
        .clone()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded Box manifest should parse");
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

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{IdempotencyClass, RiskLevel, SafetyTier};

    fn sample_access_value() -> String {
        ["sample", "access"].join("-")
    }

    #[test]
    fn config_from_access_token() {
        let access_value = sample_access_value();
        let config = BoxConfig::from_params(&json!({
            "access_token": access_value,
        }))
        .unwrap();
        assert!(matches!(config.auth, BoxAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.upload_url, DEFAULT_UPLOAD_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let access_value = sample_access_value();
        let result = BoxConfig::from_params(&json!({
            "access_token": access_value,
            "base_url": "https://box.example.com/2.0",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_custom_upload_url() {
        let access_value = sample_access_value();
        let result = BoxConfig::from_params(&json!({
            "access_token": access_value,
            "upload_url": "https://upload.example.com/api/2.0",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_credential_id_allows_custom_base_url() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://box.example.com/2.0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://box.example.com/2.0");
    }

    #[test]
    fn config_credential_id_allows_custom_upload_url() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "upload_url": "https://upload.example.com/api/2.0",
        }))
        .unwrap();
        assert_eq!(config.upload_url, "https://upload.example.com/api/2.0");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let access_value = sample_access_value();
        let result = BoxConfig::from_params(&json!({
            "access_token": access_value,
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = BoxConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = BoxConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = BoxConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = BoxConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = BoxConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let expected = ["sample", "value"].join("-");
        let configured = format!("  {expected}  ");
        let config = BoxConfig::from_params(&json!({ "access_token": configured })).unwrap();
        assert!(matches!(&config.auth, BoxAuth::BearerToken(value) if value == &expected));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"file_id": "12345"});
        assert_eq!(require_str(&input, "file_id").unwrap(), "12345");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"file_id": 42});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"file_id": null});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"file_id": [1, 2, 3]});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"file_id": true});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert_eq!(ids, OPERATION_ORDER);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let runtime_ops = operations_info();
        let manifest_ops = ordered_manifest_operations();

        assert_eq!(runtime_ops.len(), manifest_ops.len());

        for (runtime_op, (manifest_id, manifest_operation)) in
            runtime_ops.iter().zip(manifest_ops.iter())
        {
            assert_eq!(runtime_op.id.as_ref(), manifest_id);
            assert_eq!(runtime_op.summary, manifest_operation.description);
            assert_eq!(
                runtime_op.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(runtime_op.input_schema, manifest_operation.input_schema);
            assert_eq!(runtime_op.output_schema, manifest_operation.output_schema);
            assert_eq!(runtime_op.capability, manifest_operation.capability);
            assert_eq!(runtime_op.risk_level, manifest_operation.risk_level);
            assert_eq!(runtime_op.safety_tier, manifest_operation.safety_tier);
            assert_eq!(runtime_op.idempotency, manifest_operation.idempotency);
            assert_eq!(
                runtime_op.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&runtime_op.ai_hints).unwrap(),
                serde_json::to_value(&manifest_operation.ai_hints).unwrap()
            );
            assert_eq!(
                serde_json::to_value(runtime_op.rate_limit.as_ref()).unwrap(),
                serde_json::to_value(manifest_operation.rate_limit.as_ref()).unwrap()
            );
        }
    }

    #[test]
    fn operations_files_get_is_strict_idempotent() {
        let ops = operations_info();
        let get_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.files.get")
            .unwrap();
        assert!(matches!(get_op.idempotency, IdempotencyClass::Strict));
    }

    #[test]
    fn operations_files_upload_is_not_idempotent() {
        let ops = operations_info();
        let up_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.files.upload")
            .unwrap();
        assert!(matches!(up_op.idempotency, IdempotencyClass::None));
    }

    #[test]
    fn operations_files_delete_is_dangerous() {
        let ops = operations_info();
        let del_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.files.delete")
            .unwrap();
        assert!(matches!(del_op.safety_tier, SafetyTier::Dangerous));
        assert!(matches!(del_op.risk_level, RiskLevel::High));
    }

    #[test]
    fn operations_sharing_capability_correct() {
        let ops = operations_info();
        let share_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.sharing.list")
            .unwrap();
        assert_eq!(share_op.capability.as_ref(), "box.sharing.read");
    }

    #[test]
    fn operations_folders_list_capability_correct() {
        let ops = operations_info();
        let folder_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.folders.list")
            .unwrap();
        assert_eq!(folder_op.capability.as_ref(), "box.folders.read");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.ends_with(".read") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Safe),
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert!(
                    matches!(op.risk_level, RiskLevel::Low),
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "op {} missing when_to_use hint",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_serializes_to_json() {
        let ops = operations_info();
        let val = serde_json::to_value(&ops).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        for op in arr {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("ai_hints").is_some());
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
    fn doctor_result_mixed_failures() {
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
    fn doctor_check_skips_none_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("something wrong".into()),
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "something wrong");
    }

    #[test]
    fn connector_default() {
        let c = BoxConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_is_unconfigured() {
        let c = BoxConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn config_default_urls() {
        let access_value = sample_access_value();
        let config = BoxConfig::from_params(&json!({
            "access_token": access_value,
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.box.com/2.0");
        assert_eq!(config.upload_url, "https://upload.box.com/api/2.0");
    }

    #[test]
    fn config_both_custom_urls() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://custom.api.box.com",
            "upload_url": "https://custom.upload.box.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.api.box.com");
        assert_eq!(config.upload_url, "https://custom.upload.box.com");
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s2: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s2, DoctorStatus::Degraded);
    }

    #[test]
    fn require_str_nested_object_is_err() {
        let input = json!({"file_id": {"nested": true}});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"file_id": ""});
        assert_eq!(require_str(&input, "file_id").unwrap(), "");
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = BoxConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.ends_with(".write") {
                assert!(
                    !matches!(op.safety_tier, SafetyTier::Safe),
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn doctor_check_debug_format() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn operations_files_upload_is_risky() {
        let ops = operations_info();
        let up_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.files.upload")
            .unwrap();
        assert!(matches!(up_op.safety_tier, SafetyTier::Risky));
        assert!(matches!(up_op.risk_level, RiskLevel::Medium));
    }

    #[test]
    fn operations_files_get_capability_correct() {
        let ops = operations_info();
        let get_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "box.files.get")
            .unwrap();
        assert_eq!(get_op.capability.as_ref(), "box.files.read");
    }

    // -- Provisioning readiness tests --

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = BoxConfig::from_params(&json!({
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
        let access_value = sample_access_value();
        let config = BoxConfig::from_params(&json!({
            "access_token": access_value,
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.box.com"));
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let access_value = sample_access_value();
        let config = BoxConfig::from_params(&json!({
            "access_token": access_value,
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
        assert!(dbg.contains("bearer_token"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let access_value = sample_access_value();
        let config = BoxConfig::from_params(&json!({
            "access_token": access_value,
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
    }

    // -- Provisioning recipe tests --

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "box.oauth2");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth_authorize");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "box.oauth2");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_oauth_step_has_correct_urls() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let oauth_step = &v["steps"][0];
        let flow = &oauth_step["flow"];
        assert_eq!(
            flow["authorization_url"],
            "https://account.box.com/api/oauth2/authorize"
        );
        assert_eq!(flow["token_url"], "https://api.box.com/oauth2/token");
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let store_step = &v["steps"][1];
        assert_eq!(store_step["scope"], "connector:fcp.box");
        assert_eq!(store_step["key"], "access_token");
    }

    #[test]
    fn provisioning_recipe_description() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("OAuth2"));
        assert!(recipe.description.contains("Box"));
    }

    // -- Base URL policy tests --

    #[test]
    fn base_url_policy_accepts_api_box_https() {
        let (ok, message) = base_url_policy("https://api.box.com/2.0");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_upload_box_https() {
        let (ok, message) = base_url_policy("https://upload.box.com/api/2.0");
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
        let (ok, message) = base_url_policy("http://api.box.com/2.0");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.box.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_case_insensitive_host() {
        let (ok, _) = base_url_policy("https://API.BOX.COM/2.0");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:8080");
        assert!(ok);
    }

    #[test]
    fn is_local_test_host_recognizes_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_recognizes_ipv4_loopback() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_recognizes_ipv6_loopback() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("api.box.com"));
    }
}
