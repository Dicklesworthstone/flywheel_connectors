//! FCP Segment CDP Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OperationId,
    OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId,
    SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SegmentAuth, SegmentClient},
    error::SegmentError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SOURCES_LIST: &str = "segment.sources.list";
const OP_DESTINATIONS_LIST: &str = "segment.destinations.list";
const OP_TRACK: &str = "segment.track";
const OPERATION_ORDER: [&str; 3] = [OP_SOURCES_LIST, OP_DESTINATIONS_LIST, OP_TRACK];

/// Parsed and validated Segment connector configuration.
#[derive(Debug, Clone)]
struct SegmentConfig {
    auth: SegmentAuth,
    base_url: String,
}

impl SegmentConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
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

        let auth = match (api_token, credential_id) {
            (Some(key), None) => SegmentAuth::BearerToken(key),
            (None, Some(cred_id)) => SegmentAuth::CredentialId(cred_id),
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
                SegmentAuth::BearerToken(_) => "bearer_token",
                SegmentAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, SegmentAuth::BearerToken(_)),
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

/// FCP Segment CDP Connector.
pub struct SegmentConnector {
    base: Arc<BaseConnector>,
    config: Option<SegmentConfig>,
    client: Option<Arc<SegmentClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SegmentConnector {
    /// Create a new Segment connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("segment"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SegmentConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SegmentConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Segment connector");

        let client = SegmentClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.segment",
            "connector_version": "0.1.0",
            "capabilities": [
                "segment.sources.read",
                "segment.destinations.read",
                "segment.track.write"
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
            "connector_id": "fcp.segment",
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
            "segment.sources.list" => self.invoke_sources_list(client).await,
            "segment.destinations.list" => self.invoke_destinations_list(client, &input).await,
            "segment.track" => self.invoke_track(client, &input).await,
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
        info!("Segment connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_sources_list(
        &self,
        client: &SegmentClient,
    ) -> Result<serde_json::Value, SegmentError> {
        let resp = client.list_sources().await?;
        let sources = resp.get("sources").cloned().unwrap_or(json!([]));
        Ok(json!({ "sources": sources }))
    }

    async fn invoke_destinations_list(
        &self,
        client: &SegmentClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SegmentError> {
        let source_id = require_str(input, "source_id")?;
        let resp = client.list_destinations(source_id).await?;
        let destinations = resp.get("destinations").cloned().unwrap_or(json!([]));
        Ok(json!({ "destinations": destinations }))
    }

    async fn invoke_track(
        &self,
        client: &SegmentClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SegmentError> {
        let user_id = require_str(input, "user_id")?;
        let event = require_str(input, "event")?;
        let properties = input.get("properties").cloned();

        let mut body = json!({
            "userId": user_id,
            "event": event,
        });

        if let Some(props) = properties {
            body["properties"] = props;
        }

        let resp = client.track(&body).await?;
        let success = resp
            .get("success")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(json!({ "success": success }))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "segment.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "`Segment` self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Build the provisioning recipe for the `Segment` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("segment.write_key"),
        "1",
        "Provision `Segment` connector with a write key (API token)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_write_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your `Segment` write key".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_write_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: StepId::new("enter_write_key"),
                scope: "connector:fcp.segment".into(),
            },
        )
        .depends_on(StepId::new("enter_write_key")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.segment.io")
        || host.eq_ignore_ascii_case("cdn.segment.com")
        || host.eq_ignore_ascii_case("api.segmentapis.com")
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
                "Endpoint must use https and api.segment.io / cdn.segment.com / api.segmentapis.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn validate_base_url_for_auth(raw_url: &str, auth: &SegmentAuth) -> FcpResult<String> {
    let parsed = Url::parse(raw_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
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

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let host_lower = host.to_ascii_lowercase();
    let local = is_local_test_host(&host_lower);
    let secure_or_local = parsed.scheme() == "https" || local;
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    match auth {
        SegmentAuth::BearerToken(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        SegmentAuth::CredentialId(_) => {
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

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SegmentError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SegmentError::InvalidInput(format!("Missing required field: {field}")))
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
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Segment manifest should validate");
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

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> ApprovalMode {
    ApprovalMode::from(mode)
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
        requires_approval: Some(approval_mode_from_manifest(operation.requires_approval)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_api_token() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "test-bearer-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, SegmentAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = SegmentConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://api.segmentapis.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.segmentapis.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = SegmentConfig::from_params(&json!({
            "api_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = SegmentConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = SegmentConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = SegmentConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SegmentConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = SegmentConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_untrusted_base_url_for_api_token() {
        let result = SegmentConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://evil.example.com",
        }));
        let err = result.expect_err("attacker host should be rejected");
        assert!(err.to_string().contains("api.segment.io"));
    }

    #[test]
    fn config_rejects_base_url_query_string() {
        let result = SegmentConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://api.segment.io/v1?leak=1",
        }));
        let err = result.expect_err("query-bearing base_url should be rejected");
        assert!(err.to_string().contains("query string or fragment"));
    }

    #[test]
    fn config_allows_custom_https_base_url_for_credential_id() {
        let config = SegmentConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://vault-proxy.internal/segment",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://vault-proxy.internal/segment");
    }

    #[test]
    fn require_str_present() {
        let input = json!({"source_id": "src_abc"});
        assert_eq!(require_str(&input, "source_id").unwrap(), "src_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "source_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"source_id": 42});
        assert!(require_str(&input, "source_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"source_id": null});
        assert!(require_str(&input, "source_id").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn introspection_operations_preserve_runtime_order() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|operation| operation.id.as_str()).collect();
        assert_eq!(ids, OPERATION_ORDER);
    }

    fn strict_segment_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_segment_manifest()?;
        let operations = operations_info();

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
                Some(approval_mode_from_manifest(
                    manifest_operation.requires_approval
                ))
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).map_err(|error| error.to_string())?,
                serde_json::to_value(&manifest_operation.ai_hints)
                    .map_err(|error| error.to_string())?
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
    fn operations_info_json_exposes_manifest_approval_modes_and_rate_limits() {
        let ops = ops_json();
        let track = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["id"] == OP_TRACK)
            .unwrap();
        let sources = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["id"] == OP_SOURCES_LIST)
            .unwrap();

        assert_eq!(track["requires_approval"], "policy");
        assert_eq!(sources["requires_approval"], "none");
        assert_eq!(track["rate_limit"]["max"], 500);
        assert_eq!(sources["rate_limit"]["max"], 200);
        assert_eq!(track["rate_limit"]["pool_name"], "segment.track.write");
        assert_eq!(sources["rate_limit"]["pool_name"], "segment.sources.read");
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.split('.').next_back() == Some("read") {
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
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"segment.sources.list"));
        assert!(ids.contains(&"segment.destinations.list"));
        assert!(ids.contains(&"segment.track"));
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
    fn config_trims_api_token() {
        let config = SegmentConfig::from_params(&json!({ "api_token": "  tok_test  " })).unwrap();
        match &config.auth {
            SegmentAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            SegmentAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = SegmentConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn track_operation_is_risky() {
        let ops = ops_json();
        let track = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.track")
            .unwrap();
        assert_eq!(track["safety_tier"], "risky");
        assert_eq!(track["risk_level"], "medium");
    }

    #[test]
    fn sources_list_operation_is_safe() {
        let ops = ops_json();
        let sources = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.sources.list")
            .unwrap();
        assert_eq!(sources["safety_tier"], "safe");
        assert_eq!(sources["risk_level"], "low");
    }

    #[test]
    fn destinations_list_operation_is_safe() {
        let ops = ops_json();
        let dests = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.destinations.list")
            .unwrap();
        assert_eq!(dests["safety_tier"], "safe");
        assert_eq!(dests["risk_level"], "low");
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = SegmentConnector::new();
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
        let input = json!({"source_id": [1, 2, 3]});
        assert!(require_str(&input, "source_id").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"source_id": true});
        assert!(require_str(&input, "source_id").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"source_id": ""});
        assert_eq!(require_str(&input, "source_id").unwrap(), "");
    }

    #[test]
    fn operations_sources_list_capability() {
        let ops = ops_json();
        let sl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.sources.list")
            .unwrap();
        assert_eq!(sl["capability"], "segment.sources.read");
    }

    #[test]
    fn operations_destinations_list_capability() {
        let ops = ops_json();
        let dl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.destinations.list")
            .unwrap();
        assert_eq!(dl["capability"], "segment.destinations.read");
    }

    #[test]
    fn operations_track_capability() {
        let ops = ops_json();
        let t = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.track")
            .unwrap();
        assert_eq!(t["capability"], "segment.track.write");
    }

    #[test]
    fn operations_read_ops_are_strict_idempotent() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.split('.').next_back() == Some("read") {
                assert_eq!(
                    op["idempotency"], "strict",
                    "read op {} should be strict",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_track_idempotency_is_none() {
        let ops = ops_json();
        let t = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "segment.track")
            .unwrap();
        assert_eq!(t["idempotency"], "none");
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
    fn write_operations_not_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.split('.').next_back() == Some("write") {
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
    fn connector_default_impl() {
        let c = SegmentConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn operations_have_segment_prefix() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op["id"].as_str().unwrap().starts_with("segment."),
                "op {} missing segment prefix",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_have_capability() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op["capability"].as_str().is_some(),
                "op {} missing capability",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_have_safety_tier() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op["safety_tier"].as_str().is_some(),
                "op {} missing safety_tier",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty());
        }
    }

    #[test]
    fn doctor_check_with_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("all good".into()),
            critical: false,
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["message"], "all good");
    }

    #[test]
    fn doctor_result_serialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let json = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.status, r2.status);
        assert_eq!(r.checks.len(), r2.checks.len());
    }

    #[test]
    fn doctor_status_debug_format() {
        let s = DoctorStatus::Degraded;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn config_debug_does_not_leak_token() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "super-secret-token-123",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(!dbg.contains("super-secret-token-123"));
    }

    #[test]
    fn require_str_object_value_fails() {
        let input = json!({"source_id": {"nested": "value"}});
        assert!(require_str(&input, "source_id").is_err());
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "test-token",
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
        let config = SegmentConfig::from_params(&json!({
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
        let config = SegmentConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "segment.write_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_write_key");
        assert_eq!(recipe.steps[1].id.as_str(), "store_write_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_write_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "segment.write_key");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_description_contains_segment() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("Segment"));
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret { key, scope, .. } => {
                assert_eq!(key, "api_token");
                assert_eq!(scope, "connector:fcp.segment");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_prompt_step_message() {
        let recipe = provisioning_recipe();
        let prompt_step = &recipe.steps[0];
        match &prompt_step.kind {
            ProvisioningStepType::PromptSecret { message } => {
                assert!(message.contains("write key"));
            }
            other => panic!("expected PromptSecret, got {other:?}"),
        }
    }

    #[test]
    fn base_url_policy_accepts_segment_io_https() {
        let (ok, message) = base_url_policy("https://api.segment.io");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_cdn_segment_com() {
        let (ok, message) = base_url_policy("https://cdn.segment.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_segmentapis_com() {
        let (ok, message) = base_url_policy("https://api.segmentapis.com/v2");
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
        let (ok, message) = base_url_policy("http://api.segment.io");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.segment.io"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_case_insensitive() {
        let (ok, _) = base_url_policy("https://API.SEGMENT.IO");
        assert!(ok);
        let (ok, _) = base_url_policy("https://CDN.SEGMENT.COM");
        assert!(ok);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = SegmentConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.segment.io"));
    }

    #[test]
    fn provisioning_readiness_localhost_base_url_accepted() {
        let config = SegmentConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "http://localhost:8080",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_ipv4() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_other() {
        assert!(!is_local_test_host("api.segment.io"));
        assert!(!is_local_test_host("example.com"));
    }
}
