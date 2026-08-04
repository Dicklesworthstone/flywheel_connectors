//! FCP Mailchimp Connector implementation.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, Introspection,
    OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType,
    RecipeId, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{MailchimpAuth, MailchimpClient, base_url_for_dc, extract_dc},
    error::MailchimpError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_LISTS_LIST: &str = "mailchimp.lists.list";
const OP_MEMBERS_LIST: &str = "mailchimp.members.list";
const OP_MEMBERS_DELETE: &str = "mailchimp.members.delete";
const OP_CAMPAIGNS_LIST: &str = "mailchimp.campaigns.list";
const OP_CAMPAIGNS_SEND: &str = "mailchimp.campaigns.send";
const OPERATION_ORDER: &[&str] = &[
    OP_LISTS_LIST,
    OP_MEMBERS_LIST,
    OP_MEMBERS_DELETE,
    OP_CAMPAIGNS_LIST,
    OP_CAMPAIGNS_SEND,
];

/// Parsed and validated Mailchimp connector configuration.
#[derive(Debug, Clone)]
struct MailchimpConfig {
    auth: MailchimpAuth,
    base_url: Option<String>,
}

impl MailchimpConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
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

        let auth = match (api_key, credential_id) {
            (Some(key), None) => MailchimpAuth::ApiKey(key),
            (None, Some(cred_id)) => MailchimpAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if let Some(ref url) = base_url {
            reject_base_url_qfu(url)?;
        }

        Ok(Self { auth, base_url })
    }

    /// Compute the effective base URL that the client would use.
    fn effective_base_url(&self) -> String {
        match &self.base_url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => match &self.auth {
                MailchimpAuth::ApiKey(key) => {
                    let dc = extract_dc(key).unwrap_or("us1");
                    base_url_for_dc(dc)
                }
                MailchimpAuth::CredentialId(_) => base_url_for_dc("us1"),
            },
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let effective_url = self.effective_base_url();
        let (network_ok, network_message) = base_url_policy(&effective_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                MailchimpAuth::ApiKey(_) => "api_key",
                MailchimpAuth::CredentialId(_) => "credential_id",
            },
            api_key_configured: matches!(&self.auth, MailchimpAuth::ApiKey(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: effective_url,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_key_configured: bool,
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

/// FCP Mailchimp Connector.
pub struct MailchimpConnector {
    base: Arc<BaseConnector>,
    config: Option<MailchimpConfig>,
    client: Option<Arc<MailchimpClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MailchimpConnector {
    /// Create a new Mailchimp connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mailchimp"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MailchimpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MailchimpConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MailchimpConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Mailchimp connector");

        let client = MailchimpClient::new(config.auth.clone(), config.base_url.as_deref())
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
            "connector_id": "fcp.mailchimp",
            "connector_version": "0.1.0",
            "capabilities": [
                "mailchimp.lists.read",
                "mailchimp.members.read",
                "mailchimp.members.write",
                "mailchimp.members.delete",
                "mailchimp.campaigns.read",
                "mailchimp.campaigns.write"
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
        let introspection = Introspection {
            operations: typed_operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
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
            "mailchimp.lists.list" => self.invoke_lists_list(client).await,
            "mailchimp.members.list" => self.invoke_members_list(client, &input).await,
            "mailchimp.members.delete" => self.invoke_members_delete(client, &input).await,
            "mailchimp.campaigns.list" => self.invoke_campaigns_list(client).await,
            "mailchimp.campaigns.send" => self.invoke_campaigns_send(client, &input).await,
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

        let allowed = typed_operations_info()
            .iter()
            .any(|op| op.id.as_ref() == operation);

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
        info!("Mailchimp connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "mailchimp.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Mailchimp self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_lists_list(
        &self,
        client: &MailchimpClient,
    ) -> Result<serde_json::Value, MailchimpError> {
        let resp = client.list_lists().await?;
        let lists = resp
            .get("lists")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if lists.is_null() {
            return Ok(json!({ "lists": [] }));
        }
        Ok(json!({ "lists": lists }))
    }

    async fn invoke_members_list(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let list_id = require_str(input, "list_id")?;
        let resp = client.list_members(list_id).await?;
        let members = resp
            .get("members")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if members.is_null() {
            return Ok(json!({ "members": [] }));
        }
        Ok(json!({ "members": members }))
    }

    async fn invoke_members_delete(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let list_id = require_str(input, "list_id")?;
        let subscriber_hash = require_str(input, "subscriber_hash")?;
        client.delete_member(list_id, subscriber_hash).await
    }

    async fn invoke_campaigns_list(
        &self,
        client: &MailchimpClient,
    ) -> Result<serde_json::Value, MailchimpError> {
        let resp = client.list_campaigns().await?;
        let campaigns = resp
            .get("campaigns")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if campaigns.is_null() {
            return Ok(json!({ "campaigns": [] }));
        }
        Ok(json!({ "campaigns": campaigns }))
    }

    async fn invoke_campaigns_send(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let campaign_id = require_str(input, "campaign_id")?;
        client.send_campaign(campaign_id).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MailchimpError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MailchimpError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| serde_json::to_value(typed_operations_info()).unwrap_or_else(|_| json!([])))
        .clone()
}

fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Mailchimp manifest should validate");
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

/// Build the provisioning recipe for the Mailchimp connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("mailchimp.api_key"),
        "1",
        "Provision Mailchimp connector with an API key (keys end with -usXX datacenter suffix)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your Mailchimp API key (format: <key>-<dc>, e.g. abc123def-us21)"
                .into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.mailchimp".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
}

/// Reject base_url overrides with userinfo, query, or fragment. The
/// MailchimpClient concatenates via format!("{}{path}", self.base_url)
/// in every request method (client.rs:202/213/224). Without this
/// check, a base_url like
/// `https://us1.api.mailchimp.com/3.0?leak=x` would leak
/// attacker-chosen query values on every request and put the endpoint
/// path after the `?` boundary. Userinfo
/// (`https://attacker:pw@us1.api.mailchimp.com/3.0`) would bake into
/// every request URL and silently override the Authorization header.
/// Matches the hygiene in airtable / asana / gmail / notion / hubspot
/// / whatsapp / linear / clickup / monday / bitbucket / intercom /
/// dropbox.
fn reject_base_url_qfu(base_url: &str) -> FcpResult<()> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
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
    Ok(())
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
    // Mailchimp uses datacenter-specific URLs: usX.api.mailchimp.com
    let allowed_host = host.to_ascii_lowercase().ends_with(".api.mailchimp.com") || local;
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
                "Endpoint must use https and *.api.mailchimp.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MailchimpAuth;

    fn operation_capability<'a>(ops: &'a serde_json::Value, id: &str) -> Option<&'a str> {
        ops.as_array()?
            .iter()
            .find(|op| op["id"] == id)?
            .get("capability")?
            .as_str()
    }

    fn operation_json<'a>(ops: &'a serde_json::Value, id: &str) -> Option<&'a serde_json::Value> {
        ops.as_array()?
            .iter()
            .find(|op| op.get("id").and_then(serde_json::Value::as_str) == Some(id))
    }

    #[test]
    fn config_from_api_key() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "testkey-us1",
        }))
        .unwrap();
        assert!(matches!(config.auth, MailchimpAuth::ApiKey(_)));
    }

    #[test]
    fn config_from_credential_id() {
        let config = MailchimpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://mailchimp.example.com/3.0",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            Some("https://mailchimp.example.com/3.0".into())
        );
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MailchimpConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MailchimpConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MailchimpConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"list_id": "list_abc"});
        assert_eq!(require_str(&input, "list_id").unwrap(), "list_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"list_id": 42});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"list_id": null});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
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
        let valid = ["low", "medium", "high", "critical"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous", "critical", "forbidden"];
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
        assert!(ids.contains(&"mailchimp.lists.list"));
        assert!(ids.contains(&"mailchimp.members.list"));
        assert!(ids.contains(&"mailchimp.members.delete"));
        assert!(ids.contains(&"mailchimp.campaigns.list"));
        assert!(ids.contains(&"mailchimp.campaigns.send"));
    }

    #[fcp_async_core::runtime::test]
    async fn operations_members_delete_requires_dedicated_capability() {
        let ops = operations_info();
        let delete = operation_capability(&ops, "mailchimp.members.delete");

        assert_eq!(delete, Some("mailchimp.members.delete"));
        assert_ne!(delete, Some("mailchimp.members.write"));

        let typed = MailchimpConnector::new().handle_introspect().await.unwrap();
        let typed_delete = typed["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"] == "mailchimp.members.delete")
            .unwrap();
        assert_eq!(typed_delete["capability"], "mailchimp.members.delete");
        assert_eq!(typed_delete["requires_approval"], "interactive");
    }

    #[test]
    fn operation_approval_modes_match_manifest() {
        let ops = operations_info();
        assert_eq!(
            operation_json(&ops, OP_MEMBERS_DELETE).unwrap()["requires_approval"],
            "interactive"
        );
        assert_eq!(
            operation_json(&ops, OP_CAMPAIGNS_SEND).unwrap()["requires_approval"],
            "policy"
        );
        assert!(
            operation_json(&ops, OP_LISTS_LIST)
                .unwrap()
                .get("requires_approval")
                .is_none()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_dedicated_members_delete_capability() {
        let mut connector = MailchimpConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "testkey-us1",
            }))
            .await
            .unwrap();

        let handshake = connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();
        let capabilities = handshake["capabilities"].as_array().unwrap();

        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("mailchimp.members.write"))
        );
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("mailchimp.members.delete"))
        );
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
    fn config_trims_api_key() {
        let config = MailchimpConfig::from_params(&json!({ "api_key": "  key-us1  " })).unwrap();
        match &config.auth {
            MailchimpAuth::ApiKey(t) => assert_eq!(t, "key-us1"),
            MailchimpAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = MailchimpConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // -- Additional connector tests --

    #[test]
    fn connector_new_matches_default() {
        let c = MailchimpConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for s in &statuses {
            let v = serde_json::to_value(s).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn doctor_status_lowercase_serialization() {
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
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let cloned = check.clone();
        assert!(check.passed);
        assert_eq!(cloned.name, "x");
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert!(cloned.checks.is_empty());
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_result_deserialize() {
        let v = json!({"status": "unhealthy", "checks": [{"name": "a", "passed": false, "critical": true}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn operations_all_have_mailchimp_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("mailchimp."),
                "op {id} missing mailchimp prefix"
            );
        }
    }

    #[test]
    fn operations_write_ops_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".write") {
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
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("delete") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "delete op {id} should be dangerous"
                );
            }
        }
    }

    #[test]
    fn operations_send_is_risky() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("send") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "send op {id} should be risky"
                );
            }
        }
    }

    #[test]
    fn config_error_message_both_auth() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("exactly one")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_message_no_auth() {
        let result = MailchimpConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("Missing")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_non_string_credential() {
        let result = MailchimpConfig::from_params(&json!({"credential_id": 12345}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("string")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_invalid_uuid() {
        let result = MailchimpConfig::from_params(&json!({"credential_id": "not-a-uuid"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("UUID")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_base_url_none_by_default() {
        let config = MailchimpConfig::from_params(&json!({"api_key": "key-us1"})).unwrap();
        assert!(config.base_url.is_none());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"list_id": ""});
        assert_eq!(require_str(&input, "list_id").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "campaign_id").unwrap_err();
        match err {
            MailchimpError::InvalidInput(msg) => assert!(msg.contains("campaign_id")),
            _ => panic!("expected InvalidInput error"),
        }
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "none", "best_effort"];
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

    #[test]
    fn connector_default_impl() {
        let c = MailchimpConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn operations_have_mailchimp_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op["id"].as_str().unwrap().starts_with("mailchimp."),
                "op {} missing mailchimp prefix",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_have_capability() {
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty());
        }
    }

    #[test]
    fn strict_mailchimp_manifest() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        assert_eq!(manifest.connector.id.as_ref(), "fcp.mailchimp");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());
        assert_eq!(
            manifest.manifest.interface_hash,
            manifest.compute_interface_hash().unwrap()
        );
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let operations = typed_operations_info();
        assert_eq!(operations.len(), OPERATION_ORDER.len());

        for (index, operation) in operations.iter().enumerate() {
            assert_eq!(operation.id.as_ref(), OPERATION_ORDER[index]);
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_ref())
                .expect("runtime operation should come from manifest");
            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_ref(),
                Some(&manifest_operation.description)
            );
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                operation.ai_hints.when_to_use.as_str(),
                manifest_operation.ai_hints.when_to_use.as_str()
            );
            assert_eq!(
                &operation.ai_hints.common_mistakes,
                &manifest_operation.ai_hints.common_mistakes
            );
            assert_eq!(
                &operation.ai_hints.examples,
                &manifest_operation.ai_hints.examples
            );
            let actual_related = operation
                .ai_hints
                .related
                .iter()
                .map(std::convert::AsRef::as_ref)
                .collect::<Vec<_>>();
            let expected_related = manifest_operation
                .ai_hints
                .related
                .iter()
                .map(std::convert::AsRef::as_ref)
                .collect::<Vec<_>>();
            assert_eq!(actual_related, expected_related);
        }
    }

    #[test]
    fn manifest_schema_is_the_runtime_introspection_schema() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let operations = typed_operations_info();

        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_ref())
                .expect("runtime operation should come from manifest");
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
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
    fn require_str_object_value_fails() {
        let input = json!({"list_id": {"nested": "value"}});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_array_value_fails() {
        let input = json!({"list_id": [1, 2, 3]});
        assert!(require_str(&input, "list_id").is_err());
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_api_key_mode() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "testkey-us21",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert!(readiness.base_url.contains("us21"));
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = MailchimpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("*.api.mailchimp.com"));
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "mailchimp.api_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "mailchimp.api_key");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_description_mentions_datacenter() {
        let recipe = provisioning_recipe();
        assert!(
            recipe
                .description
                .to_ascii_lowercase()
                .contains("datacenter")
                || recipe.description.contains("-usXX")
        );
    }

    #[test]
    fn base_url_policy_accepts_mailchimp_https() {
        let (ok, message) = base_url_policy("https://us1.api.mailchimp.com/3.0");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_different_datacenters() {
        for dc in &["us1", "us21", "eu1", "us7"] {
            let url = format!("https://{dc}.api.mailchimp.com/3.0");
            let (ok, _) = base_url_policy(&url);
            assert!(ok, "should accept {url}");
        }
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
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://us1.api.mailchimp.com/3.0");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("*.api.mailchimp.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_bare_api_mailchimp_com() {
        // "api.mailchimp.com" without a datacenter prefix should be rejected
        // because it doesn't end with ".api.mailchimp.com"
        let (ok, _) = base_url_policy("https://api.mailchimp.com/3.0");
        assert!(!ok);
    }

    #[test]
    fn effective_base_url_from_api_key() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "abc123-us7",
        }))
        .unwrap();
        assert_eq!(
            config.effective_base_url(),
            "https://us7.api.mailchimp.com/3.0"
        );
    }

    #[test]
    fn effective_base_url_custom_override() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://us5.api.mailchimp.com/3.0/",
        }))
        .unwrap();
        // trailing slash should be trimmed
        assert_eq!(
            config.effective_base_url(),
            "https://us5.api.mailchimp.com/3.0"
        );
    }

    #[test]
    fn effective_base_url_credential_id_defaults() {
        let config = MailchimpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert_eq!(
            config.effective_base_url(),
            "https://us1.api.mailchimp.com/3.0"
        );
    }

    #[test]
    fn is_local_test_host_matches() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("us1.api.mailchimp.com"));
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
        assert!(dbg.contains("api_key"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
        assert_eq!(readiness.base_url, cloned.base_url);
    }

    #[test]
    fn from_params_accepts_clean_base_url() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://us1.api.mailchimp.com/3.0",
        }))
        .unwrap();
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://us1.api.mailchimp.com/3.0")
        );
    }

    #[test]
    fn from_params_rejects_base_url_query_string() {
        let err = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://us1.api.mailchimp.com/3.0?leak=x",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_base_url_fragment() {
        let err = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://us1.api.mailchimp.com/3.0#frag",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_params_rejects_base_url_userinfo() {
        let err = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://attacker:pw@us1.api.mailchimp.com/3.0",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_base_url_unparseable() {
        let err = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "not a url",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }
}
