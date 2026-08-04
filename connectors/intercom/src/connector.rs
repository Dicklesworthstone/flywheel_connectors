//! FCP `Intercom` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, OperationSection};
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
    client::{DEFAULT_BASE_URL, IntercomAuth, IntercomClient},
    error::IntercomError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_CONTACTS_LIST: &str = "intercom.contacts.list";
const OP_CONTACTS_CREATE: &str = "intercom.contacts.create";
const OP_CONTACTS_DELETE: &str = "intercom.contacts.delete";
const OP_CONVERSATIONS_LIST: &str = "intercom.conversations.list";
const OP_CONVERSATIONS_REPLY: &str = "intercom.conversations.reply";
const OP_TAGS_LIST: &str = "intercom.tags.list";
const OPERATION_ORDER: [&str; 6] = [
    OP_CONTACTS_LIST,
    OP_CONTACTS_CREATE,
    OP_CONTACTS_DELETE,
    OP_CONVERSATIONS_LIST,
    OP_CONVERSATIONS_REPLY,
    OP_TAGS_LIST,
];

/// Parsed and validated `Intercom` connector configuration.
#[derive(Debug, Clone)]
struct IntercomConfig {
    auth: IntercomAuth,
    base_url: String,
}

impl IntercomConfig {
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
            (Some(token), None) => IntercomAuth::BearerToken(token),
            (None, Some(cred_id)) => IntercomAuth::CredentialId(cred_id),
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
        reject_base_url_qfu(&base_url)?;

        // br-gs71m: enforce endpoint policy at the configure boundary.
        // Mirrors the zapier (63493e6e) / teams (9a2aabd2) / datadog
        // (c2339e04) fixes. The pre-existing reject_base_url_qfu only
        // refused userinfo/query/fragment shapes — `https://intercom.example.com`
        // would still pass it AND construct an IntercomClient carrying
        // the bearer token. base_url_policy was already informational
        // (network_ok=false on self_check) but did not fail
        // configuration. Promoting it to a hard refuse closes the
        // bearer-token-routing-to-attacker vector. localhost /
        // 127.0.0.1 / ::1 stay allowed for tests via
        // is_local_test_host.
        let (network_ok, network_message) = base_url_policy(&base_url);
        if !network_ok {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: network_message,
            });
        }

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                IntercomAuth::BearerToken(_) => "bearer_token",
                IntercomAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, IntercomAuth::BearerToken(_)),
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

/// FCP `Intercom` Connector.
pub struct IntercomConnector {
    base: Arc<BaseConnector>,
    config: Option<IntercomConfig>,
    client: Option<Arc<IntercomClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl IntercomConnector {
    /// Create a new `Intercom` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("intercom"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for IntercomConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl IntercomConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = IntercomConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Intercom connector");

        let client = IntercomClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.intercom",
            "connector_version": "0.1.0",
            "capabilities": [
                "intercom.contacts.read",
                "intercom.contacts.write",
                // br-5g8rj: contact deletion is irreversible
                // (RiskLevel::High / SafetyTier::Dangerous) and is
                // gated by a dedicated capability. A token issued
                // for the create/update workflow cannot also delete.
                "intercom.contacts.delete",
                "intercom.conversations.read",
                "intercom.conversations.write",
                "intercom.tags.read"
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
            "intercom.contacts.list" => self.invoke_contacts_list(client, &input).await,
            "intercom.contacts.create" => self.invoke_contacts_create(client, &input).await,
            "intercom.contacts.delete" => self.invoke_contacts_delete(client, &input).await,
            "intercom.conversations.list" => self.invoke_conversations_list(client, &input).await,
            "intercom.conversations.reply" => self.invoke_conversations_reply(client, &input).await,
            "intercom.tags.list" => self.invoke_tags_list(client).await,
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
            .any(|known| known.id.as_str() == operation);

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
        info!("Intercom connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_contacts_list(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let per_page = input.get("per_page").and_then(serde_json::Value::as_i64);
        let starting_after = input
            .get("starting_after")
            .and_then(serde_json::Value::as_str);
        let data = client.list_contacts(per_page, starting_after).await?;
        Ok(data)
    }

    async fn invoke_contacts_create(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let _ = require_str(input, "role")?;
        let data = client.create_contact(input).await?;
        Ok(data)
    }

    async fn invoke_contacts_delete(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let contact_id = require_str(input, "contact_id")?;
        client.delete_contact(contact_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_conversations_list(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let per_page = input.get("per_page").and_then(serde_json::Value::as_i64);
        let starting_after = input
            .get("starting_after")
            .and_then(serde_json::Value::as_str);
        let data = client.list_conversations(per_page, starting_after).await?;
        Ok(data)
    }

    async fn invoke_conversations_reply(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let conversation_id = require_str(input, "conversation_id")?;
        let _ = require_str(input, "body")?;
        let _ = require_str(input, "message_type")?;

        let body = json!({
            "body": input["body"],
            "message_type": input["message_type"],
            "type": "admin",
            "admin_id": input.get("admin_id").cloned().unwrap_or_else(|| json!("0")),
        });

        let data = client.reply_to_conversation(conversation_id, &body).await?;
        Ok(data)
    }

    async fn invoke_tags_list(
        &self,
        client: &IntercomClient,
    ) -> Result<serde_json::Value, IntercomError> {
        let data = client.list_tags().await?;
        Ok(data)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "intercom.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Intercom self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, IntercomError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IntercomError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Intercom connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("intercom.bearer_token"),
        "1",
        "Provision Intercom connector with an OAuth2 access token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("obtain_token"),
        ProvisioningStepType::OpenUrl {
            url: "https://app.intercom.com/developers/_".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Intercom access token".into(),
            },
        )
        .depends_on(StepId::new("obtain_token")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.intercom".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
    )
}

/// Reject `base_url` overrides with userinfo, query, or fragment. The
/// `IntercomClient` concatenates via `format!("{}{path}", self.base_url)`
/// in every request method (client.rs:158/176/188); without this
/// check, a `base_url` like `https://api.intercom.io?leak=x` would leak
/// attacker-chosen query values on every request and put the endpoint
/// path after the `?` boundary. Userinfo would bake into every
/// request URL and silently override the Authorization header.
/// Matches the hygiene in airtable / asana / gmail / notion / hubspot
/// / whatsapp / linear / clickup / monday / bitbucket.
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
    // br-gs71m: exact-host equality against the Intercom regional API
    // hosts. Substring matching (`contains("intercom.io")`) is unsafe
    // because `intercom.io.evil.example` would pass. Intercom
    // currently exposes three regional API endpoints — US (default),
    // EU, and AU — per https://developers.intercom.com/docs/references/rest-api/api-references.
    let allowed_host = local
        || ALLOWED_INTERCOM_HOSTS
            .iter()
            .any(|allowed| host.eq_ignore_ascii_case(allowed));
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
                "Endpoint must use https and one of {ALLOWED_INTERCOM_HOSTS:?} (localhost/127.0.0.1/::1 allowed for tests): {base_url}",
            ),
        )
    }
}

/// br-gs71m: allow-listed Intercom API hosts. Intercom regions per
/// <https://developers.intercom.com/docs/build-an-integration/learn-more/rest-apis/api-base-urls/>
const ALLOWED_INTERCOM_HOSTS: &[&str] = &[
    "api.intercom.io",    // US (default)
    "api.eu.intercom.io", // EU region
    "api.au.intercom.io", // AU region
];

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            serde_json::to_value(typed_operations_info())
                .expect("manifest-derived Intercom operations should serialize")
        })
        .clone()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Intercom manifest should validate");
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
        requires_approval: Some(ApprovalMode::from(operation.requires_approval)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, IntercomAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = IntercomConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url_within_policy() {
        // br-gs71m: from_params accepts policy-conforming Intercom
        // hosts (api.intercom.io / api.eu.intercom.io / api.au.intercom.io
        // over https) when the caller overrides base_url. The pre-fix
        // test asserted `https://intercom.example.com` was accepted —
        // that was the bug; `intercom.example.com` is NOT an Intercom
        // host and would have routed the bearer token to the
        // attacker. Now uses the EU regional host to lock in the
        // policy-conforming override path.
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.eu.intercom.io",
        }))
        .expect("api.eu.intercom.io must be accepted");
        assert_eq!(config.base_url, "https://api.eu.intercom.io");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = IntercomConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = IntercomConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = IntercomConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"role": "user"});
        assert_eq!(require_str(&input, "role").unwrap(), "user");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"role": 42});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"role": null});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 6);
    }

    #[test]
    fn introspection_operations_preserve_runtime_order() {
        let ops = typed_operations_info();
        let ids: Vec<&str> = ops.iter().map(|operation| operation.id.as_str()).collect();
        assert_eq!(ids, OPERATION_ORDER);
    }

    fn strict_intercom_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_intercom_manifest()?;
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
                Some(ApprovalMode::from(manifest_operation.requires_approval))
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
        let ops = operations_info();
        let create = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["id"] == OP_CONTACTS_CREATE)
            .unwrap();
        let delete = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["id"] == OP_CONTACTS_DELETE)
            .unwrap();
        let list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["id"] == OP_CONTACTS_LIST)
            .unwrap();

        assert_eq!(create["requires_approval"], "policy");
        assert_eq!(delete["requires_approval"], "interactive");
        assert_eq!(list["requires_approval"], "none");
        assert_eq!(delete["capability"], "intercom.contacts.delete");
        assert_eq!(create["rate_limit"]["max"], 100);
        assert_eq!(delete["rate_limit"]["max"], 100);
        assert_eq!(list["rate_limit"]["max"], 500);
        assert_eq!(create["rate_limit"]["pool_name"], "intercom.contacts.write");
        assert_eq!(
            delete["rate_limit"]["pool_name"],
            "intercom.contacts.delete"
        );
        assert_eq!(list["rate_limit"]["pool_name"], "intercom.contacts.read");
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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
        assert!(ids.contains(&"intercom.contacts.list"));
        assert!(ids.contains(&"intercom.contacts.create"));
        assert!(ids.contains(&"intercom.contacts.delete"));
        assert!(ids.contains(&"intercom.conversations.list"));
        assert!(ids.contains(&"intercom.conversations.reply"));
        assert!(ids.contains(&"intercom.tags.list"));
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
    fn config_trims_access_token() {
        let config =
            IntercomConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            IntercomAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            IntercomAuth::CredentialId(_) => panic!("expected BearerToken"),
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
        let c = IntercomConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // ── Additional tests for expanded coverage ────────────────────

    #[test]
    fn connector_new_has_zero_counters() {
        let c = IntercomConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_clone_preserves_auth() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok_abc"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(cloned.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_clone_preserves_base_url() {
        // br-gs71m: pre-fix used `https://custom.io` (now policy-rejected).
        // The test's intent is to verify clone preserves base_url —
        // the policy allow-list is unrelated to that property. Use the
        // AU regional host to get a non-default policy-allowed URL.
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.au.intercom.io"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "https://api.au.intercom.io");
        assert_eq!(cloned.base_url, "https://api.au.intercom.io");
    }

    #[test]
    fn config_debug_format() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("IntercomConfig"));
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            let back: DoctorStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_debug_format() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("fail detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "fail detail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("OK".into()),
            critical: false,
        };
        let serialized = serde_json::to_string(&c).unwrap();
        let back: DoctorCheck = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "connectivity");
        assert!(back.passed);
        assert_eq!(back.message, Some("OK".into()));
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
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
                critical: true,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
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
    fn doctor_result_serializes_with_message() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: Some("detail here".into()),
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"][0]["message"], "detail here");
    }

    #[test]
    fn operations_contacts_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.contacts.create")
            .unwrap();
        assert_eq!(op["safety_tier"], "risky");
        assert_eq!(op["risk_level"], "medium");
    }

    #[test]
    fn operations_contacts_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.contacts.delete")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    /// br-5g8rj: contacts.delete must require a DEDICATED capability,
    /// not the generic contacts.write shared with create/update.
    /// Locks in the split through the manifest-derived operation
    /// catalog so a future regression that re-conflates them is
    /// caught at test time.
    #[test]
    fn operations_contacts_delete_has_dedicated_capability() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();

        let delete = arr
            .iter()
            .find(|op| op["id"] == "intercom.contacts.delete")
            .expect("contacts.delete operation must be present");
        assert_eq!(
            delete["capability"].as_str().unwrap(),
            "intercom.contacts.delete",
            "delete must require its own capability id, not the generic write",
        );
        // Sanity: still high-risk + dangerous.
        assert_eq!(delete["risk_level"], "high");
        assert_eq!(delete["safety_tier"], "dangerous");

        // create still routes through generic write; only delete
        // is split out.
        let create = arr
            .iter()
            .find(|op| op["id"] == "intercom.contacts.create")
            .expect("contacts.create operation must be present");
        assert_eq!(
            create["capability"].as_str().unwrap(),
            "intercom.contacts.write",
            "create still uses the generic write capability",
        );
        assert_ne!(
            create["capability"].as_str().unwrap(),
            delete["capability"].as_str().unwrap(),
            "create and delete must require different capabilities",
        );
    }

    #[test]
    fn operations_conversations_reply_not_idempotent() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.conversations.reply")
            .unwrap();
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn operations_tags_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.tags.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn operations_all_prefixed_intercom() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("intercom."),
                "op {id} missing intercom. prefix"
            );
        }
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"role": true});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"role": [1, 2, 3]});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"role": ""});
        assert_eq!(require_str(&input, "role").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_content() {
        let input = json!({});
        match require_str(&input, "contact_id").unwrap_err() {
            IntercomError::InvalidInput(msg) => {
                assert!(msg.contains("contact_id"));
            }
            e => panic!("expected InvalidInput, got {e:?}"),
        }
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = IntercomConfig::from_params(&json!({
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
        let config = IntercomConfig::from_params(&json!({
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
        let config = IntercomConfig::from_params(&json!({
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
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "intercom.bearer_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "obtain_token");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "obtain_token");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "intercom.bearer_token");
        assert_eq!(v["steps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn base_url_policy_accepts_intercom_https() {
        let (ok, message) = base_url_policy("https://api.intercom.io");
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
        let (ok, message) = base_url_policy("http://api.intercom.io");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.intercom.io"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn from_params_rejects_non_intercom_host() {
        // br-gs71m: pre-fix this test asserted that
        // `https://evil.example.com` succeeded at from_params and that
        // the rejection only surfaced through provisioning_readiness.
        // That was the bug — IntercomClient was already constructed
        // with the bearer token before any policy check fired. The
        // post-fix invariant: non-Intercom base_url is refused at
        // from_params; the IntercomClient is never built for it.
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .expect_err("non-intercom base_url must be rejected at from_params");
        match err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(
                    message.contains("intercom.io"),
                    "rejection must name the policy: {message}"
                );
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    /// br-gs71m: substring matching is INSUFFICIENT — a host like
    /// `intercom.io.evil.example` containing `intercom.io` as a
    /// subdomain label must be rejected. Locks in exact-host equality.
    #[test]
    fn from_params_rejects_substring_collision_host() {
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://intercom.io.evil.example",
        }))
        .expect_err("substring-collision host must be rejected");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));

        let err2 = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil-intercom.io",
        }))
        .expect_err("prefix-trick host must be rejected");
        assert!(matches!(err2, FcpError::InvalidRequest { .. }));
    }

    /// br-gs71m: http (non-https) on an Intercom host is also a
    /// downgrade attempt — reject unless localhost.
    #[test]
    fn from_params_rejects_http_non_local_host() {
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://api.intercom.io",
        }))
        .expect_err("http://api.intercom.io must be rejected (https required)");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    /// br-gs71m: every regional API host (US/EU/AU) must pass the
    /// policy. Regression guard — if a future region addition forgets
    /// to add its host to `ALLOWED_INTERCOM_HOSTS`, this fails fast.
    #[test]
    fn from_params_accepts_all_regional_hosts() {
        for host in [
            "api.intercom.io",
            "api.eu.intercom.io",
            "api.au.intercom.io",
        ] {
            let url = format!("https://{host}");
            let config = IntercomConfig::from_params(&json!({
                "access_token": "tok",
                "base_url": url.clone(),
            }))
            .unwrap_or_else(|err| panic!("regional host {host} must be accepted: {err}"));
            assert_eq!(config.base_url, url);
        }
    }

    /// br-gs71m: localhost / 127.0.0.1 / `::1` stay allowed for tests.
    #[test]
    fn from_params_accepts_localhost_for_tests() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:8080",
        }))
        .expect("localhost must be accepted");
        assert_eq!(config.base_url, "http://localhost:8080");

        let config2 = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://127.0.0.1:9090/api",
        }))
        .expect("127.0.0.1 must be accepted");
        assert_eq!(config2.base_url, "http://127.0.0.1:9090/api");
    }

    #[test]
    fn from_params_accepts_clean_base_url() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.intercom.io",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.intercom.io");
    }

    #[test]
    fn from_params_rejects_base_url_query_string() {
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.intercom.io?leak=x",
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
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.intercom.io#frag",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_params_rejects_base_url_userinfo() {
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://attacker:pw@api.intercom.io",
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
        let err = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "not a url",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }
}
