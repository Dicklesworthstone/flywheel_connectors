//! Azure connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    client::{AzureApiVersions, AzureClient},
    types::{AzureAuth, SetSecretAttributes, SetSecretRequest},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_LIST_SUBSCRIPTIONS: &str = "azure.management.list_subscriptions";
const OP_LIST_RESOURCE_GROUPS: &str = "azure.management.list_resource_groups";
const OP_LIST_RESOURCES: &str = "azure.management.list_resources";
const OP_BLOB_LIST_CONTAINERS: &str = "azure.storage.blob_list_containers";
const OP_BLOB_LIST_BLOBS: &str = "azure.storage.blob_list_blobs";
const OP_BLOB_GET: &str = "azure.storage.blob_get";
const OP_BLOB_PUT: &str = "azure.storage.blob_put";
const OP_BLOB_DELETE: &str = "azure.storage.blob_delete";
const OP_KEYVAULT_LIST_SECRETS: &str = "azure.keyvault.list_secrets";
const OP_KEYVAULT_READ_VALUE: &str = "azure.keyvault.get_secret";
const OP_KEYVAULT_WRITE_VALUE: &str = "azure.keyvault.set_secret";

// Capability IDs
const CAP_MANAGEMENT_READ: &str = "azure.management.read";
const CAP_STORAGE_READ: &str = "azure.storage.read";
const CAP_STORAGE_WRITE: &str = "azure.storage.write";
const CAP_KEYVAULT_READ: &str = "azure.keyvault.read";
const CAP_KEYVAULT_WRITE: &str = "azure.keyvault.write";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/azure_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/azure_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/azure_connector_verification.sh",
    "fwc manifest fix connectors/azure/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-azure --all-targets",
    "rch exec -- cargo fmt -p fcp-azure -- --check",
    "rch exec -- cargo test -p fcp-azure --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-azure --all-targets -- -D warnings",
];

#[derive(Clone, Deserialize)]
pub struct AzureConfig {
    #[serde(default = "default_management_url")]
    pub management_url: String,
    #[serde(flatten)]
    pub auth: AzureAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub api_versions: AzureApiVersions,
}

fn default_management_url() -> String {
    "https://management.azure.com".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for AzureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureConfig")
            .field("management_url", &self.management_url)
            .field("auth", &self.auth)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("api_versions", &self.api_versions)
            .finish()
    }
}

impl AzureConfig {
    fn validate(&self) -> Result<(), String> {
        validate_management_url(&self.management_url)?;
        self.api_versions.validate()?;
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be > 0".into());
        }

        if matches!(
            &self.auth,
            AzureAuth::BearerToken { bearer_token } if bearer_token.trim().is_empty()
        ) {
            return Err("bearer_token is required".into());
        }

        Ok(())
    }

    fn normalized(mut self) -> Self {
        self.api_versions = self.api_versions.normalized();
        self
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let raw: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;
        let config = raw.normalized();

        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;

        Ok(config)
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        ProvisioningReadiness {
            auth_mode: self.auth.redacted_label(),
            management_url: self.management_url.clone(),
            request_timeout_ms: self.request_timeout_ms,
            api_versions: self.api_versions.clone(),
            credential_injection_required: self.auth.is_secretless(),
            supported_overrides: SupportedOverrides {
                blob_base_url: "https://<account>.blob.core.windows.net",
                vault_base_url: "https://<vault>.vault.azure.net",
            },
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
}

fn validate_controlled_base_url<F>(
    url: &str,
    label: &str,
    expected_host_description: &str,
    host_allowed: F,
) -> Result<(), String>
where
    F: FnOnce(&str) -> bool,
{
    let parsed =
        Url::parse(url).map_err(|error| format!("{label} must be a valid URL: {error}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} must not include embedded credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "{label} must not include a query string or fragment"
        ));
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(format!("{label} must not include a path"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("{label} must include a host"))?;
    if is_local_test_host(host) {
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(format!(
                "{label} must use https, or http/https when targeting localhost for verification"
            ));
        }
        return Ok(());
    }
    if parsed.scheme() != "https" {
        return Err(format!("{label} must use https"));
    }
    if parsed.port_or_known_default() != Some(443) {
        return Err(format!("{label} must resolve to port 443"));
    }
    if !host_allowed(host) {
        return Err(format!(
            "{label} host must match {expected_host_description}"
        ));
    }
    Ok(())
}

fn validate_management_url(url: &str) -> Result<(), String> {
    if url.trim().is_empty() {
        return Err("management_url cannot be empty".into());
    }
    validate_controlled_base_url(url, "management_url", "management.azure.com", |host| {
        host.eq_ignore_ascii_case("management.azure.com")
    })
}

fn validate_blob_base_url(url: &str) -> Result<(), String> {
    validate_controlled_base_url(url, "blob_base_url", "*.blob.core.windows.net", |host| {
        host.ends_with(".blob.core.windows.net")
    })
}

fn validate_vault_base_url(url: &str) -> Result<(), String> {
    validate_controlled_base_url(url, "vault_base_url", "*.vault.azure.net", |host| {
        host.ends_with(".vault.azure.net")
    })
}

fn validate_optional_override(
    url: Option<&str>,
    label: &str,
    validator: fn(&str) -> Result<(), String>,
) -> FcpResult<()> {
    if let Some(url) = url {
        validator(url).map_err(|message| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label}: {message}"),
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
struct SupportedOverrides {
    blob_base_url: &'static str,
    vault_base_url: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    management_url: String,
    request_timeout_ms: u64,
    api_versions: AzureApiVersions,
    credential_injection_required: bool,
    supported_overrides: SupportedOverrides,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Azure subscription, resource group, Blob Storage account, and Key Vault for verification.",
            "Provide either a scoped bearer token or a credential_id backed by a host/egress injector before expecting self_check or invoke to succeed.",
            "Point management_url, blob_base_url, and vault_base_url at localhost verification stubs when you need deterministic test coverage without touching live Azure resources.",
        ],
        dedicated_environment: "Use staging-only subscriptions, storage accounts, blob containers, and Key Vaults. Blob writes and Key Vault secret updates can overwrite live state and must never target production during verification.",
        redaction_rules: vec![
            "Never log bearer tokens or credential injection identifiers alongside tenant-specific context.",
            "Redact Authorization headers, Key Vault secret values, blob payloads, tenant IDs, subscription IDs, storage account names, and vault names from captured artifacts unless they are already public test fixtures.",
            "Treat resource group names, resource IDs, blob names, and Key Vault secret names as sensitive in operator transcripts.",
        ],
        limitations: vec![
            "Self-check currently proves readiness by calling Azure Resource Manager list_subscriptions.",
            "Deterministic verification relies on localhost override endpoints for management_url, blob_base_url, and vault_base_url rather than live Azure APIs.",
            "This connector exposes management, blob, and Key Vault slices but does not currently cover broader Azure resource mutation workflows.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "credential_injection_required",
                symptom: "health or self_check reports credential injection required",
                action: "Provide a concrete bearer token for direct verification or ensure the host/egress proxy injects the credential_id before rerunning the bundle.",
            },
            RemediationHint {
                code: "auth_failed",
                symptom: "self_check or invoke returns Unauthorized or Forbidden",
                action: "Verify the bearer token audience and scope for ARM, Blob Storage, or Key Vault, and confirm the token is not expired.",
            },
            RemediationHint {
                code: "override_host_policy",
                symptom: "invoke rejects blob_base_url or vault_base_url before making a request",
                action: "Use https://<account>.blob.core.windows.net, https://<vault>.vault.azure.net, or localhost verification stubs without paths, query strings, fragments, or embedded credentials.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self {
            ready,
            passed: ready,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug)]
pub struct AzureConnector {
    base: BaseConnector,
    config: Option<AzureConfig>,
    client: Option<AzureClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AzureConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.azure")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(digest.finalize()))
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        report
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(AzureConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|_| "Configuration loaded".into())
                .or_else(|| {
                    Some("Not configured; run configure before handshake or invoke".into())
                }),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: self
                .client
                .as_ref()
                .map(|_| "Client initialized".into())
                .or_else(|| Some("Client not initialized; re-run configure".into())),
            critical: true,
        });

        if let (Some(config), Some(readiness)) = (&self.config, &provisioning) {
            let (management_url_ok, management_message) = match validate_management_url(
                &config.management_url,
            ) {
                Ok(()) => (
                    true,
                    format!(
                        "Management URL accepted for Azure Resource Manager or localhost verification: {}",
                        config.management_url
                    ),
                ),
                Err(error) => (false, error),
            };
            checks.push(DoctorCheck {
                name: "management_url".into(),
                passed: management_url_ok,
                message: Some(management_message),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "request_timeout_ms".into(),
                passed: readiness.request_timeout_ms > 0,
                message: Some(format!(
                    "HTTP timeout configured to {}ms",
                    readiness.request_timeout_ms
                )),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "api_versions".into(),
                passed: true,
                message: Some(format!(
                    "Effective Azure API versions: {}",
                    readiness.api_versions.summary()
                )),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                passed: !readiness.credential_injection_required,
                message: Some(if readiness.credential_injection_required {
                    "Configured with credential_id; the host or egress proxy must inject a concrete Azure bearer token before self_check or invoke can prove live readiness".into()
                } else {
                    "Bearer token is configured directly for self_check and invoke".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "override_host_policy".into(),
                passed: true,
                message: Some(
                    "blob_base_url and vault_base_url must target the expected Azure hosts or localhost verification stubs; paths, query strings, fragments, and embedded credentials are rejected".into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }

    fn capability_for_operation(operation: &str) -> Option<CapabilityId> {
        let capability = match operation {
            OP_LIST_SUBSCRIPTIONS | OP_LIST_RESOURCE_GROUPS | OP_LIST_RESOURCES => {
                CAP_MANAGEMENT_READ
            }
            OP_BLOB_LIST_CONTAINERS | OP_BLOB_LIST_BLOBS | OP_BLOB_GET => CAP_STORAGE_READ,
            OP_BLOB_PUT | OP_BLOB_DELETE => CAP_STORAGE_WRITE,
            OP_KEYVAULT_LIST_SECRETS | OP_KEYVAULT_READ_VALUE => CAP_KEYVAULT_READ,
            OP_KEYVAULT_WRITE_VALUE => CAP_KEYVAULT_WRITE,
            _ => return None,
        };
        Some(CapabilityId::from_static(capability))
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing string field: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

impl Default for AzureConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn schema(required: &[&str]) -> serde_json::Value {
    if required.is_empty() {
        json!({ "type": "object" })
    } else {
        json!({ "type": "object", "required": required })
    }
}

fn string_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "description": description,
    })
}

fn nullable_string_schema(description: &str) -> Value {
    json!({
        "type": ["string", "null"],
        "description": description,
    })
}

fn nullable_bool_schema(description: &str) -> Value {
    json!({
        "type": ["boolean", "null"],
        "description": description,
    })
}

fn nullable_integer_schema(description: &str) -> Value {
    json!({
        "type": ["integer", "null"],
        "description": description,
    })
}

fn any_json_schema(description: &str) -> Value {
    json!({ "description": description })
}

fn subscription_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "subscription_id": nullable_string_schema("Azure subscription identifier."),
            "display_name": nullable_string_schema("Human-readable subscription name."),
            "state": nullable_string_schema("Azure subscription lifecycle state."),
            "tenant_id": nullable_string_schema("Microsoft Entra tenant associated with the subscription."),
        },
    })
}

fn resource_group_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": nullable_string_schema("Azure resource group resource ID."),
            "name": nullable_string_schema("Azure resource group name."),
            "location": nullable_string_schema("Azure region for the resource group."),
            "tags": any_json_schema("Azure resource group tags as returned by ARM."),
            "properties": any_json_schema("Azure resource group properties payload as returned by ARM."),
        },
    })
}

fn resource_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": nullable_string_schema("Azure resource ID."),
            "name": nullable_string_schema("Azure resource name."),
            "resource_type": nullable_string_schema("Azure resource type, for example Microsoft.Storage/storageAccounts."),
            "location": nullable_string_schema("Azure region for the resource."),
            "tags": any_json_schema("Azure resource tags as returned by ARM."),
        },
    })
}

fn blob_container_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": nullable_string_schema("Blob container name."),
            "last_modified": nullable_string_schema("Last-modified timestamp reported by Azure Blob Storage."),
            "public_access": nullable_string_schema("Public access level, when configured."),
        },
    })
}

fn blob_item_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": nullable_string_schema("Blob name."),
            "content_length": nullable_integer_schema("Blob size in bytes."),
            "content_type": nullable_string_schema("Blob content type."),
            "last_modified": nullable_string_schema("Last-modified timestamp reported by Azure Blob Storage."),
        },
    })
}

fn secret_attributes_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "properties": {
            "enabled": nullable_bool_schema("Whether the secret is enabled."),
            "created": nullable_integer_schema("Unix timestamp when the secret version was created."),
            "updated": nullable_integer_schema("Unix timestamp when the secret version was last updated."),
        },
    })
}

fn secret_item_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": nullable_string_schema("Azure Key Vault secret identifier."),
            "attributes": secret_attributes_schema(),
            "tags": any_json_schema("Secret metadata tags returned by Azure Key Vault."),
        },
    })
}

fn secret_bundle_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "value": nullable_string_schema("Secret value. Treat as sensitive and avoid logging it."),
            "id": nullable_string_schema("Azure Key Vault secret identifier."),
            "attributes": secret_attributes_schema(),
            "tags": any_json_schema("Secret metadata tags returned by Azure Key Vault."),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn op(
    id: &'static str,
    summary: &'static str,
    description: &'static str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    when_to_use: &'static str,
    common_mistakes: &'static [&'static str],
    related: &'static [&'static str],
    requires_approval: Option<ApprovalMode>,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: common_mistakes
                .iter()
                .map(|value| (*value).into())
                .collect(),
            examples: Vec::new(),
            related: related
                .iter()
                .map(|value| CapabilityId::from_static(value))
                .collect(),
        },
        rate_limit: None,
        requires_approval,
    }
}

fn management_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_LIST_SUBSCRIPTIONS,
            "List Azure subscriptions",
            "List Azure subscriptions visible to the configured credentials.",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            schema(&[]),
            json!({
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": {
                        "type": "array",
                        "items": subscription_schema(),
                    },
                    "next_link": nullable_string_schema("Continuation URL for the next page of subscriptions."),
                },
            }),
            "Enumerate Azure subscriptions available to the configured credentials",
            &[
                "Assuming subscription visibility guarantees access to every resource group or storage account.",
            ],
            &[OP_LIST_RESOURCE_GROUPS],
            None,
        ),
        op(
            OP_LIST_RESOURCE_GROUPS,
            "List resource groups in a subscription",
            "List Azure resource groups within a specific subscription.",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["subscription_id"],
                "properties": {
                    "subscription_id": string_schema("Azure subscription identifier."),
                },
            }),
            json!({
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": {
                        "type": "array",
                        "items": resource_group_schema(),
                    },
                    "next_link": nullable_string_schema("Continuation URL for the next page of resource groups."),
                },
            }),
            "List resource groups within a specific Azure subscription",
            &["Passing a display name instead of the Azure subscription ID."],
            &[OP_LIST_SUBSCRIPTIONS, OP_LIST_RESOURCES],
            None,
        ),
        op(
            OP_LIST_RESOURCES,
            "List resources in a resource group",
            "List Azure resources within a specific resource group.",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["subscription_id", "resource_group"],
                "properties": {
                    "subscription_id": string_schema("Azure subscription identifier."),
                    "resource_group": string_schema("Azure resource group name."),
                },
            }),
            json!({
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": {
                        "type": "array",
                        "items": resource_schema(),
                    },
                    "next_link": nullable_string_schema("Continuation URL for the next page of resources."),
                },
            }),
            "Enumerate resources within a specific Azure resource group",
            &["Using the wrong subscription_id for the targeted resource group."],
            &[OP_LIST_RESOURCE_GROUPS],
            None,
        ),
    ]
}

fn blob_list_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_BLOB_LIST_CONTAINERS,
            "List blob storage containers",
            "List blob containers for an Azure Storage account.",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["storage_account"],
                "properties": {
                    "storage_account": string_schema("Azure Storage account name."),
                    "blob_base_url": string_schema("Optional override for the blob endpoint root, for example https://account.blob.core.windows.net."),
                },
            }),
            json!({
                "type": "object",
                "required": ["containers"],
                "properties": {
                    "containers": {
                        "type": "array",
                        "items": blob_container_schema(),
                    },
                    "next_marker": nullable_string_schema("Azure continuation marker for the next page of containers."),
                },
            }),
            "List blob containers in an Azure storage account",
            &["Passing a full endpoint URL as storage_account instead of only the account name."],
            &[OP_BLOB_LIST_BLOBS],
            None,
        ),
        op(
            OP_BLOB_LIST_BLOBS,
            "List blobs in a container",
            "List blobs within a specific Azure Storage container.",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["storage_account", "container"],
                "properties": {
                    "storage_account": string_schema("Azure Storage account name."),
                    "container": string_schema("Blob container name."),
                    "prefix": string_schema("Optional blob name prefix for narrowing the listing."),
                    "blob_base_url": string_schema("Optional override for the blob endpoint root, for example https://account.blob.core.windows.net."),
                },
            }),
            json!({
                "type": "object",
                "required": ["blobs"],
                "properties": {
                    "blobs": {
                        "type": "array",
                        "items": blob_item_schema(),
                    },
                    "next_marker": nullable_string_schema("Azure continuation marker for the next page of blobs."),
                },
            }),
            "List blobs within a specific Azure storage container",
            &[
                "Forgetting that container names and blob names are evaluated by Azure exactly as provided.",
            ],
            &[OP_BLOB_LIST_CONTAINERS, OP_BLOB_GET, OP_BLOB_DELETE],
            None,
        ),
    ]
}

fn blob_get_put_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_BLOB_GET,
            "Download a blob",
            "Download a blob and return its contents base64-encoded.",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["storage_account", "container", "blob_name"],
                "properties": {
                    "storage_account": string_schema("Azure Storage account name."),
                    "container": string_schema("Blob container name."),
                    "blob_name": string_schema("Blob name."),
                    "blob_base_url": string_schema("Optional override for the blob endpoint root, for example https://account.blob.core.windows.net."),
                },
            }),
            json!({
                "type": "object",
                "required": ["content_base64"],
                "properties": {
                    "content_base64": string_schema("Blob bytes encoded as base64."),
                    "content_type": nullable_string_schema("Blob content type reported by Azure Storage."),
                    "content_length": nullable_integer_schema("Blob size in bytes."),
                },
            }),
            "Download or read the contents of a specific blob",
            &["Treating content_base64 as plain UTF-8 text instead of decoding it first."],
            &[OP_BLOB_LIST_BLOBS, OP_BLOB_PUT],
            None,
        ),
        op(
            OP_BLOB_PUT,
            "Upload a blob",
            "Upload or overwrite a blob in Azure Storage.",
            CAP_STORAGE_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["storage_account", "container", "blob_name", "content_base64"],
                "properties": {
                    "storage_account": string_schema("Azure Storage account name."),
                    "container": string_schema("Blob container name."),
                    "blob_name": string_schema("Blob name."),
                    "content_base64": string_schema("Blob bytes encoded as base64."),
                    "content_type": string_schema("Optional content type to send with the blob upload."),
                    "blob_base_url": string_schema("Optional override for the blob endpoint root, for example https://account.blob.core.windows.net."),
                },
            }),
            json!({
                "type": "object",
                "required": ["created"],
                "properties": {
                    "created": {
                        "type": "boolean",
                        "description": "Whether Azure Storage accepted the blob write.",
                    },
                    "blob_name": nullable_string_schema("Blob name echoed back by the connector."),
                },
            }),
            "Upload or overwrite a blob in an Azure storage container",
            &[
                "Sending raw bytes instead of base64-encoded content_base64.",
                "Assuming the upload is preview-only when it can overwrite an existing blob.",
            ],
            &[OP_BLOB_GET, OP_BLOB_DELETE],
            None,
        ),
    ]
}

fn blob_delete_operation() -> Vec<OperationInfo> {
    vec![op(
        OP_BLOB_DELETE,
        "Delete a blob",
        "Delete a blob from Azure Storage.",
        CAP_STORAGE_WRITE,
        RiskLevel::Medium,
        SafetyTier::Risky,
        IdempotencyClass::BestEffort,
        json!({
            "type": "object",
            "required": ["storage_account", "container", "blob_name"],
            "properties": {
                "storage_account": string_schema("Azure Storage account name."),
                "container": string_schema("Blob container name."),
                "blob_name": string_schema("Blob name."),
                "blob_base_url": string_schema("Optional override for the blob endpoint root, for example https://account.blob.core.windows.net."),
            },
        }),
        json!({
            "type": "object",
            "required": ["deleted"],
            "properties": {
                "deleted": {
                    "type": "boolean",
                    "description": "Whether Azure Storage accepted the blob delete.",
                },
                "blob_name": nullable_string_schema("Blob name echoed back by the connector."),
            },
        }),
        "Delete a blob from an Azure storage container",
        &["Assuming delete is a dry-run operation; it removes the target blob."],
        &[OP_BLOB_LIST_BLOBS],
        None,
    )]
}

fn keyvault_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_KEYVAULT_LIST_SECRETS,
            "List Key Vault secrets",
            "List Azure Key Vault secret metadata without returning secret values.",
            CAP_KEYVAULT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["vault_name"],
                "properties": {
                    "vault_name": string_schema("Azure Key Vault name."),
                    "vault_base_url": string_schema("Optional override for the Key Vault endpoint root, for example https://vault-name.vault.azure.net."),
                },
            }),
            json!({
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": {
                        "type": "array",
                        "items": secret_item_schema(),
                    },
                    "next_link": nullable_string_schema("Continuation URL for the next page of secrets."),
                },
            }),
            "List secret names stored in an Azure Key Vault",
            &["Expecting this operation to return secret values; it only returns metadata."],
            &[OP_KEYVAULT_READ_VALUE],
            None,
        ),
        op(
            OP_KEYVAULT_READ_VALUE,
            "Get a Key Vault secret value",
            "Retrieve a secret value and metadata from Azure Key Vault.",
            CAP_KEYVAULT_READ,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["vault_name", "secret_name"],
                "properties": {
                    "vault_name": string_schema("Azure Key Vault name."),
                    "secret_name": string_schema("Azure Key Vault secret name."),
                    "vault_base_url": string_schema("Optional override for the Key Vault endpoint root, for example https://vault-name.vault.azure.net."),
                },
            }),
            secret_bundle_schema(),
            "Retrieve the actual value of a specific secret from Azure Key Vault",
            &["Logging or pasting the returned secret value into shared transcripts."],
            &[OP_KEYVAULT_LIST_SECRETS, OP_KEYVAULT_WRITE_VALUE],
            None,
        ),
        op(
            OP_KEYVAULT_WRITE_VALUE,
            "Set a Key Vault secret",
            "Create or update a secret value in Azure Key Vault.",
            CAP_KEYVAULT_WRITE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            json!({
                "type": "object",
                "required": ["vault_name", "secret_name", "value"],
                "properties": {
                    "vault_name": string_schema("Azure Key Vault name."),
                    "secret_name": string_schema("Azure Key Vault secret name."),
                    "value": string_schema("Secret value to store in Azure Key Vault."),
                    "tags": any_json_schema("Optional metadata tags to attach to the secret."),
                    "content_type": string_schema("Optional content type metadata for the secret."),
                    "enabled": {
                        "type": "boolean",
                        "description": "Optional enabled flag for the new secret version.",
                    },
                    "vault_base_url": string_schema("Optional override for the Key Vault endpoint root, for example https://vault-name.vault.azure.net."),
                },
            }),
            secret_bundle_schema(),
            "Create or update a secret in Azure Key Vault",
            &[
                "Using a production vault for verification writes.",
                "Forgetting this mutates live secret material.",
            ],
            &[OP_KEYVAULT_READ_VALUE, OP_KEYVAULT_LIST_SECRETS],
            Some(ApprovalMode::Interactive),
        ),
    ]
}

fn operations_info() -> Vec<OperationInfo> {
    let mut ops = management_operations();
    ops.extend(blob_list_operations());
    ops.extend(blob_get_put_operations());
    ops.extend(blob_delete_operation());
    ops.extend(keyvault_operations());
    ops
}

impl AzureConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let Some(capability) = Self::capability_for_operation(operation) else {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        };
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Azure client".into(),
        })?;

        let output = match operation {
            OP_LIST_SUBSCRIPTIONS => serde_json::to_value(
                client
                    .list_subscriptions()
                    .await
                    .map_err(|e| e.to_fcp_error())?,
            )
            .map_err(|e| FcpError::Internal {
                message: e.to_string(),
            })?,

            OP_LIST_RESOURCE_GROUPS => {
                let subscription_id = Self::require_str(&req.input, "subscription_id")?;
                serde_json::to_value(
                    client
                        .list_resource_groups(subscription_id)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_LIST_RESOURCES => {
                let subscription_id = Self::require_str(&req.input, "subscription_id")?;
                let resource_group = Self::require_str(&req.input, "resource_group")?;
                serde_json::to_value(
                    client
                        .list_resources(subscription_id, resource_group)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_LIST_CONTAINERS => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_list_containers(storage_account, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_LIST_BLOBS => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let prefix = req.input.get("prefix").and_then(|v| v.as_str());
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_list_blobs(storage_account, container, prefix, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_GET => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_name = Self::require_str(&req.input, "blob_name")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_get(storage_account, container, blob_name, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_PUT => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_name = Self::require_str(&req.input, "blob_name")?;
                let content_base64 = Self::require_str(&req.input, "content_base64")?;
                let content_type = req.input.get("content_type").and_then(|v| v.as_str());
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_put(
                            storage_account,
                            container,
                            blob_name,
                            content_base64,
                            content_type,
                            blob_base_url,
                        )
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_DELETE => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_name = Self::require_str(&req.input, "blob_name")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_delete(storage_account, container, blob_name, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_LIST_SECRETS => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                serde_json::to_value(
                    client
                        .keyvault_list_secrets(vault_name, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_READ_VALUE => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let secret_name = Self::require_str(&req.input, "secret_name")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                serde_json::to_value(
                    client
                        .keyvault_get_secret(vault_name, secret_name, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_WRITE_VALUE => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let secret_name = Self::require_str(&req.input, "secret_name")?;
                let value = Self::require_str(&req.input, "value")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                let tags = req.input.get("tags").cloned();
                let content_type = req
                    .input
                    .get("content_type")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                let enabled = req
                    .input
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool);

                let set_req = SetSecretRequest {
                    value: value.into(),
                    tags,
                    content_type,
                    attributes: enabled.map(|e| SetSecretAttributes { enabled: Some(e) }),
                };
                serde_json::to_value(
                    client
                        .keyvault_set_secret(vault_name, secret_name, &set_req, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

fcp_core::impl_fcp_sealed!(AzureConnector);

#[async_trait]
impl FcpConnector for AzureConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let azure = AzureConfig::from_value(config)?;
        let client = AzureClient::new(
            azure.auth.clone(),
            azure.retry.clone(),
            azure.api_versions.clone(),
            Duration::from_millis(azure.request_timeout_ms),
        )
        .map_err(|error| FcpError::Internal {
            message: format!("Client init: {error}"),
        })?
        .with_management_url(&azure.management_url);

        self.client = Some(client);
        self.config = Some(azure);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let HandshakeRequest {
            host_public_key,
            zone,
            nonce,
            capabilities_requested,
            requested_instance_id,
            ..
        } = req;
        if let Some(instance_id) = requested_instance_id {
            self.base.instance_id = instance_id;
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            host_public_key,
            zone,
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self
            .config
            .as_ref()
            .map(AzureConfig::provisioning_readiness);
        let credential_injection_required =
            self.client.as_ref().is_some_and(AzureClient::is_secretless);
        let mut snapshot = if self.config.is_some() && self.client.is_some() {
            if credential_injection_required {
                HealthSnapshot::degraded("credential injection required")
            } else {
                HealthSnapshot::ready()
            }
        } else {
            HealthSnapshot::degraded("not configured")
        };
        if credential_injection_required {
            snapshot.status = HealthState::Degraded {
                reason: "credential injection required".into(),
            };
        }
        snapshot.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "auth_mode": self
                .config
                .as_ref()
                .map(|config| config.auth.redacted_label()),
            "management_url": self
                .config
                .as_ref()
                .map(|config| config.management_url.clone()),
            "api_versions": self
                .config
                .as_ref()
                .map(|config| config.api_versions.clone()),
            "credential_injection_required": credential_injection_required,
            "supported_overrides": {
                "blob_base_url": "https://<account>.blob.core.windows.net",
                "vault_base_url": "https://<vault>.vault.azure.net",
            },
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let provisioning = self
            .config
            .as_ref()
            .map(AzureConfig::provisioning_readiness);
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                provisioning.as_ref(),
            ));
        };

        if client.is_secretless() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection is required for health checks",
                ),
                provisioning.as_ref(),
            ));
        }

        match client.health_check().await {
            Ok(()) => {
                Ok(self.attach_self_check_details(SelfCheckReport::ok(), provisioning.as_ref()))
            }
            Err(error) if error.is_retryable() => Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                provisioning.as_ref(),
            )),
            Err(error) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("self_check_failed", error.to_string()),
                provisioning.as_ref(),
            )),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{CapabilityToken, RequestId, ZoneId};

    fn valid_config() -> serde_json::Value {
        json!({
            "mode": "bearer_token",
            "bearer_token": "test-token",
            "api_versions": AzureApiVersions::compiled_defaults()
        })
    }

    fn valid_secretless_config() -> serde_json::Value {
        json!({
            "mode": "credential_id",
            "credential_id": "00000000-0000-0000-0000-000000000001"
        })
    }

    #[test]
    fn new_connector_starts_unconfigured() {
        assert!(AzureConnector::new().config.is_none());
    }

    #[test]
    fn manifest_hash_is_stable() {
        assert_eq!(
            AzureConnector::manifest_hash(),
            AzureConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_accepts_bearer_token() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            assert!(connector.client.is_some());
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_token() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": ""
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_management_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": "tok",
                    "management_url": ""
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_api_version() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": "tok",
                    "api_versions": {
                        "keyvault": "   "
                    }
                }))
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                FcpError::InvalidRequest {
                    code: 1001,
                    ref message
                } if message.contains("api_versions.keyvault")
            ));
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_zero_request_timeout() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": "tok",
                    "request_timeout_ms": 0
                }))
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                FcpError::InvalidRequest {
                    code: 1001,
                    ref message
                } if message.contains("request_timeout_ms")
            ));
        })
        .unwrap();
    }

    #[test]
    fn management_url_requires_https_and_azure_host() {
        assert!(validate_management_url("https://management.azure.com").is_ok());
        assert!(validate_management_url("http://management.azure.com").is_err());
        assert!(validate_management_url("https://example.com").is_err());
        assert!(validate_management_url("https://user:pass@management.azure.com").is_err());
        assert!(validate_management_url("https://management.azure.com/subscriptions").is_err());
        assert!(validate_management_url("http://127.0.0.1:4011").is_ok());
    }

    #[test]
    fn override_urls_require_https_and_expected_hosts() {
        assert!(validate_blob_base_url("https://acct.blob.core.windows.net").is_ok());
        assert!(validate_blob_base_url("http://acct.blob.core.windows.net").is_err());
        assert!(validate_blob_base_url("https://example.com").is_err());
        assert!(validate_blob_base_url("https://user:pass@acct.blob.core.windows.net").is_err());
        assert!(validate_blob_base_url("http://localhost:4012").is_ok());

        assert!(validate_vault_base_url("https://vault-one.vault.azure.net").is_ok());
        assert!(validate_vault_base_url("http://vault-one.vault.azure.net").is_err());
        assert!(validate_vault_base_url("https://example.com").is_err());
        assert!(validate_vault_base_url("https://user:pass@vault-one.vault.azure.net").is_err());
        assert!(validate_vault_base_url("http://localhost:4013").is_ok());
    }

    #[test]
    fn doctor_reports_not_configured() {
        let doctor = AzureConnector::new().doctor();
        assert!(!doctor.passed);
        assert_eq!(doctor.checks[0].name, "configuration");
    }

    #[test]
    fn doctor_reports_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let doctor = connector.doctor();
            assert!(doctor.passed);
            let doctor_json = serde_json::to_value(&doctor).unwrap();
            assert_eq!(
                doctor_json["provisioning"]["api_versions"]["subscriptions"],
                AzureApiVersions::compiled_defaults().subscriptions
            );
        })
        .unwrap();
    }

    #[test]
    fn configure_accepts_custom_api_versions() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": "test-token",
                    "api_versions": {
                        "subscriptions": "2022-12-01",
                        "resource_groups": "2021-04-01",
                        "resources": "2021-04-01",
                        "keyvault": "2025-07-01",
                        "blob": "2026-02-06"
                    }
                }))
                .await
                .unwrap();

            let client = connector.client.as_ref().expect("client");
            assert_eq!(client.keyvault_api_version(), "2025-07-01");
            assert_eq!(client.blob_api_version(), "2026-02-06");

            let health = connector.health().await;
            let details = health.details.expect("health details");
            assert_eq!(details["api_versions"]["keyvault"], "2025-07-01");
            assert_eq!(details["api_versions"]["blob"], "2026-02-06");
        })
        .unwrap();
    }

    #[test]
    fn doctor_reports_credential_injection_required() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector
                .configure(valid_secretless_config())
                .await
                .unwrap();
            let doctor = connector.doctor();
            assert!(!doctor.passed);
            assert!(doctor.checks.iter().any(|check| {
                check.name == "credential_injection" && !check.passed && check.critical
            }));
        })
        .unwrap();
    }

    #[test]
    fn simulate_allows_requests() {
        fcp_async_core::runtime::block_on_sync(async {
            let response = AzureConnector::new()
                .simulate(SimulateRequest {
                    r#type: "simulate".into(),
                    id: RequestId::new("sim-1"),
                    connector_id: ConnectorId::from_static("fcp.azure"),
                    operation: OperationId::from_static(OP_LIST_SUBSCRIPTIONS),
                    zone_id: ZoneId::work(),
                    input: json!({}),
                    capability_token: CapabilityToken::test_token(),
                    estimate_cost: false,
                    check_availability: false,
                    context: None,
                    correlation_id: None,
                })
                .await
                .unwrap();
            assert!(response.would_succeed);
        })
        .unwrap();
    }

    #[test]
    fn subscribe_returns_streaming_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let err = connector
                .subscribe(SubscribeRequest {
                    r#type: "subscribe".into(),
                    id: RequestId::new("sub-1"),
                    topics: vec!["test".into()],
                    since: None,
                    max_events_per_sec: None,
                    batch_ms: None,
                    window_size: None,
                    capability_token: Some(CapabilityToken::test_token()),
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }

    #[test]
    fn unsubscribe_returns_streaming_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let err = connector
                .unsubscribe(UnsubscribeRequest {
                    r#type: "unsubscribe".into(),
                    id: RequestId::new("unsub-1"),
                    topics: vec!["test".into()],
                    capability_token: Some(CapabilityToken::test_token()),
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }

    #[test]
    fn health_degraded_when_not_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let snapshot = connector.health().await;
            assert!(!snapshot.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn health_ready_when_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let snapshot = connector.health().await;
            assert!(snapshot.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn health_degraded_when_credential_injection_is_required() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector
                .configure(valid_secretless_config())
                .await
                .unwrap();
            let snapshot = connector.health().await;
            assert!(!snapshot.is_ready());
            assert!(matches!(
                snapshot.status,
                HealthState::Degraded { reason } if reason == "credential injection required"
            ));
            assert_eq!(
                snapshot
                    .details
                    .as_ref()
                    .and_then(|details| details.get("credential_injection_required")),
                Some(&json!(true))
            );
        })
        .unwrap();
    }

    #[test]
    fn self_check_returns_degraded_when_not_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let report = connector.self_check().await.unwrap();
            assert!(matches!(report.status, fcp_core::SelfCheckStatus::Degraded));
        })
        .unwrap();
    }

    #[test]
    fn shutdown_clears_state() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            connector
                .shutdown(ShutdownRequest {
                    r#type: "shutdown".into(),
                    deadline_ms: 5_000,
                    drain: false,
                    reason: None,
                })
                .await
                .unwrap();
            assert!(connector.config.is_none());
            assert!(connector.client.is_none());
        })
        .unwrap();
    }

    #[test]
    fn introspect_returns_all_operations() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 11);

        let op_ids: Vec<&str> = introspection
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        assert!(op_ids.contains(&OP_LIST_SUBSCRIPTIONS));
        assert!(op_ids.contains(&OP_LIST_RESOURCE_GROUPS));
        assert!(op_ids.contains(&OP_LIST_RESOURCES));
        assert!(op_ids.contains(&OP_BLOB_LIST_CONTAINERS));
        assert!(op_ids.contains(&OP_BLOB_LIST_BLOBS));
        assert!(op_ids.contains(&OP_BLOB_GET));
        assert!(op_ids.contains(&OP_BLOB_PUT));
        assert!(op_ids.contains(&OP_BLOB_DELETE));
        assert!(op_ids.contains(&OP_KEYVAULT_LIST_SECRETS));
        assert!(op_ids.contains(&OP_KEYVAULT_READ_VALUE));
        assert!(op_ids.contains(&OP_KEYVAULT_WRITE_VALUE));
    }

    #[test]
    fn introspection_exposes_typed_management_output_schema() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let operation = introspection
            .operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_LIST_SUBSCRIPTIONS)
            .expect("list_subscriptions operation should exist");
        assert_eq!(operation.idempotency, IdempotencyClass::Strict);
        assert_eq!(operation.output_schema["required"], json!(["value"]));
        assert_eq!(
            operation.output_schema["properties"]["value"]["type"],
            json!("array")
        );
        assert!(
            operation
                .description
                .as_deref()
                .is_some_and(|description| description.contains("configured credentials"))
        );
    }

    #[test]
    fn introspection_exposes_blob_put_override_schema() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let operation = introspection
            .operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_BLOB_PUT)
            .expect("blob_put operation should exist");
        assert_eq!(
            operation.input_schema["required"],
            json!([
                "storage_account",
                "container",
                "blob_name",
                "content_base64"
            ])
        );
        assert_eq!(
            operation.input_schema["properties"]["blob_base_url"]["type"],
            json!("string")
        );
        assert_eq!(
            operation.output_schema["properties"]["created"]["type"],
            json!("boolean")
        );
    }

    #[test]
    fn keyvault_set_secret_requires_approval() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let set_secret_op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == OP_KEYVAULT_WRITE_VALUE)
            .expect("keyvault_set_secret operation should exist");
        assert_eq!(
            set_secret_op.requires_approval,
            Some(ApprovalMode::Interactive)
        );
    }

    #[test]
    fn read_only_ops_do_not_require_approval() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let read_ops = [
            OP_LIST_SUBSCRIPTIONS,
            OP_LIST_RESOURCE_GROUPS,
            OP_LIST_RESOURCES,
            OP_BLOB_LIST_CONTAINERS,
            OP_BLOB_LIST_BLOBS,
            OP_BLOB_GET,
            OP_KEYVAULT_LIST_SECRETS,
            OP_KEYVAULT_READ_VALUE,
        ];
        for op_id in read_ops {
            let operation = introspection
                .operations
                .iter()
                .find(|o| o.id.as_str() == op_id)
                .expect("read operation should exist");
            assert_eq!(
                operation.requires_approval, None,
                "{op_id} should not require approval"
            );
        }
    }

    #[test]
    fn capability_mapping_is_complete() {
        let ops = [
            OP_LIST_SUBSCRIPTIONS,
            OP_LIST_RESOURCE_GROUPS,
            OP_LIST_RESOURCES,
            OP_BLOB_LIST_CONTAINERS,
            OP_BLOB_LIST_BLOBS,
            OP_BLOB_GET,
            OP_BLOB_PUT,
            OP_BLOB_DELETE,
            OP_KEYVAULT_LIST_SECRETS,
            OP_KEYVAULT_READ_VALUE,
            OP_KEYVAULT_WRITE_VALUE,
        ];
        for op_id in ops {
            assert!(
                AzureConnector::capability_for_operation(op_id).is_some(),
                "no capability mapping for {op_id}"
            );
        }
    }

    #[test]
    fn unknown_operation_has_no_capability() {
        assert!(AzureConnector::capability_for_operation("azure.unknown").is_none());
    }

    #[test]
    fn connector_id_is_fcp_azure() {
        let connector = AzureConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.azure");
    }

    #[test]
    fn default_impl_works() {
        let connector = AzureConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.azure");
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            AzureConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(AzureConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(AzureConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(AzureConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }
}
